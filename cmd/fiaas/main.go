// Command fiaas is the forge-iaas CLI (see CONTRACT.md).
//
// Every command accepts --json. Two modes:
//
//   - Remote mode: --server is set, or a login config exists. Commands
//     call the REST API with the stored key (from `fiaas login`, or the
//     FIAAS_AGENT_KEY environment variable as a fallback).
//   - Local mode: no server configured. Commands operate on the local
//     store file by running the API server's own handler in-process
//     (via httptest) as actor "local" with all scopes. This reuses the
//     API's auth/scope/redaction logic instead of duplicating it.
//
// Local mode needs a store opener: the coordinator sets OpenStore to
// the real internal/store opener. Until then, local commands fail with
// a clear "store not wired" error instead of faking results, while
// remote mode works fully. `fiaas runner` additionally needs
// RunnerLoop (internal/runner); remote polling is DEFERRED in v1 —
// `fiaas runner --server` errors rather than pretending to poll.
//
// Key handling: `fiaas login` stores server+key in
// ~/.config/fiaas/config.json with 0600 permissions (FIAAS_CONFIG_PATH
// overrides the path, for tests). `fiaas key create` prints the key
// ONCE; it is never stored by the CLI.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/azmi2409/forge-iaas/internal/api"
	"github.com/azmi2409/forge-iaas/internal/dashboard"
	"github.com/azmi2409/forge-iaas/internal/mcp"
)

var (
	jsonOut    bool
	serverFlag string
)

// OpenStore opens the local store for local mode. It is a variable so
// the coordinator can wire the real internal/store opener without this
// package importing it. The argument is the SQLite path (FIAAS_DB_PATH
// or ./forge-iaas.db); a coordinator implementation should also honor
// FIAAS_DATABASE_URL. When nil, local commands report that the store
// is not wired instead of fabricating results.
var OpenStore func(path string) (api.Store, error)

// RunnerLoop executes queued runs against the local store until ctx is
// done (supplied by internal/runner via the coordinator). When nil,
// `fiaas runner` and the serve command's in-process runner report that
// execution is not wired instead of pretending to run anything.
var RunnerLoop func(ctx context.Context, store api.Store) error

// ---------------------------------------------------------------- config

type loginConfig struct {
	Server string `json:"server"`
	Key    string `json:"key"`
}

// configPath returns the login config path. FIAAS_CONFIG_PATH is a
// test hook; otherwise ~/.config/fiaas/config.json.
func configPath() (string, error) {
	if p := os.Getenv("FIAAS_CONFIG_PATH"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "fiaas", "config.json"), nil
}

func loadConfig() (*loginConfig, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &loginConfig{}, nil
		}
		return nil, err
	}
	var cfg loginConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("corrupt config %s: %w", p, err)
	}
	return &cfg, nil
}

// writeConfig stores the login config with 0600 permissions, enforced
// even when the file already exists with wider permissions.
func writeConfig(cfg *loginConfig) (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(p, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// ---------------------------------------------------------------- clients

type apiClient interface {
	do(method, path string, body any) (int, []byte, error)
}

type remoteClient struct {
	base string
	key  string
	http *http.Client
}

func (c *remoteClient) do(method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, strings.TrimSuffix(c.base, "/")+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

type localClient struct {
	handler http.Handler
}

func (c *localClient) do(method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, path, rdr)
	if err != nil {
		return 0, nil, err
	}
	// In-process: httptest request/response, no network port.
	rec := newResponseRecorder()
	c.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), nil
}

// responseRecorder is a minimal httptest-like recorder kept local so
// this file does not import net/http/httptest in production code.
type responseRecorder struct {
	HeaderMap http.Header
	Body      bytes.Buffer
	Code      int
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{HeaderMap: http.Header{}, Code: 200}
}

func (r *responseRecorder) Header() http.Header { return r.HeaderMap }
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.Body.Write(b)
}
func (r *responseRecorder) WriteHeader(code int) { r.Code = code }

func dbPath() string {
	if p := os.Getenv("FIAAS_DB_PATH"); p != "" {
		return p
	}
	return "./forge-iaas.db"
}

func openLocalStore() (api.Store, error) {
	if OpenStore == nil {
		return nil, fmt.Errorf("local store is not wired: the coordinator must set fiaas.OpenStore " +
			"to the internal/store opener (remote mode with --server still works)")
	}
	return OpenStore(dbPath())
}

// resolveClient picks remote mode when --server is set or a login
// config names a server; otherwise it builds the in-process local
// client (which requires OpenStore).
func resolveClient() (apiClient, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	server := serverFlag
	if server == "" {
		server = cfg.Server
	}
	if server != "" {
		key := cfg.Key
		if key == "" {
			key = os.Getenv("FIAAS_AGENT_KEY")
		}
		return &remoteClient{base: server, key: key, http: &http.Client{Timeout: 60 * time.Second}}, nil
	}
	store, err := openLocalStore()
	if err != nil {
		return nil, err
	}
	srv := api.NewServer(store, api.Options{AllowAnon: true})
	return &localClient{handler: srv.Handler()}, nil
}

// callJSON performs one API call and decodes the JSON object response.
// On HTTP error it returns the server's {"error": ...} message.
func callJSON(c apiClient, method, path string, body any) (map[string]any, int, error) {
	status, raw, err := c.do(method, path, body)
	if err != nil {
		return nil, status, err
	}
	var m map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, status, fmt.Errorf("server returned non-JSON (HTTP %d): %s", status, strings.TrimSpace(string(raw)))
		}
	} else {
		m = map[string]any{}
	}
	if status >= 400 {
		if msg, ok := m["error"].(string); ok && msg != "" {
			return m, status, fmt.Errorf("%s", msg)
		}
		return m, status, fmt.Errorf("HTTP %d", status)
	}
	m["_raw"] = string(raw)
	return m, status, nil
}

// emit prints raw JSON in --json mode, else the human summary.
func emit(cmd *cobra.Command, raw string, human string) {
	if jsonOut {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			pretty, _ := json.MarshalIndent(v, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(pretty))
			return
		}
		fmt.Fprintln(cmd.OutOrStdout(), raw)
		return
	}
	fmt.Fprintln(cmd.OutOrStdout(), human)
}

func rawOf(m map[string]any) string {
	if r, ok := m["_raw"].(string); ok {
		return r
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func serverFlagChanged(cmd *cobra.Command) bool {
	f := cmd.Root().PersistentFlags().Lookup("server")
	return f != nil && f.Changed
}

// ---------------------------------------------------------------- root

func newRootCmd() *cobra.Command {
	jsonOut = false
	serverFlag = ""
	root := &cobra.Command{
		Use:           "fiaas",
		Short:         "forge-iaas: agent-ready Terraform control plane (TACOS)",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	// CONTRACT.md names the exact command set; cobra's default
	// completion command is not one of them.
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "output JSON")
	root.PersistentFlags().StringVar(&serverFlag, "server", "", "API server URL (remote mode; defaults to the login config)")
	root.AddCommand(newInitCmd(), newLoginCmd(), newWorkspaceCmd(), newRunCmd(),
		newStateCmd(), newVariableCmd(), newModuleCmd(), newDriftCmd(),
		newServeCmd(), newRunnerCmd(), newMCPCmd(), newKeyCmd())
	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- init / login

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init <name>",
		Short: "Scaffold a workspace config directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			dir := name
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			yaml := "name: " + name + "\nexecution_mode: local\n"
			if err := os.WriteFile(filepath.Join(dir, "fiaas.yaml"), []byte(yaml), 0o644); err != nil {
				return err
			}
			tf := "# forge-iaas workspace scaffold: " + name + "\n" +
				"# Add resource blocks here. Runs execute HCL via the OpenTofu binary;\n" +
				"# forge-iaas itself does not parse HCL or speak the provider protocol.\n"
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644); err != nil {
				return err
			}
			summary := map[string]any{"name": name, "dir": dir, "files": []string{"fiaas.yaml", "main.tf"}}
			b, _ := json.Marshal(summary)
			emit(cmd, string(b), "Scaffolded workspace config dir "+dir+" (fiaas.yaml, main.tf).")
			return nil
		},
	}
}

func newLoginCmd() *cobra.Command {
	var srv, key string
	c := &cobra.Command{
		Use:   "login",
		Short: "Store server URL + agent key in ~/.config/fiaas/config.json (0600)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if srv == "" {
				return fmt.Errorf("missing --server (e.g. --server http://localhost:8080)")
			}
			if key == "" {
				key = os.Getenv("FIAAS_AGENT_KEY")
			}
			if key == "" {
				return fmt.Errorf("missing --key (or set FIAAS_AGENT_KEY)")
			}
			p, err := writeConfig(&loginConfig{Server: srv, Key: key})
			if err != nil {
				return err
			}
			// Never print the key.
			b, _ := json.Marshal(map[string]any{"server": srv, "config": p})
			emit(cmd, string(b), "Logged in to "+srv+" (key stored 0600 at "+p+").")
			return nil
		},
	}
	c.Flags().StringVar(&srv, "server", "", "API server URL")
	c.Flags().StringVar(&key, "key", "", "agent key (fiak_…); falls back to FIAAS_AGENT_KEY")
	return c
}

// ---------------------------------------------------------------- workspace

func newWorkspaceCmd() *cobra.Command {
	var orgFlag, vcsRepo, vcsBranch, workDir, configPathFlag, execMode string
	var autoApply bool
	ws := &cobra.Command{Use: "workspace", Short: "Manage workspaces"}
	list := &cobra.Command{
		Use:   "list",
		Short: "List workspaces (all organizations, or --org)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient()
			if err != nil {
				return err
			}
			if orgFlag != "" {
				m, _, err := callJSON(c, "GET", "/api/v1/organizations/"+orgFlag+"/workspaces", nil)
				if err != nil {
					return err
				}
				emit(cmd, rawOf(m), summarizeList(m, "workspaces", "name"))
				return nil
			}
			orgs, _, err := callJSON(c, "GET", "/api/v1/organizations", nil)
			if err != nil {
				return err
			}
			var lines []string
			var all []any
			for _, o := range listOf(orgs, "organizations") {
				slug := str(o, "slug")
				wm, _, err := callJSON(c, "GET", "/api/v1/organizations/"+slug+"/workspaces", nil)
				if err != nil {
					return err
				}
				for _, w := range listOf(wm, "workspaces") {
					all = append(all, w)
					lines = append(lines, str(w, "slug")+"  id="+str(w, "id")+"  org="+slug+"  mode="+str(w, "execution_mode"))
				}
			}
			b, _ := json.Marshal(map[string]any{"workspaces": all})
			emit(cmd, string(b), strings.Join(lines, "\n"))
			return nil
		},
	}
	list.Flags().StringVar(&orgFlag, "org", "", "organization slug")
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if orgFlag == "" {
				return fmt.Errorf("missing --org")
			}
			c, err := resolveClient()
			if err != nil {
				return err
			}
			body := map[string]any{"name": args[0], "vcs_repo": vcsRepo, "vcs_branch": vcsBranch,
				"work_dir": workDir, "config_path": configPathFlag, "execution_mode": execMode, "auto_apply": autoApply}
			m, _, err := callJSON(c, "POST", "/api/v1/organizations/"+orgFlag+"/workspaces", body)
			if err != nil {
				return err
			}
			emit(cmd, rawOf(m), "Created workspace "+str(m, "slug")+" (id "+str(m, "id")+").")
			return nil
		},
	}
	create.Flags().StringVar(&orgFlag, "org", "", "organization slug")
	create.Flags().StringVar(&vcsRepo, "vcs-repo", "", "VCS repository")
	create.Flags().StringVar(&vcsBranch, "vcs-branch", "", "VCS branch")
	create.Flags().StringVar(&workDir, "work-dir", "", "working directory in the repo")
	create.Flags().StringVar(&configPathFlag, "config-path", "", "local dir with .tf files")
	create.Flags().StringVar(&execMode, "execution-mode", "remote", "remote or local")
	create.Flags().BoolVar(&autoApply, "auto-apply", false, "auto-apply approved plans (default false)")
	get := &cobra.Command{
		Use:   "get <workspace>",
		Short: "Get a workspace by id or slug",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient()
			if err != nil {
				return err
			}
			m, _, err := callJSON(c, "GET", "/api/v1/workspaces/"+args[0], nil)
			if err != nil {
				return err
			}
			emit(cmd, rawOf(m), str(m, "name")+" ("+str(m, "slug")+") mode="+str(m, "execution_mode")+" auto-apply="+fmt.Sprint(m["auto_apply"]))
			return nil
		},
	}
	ws.AddCommand(list, create, get)
	return ws
}

func listOf(m map[string]any, key string) []map[string]any {
	var out []map[string]any
	if arr, ok := m[key].([]any); ok {
		for _, item := range arr {
			if om, ok := item.(map[string]any); ok {
				out = append(out, om)
			}
		}
	}
	return out
}

func summarizeList(m map[string]any, key, nameField string) string {
	var lines []string
	for _, item := range listOf(m, key) {
		lines = append(lines, str(item, nameField)+"  id="+str(item, "id"))
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------- run

func newRunCmd() *cobra.Command {
	var wait bool
	var note string
	run := &cobra.Command{Use: "run", Short: "Manage runs"}
	for _, typ := range []string{"plan", "apply", "destroy"} {
		typ := typ
		sub := &cobra.Command{
			Use:   typ + " <workspace>",
			Short: "Create a " + typ + " run (queued; nothing executes until the runner picks it up)",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := resolveClient()
				if err != nil {
					return err
				}
				m, _, err := callJSON(c, "POST", "/api/v1/workspaces/"+args[0]+"/runs",
					map[string]any{"type": typ, "trigger": "cli"})
				if err != nil {
					return err
				}
				runID := str(m, "run_id")
				emit(cmd, rawOf(m), typ+" run "+runID+" queued (status "+str(m, "status")+").")
				if wait {
					return waitForRun(cmd, c, runID)
				}
				return nil
			},
		}
		run.AddCommand(sub)
	}
	approve := &cobra.Command{
		Use:   "approve <run-id>",
		Short: "Approve a plan run (creates a queued apply run; needs apply-scoped key in remote mode)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient()
			if err != nil {
				return err
			}
			body := map[string]any{}
			if note != "" {
				body["override_note"] = note
			}
			m, _, err := callJSON(c, "POST", "/api/v1/runs/"+args[0]+"/approve", body)
			if err != nil {
				return err
			}
			emit(cmd, rawOf(m), "Approved plan run "+str(m, "run_id")+" -> apply run "+str(m, "apply_run_id")+" queued.")
			return nil
		},
	}
	approve.Flags().StringVar(&note, "note", "", "override note (required when policy is advisory)")
	discard := &cobra.Command{
		Use:   "discard <run-id>",
		Short: "Discard a planned run",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient()
			if err != nil {
				return err
			}
			m, _, err := callJSON(c, "POST", "/api/v1/runs/"+args[0]+"/discard", map[string]any{})
			if err != nil {
				return err
			}
			emit(cmd, rawOf(m), "Discarded run "+str(m, "run_id")+" (status "+str(m, "status")+").")
			return nil
		},
	}
	run.PersistentFlags().BoolVar(&wait, "wait", false, "wait for the run to reach a terminal/approval status (up to ~60s)")
	run.AddCommand(approve, discard)
	return run
}

func waitForRun(cmd *cobra.Command, c apiClient, runID string) error {
	terminal := map[string]bool{
		"awaiting_approval": true, "applied": true, "failed": true,
		"discarded": true, "canceled": true,
	}
	var last string
	for i := 0; i < 30; i++ {
		m, _, err := callJSON(c, "GET", "/api/v1/runs/"+runID, nil)
		if err != nil {
			return err
		}
		last = str(m, "status")
		if terminal[last] {
			if !jsonOut {
				fmt.Fprintln(cmd.OutOrStdout(), "Run "+runID+" status: "+last)
			}
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Run "+runID+" still "+last+" after ~60s; the runner may not be running (fiaas runner / fiaas serve).")
	return nil
}

// ---------------------------------------------------------------- state / variable / module / drift

func newStateCmd() *cobra.Command {
	state := &cobra.Command{Use: "state", Short: "Inspect state (redacted only)"}
	show := &cobra.Command{
		Use:   "show <workspace>",
		Short: "Show the latest state, redacted to types/names/addresses only",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient()
			if err != nil {
				return err
			}
			m, _, err := callJSON(c, "GET", "/api/v1/workspaces/"+args[0]+"/state", nil)
			if err != nil {
				return err
			}
			var lines []string
			if arr, ok := m["resources"].([]any); ok {
				for _, r := range arr {
					if rm, ok := r.(map[string]any); ok {
						lines = append(lines, str(rm, "address")+" ("+str(rm, "type")+")")
					}
				}
			}
			emit(cmd, rawOf(m), "State version "+fmt.Sprint(m["state_version"])+":\n"+strings.Join(lines, "\n"))
			return nil
		},
	}
	state.AddCommand(show)
	return state
}

func newVariableCmd() *cobra.Command {
	var sensitive bool
	var category string
	variable := &cobra.Command{Use: "variable", Short: "Manage workspace variables"}
	set := &cobra.Command{
		Use:   "set <workspace> KEY=VALUE",
		Short: "Set a workspace variable (sensitive values are masked on read)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			kv := strings.SplitN(args[1], "=", 2)
			if len(kv) != 2 || kv[0] == "" {
				return fmt.Errorf("expected KEY=VALUE, got %q", args[1])
			}
			c, err := resolveClient()
			if err != nil {
				return err
			}
			m, _, err := callJSON(c, "POST", "/api/v1/workspaces/"+args[0]+"/variables",
				map[string]any{"key": kv[0], "value": kv[1], "sensitive": sensitive, "category": category})
			if err != nil {
				return err
			}
			emit(cmd, rawOf(m), "Set variable "+str(m, "key")+" (value "+str(m, "value")+").")
			return nil
		},
	}
	set.Flags().BoolVar(&sensitive, "sensitive", false, "mask the value on read")
	set.Flags().StringVar(&category, "category", "terraform", "terraform or env")
	variable.AddCommand(set)
	return variable
}

func newModuleCmd() *cobra.Command {
	var ns, name, provider, version, readme string
	module := &cobra.Command{Use: "module", Short: "Manage registry modules"}
	publish := &cobra.Command{
		Use:   "publish <dir>",
		Short: "Publish a module directory (tarball) to the registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := args[0]
			if ns == "" || name == "" || provider == "" || version == "" {
				if meta, err := readModuleJSON(dir); err == nil {
					if ns == "" {
						ns = meta["namespace"]
					}
					if name == "" {
						name = meta["name"]
					}
					if provider == "" {
						provider = meta["provider"]
					}
					if version == "" {
						version = meta["version"]
					}
					if readme == "" {
						readme = meta["readme"]
					}
				}
			}
			if ns == "" || name == "" || provider == "" || version == "" {
				return fmt.Errorf("module publish needs --namespace, --name, --provider, --version, or a module.json in the dir")
			}
			if readme == "" {
				if b, err := os.ReadFile(filepath.Join(dir, "README.md")); err == nil {
					readme = string(b)
				}
			}
			tarball, err := tarGzipDir(dir)
			if err != nil {
				return err
			}
			c, err := resolveClient()
			if err != nil {
				return err
			}
			m, _, err := callJSON(c, "POST", "/api/v1/registry/modules", map[string]any{
				"namespace": ns, "name": name, "provider": provider, "version": version,
				"readme": readme, "tarball_base64": base64.StdEncoding.EncodeToString(tarball),
			})
			if err != nil {
				return err
			}
			emit(cmd, rawOf(m), "Published module "+ns+"/"+name+" v"+version+".")
			return nil
		},
	}
	publish.Flags().StringVar(&ns, "namespace", "", "module namespace")
	publish.Flags().StringVar(&name, "name", "", "module name")
	publish.Flags().StringVar(&provider, "provider", "", "provider")
	publish.Flags().StringVar(&version, "version", "", "semver X.Y.Z")
	publish.Flags().StringVar(&readme, "readme", "", "README text (defaults to README.md in the dir)")
	module.AddCommand(publish)
	return module
}

func readModuleJSON(dir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "module.json"))
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func tarGzipDir(dir string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func newDriftCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "drift <workspace>",
		Short: "Show the latest drift report for a workspace (drift checks never apply)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := resolveClient()
			if err != nil {
				return err
			}
			m, _, err := callJSON(c, "GET", "/api/v1/workspaces/"+args[0]+"/drift", nil)
			if err != nil {
				return err
			}
			emit(cmd, rawOf(m), "Drifted: "+fmt.Sprint(m["drifted"])+" (report "+str(m, "id")+").")
			return nil
		},
	}
}

// ---------------------------------------------------------------- serve / runner / mcp / key

func newServeCmd() *cobra.Command {
	var addr string
	var allowAnon bool
	c := &cobra.Command{
		Use:   "serve",
		Short: "Serve the API + runner queue + web UI + MCP",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openLocalStore()
			if err != nil {
				return err
			}
			var runLoop api.RunLoop
			if RunnerLoop != nil {
				rl := RunnerLoop
				runLoop = func(ctx context.Context) error { return rl(ctx, store) }
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: in-process runner not wired (coordinator must set fiaas.RunnerLoop); runs will stay queued until fiaas runner runs.")
			}
			apiSrv := api.NewServer(store, api.Options{AllowAnon: allowAnon, RunLoop: runLoop})
			mcpPol, mcpCost := mcpPolicyCost()
			mcpSrv := mcp.NewServer(store, mcp.Options{AllowAnon: allowAnon, Policy: mcpPol, Cost: mcpCost})
			top := newServeMux(apiSrv, mcpSrv)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			if runLoop != nil {
				go func() {
					if err := apiSrv.Start(ctx); err != nil && ctx.Err() == nil {
						fmt.Fprintln(cmd.ErrOrStderr(), "runner loop error:", err)
					}
				}()
			}
			srv := &http.Server{Addr: addr, Handler: top}
			go func() {
				<-ctx.Done()
				shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutCtx)
			}()
			fmt.Fprintln(cmd.ErrOrStderr(), "forge-iaas serving on "+addr+" (API + dashboard + /mcp)")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	defAddr := os.Getenv("FIAAS_ADDR")
	if defAddr == "" {
		defAddr = ":8080"
	}
	c.Flags().StringVar(&addr, "addr", defAddr, "listen address (env FIAAS_ADDR)")
	c.Flags().BoolVar(&allowAnon, "allow-anon", false, "allow unauthenticated requests as local (dev only)")
	return c
}

// newServeMux composes the API, MCP, and dashboard handlers. The API
// handler owns /api/v1/*, /healthz, and /webhook/*; MCP owns /mcp;
// everything else is the dashboard.
func newServeMux(apiSrv *api.Server, mcpSrv *mcp.Server) http.Handler {
	top := http.NewServeMux()
	top.Handle("/api/v1/", apiSrv.Handler())
	top.Handle("/healthz", apiSrv.Handler())
	top.Handle("/webhook/", apiSrv.Handler())
	top.Handle("/mcp", mcpSrv.Handler())
	top.Handle("/mcp/", mcpSrv.Handler())
	top.Handle("/", dashboard.Handler())
	return top
}

func newRunnerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "runner",
		Short: "Polling runner against the LOCAL store file (remote polling is deferred in v1)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverFlagChanged(cmd) || serverFlag != "" {
				return fmt.Errorf("remote polling is deferred in v1: fiaas runner works against the local store file only; run it on the same machine as the store, or use fiaas serve's in-process runner")
			}
			store, err := openLocalStore()
			if err != nil {
				return err
			}
			if RunnerLoop == nil {
				return fmt.Errorf("runner execution is not wired: the coordinator must set fiaas.RunnerLoop " +
					"to the internal/runner loop; nothing has been executed")
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			fmt.Fprintln(cmd.ErrOrStderr(), "forge-iaas runner polling the local store (Ctrl-C to stop)…")
			return RunnerLoop(ctx, store)
		},
	}
}

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "MCP over stdio against the local store file (no running server required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openLocalStore()
			if err != nil {
				return err
			}
			opts := mcp.Options{}
			key := os.Getenv("FIAAS_AGENT_KEY")
			if key == "" {
				if cfg, err := loadConfig(); err == nil {
					key = cfg.Key
				}
			}
			if key != "" {
				rec, err := store.AuthenticateKey(key)
				if err != nil {
					return fmt.Errorf("agent key authentication failed: %w", err)
				}
				opts.AgentKey = rec
			}
			// Policy/Cost evaluators are wired to internal/policy.
			mcpPol, mcpCost := mcpPolicyCost()
			opts.Policy, opts.Cost = mcpPol, mcpCost
			srv := mcp.NewServer(store, opts)
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			return srv.RunStdio(ctx)
		},
	}
}

func newKeyCmd() *cobra.Command {
	var orgFlag, wsFlag, scopesFlag string
	key := &cobra.Command{Use: "key", Short: "Manage agent keys (local store only)"}
	create := &cobra.Command{
		Use:   "create",
		Short: "Create an agent key on the local store; prints the key ONCE",
		RunE: func(cmd *cobra.Command, args []string) error {
			if serverFlag != "" {
				return fmt.Errorf("key create operates on the local store only; unset --server")
			}
			if orgFlag == "" {
				return fmt.Errorf("missing --org")
			}
			if scopesFlag == "" {
				return fmt.Errorf("missing --scopes (comma-separated: plan, apply, destroy, state:read-redacted, registry:publish, admin)")
			}
			scopes := splitScopes(scopesFlag)
			for _, sc := range scopes {
				switch sc {
				case "plan", "apply", "destroy", "state:read-redacted", "registry:publish", "admin":
				default:
					return fmt.Errorf("unknown scope %q", sc)
				}
			}
			store, err := openLocalStore()
			if err != nil {
				return err
			}
			org, err := store.GetOrganization(orgFlag)
			if err != nil || org == nil {
				return fmt.Errorf("organization not found: %s", orgFlag)
			}
			plain, rec, err := store.CreateAgentKey(org.ID, wsFlag, scopes)
			if err != nil {
				return err
			}
			b, _ := json.Marshal(map[string]any{"key": plain, "prefix": rec.Prefix, "org_id": rec.OrgID, "scopes": rec.Scopes})
			if jsonOut {
				fmt.Fprintln(cmd.OutOrStdout(), string(b))
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), plain)
				fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: this key is shown ONCE. Store it now; forge-iaas keeps only its hash.")
			}
			return nil
		},
	}
	create.Flags().StringVar(&orgFlag, "org", "", "organization slug or id")
	create.Flags().StringVar(&wsFlag, "workspace", "", "workspace id to scope the key to (optional)")
	create.Flags().StringVar(&scopesFlag, "scopes", "", "comma-separated scopes")
	key.AddCommand(create)
	return key
}

func splitScopes(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
