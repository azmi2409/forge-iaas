package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/azmi2409/forge-iaas/internal/api"
	"github.com/azmi2409/forge-iaas/internal/model"
)

// stubStore embeds api.Store so only the methods a test path touches
// need implementations; anything else panics if unexpectedly called.
type stubStore struct {
	api.Store
	orgs       []*model.Organization
	workspaces []*model.Workspace
	runs       []*model.Run
}

func (s *stubStore) ListOrganizations() ([]*model.Organization, error) { return s.orgs, nil }

func (s *stubStore) GetOrganization(idOrSlug string) (*model.Organization, error) {
	for _, o := range s.orgs {
		if o.ID == idOrSlug || o.Slug == idOrSlug {
			return o, nil
		}
	}
	return nil, errNotFound
}

func (s *stubStore) ListWorkspaces(orgID string) ([]*model.Workspace, error) {
	var out []*model.Workspace
	for _, w := range s.workspaces {
		if w.OrgID == orgID {
			out = append(out, w)
		}
	}
	return out, nil
}

func (s *stubStore) GetWorkspace(idOrSlug string) (*model.Workspace, error) {
	for _, w := range s.workspaces {
		if w.ID == idOrSlug || w.Slug == idOrSlug {
			return w, nil
		}
	}
	return nil, errNotFound
}

func (s *stubStore) CreateRun(r *model.Run) (*model.Run, error) {
	r.ID = "run-1"
	s.runs = append(s.runs, r)
	return r, nil
}

func (s *stubStore) AppendAudit(e *model.AuditEntry) error { return nil }

type errString string

func (e errString) Error() string { return string(e) }

const errNotFound = errString("not found")

func runRoot(t *testing.T, args []string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func withIsolatedConfig(t *testing.T) {
	t.Helper()
	t.Setenv("FIAAS_CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	// No server anywhere: local mode must not pick up a real config.
	t.Setenv("FIAAS_AGENT_KEY", "")
	old := OpenStore
	t.Cleanup(func() { OpenStore = old })
}

func TestJSONFlagParsing(t *testing.T) {
	withIsolatedConfig(t)
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t, []string{"--json", "init", "demo"})
	if err != nil {
		t.Fatalf("init --json: %v (out %q)", err, out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &m); err != nil {
		t.Fatalf("expected JSON output, got %q: %v", out, err)
	}
	if m["name"] != "demo" {
		t.Fatalf("expected name demo, got %v", m)
	}
	if _, err := os.Stat(filepath.Join(dir, "demo", "main.tf")); err != nil {
		t.Fatalf("init must scaffold main.tf: %v", err)
	}
	// Without --json the same command prints human text, not JSON.
	out, err = runRoot(t, []string{"init", "demo2"})
	if err != nil {
		t.Fatalf("init: %v (out %q)", err, out)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Fatalf("non-json init printed JSON: %q", out)
	}
}

func TestLoginFilePerms0600(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	// Pre-create with loose perms: login must tighten to 0600.
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIAAS_CONFIG_PATH", cfgPath)
	out, err := runRoot(t, []string{"login", "--server", "http://localhost:8080", "--key", "fiak_testkey123"})
	if err != nil {
		t.Fatalf("login: %v (out %q)", err, out)
	}
	if strings.Contains(out, "fiak_testkey123") {
		t.Fatalf("login output must never print the key: %q", out)
	}
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config perms must be 0600, got %o", info.Mode().Perm())
	}
	data, _ := os.ReadFile(cfgPath)
	var cfg loginConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "http://localhost:8080" || cfg.Key != "fiak_testkey123" {
		t.Fatalf("config not stored correctly: %+v", cfg)
	}
}

func TestSplitScopesAndKeyValue(t *testing.T) {
	scopes := splitScopes("plan, apply ,destroy")
	if len(scopes) != 3 || scopes[1] != "apply" {
		t.Fatalf("splitScopes wrong: %v", scopes)
	}
	kv := strings.SplitN("DB_HOST=localhost", "=", 2)
	if len(kv) != 2 || kv[0] != "DB_HOST" || kv[1] != "localhost" {
		t.Fatalf("KEY=VALUE split wrong: %v", kv)
	}
}

func TestTarGzipDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("# tf"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := tarGzipDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Fatalf("expected gzip output, got %d bytes", len(b))
	}
}

func TestLocalModeViaOpenStore(t *testing.T) {
	withIsolatedConfig(t)
	stub := &stubStore{
		orgs: []*model.Organization{{ID: "org-1", Name: "Acme", Slug: "acme", CreatedAt: time.Now()}},
		workspaces: []*model.Workspace{
			{ID: "ws-1", OrgID: "org-1", Name: "prod", Slug: "prod", ExecutionMode: "local"},
		},
	}
	OpenStore = func(path string) (api.Store, error) { return stub, nil }
	out, err := runRoot(t, []string{"workspace", "list"})
	if err != nil {
		t.Fatalf("workspace list (local): %v (out %q)", err, out)
	}
	if !strings.Contains(out, "prod") {
		t.Fatalf("expected workspace prod in output: %q", out)
	}
	out, err = runRoot(t, []string{"run", "plan", "prod"})
	if err != nil {
		t.Fatalf("run plan (local): %v (out %q)", err, out)
	}
	if !strings.Contains(out, "queued") {
		t.Fatalf("expected queued run in output: %q", out)
	}
}

func TestLocalModeWithoutOpenStoreErrorsClearly(t *testing.T) {
	withIsolatedConfig(t)
	OpenStore = nil
	_, err := runRoot(t, []string{"workspace", "list"})
	if err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("expected 'not wired' error, got %v", err)
	}
}
