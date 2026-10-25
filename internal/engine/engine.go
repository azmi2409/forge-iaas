// Package engine implements the forge-iaas execution engines.
//
// Two engines exist:
//
//   - MockEngine: parses .tf files for `resource "TYPE" "NAME"` lines
//     only (simple line scan, no HCL parser). It NEVER touches real
//     infrastructure. Every mock output string carries the marker
//     "MOCK ENGINE — no real infrastructure". The mock is selected
//     only when FIAAS_ENGINE=mock (see NewFromEnv) or in tests;
//     the production default is the tofu engine.
//   - TofuEngine: shells out to the OpenTofu binary (`tofu`). If the
//     binary is missing or init fails, it returns a LOUD error —
//     never a fake success, never a fabricated plan.
//
// Clean-room note: this package was written from the behaviour
// described in docs/INTERFACES.md and CONTRACT.md only. No
// Terraform/HashiCorp source was accessed or copied.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// Engine is the execution-engine interface (see docs/INTERFACES.md).
// vars is partitioned (see model.EngineVars): Terraform variables
// become TF_VAR_* and Env variables become raw process environment.
// That partition is load-bearing for cloud providers — the AWS
// provider reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
// AWS_REGION from the environment, not from TF_VAR_*.
type Engine interface {
	Plan(ctx context.Context, ws *model.Workspace, vars model.EngineVars) (*model.PlanSummary, error)
	Apply(ctx context.Context, ws *model.Workspace, plan *model.PlanSummary, vars model.EngineVars) (newState []byte, err error)
	Destroy(ctx context.Context, ws *model.Workspace, vars model.EngineVars) (newState []byte, err error)
}

// MockMarker appears in every mock engine output/log string.
const MockMarker = "MOCK ENGINE — no real infrastructure"

// NewFromEnv returns the mock engine when FIAAS_ENGINE=mock, and
// the tofu engine otherwise (binary from FIAAS_TOFU_BIN, default
// "tofu"). The mock is never the production default.
func NewFromEnv() Engine {
	if os.Getenv("FIAAS_ENGINE") == "mock" {
		return NewMockEngine()
	}
	return NewTofuEngine(tofuBinFromEnv())
}

func tofuBinFromEnv() string {
	if v := os.Getenv("FIAAS_TOFU_BIN"); v != "" {
		return v
	}
	return "tofu"
}

// ---------------------------------------------------------------------------
// Mock engine
// ---------------------------------------------------------------------------

// MockEngine parses .tf files for resource lines only.
type MockEngine struct{}

// NewMockEngine returns a mock engine. For tests and demos only.
func NewMockEngine() *MockEngine { return &MockEngine{} }

// resourceLine matches `resource "TYPE" "NAME"` on a single line.
var resourceLine = regexp.MustCompile(`^\s*resource\s+"([^"]+)"\s+"([^"]+)"`)

type mockResource struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// discover reads ws.ConfigPath and returns the resources declared in
// its .tf files, in deterministic order (sorted filenames, then line
// order). Duplicates are kept in first-seen order only once.
func (m *MockEngine) discover(ws *model.Workspace) ([]mockResource, error) {
	if ws == nil {
		return nil, fmt.Errorf("mock engine: nil workspace (%s)", MockMarker)
	}
	dir := ws.ConfigPath
	if dir == "" {
		return nil, fmt.Errorf("mock engine: workspace %s has no config path (%s)", ws.ID, MockMarker)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("mock engine: cannot read config dir %s: %w (%s)", dir, err, MockMarker)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".tf") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	seen := map[string]bool{}
	var out []mockResource
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, fmt.Errorf("mock engine: cannot read %s: %w (%s)", f, err, MockMarker)
		}
		for _, line := range strings.Split(string(b), "\n") {
			mm := resourceLine.FindStringSubmatch(line)
			if mm == nil {
				continue
			}
			key := mm[1] + "." + mm[2]
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, mockResource{Type: mm[1], Name: mm[2]})
		}
	}
	return out, nil
}

// mockStateSet parses a mock state JSON document into a set of
// "type.name" addresses already present in state. Unparseable or
// empty state yields an empty set (first plan: everything creates).
func mockStateSet(state []byte) map[string]bool {
	set := map[string]bool{}
	if len(state) == 0 {
		return set
	}
	var st struct {
		Resources []struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(state, &st); err != nil {
		return set
	}
	for _, r := range st.Resources {
		set[r.Type+"."+r.Name] = true
	}
	return set
}

func mockPlanSummary(resources []mockResource, inState map[string]bool) *model.PlanSummary {
	sum := &model.PlanSummary{}
	note := struct {
		Note      string `json:"note"`
		Resources []struct {
			Address string `json:"address"`
			Type    string `json:"type"`
			Action  string `json:"action"`
		} `json:"resources"`
	}{Note: MockMarker}
	for _, r := range resources {
		action := "create"
		if inState[r.Type+"."+r.Name] {
			action = "no-op"
		} else {
			sum.Add++
		}
		// Attributes pass through RedactAttributes even though the
		// mock emits no sensitive keys, so the redaction path is
		// exercised for every plan resource.
		attrs := model.RedactAttributes(map[string]any{"id": "mock-" + r.Type + "-" + r.Name})
		if action == "create" {
			// A not-yet-created resource has no id; keep only the
			// redacted shape with no value that could be mistaken
			// for a real identifier.
			attrs = model.RedactAttributes(map[string]any{})
		}
		sum.Resources = append(sum.Resources, model.ResourceChange{
			Address:    r.Type + "." + r.Name,
			Type:       r.Type,
			Action:     action,
			Attributes: attrs,
		})
		note.Resources = append(note.Resources, struct {
			Address string `json:"address"`
			Type    string `json:"type"`
			Action  string `json:"action"`
		}{Address: r.Type + "." + r.Name, Type: r.Type, Action: action})
	}
	if sum.Resources == nil {
		sum.Resources = []model.ResourceChange{}
	}
	raw, _ := json.Marshal(note)
	sum.RawPlanJSON = raw
	return sum
}

// Plan reports every discovered resource as a create. This is the
// first-plan rule: with no prior state, everything is new.
func (m *MockEngine) Plan(ctx context.Context, ws *model.Workspace, vars model.EngineVars) (*model.PlanSummary, error) {
	return m.PlanWithState(ctx, ws, vars, nil)
}

// PlanWithState is the state-aware plan used by the runner: resources
// already in the given state JSON are no-ops, new ones are creates.
// It is not part of the Engine interface; the runner uses it when
// the engine offers it (duck-typed).
func (m *MockEngine) PlanWithState(ctx context.Context, ws *model.Workspace, vars model.EngineVars, state []byte) (*model.PlanSummary, error) {
	_ = ctx
	_ = vars // mock ignores variable values; they are never logged
	resources, err := m.discover(ws)
	if err != nil {
		return nil, err
	}
	return mockPlanSummary(resources, mockStateSet(state)), nil
}

// mockStateDoc builds a state-version-4 JSON document for the given
// resources, with mock ids. The marker is embedded so every mock
// state output identifies itself.
func mockStateDoc(resources []mockResource) []byte {
	type instance struct {
		Attributes map[string]any `json:"attributes"`
	}
	type resource struct {
		Mode      string     `json:"mode"`
		Type      string     `json:"type"`
		Name      string     `json:"name"`
		Instances []instance `json:"instances"`
	}
	doc := struct {
		Version   int        `json:"version"`
		MockNote  string     `json:"mock_note"`
		Resources []resource `json:"resources"`
	}{Version: 4, MockNote: MockMarker, Resources: []resource{}}
	for _, r := range resources {
		doc.Resources = append(doc.Resources, resource{
			Mode: "managed", Type: r.Type, Name: r.Name,
			Instances: []instance{{Attributes: map[string]any{"id": "mock-" + r.Type + "-" + r.Name}}},
		})
	}
	b, _ := json.Marshal(doc)
	return b
}

// Apply returns a version-4 state document with mock ids for every
// discovered resource. It reflects the current config on disk.
func (m *MockEngine) Apply(ctx context.Context, ws *model.Workspace, plan *model.PlanSummary, vars model.EngineVars) ([]byte, error) {
	_ = ctx
	_ = plan // mock apply reflects current config, not the stale plan
	_ = vars // never logged
	resources, err := m.discover(ws)
	if err != nil {
		return nil, err
	}
	return mockStateDoc(resources), nil
}

// Destroy returns an empty-resources state document.
func (m *MockEngine) Destroy(ctx context.Context, ws *model.Workspace, vars model.EngineVars) ([]byte, error) {
	_ = ctx
	_ = vars // never logged
	if _, err := m.discover(ws); err != nil {
		return nil, err
	}
	return mockStateDoc(nil), nil
}

// ---------------------------------------------------------------------------
// OpenTofu engine
// ---------------------------------------------------------------------------

// TofuEngine shells out to the OpenTofu binary.
type TofuEngine struct {
	bin string
}

// NewTofuEngine returns an engine for the given binary path/name.
// An empty bin means "tofu" (from PATH).
func NewTofuEngine(bin string) *TofuEngine {
	if bin == "" {
		bin = "tofu"
	}
	return &TofuEngine{bin: bin}
}

// resolveBin returns a LOUD error when the binary cannot be found,
// so callers never proceed to a fabricated result.
func (t *TofuEngine) resolveBin() error {
	if strings.Contains(t.bin, string(os.PathSeparator)) {
		if _, err := os.Stat(t.bin); err != nil {
			return fmt.Errorf("tofu engine: binary %q not found (%v); install OpenTofu and set FIAAS_TOFU_BIN — refusing to fabricate a plan or state", t.bin, err)
		}
		return nil
	}
	if _, err := exec.LookPath(t.bin); err != nil {
		return fmt.Errorf("tofu engine: binary %q not found in PATH (%v); install OpenTofu and set FIAAS_TOFU_BIN — refusing to fabricate a plan or state", t.bin, err)
	}
	return nil
}

func (t *TofuEngine) workDir(ws *model.Workspace) (string, error) {
	if ws == nil {
		return "", fmt.Errorf("tofu engine: nil workspace")
	}
	if ws.ConfigPath == "" {
		return "", fmt.Errorf("tofu engine: workspace %s has no config path; refusing to run tofu with no configuration", ws.ID)
	}
	return ws.ConfigPath, nil
}

// secretValues returns variable values for redacting command output
// before it is ever embedded in an error.
func secretValues(vars model.EngineVars) []string {
	return vars.AllValues()
}

// awsEnvKeys are the environment keys the AWS provider (and the AWS
// SDKs it uses) reads for credentials, region, and identity. They
// are stripped from the inherited process environment unless the
// workspace explicitly sets them as env variables: otherwise a
// workspace with no AWS credentials would silently inherit the
// server process's credentials, and a workspace's own credentials
// could be shadowed by ambient ones. Stripping is what makes AWS
// support deterministic per workspace — and auditable, since the
// only credentials a run can see are the ones the workspace set.
var awsEnvKeys = map[string]bool{
	"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true,
	"AWS_SESSION_TOKEN": true, "AWS_SECURITY_TOKEN": true,
	"AWS_REGION": true, "AWS_DEFAULT_REGION": true,
	"AWS_PROFILE": true, "AWS_CONFIG_FILE": true,
	"AWS_SHARED_CREDENTIALS_FILE": true, "AWS_ROLE_ARN": true,
	"AWS_ROLE_SESSION_NAME": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true,
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": true,
	"AWS_CONTAINER_CREDENTIALS_FULL_URI":     true,
	// NOTE: AWS_CA_BUNDLE is deliberately NOT stripped. It is TLS
	// trust configuration (which CA bundle to verify AWS endpoints
	// with, e.g. behind an egress proxy), not account identity —
	// stripping it would break AWS access in proxied environments
	// for workspaces that set their own credentials.
}

// buildEnv builds the subprocess environment for a tofu run:
// inherited process env, minus any key the workspace overrides and
// minus ambient AWS keys the workspace did not set, plus
// TF_VAR_<key> for terraform variables and verbatim <key> for env
// variables. Later entries win for any key that still duplicates.
func buildEnv(vars model.EngineVars) []string {
	overridden := map[string]bool{}
	for k := range vars.Env {
		overridden[k] = true
	}
	for k := range vars.Terraform {
		overridden["TF_VAR_"+k] = true
	}
	var env []string
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if overridden[key] {
			continue
		}
		if awsEnvKeys[key] && vars.Env[key] == "" {
			// Ambient AWS credential/region/profile: strip it.
			// The workspace either sets it explicitly or the
			// provider fails loudly with no credentials.
			continue
		}
		env = append(env, e)
	}
	env = append(env, "CHECKPOINT_DISABLE=1", "TF_INPUT=0")
	for k, v := range vars.Terraform {
		env = append(env, "TF_VAR_"+k+"="+v)
	}
	for k, v := range vars.Env {
		env = append(env, k+"="+v)
	}
	return env
}

// runTofu executes tofu in dir with TF_VAR_* env entries for
// terraform variables and verbatim env entries for env variables
// (notably AWS_* for the AWS provider). Stdout and stderr are
// captured; on failure the returned error carries the redacted
// tail of the output, never variable values.
func (t *TofuEngine) runTofu(ctx context.Context, dir string, vars model.EngineVars, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, t.bin, args...)
	cmd.Dir = dir
	cmd.Env = buildEnv(vars)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		combined := strings.TrimSpace(stdout.String() + "\n" + stderr.String())
		combined = model.RedactText(combined, secretValues(vars)...)
		if len(combined) > 2000 {
			combined = combined[len(combined)-2000:]
		}
		return nil, fmt.Errorf("tofu engine: `tofu %s` failed: %w; output: %s", strings.Join(args, " "), err, combined)
	}
	return stdout.Bytes(), nil
}

func (t *TofuEngine) init(ctx context.Context, dir string, vars model.EngineVars) error {
	_, err := t.runTofu(ctx, dir, vars, "init", "-input=false")
	if err != nil {
		return fmt.Errorf("tofu engine: init failed — refusing to continue with a fabricated plan: %w", err)
	}
	return nil
}

// Plan runs init, plan -json -out, then show -json to parse
// resource_changes into a redacted PlanSummary.
func (t *TofuEngine) Plan(ctx context.Context, ws *model.Workspace, vars model.EngineVars) (*model.PlanSummary, error) {
	if err := t.resolveBin(); err != nil {
		return nil, err
	}
	dir, err := t.workDir(ws)
	if err != nil {
		return nil, err
	}
	if err := t.init(ctx, dir, vars); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, "fiaas-plan-*.tfplan")
	if err != nil {
		return nil, fmt.Errorf("tofu engine: cannot create plan file: %w", err)
	}
	planPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(planPath)

	// Task spec says `plan -json -out`; some tofu/terraform builds
	// reject combining -json with -out, so fall back to a plain
	// plan -out and rely on `show -json` for the machine-readable
	// resource_changes either way. A genuine config error fails
	// both attempts and is reported loudly.
	if _, err := t.runTofu(ctx, dir, vars, "plan", "-json", "-out="+planPath, "-input=false"); err != nil {
		if !strings.Contains(err.Error(), "json") {
			return nil, err
		}
		if _, err2 := t.runTofu(ctx, dir, vars, "plan", "-out="+planPath, "-input=false"); err2 != nil {
			return nil, err2
		}
	}
	showOut, err := t.runTofu(ctx, dir, vars, "show", "-json", planPath)
	if err != nil {
		return nil, fmt.Errorf("tofu engine: `tofu show -json` failed after a successful plan: %w", err)
	}
	var show struct {
		ResourceChanges []struct {
			Address string `json:"address"`
			Type    string `json:"type"`
			Change  struct {
				Actions []string       `json:"actions"`
				After   map[string]any `json:"after"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal(showOut, &show); err != nil {
		return nil, fmt.Errorf("tofu engine: cannot parse `tofu show -json` output: %w", err)
	}
	sum := &model.PlanSummary{RawPlanJSON: showOut}
	for _, rc := range show.ResourceChanges {
		action := tofuAction(rc.Change.Actions)
		switch action {
		case "create":
			sum.Add++
		case "update":
			sum.Change++
		case "delete":
			sum.Destroy++
		}
		sum.Resources = append(sum.Resources, model.ResourceChange{
			Address:    rc.Address,
			Type:       rc.Type,
			Action:     action,
			Attributes: model.RedactAttributes(rc.Change.After),
		})
	}
	if sum.Resources == nil {
		sum.Resources = []model.ResourceChange{}
	}
	return sum, nil
}

// tofuAction maps tofu change actions to PlanSummary actions.
// ["delete","create"] (replacement) counts as an update.
func tofuAction(actions []string) string {
	if len(actions) == 0 {
		return "no-op"
	}
	joined := strings.Join(actions, ",")
	switch joined {
	case "create":
		return "create"
	case "update":
		return "update"
	case "delete":
		return "delete"
	case "no-op":
		return "no-op"
	case "delete,create", "create,delete":
		return "update"
	default:
		// Unknown multi-action shape: safest is "update" (a change,
		// not a silent no-op, not an invented create/destroy).
		return "update"
	}
}

// Apply runs init + apply -auto-approve and returns the state file
// tofu wrote. If no state file exists afterwards, that is a loud
// error, not an occasion to invent state.
func (t *TofuEngine) Apply(ctx context.Context, ws *model.Workspace, plan *model.PlanSummary, vars model.EngineVars) ([]byte, error) {
	_ = plan // tofu applies the config on disk, not the summary
	if err := t.resolveBin(); err != nil {
		return nil, err
	}
	dir, err := t.workDir(ws)
	if err != nil {
		return nil, err
	}
	if err := t.init(ctx, dir, vars); err != nil {
		return nil, err
	}
	if _, err := t.runTofu(ctx, dir, vars, "apply", "-auto-approve", "-input=false"); err != nil {
		return nil, err
	}
	state, err := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if err != nil {
		return nil, fmt.Errorf("tofu engine: apply reported success but no terraform.tfstate was written in %s: %w — refusing to fabricate state", dir, err)
	}
	return state, nil
}

// Destroy runs init + destroy -auto-approve and returns the state
// file. If tofu wrote no state file (e.g. nothing ever existed),
// the canonical empty version-4 state is returned and documented
// here as the destroy outcome, not as invented infrastructure.
func (t *TofuEngine) Destroy(ctx context.Context, ws *model.Workspace, vars model.EngineVars) ([]byte, error) {
	if err := t.resolveBin(); err != nil {
		return nil, err
	}
	dir, err := t.workDir(ws)
	if err != nil {
		return nil, err
	}
	if err := t.init(ctx, dir, vars); err != nil {
		return nil, err
	}
	if _, err := t.runTofu(ctx, dir, vars, "destroy", "-auto-approve", "-input=false"); err != nil {
		return nil, err
	}
	state, err := os.ReadFile(filepath.Join(dir, "terraform.tfstate"))
	if err != nil {
		return []byte(`{"version":4,"resources":[]}`), nil
	}
	return state, nil
}
