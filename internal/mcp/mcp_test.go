package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// fakeStore mirrors the API test fake, scoped to MCP's Store interface.
type fakeStore struct {
	mu         sync.Mutex
	seq        int
	orgs       map[string]*model.Organization
	workspaces map[string]*model.Workspace
	runs       map[string]*model.Run
	states     map[string]*model.StateVersion
	modules    []*model.Module
	keys       map[string]*model.AgentKey
	audit      []*model.AuditEntry
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		orgs: map[string]*model.Organization{}, workspaces: map[string]*model.Workspace{},
		runs: map[string]*model.Run{}, states: map[string]*model.StateVersion{},
		keys: map[string]*model.AgentKey{},
	}
}

func (f *fakeStore) next(p string) string { f.seq++; return fmt.Sprintf("%s-%d", p, f.seq) }

func (f *fakeStore) addKey(scopes []string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	plain := "fiak_" + hex.EncodeToString(b)
	f.keys[plain] = &model.AgentKey{ID: f.next("key"), Prefix: plain[:12], Scopes: scopes, CreatedAt: time.Now()}
	return plain
}

func (f *fakeStore) AuthenticateKey(plaintext string) (*model.AgentKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[plaintext]
	if !ok {
		return nil, fmt.Errorf("unknown key")
	}
	return k, nil
}

func (f *fakeStore) CreateOrganization(name, slug string) (*model.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := &model.Organization{ID: f.next("org"), Name: name, Slug: slug, CreatedAt: time.Now()}
	f.orgs[o.ID] = o
	f.orgs[o.Slug] = o
	return o, nil
}

func (f *fakeStore) GetOrganization(idOrSlug string) (*model.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.orgs[idOrSlug]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return o, nil
}

func (f *fakeStore) ListOrganizations() ([]*model.Organization, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var out []*model.Organization
	for _, o := range f.orgs {
		if !seen[o.ID] {
			seen[o.ID] = true
			out = append(out, o)
		}
	}
	return out, nil
}

func (f *fakeStore) CreateWorkspace(w *model.Workspace) (*model.Workspace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.ID = f.next("ws")
	f.workspaces[w.ID] = w
	f.workspaces[w.Slug] = w
	return w, nil
}

func (f *fakeStore) GetWorkspace(idOrSlug string) (*model.Workspace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w, ok := f.workspaces[idOrSlug]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return w, nil
}

func (f *fakeStore) ListWorkspaces(orgID string) ([]*model.Workspace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	var out []*model.Workspace
	for _, w := range f.workspaces {
		if w.OrgID == orgID && !seen[w.ID] {
			seen[w.ID] = true
			out = append(out, w)
		}
	}
	return out, nil
}

func (f *fakeStore) CreateRun(r *model.Run) (*model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.ID = f.next("run")
	f.runs[r.ID] = r
	return r, nil
}

func (f *fakeStore) GetRun(id string) (*model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runs[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return r, nil
}

func (f *fakeStore) UpdateRun(r *model.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs[r.ID] = r
	return nil
}

func (f *fakeStore) SetVariable(wsID, setID, key, plaintext string, sensitive bool, category string) (*model.Variable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	disp := plaintext
	if sensitive {
		disp = "***"
	}
	return &model.Variable{ID: f.next("var"), WorkspaceID: wsID, Key: key, DisplayValue: disp, Sensitive: sensitive, Category: category}, nil
}

func (f *fakeStore) ListVariables(wsID string) ([]*model.Variable, error) { return nil, nil }

func (f *fakeStore) LatestStateVersion(wsID string) (*model.StateVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sv, ok := f.states[wsID]
	if !ok {
		return nil, fmt.Errorf("no state")
	}
	return sv, nil
}

func (f *fakeStore) CreateModule(m *model.Module, tarball []byte) (*model.Module, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m.ID = f.next("mod")
	f.modules = append(f.modules, m)
	return m, nil
}

func (f *fakeStore) ListModules() ([]*model.Module, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.modules, nil
}

func (f *fakeStore) CreatePolicySet(orgID, wsID, name string, rules []byte) (*model.PolicySet, error) {
	return &model.PolicySet{ID: f.next("pol"), OrgID: orgID, WorkspaceID: wsID, Name: name, RulesJSON: rules}, nil
}

func (f *fakeStore) ListPolicySets(orgID string) ([]*model.PolicySet, error) { return nil, nil }

func (f *fakeStore) AppendAudit(e *model.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audit = append(f.audit, e)
	return nil
}

func (f *fakeStore) ListAudit(wsID string, limit int) ([]*model.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.audit, nil
}

func (f *fakeStore) LatestDriftReport(wsID string) (*model.DriftReport, error) {
	return nil, fmt.Errorf("no drift report")
}

// --- client harness ---

type mcpClient struct {
	t   *testing.T
	cs  *sdk.ClientSession
	ctx context.Context
}

func newMCPClient(t *testing.T, store *fakeStore, opts Options) *mcpClient {
	t.Helper()
	srv := NewServer(store, opts)
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "v1"}, nil)
	t1, t2 := sdk.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.SDK().Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return &mcpClient{t: t, cs: cs, ctx: ctx}
}

func (c *mcpClient) call(name string, args map[string]any) *sdk.CallToolResult {
	c.t.Helper()
	res, err := c.cs.CallTool(c.ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		c.t.Fatalf("call %s: %v", name, err)
	}
	return res
}

func toolText(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestMCPToolListIsExactlyContract(t *testing.T) {
	fs := newFakeStore()
	c := newMCPClient(t, fs, Options{AllowAnon: true})
	var names []string
	for tool, err := range c.cs.Tools(c.ctx, nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		names = append(names, tool.Name)
	}
	want := []string{"workspace_list", "workspace_create", "workspace_get", "run_plan", "run_get",
		"run_approve", "run_discard", "state_read_redacted", "drift_check", "variable_set",
		"module_publish", "module_get", "policy_check", "cost_estimate", "audit_list"}
	if len(names) != len(want) {
		t.Fatalf("want %d tools, got %d: %v", len(want), len(names), names)
	}
	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing tool %s in %v", w, names)
		}
	}
}

func TestMCPPlanApproveScopeRules(t *testing.T) {
	fs := newFakeStore()
	adminKey := fs.addKey([]string{model.ScopeAdmin})
	planKey := fs.addKey([]string{model.ScopePlan})
	applyKey := fs.addKey([]string{model.ScopeApply})
	// Seed org + workspace directly in the fake.
	org, _ := fs.CreateOrganization("Acme", "acme")
	ws, _ := fs.CreateWorkspace(&model.Workspace{OrgID: org.ID, Name: "prod", Slug: "prod", ExecutionMode: "local"})

	c := newMCPClient(t, fs, Options{}) // no bound key; per-call agent_key
	res := c.call("run_plan", map[string]any{"workspace": ws.Slug, "agent_key": planKey})
	if res.IsError {
		t.Fatalf("run_plan with plan key should succeed: %s", toolText(t, res))
	}
	text := toolText(t, res)
	if !strings.Contains(text, "will not apply anything") {
		t.Fatalf("run_plan result must state the approval gate: %s", text)
	}
	// Extract the plan run id from the fake (only run so far).
	fs.mu.Lock()
	var planID string
	for id := range fs.runs {
		planID = id
	}
	fs.runs[planID].Status = model.StatusAwaitingApproval
	fs.runs[planID].Policy = &model.PolicyResult{Result: model.PolicyPass}
	fs.mu.Unlock()

	// Plan-scoped key cannot approve.
	res = c.call("run_approve", map[string]any{"run_id": planID, "agent_key": planKey})
	if !res.IsError {
		t.Fatalf("run_approve with plan key must fail, got: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "plan-scoped keys cannot approve") {
		t.Fatalf("approve rejection must name the scope rule: %s", toolText(t, res))
	}
	// Apply-scoped key can.
	res = c.call("run_approve", map[string]any{"run_id": planID, "agent_key": applyKey})
	if res.IsError {
		t.Fatalf("run_approve with apply key should succeed: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "apply run") {
		t.Fatalf("approve result must mention the apply run: %s", toolText(t, res))
	}
	// Admin key path also works via bound key.
	c2 := newMCPClient(t, fs, Options{AgentKey: mustKey(t, fs, adminKey)})
	res = c2.call("run_get", map[string]any{"run_id": planID})
	if res.IsError {
		t.Fatalf("run_get with admin key should succeed: %s", toolText(t, res))
	}
	if !strings.Contains(toolText(t, res), "Approval gate:") {
		t.Fatalf("run_get must state the approval gate: %s", toolText(t, res))
	}
}

func mustKey(t *testing.T, fs *fakeStore, plain string) *model.AgentKey {
	t.Helper()
	rec, err := fs.AuthenticateKey(plain)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return rec
}

func TestMCPStateReadRedacted(t *testing.T) {
	fs := newFakeStore()
	stateKey := fs.addKey([]string{model.ScopeStateRead})
	planKey := fs.addKey([]string{model.ScopePlan})
	org, _ := fs.CreateOrganization("Acme", "acme")
	ws, _ := fs.CreateWorkspace(&model.Workspace{OrgID: org.ID, Name: "prod", Slug: "prod"})
	fs.mu.Lock()
	fs.states[ws.ID] = &model.StateVersion{ID: "sv-1", WorkspaceID: ws.ID, Version: 2,
		Data: []byte(`{"version":4,"resources":[{"type":"aws_instance","name":"web","instances":[{"attributes":{"id":"i-123","password":"hunter2-secret"}}]}]}`)}
	fs.mu.Unlock()
	c := newMCPClient(t, fs, Options{})
	res := c.call("state_read_redacted", map[string]any{"workspace": ws.Slug, "agent_key": stateKey})
	if res.IsError {
		t.Fatalf("state_read_redacted should succeed: %s", toolText(t, res))
	}
	text := toolText(t, res)
	for _, leaked := range []string{"hunter2-secret", "i-123"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("state tool leaked %q: %s", leaked, text)
		}
	}
	if !strings.Contains(text, "aws_instance.web") {
		t.Fatalf("expected resource address in redacted state: %s", text)
	}
	// Plan-scoped key cannot read state.
	res = c.call("state_read_redacted", map[string]any{"workspace": ws.Slug, "agent_key": planKey})
	if !res.IsError {
		t.Fatalf("state read with plan key must fail")
	}
}

func TestMCPVariableSetNeverEchoesSensitive(t *testing.T) {
	fs := newFakeStore()
	planKey := fs.addKey([]string{model.ScopePlan})
	org, _ := fs.CreateOrganization("Acme", "acme")
	ws, _ := fs.CreateWorkspace(&model.Workspace{OrgID: org.ID, Name: "prod", Slug: "prod"})
	c := newMCPClient(t, fs, Options{})
	res := c.call("variable_set", map[string]any{
		"workspace": ws.Slug, "key": "DB_PASSWORD", "value": "hunter2-secret",
		"sensitive": true, "agent_key": planKey,
	})
	if res.IsError {
		t.Fatalf("variable_set should succeed: %s", toolText(t, res))
	}
	if strings.Contains(toolText(t, res), "hunter2-secret") {
		t.Fatalf("variable_set echoed sensitive value: %s", toolText(t, res))
	}
}
