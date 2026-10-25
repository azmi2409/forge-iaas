package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// fakeStore is an in-memory Store for handler tests. It never stores a
// plaintext sensitive value in a readable field: variables keep the
// plaintext only in a private map, and ListVariables returns masked
// display values, mirroring the real store contract.
type fakeStore struct {
	mu         sync.Mutex
	seq        int
	orgs       map[string]*model.Organization
	workspaces map[string]*model.Workspace
	runs       map[string]*model.Run
	variables  map[string][]*model.Variable
	plainVars  map[string]map[string]string
	states     map[string]*model.StateVersion
	modules    []*model.Module
	policies   []*model.PolicySet
	keys       map[string]*model.AgentKey // plaintext -> record
	audit      []*model.AuditEntry
	drift      map[string]*model.DriftReport
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		orgs: map[string]*model.Organization{}, workspaces: map[string]*model.Workspace{},
		runs: map[string]*model.Run{}, variables: map[string][]*model.Variable{},
		plainVars: map[string]map[string]string{}, states: map[string]*model.StateVersion{},
		keys: map[string]*model.AgentKey{}, drift: map[string]*model.DriftReport{},
	}
}

func (f *fakeStore) next(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

func (f *fakeStore) addKey(prefix string, scopes []string, orgID, wsID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	plain := "fiak_" + hex.EncodeToString(b)
	f.keys[plain] = &model.AgentKey{ID: f.next("key"), Prefix: plain[:12], OrgID: orgID, WorkspaceID: wsID, Scopes: scopes, CreatedAt: time.Now()}
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

func (f *fakeStore) UpdateWorkspace(w *model.Workspace) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.workspaces[w.ID] = w
	return nil
}

func (f *fakeStore) DeleteWorkspace(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if w, ok := f.workspaces[id]; ok {
		delete(f.workspaces, id)
		delete(f.workspaces, w.Slug)
	}
	return nil
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

func (f *fakeStore) ListRuns(wsID string, limit int) ([]*model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*model.Run
	for _, r := range f.runs {
		if r.WorkspaceID == wsID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeStore) SetVariable(wsID, setID, key, plaintext string, sensitive bool, category string) (*model.Variable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.plainVars[wsID] == nil {
		f.plainVars[wsID] = map[string]string{}
	}
	f.plainVars[wsID][key] = plaintext
	disp := plaintext
	if sensitive {
		disp = "***"
	}
	v := &model.Variable{ID: f.next("var"), WorkspaceID: wsID, Key: key, DisplayValue: disp, Sensitive: sensitive, Category: category}
	vars := f.variables[wsID]
	for i, old := range vars {
		if old.Key == key {
			vars[i] = v
			f.variables[wsID] = vars
			return v, nil
		}
	}
	f.variables[wsID] = append(vars, v)
	return v, nil
}

func (f *fakeStore) ListVariables(wsID string) ([]*model.Variable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.variables[wsID], nil
}

func (f *fakeStore) LatestStateVersion(wsID string) (*model.StateVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sv, ok := f.states[wsID]
	if !ok {
		return nil, fmt.Errorf("no state")
	}
	return sv, nil
}

func (f *fakeStore) ListStateVersions(wsID string) ([]*model.StateVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sv, ok := f.states[wsID]; ok {
		return []*model.StateVersion{sv}, nil
	}
	return nil, nil
}

// setState seeds a raw state document for tests (test-only helper).
func (f *fakeStore) setState(wsID string, raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states[wsID] = &model.StateVersion{ID: f.next("sv"), WorkspaceID: wsID, Version: 1, Data: []byte(raw), CreatedAt: time.Now()}
}

func (f *fakeStore) CreateModule(m *model.Module, tarball []byte) (*model.Module, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, old := range f.modules {
		if old.Namespace == m.Namespace && old.Name == m.Name && old.Version == m.Version {
			return nil, fmt.Errorf("duplicate version")
		}
	}
	m.ID = f.next("mod")
	f.modules = append(f.modules, m)
	return m, nil
}

func (f *fakeStore) GetModule(ns, name, provider, version string) (*model.Module, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.modules {
		if m.Namespace == ns && m.Name == name && m.Version == version {
			return m, nil, nil
		}
	}
	return nil, nil, fmt.Errorf("not found")
}

func (f *fakeStore) ListModules() ([]*model.Module, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.modules, nil
}

func (f *fakeStore) CreatePolicySet(orgID, wsID, name string, rules []byte) (*model.PolicySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &model.PolicySet{ID: f.next("pol"), OrgID: orgID, WorkspaceID: wsID, Name: name, RulesJSON: rules, CreatedAt: time.Now()}
	f.policies = append(f.policies, p)
	return p, nil
}

func (f *fakeStore) ListPolicySets(orgID string) ([]*model.PolicySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*model.PolicySet
	for _, p := range f.policies {
		if p.OrgID == orgID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fakeStore) CreateAgentKey(orgID, wsID string, scopes []string) (string, *model.AgentKey, error) {
	plain := f.addKey("fiak_", scopes, orgID, wsID)
	f.mu.Lock()
	rec := f.keys[plain]
	f.mu.Unlock()
	return plain, rec, nil
}

func (f *fakeStore) AppendAudit(e *model.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e.ID = f.next("audit")
	f.audit = append(f.audit, e)
	return nil
}

func (f *fakeStore) ListAudit(wsID string, limit int) ([]*model.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*model.AuditEntry
	for _, e := range f.audit {
		if wsID == "" || e.WorkspaceID == wsID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeStore) LatestDriftReport(wsID string) (*model.DriftReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.drift[wsID]
	if !ok {
		return nil, fmt.Errorf("no drift report")
	}
	return r, nil
}

// --- request helpers ---

type testServer struct {
	store *fakeStore
	srv   *Server
}

func newTestServer(allowAnon bool) *testServer {
	fs := newFakeStore()
	return &testServer{store: fs, srv: NewServer(fs, Options{AllowAnon: allowAnon})}
}

func (ts *testServer) do(t *testing.T, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	ts.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not JSON object: %v (body %q)", err, rec.Body.String())
	}
	return m
}

func mustOrgWorkspace(t *testing.T, ts *testServer, adminKey string) (orgID, wsID string) {
	t.Helper()
	rec := ts.do(t, "POST", "/api/v1/organizations", adminKey, `{"name":"Acme","slug":"acme"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org: %d %s", rec.Code, rec.Body.String())
	}
	orgID = decodeBody(t, rec)["id"].(string)
	rec = ts.do(t, "POST", "/api/v1/organizations/acme/workspaces", adminKey, `{"name":"prod","execution_mode":"local"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create workspace: %d %s", rec.Code, rec.Body.String())
	}
	wsID = decodeBody(t, rec)["id"].(string)
	return orgID, wsID
}

func TestCreateOrgWorkspaceRun(t *testing.T) {
	ts := newTestServer(false)
	admin := ts.store.addKey("admin", []string{model.ScopeAdmin}, "", "")
	_, wsID := mustOrgWorkspace(t, ts, admin)
	rec := ts.do(t, "POST", "/api/v1/workspaces/"+wsID+"/runs", admin, `{"type":"plan"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create run: %d %s", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	if m["run_id"] == nil || m["run_id"] == "" {
		t.Fatalf("expected run_id, got %v", m)
	}
	if m["status"] != model.StatusQueued {
		t.Fatalf("expected queued, got %v", m["status"])
	}
	// Run detail round-trips.
	rec = ts.do(t, "GET", "/api/v1/runs/"+m["run_id"].(string), admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get run: %d %s", rec.Code, rec.Body.String())
	}
}

func TestApproveScopeRules(t *testing.T) {
	ts := newTestServer(false)
	admin := ts.store.addKey("admin", []string{model.ScopeAdmin}, "", "")
	planKey := ts.store.addKey("plan", []string{model.ScopePlan}, "", "")
	applyKey := ts.store.addKey("apply", []string{model.ScopeApply}, "", "")
	_, wsID := mustOrgWorkspace(t, ts, admin)

	newPlanRun := func(policy *model.PolicyResult) string {
		rec := ts.do(t, "POST", "/api/v1/workspaces/"+wsID+"/runs", admin, `{"type":"plan"}`)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("create run: %d %s", rec.Code, rec.Body.String())
		}
		id := decodeBody(t, rec)["run_id"].(string)
		ts.store.mu.Lock()
		ts.store.runs[id].Status = model.StatusAwaitingApproval
		ts.store.runs[id].Policy = policy
		ts.store.mu.Unlock()
		return id
	}

	// Plan-scoped key is rejected with 403.
	id := newPlanRun(&model.PolicyResult{Result: model.PolicyPass})
	rec := ts.do(t, "POST", "/api/v1/runs/"+id+"/approve", planKey, `{}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plan-scoped approve: want 403, got %d %s", rec.Code, rec.Body.String())
	}

	// Advisory policy without override_note -> 400.
	id = newPlanRun(&model.PolicyResult{Result: model.PolicyAdvisory, Messages: []string{"unknown rule form"}})
	rec = ts.do(t, "POST", "/api/v1/runs/"+id+"/approve", applyKey, `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("advisory without note: want 400, got %d %s", rec.Code, rec.Body.String())
	}

	// Advisory policy with override_note -> 200 with apply_run_id.
	rec = ts.do(t, "POST", "/api/v1/runs/"+id+"/approve", applyKey, `{"override_note":"accepted risk, tracked"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("advisory with note: want 200, got %d %s", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	if m["apply_run_id"] == nil || m["apply_run_id"] == "" {
		t.Fatalf("expected apply_run_id, got %v", m)
	}
	if m["run_id"] != id {
		t.Fatalf("expected run_id %s, got %v", id, m["run_id"])
	}

	// Policy fail blocks apply -> 409.
	id = newPlanRun(&model.PolicyResult{Result: model.PolicyFail, Messages: []string{"deny_destroy"}})
	rec = ts.do(t, "POST", "/api/v1/runs/"+id+"/approve", applyKey, `{"override_note":"nope"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("failed policy approve: want 409, got %d %s", rec.Code, rec.Body.String())
	}

	// Policy pass with apply-scoped key -> 200 with apply_run_id.
	id = newPlanRun(&model.PolicyResult{Result: model.PolicyPass})
	rec = ts.do(t, "POST", "/api/v1/runs/"+id+"/approve", applyKey, `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("pass approve: want 200, got %d %s", rec.Code, rec.Body.String())
	}
	if decodeBody(t, rec)["apply_run_id"] == nil {
		t.Fatalf("expected apply_run_id on pass approve")
	}
}

func TestSensitiveVariableMasked(t *testing.T) {
	ts := newTestServer(false)
	admin := ts.store.addKey("admin", []string{model.ScopeAdmin}, "", "")
	_, wsID := mustOrgWorkspace(t, ts, admin)
	rec := ts.do(t, "POST", "/api/v1/workspaces/"+wsID+"/variables", admin,
		`{"key":"DB_PASSWORD","value":"hunter2-secret","sensitive":true,"category":"env"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("set variable: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2-secret") {
		t.Fatalf("set response leaked sensitive value: %s", rec.Body.String())
	}
	rec = ts.do(t, "GET", "/api/v1/workspaces/"+wsID+"/variables", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list variables: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2-secret") {
		t.Fatalf("variable list leaked sensitive value: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"***"`) {
		t.Fatalf("expected masked value in %s", rec.Body.String())
	}
	// Audit must not contain the value either.
	rec = ts.do(t, "GET", "/api/v1/audit?workspace="+wsID, admin, "")
	if strings.Contains(rec.Body.String(), "hunter2-secret") {
		t.Fatalf("audit leaked sensitive value: %s", rec.Body.String())
	}
}

func TestStateEndpointRedactedOnly(t *testing.T) {
	ts := newTestServer(false)
	admin := ts.store.addKey("admin", []string{model.ScopeAdmin}, "", "")
	stateKey := ts.store.addKey("state", []string{model.ScopeStateRead}, "", "")
	_, wsID := mustOrgWorkspace(t, ts, admin)
	ts.store.setState(wsID, `{"version":4,"resources":[{"type":"aws_instance","name":"web","instances":[{"attributes":{"id":"i-123","password":"hunter2-secret","instance_type":"t3.micro"}}]}]}`)
	rec := ts.do(t, "GET", "/api/v1/workspaces/"+wsID+"/state", stateKey, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get state: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, leaked := range []string{"hunter2-secret", "i-123", "t3.micro", "password"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("state view leaked %q: %s", leaked, body)
		}
	}
	if !strings.Contains(body, "aws_instance.web") {
		t.Fatalf("expected resource address in state view: %s", body)
	}
	// State versions: metadata only.
	rec = ts.do(t, "GET", "/api/v1/workspaces/"+wsID+"/state/versions", stateKey, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list state versions: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2-secret") {
		t.Fatalf("state versions leaked raw state: %s", rec.Body.String())
	}
	// A plan-scoped key may not read state.
	planKey := ts.store.addKey("plan", []string{model.ScopePlan}, "", "")
	rec = ts.do(t, "GET", "/api/v1/workspaces/"+wsID+"/state", planKey, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plan-scoped state read: want 403, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestUnauthenticated401WhenAnonDisabled(t *testing.T) {
	ts := newTestServer(false)
	rec := ts.do(t, "GET", "/api/v1/organizations", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: want 401, got %d %s", rec.Code, rec.Body.String())
	}
	rec = ts.do(t, "GET", "/healthz", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz must not require auth: %d %s", rec.Code, rec.Body.String())
	}
}

func TestAllowAnonActsAsLocal(t *testing.T) {
	ts := newTestServer(true)
	rec := ts.do(t, "GET", "/api/v1/organizations", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("allow-anon list orgs: want 200, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestWebhookCreatesSpeculativePlanOnly(t *testing.T) {
	ts := newTestServer(false)
	admin := ts.store.addKey("admin", []string{model.ScopeAdmin}, "", "")
	_, wsID := mustOrgWorkspace(t, ts, admin)
	// Workspace has auto_apply=true; webhook must still only plan.
	ts.store.mu.Lock()
	ts.store.workspaces[wsID].AutoApply = true
	ts.store.mu.Unlock()
	rec := ts.do(t, "POST", "/webhook/vcs", "", `{"workspace_id":"`+wsID+`"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("webhook: want 202, got %d %s", rec.Code, rec.Body.String())
	}
	m := decodeBody(t, rec)
	if m["speculative"] != true {
		t.Fatalf("webhook response must flag speculative: %v", m)
	}
	runID := m["run_id"].(string)
	ts.store.mu.Lock()
	run := ts.store.runs[runID]
	ts.store.mu.Unlock()
	if run.Type != model.RunPlan {
		t.Fatalf("webhook run type must be plan, got %s", run.Type)
	}
}
