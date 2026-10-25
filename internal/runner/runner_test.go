package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azmi2409/forge-iaas/internal/engine"
	"github.com/azmi2409/forge-iaas/internal/model"
)

// --- in-memory fakes (test-only) -------------------------------------------

type fakeVar struct {
	plain     string
	sensitive bool
}

type fakeStore struct {
	mu         sync.Mutex
	workspaces map[string]*model.Workspace
	runs       []*model.Run
	runsByID   map[string]*model.Run
	logs       map[string][]string
	locks      map[string]string
	states     map[string][]*model.StateVersion
	drifts     []*model.DriftReport
	policySets []*model.PolicySet
	vars       map[string]map[string]fakeVar
	next       int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		workspaces: map[string]*model.Workspace{},
		runsByID:   map[string]*model.Run{},
		logs:       map[string][]string{},
		locks:      map[string]string{},
		states:     map[string][]*model.StateVersion{},
		vars:       map[string]map[string]fakeVar{},
	}
}

func (f *fakeStore) id(prefix string) string {
	f.next++
	return fmt.Sprintf("%s-%d", prefix, f.next)
}

func (f *fakeStore) addWorkspace(ws *model.Workspace) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.workspaces[ws.ID] = ws
}

func (f *fakeStore) addRun(r *model.Run) *model.Run {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.ID == "" {
		r.ID = f.id("run")
	}
	f.runs = append(f.runs, r)
	f.runsByID[r.ID] = r
	return r
}

func (f *fakeStore) GetWorkspaceByID(id string) (*model.Workspace, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ws, ok := f.workspaces[id]
	if !ok {
		return nil, fmt.Errorf("workspace %s not found", id)
	}
	return ws, nil
}

func (f *fakeStore) GetRun(id string) (*model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.runsByID[id]
	if !ok {
		return nil, fmt.Errorf("run %s not found", id)
	}
	return r, nil
}

func (f *fakeStore) UpdateRun(r *model.Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runsByID[r.ID] = r
	for i, old := range f.runs {
		if old.ID == r.ID {
			f.runs[i] = r
		}
	}
	return nil
}

func (f *fakeStore) AppendRunLog(id, line string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs[id] = append(f.logs[id], line)
	return nil
}

func (f *fakeStore) ClaimQueuedRun() (*model.Run, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.runs {
		if r.Status == model.StatusQueued {
			switch r.Type {
			case model.RunApply, model.RunDestroy:
				r.Status = model.StatusApplying
			default:
				r.Status = model.StatusPlanning
			}
			return r, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) TryLockWorkspace(id, holder string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.locks[id]; ok && cur != holder {
		return false, nil
	}
	f.locks[id] = holder
	return true, nil
}

func (f *fakeStore) UnlockWorkspace(id, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.locks[id]; !ok || cur != holder {
		return fmt.Errorf("workspace %s not locked by %s", id, holder)
	}
	delete(f.locks, id)
	return nil
}

func (f *fakeStore) LatestStateVersion(wsID string) (*model.StateVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.states[wsID]
	if len(list) == 0 {
		return nil, nil
	}
	return list[len(list)-1], nil
}

func (f *fakeStore) CreateStateVersion(wsID string, data []byte) (*model.StateVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sv := &model.StateVersion{
		ID:          f.id("sv"),
		WorkspaceID: wsID,
		Version:     len(f.states[wsID]) + 1,
		Data:        append([]byte(nil), data...),
		CreatedAt:   time.Now().UTC(),
	}
	f.states[wsID] = append(f.states[wsID], sv)
	return sv, nil
}

func (f *fakeStore) ListPolicySets(orgID string) ([]*model.PolicySet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*model.PolicySet
	for _, s := range f.policySets {
		if s.OrgID == orgID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeStore) GetVariablePlaintext(wsID, key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vars[wsID][key]
	if !ok {
		return "", false, nil
	}
	return v.plain, true, nil
}

func (f *fakeStore) ListVariables(wsID string) ([]*model.Variable, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*model.Variable
	for k, v := range f.vars[wsID] {
		display := v.plain
		if v.sensitive {
			display = "***"
		}
		out = append(out, &model.Variable{WorkspaceID: wsID, Key: k, DisplayValue: display, Sensitive: v.sensitive})
	}
	return out, nil
}

func (f *fakeStore) CreateRun(r *model.Run) (*model.Run, error) { return f.addRun(r), nil }

func (f *fakeStore) CreateDriftReport(r *model.DriftReport) (*model.DriftReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.ID == "" {
		r.ID = f.id("drift")
	}
	f.drifts = append(f.drifts, r)
	return r, nil
}

type fakePolicy struct {
	result   string
	messages []string
}

func (p fakePolicy) Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult {
	return model.PolicyResult{Result: p.result, Messages: p.messages}
}

// denyDestroyPolicy fails any run when a policy set has DenyDestroy,
// mirroring the contract rule without importing the policy package.
type denyDestroyPolicy struct{}

func (denyDestroyPolicy) Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult {
	for _, s := range sets {
		var rules model.PolicyRules
		if err := json.Unmarshal(s.RulesJSON, &rules); err == nil && rules.DenyDestroy {
			return model.PolicyResult{Result: model.PolicyFail, Messages: []string{"destroy denied by policy"}}
		}
	}
	return model.PolicyResult{Result: model.PolicyPass}
}

type fakeCost struct{}

func (fakeCost) Estimate(plan *model.PlanSummary) model.CostEstimate {
	return model.CostEstimate{MonthlyUSD: 42, Note: "estimate from static price table, not a cloud bill"}
}

// --- helpers ---------------------------------------------------------------

const testSecret = "my-token-value-xyz-secret"

func setupWS(t *testing.T, store *fakeStore, tf string) *model.Workspace {
	t.Helper()
	dir := t.TempDir()
	if err := writeTFHelper(t, dir, tf); err != nil {
		t.Fatal(err)
	}
	ws := &model.Workspace{ID: "ws-1", OrgID: "org-1", ConfigPath: dir}
	store.addWorkspace(ws)
	store.vars[ws.ID] = map[string]fakeVar{
		"api_token": {plain: testSecret, sensitive: true},
		"region":    {plain: "ap-southeast-1", sensitive: false},
	}
	return ws
}

func writeTFHelper(t *testing.T, dir, tf string) error {
	t.Helper()
	return os.WriteFile(dir+"/main.tf", []byte(tf), 0o644)
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func runStatus(t *testing.T, store *fakeStore, id string) *model.Run {
	t.Helper()
	r, err := store.GetRun(id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func logsContainSecret(store *fakeStore, secret string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, lines := range store.logs {
		for _, l := range lines {
			if strings.Contains(l, secret) {
				return true
			}
		}
	}
	return false
}

// --- tests -----------------------------------------------------------------

func TestRunnerPlanAwaitingApproval(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	ws := setupWS(t, store, "resource \"aws_instance\" \"web\" {}\nresource \"aws_s3_bucket\" \"data\" {}\n")
	planRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunPlan, Status: model.StatusQueued})
	r := New(store, engine.NewMockEngine(), fakePolicy{result: model.PolicyPass}, fakeCost{})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	got := runStatus(t, store, planRun.ID)
	if got.Status != model.StatusAwaitingApproval {
		t.Fatalf("plan run status = %q, want awaiting_approval (error: %q)", got.Status, got.Error)
	}
	if got.Plan == nil || got.Plan.Add != 2 {
		t.Fatalf("plan = %+v, want Add=2", got.Plan)
	}
	if got.Policy == nil || got.Policy.Result != model.PolicyPass {
		t.Fatalf("policy = %+v, want pass", got.Policy)
	}
	if got.Cost == nil || got.Cost.Note != "estimate from static price table, not a cloud bill" {
		t.Fatalf("cost = %+v, want disclaimer note", got.Cost)
	}
	if logsContainSecret(store, testSecret) {
		t.Fatal("sensitive variable value leaked into run logs")
	}
}

func TestRunnerPolicyFail(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	ws := setupWS(t, store, "resource \"aws_instance\" \"web\" {}\n")
	planRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunPlan, Status: model.StatusQueued})
	r := New(store, engine.NewMockEngine(), fakePolicy{result: model.PolicyFail, messages: []string{"instance type denied"}}, fakeCost{})
	if err := r.RunOnce(ctx); err == nil {
		t.Fatal("expected RunOnce error for policy fail, got nil")
	}
	got := runStatus(t, store, planRun.ID)
	if got.Status != model.StatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !strings.Contains(got.Error, "instance type denied") {
		t.Fatalf("error = %q, want policy message stored", got.Error)
	}
	if sv, _ := store.LatestStateVersion(ws.ID); sv != nil {
		t.Fatal("policy-failed plan must not create a state version")
	}
}

func TestRunnerApplyLockHeld(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	ws := setupWS(t, store, "resource \"aws_instance\" \"web\" {}\n")
	store.locks[ws.ID] = "other-run"
	applyRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunApply, Status: model.StatusQueued})
	r := New(store, engine.NewMockEngine(), fakePolicy{result: model.PolicyPass}, fakeCost{})
	if err := r.RunOnce(ctx); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("RunOnce err = %v, want lock error", err)
	}
	got := runStatus(t, store, applyRun.ID)
	if got.Status != model.StatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if sv, _ := store.LatestStateVersion(ws.ID); sv != nil {
		t.Fatal("lock-blocked apply must not create a state version")
	}
	// The pre-existing lock is untouched, and the run was not re-queued.
	if store.locks[ws.ID] != "other-run" {
		t.Fatalf("lock holder = %q, want other-run", store.locks[ws.ID])
	}
}

func TestRunnerApplySuccess(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	ws := setupWS(t, store, "resource \"aws_instance\" \"web\" {}\n")
	r := New(store, engine.NewMockEngine(), fakePolicy{result: model.PolicyPass}, fakeCost{})
	planRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunPlan, Status: model.StatusQueued})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("plan RunOnce: %v", err)
	}
	applyRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunApply, Status: model.StatusQueued, PlanRunID: planRun.ID})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("apply RunOnce: %v", err)
	}
	got := runStatus(t, store, applyRun.ID)
	if got.Status != model.StatusApplied {
		t.Fatalf("apply status = %q, want applied (error: %q)", got.Status, got.Error)
	}
	sv, err := store.LatestStateVersion(ws.ID)
	if err != nil || sv == nil {
		t.Fatalf("latest state = %v, %v, want a state version", sv, err)
	}
	if sv.Version != 1 {
		t.Fatalf("state version = %d, want 1", sv.Version)
	}
	if !strings.Contains(string(sv.Data), "mock-aws_instance-web") {
		t.Fatalf("state missing mock id: %s", sv.Data)
	}
	// Lock must be released after a successful apply.
	if ok, _ := store.TryLockWorkspace(ws.ID, "after-apply"); !ok {
		t.Fatal("workspace lock still held after successful apply")
	}
}

func TestRunnerDestroyDeniedByPolicy(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	ws := setupWS(t, store, "resource \"aws_instance\" \"web\" {}\n")
	store.policySets = append(store.policySets, &model.PolicySet{
		ID: "ps-1", OrgID: "org-1", Name: "no-destroy",
		RulesJSON: []byte(`{"deny_destroy":true}`),
	})
	destroyRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunDestroy, Status: model.StatusQueued})
	r := New(store, engine.NewMockEngine(), denyDestroyPolicy{}, fakeCost{})
	if err := r.RunOnce(ctx); err == nil || !strings.Contains(err.Error(), "destroy denied") {
		t.Fatalf("RunOnce err = %v, want destroy-denied error", err)
	}
	got := runStatus(t, store, destroyRun.ID)
	if got.Status != model.StatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if sv, _ := store.LatestStateVersion(ws.ID); sv != nil {
		t.Fatal("policy-blocked destroy must not create a state version")
	}
}

func TestRunnerDriftNeverApplies(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	ws := setupWS(t, store, "resource \"aws_instance\" \"web\" {}\n")
	r := New(store, engine.NewMockEngine(), fakePolicy{result: model.PolicyPass}, fakeCost{})
	planRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunPlan, Status: model.StatusQueued})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("plan: %v", err)
	}
	store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunApply, Status: model.StatusQueued, PlanRunID: planRun.ID})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// New resource appears after apply: drift should detect it and
	// must NOT create a new state version.
	if err := writeFile(ws.ConfigPath+"/extra.tf", "resource \"aws_s3_bucket\" \"new\" {}\n"); err != nil {
		t.Fatal(err)
	}
	driftRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunDrift, Status: model.StatusQueued})
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("drift: %v", err)
	}
	got := runStatus(t, store, driftRun.ID)
	if got.Status != model.StatusApplied {
		t.Fatalf("drift status = %q, want applied (check completed)", got.Status)
	}
	store.mu.Lock()
	driftCount := len(store.drifts)
	drifted := false
	if driftCount > 0 {
		drifted = store.drifts[driftCount-1].Drifted
	}
	store.mu.Unlock()
	if driftCount != 1 || !drifted {
		t.Fatalf("drift reports = %d drifted=%v, want 1 report with drifted=true", driftCount, drifted)
	}
	sv, _ := store.LatestStateVersion(ws.ID)
	if sv.Version != 1 {
		t.Fatalf("state version after drift = %d, want 1 (drift must not apply)", sv.Version)
	}
}

func TestRunnerRunLoopProcessesQueuedRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	store := newFakeStore()
	ws := setupWS(t, store, "resource \"aws_instance\" \"web\" {}\n")
	planRun := store.addRun(&model.Run{WorkspaceID: ws.ID, Type: model.RunPlan, Status: model.StatusQueued})
	r := New(store, engine.NewMockEngine(), fakePolicy{result: model.PolicyPass}, fakeCost{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunLoop(ctx, 10*time.Millisecond)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runStatus(t, store, planRun.ID).Status == model.StatusAwaitingApproval {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("RunLoop did not process the queued plan run in time")
}

func TestRunnerRunOnceEmptyQueue(t *testing.T) {
	r := New(newFakeStore(), engine.NewMockEngine(), fakePolicy{result: model.PolicyPass}, fakeCost{})
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("empty queue RunOnce = %v, want nil", err)
	}
}
