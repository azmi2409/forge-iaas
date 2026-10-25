package sqlite

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azmi2409/forge-iaas/internal/model"
	"github.com/azmi2409/forge-iaas/internal/store"
)

var testKey = bytes.Repeat([]byte("k"), 32)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "test.db"), testKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func mustOrg(t *testing.T, s *SQLiteStore, name, slug string) *model.Organization {
	t.Helper()
	o, err := s.CreateOrganization(name, slug)
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	return o
}

func mustWorkspace(t *testing.T, s *SQLiteStore, orgID, name string) *model.Workspace {
	t.Helper()
	w, err := s.CreateWorkspace(&model.Workspace{OrgID: orgID, Name: name, ExecutionMode: "remote"})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	return w
}

func TestNewRequires32ByteKey(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "x.db"), nil); err == nil {
		t.Fatal("expected error for nil key")
	}
	if _, err := New(filepath.Join(t.TempDir(), "x.db"), []byte("short")); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestOrgWorkspaceCRUD(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	if _, err := s.CreateOrganization("Dup", "acme"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected slug conflict, got %v", err)
	}
	got, err := s.GetOrganization("acme")
	if err != nil || got.ID != o.ID {
		t.Fatalf("GetOrganization by slug: %v %+v", err, got)
	}
	got, err = s.GetOrganization(o.ID)
	if err != nil || got.Slug != "acme" {
		t.Fatalf("GetOrganization by id: %v %+v", err, got)
	}
	if _, err := s.GetOrganization("nope"); err == nil {
		t.Fatal("expected not-found for unknown org")
	}
	orgs, err := s.ListOrganizations()
	if err != nil || len(orgs) != 1 {
		t.Fatalf("ListOrganizations: %v %d", err, len(orgs))
	}

	p, err := s.CreateProject(o.ID, "Platform", "platform")
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	projects, err := s.ListProjects(o.ID)
	if err != nil || len(projects) != 1 || projects[0].ID != p.ID {
		t.Fatalf("ListProjects: %v %+v", err, projects)
	}

	w := mustWorkspace(t, s, o.ID, "Web App")
	if w.Slug != "web-app" {
		t.Fatalf("expected derived slug web-app, got %q", w.Slug)
	}
	if w.ExecutionMode != "remote" {
		t.Fatalf("expected remote mode, got %q", w.ExecutionMode)
	}
	gotW, err := s.GetWorkspace(w.ID)
	if err != nil || gotW.Name != "Web App" {
		t.Fatalf("GetWorkspace by id: %v %+v", err, gotW)
	}
	gotW, err = s.GetWorkspace("web-app")
	if err != nil || gotW.ID != w.ID {
		t.Fatalf("GetWorkspace by slug: %v %+v", err, gotW)
	}
	gotW, err = s.GetWorkspaceByID(w.ID)
	if err != nil || gotW.ID != w.ID {
		t.Fatalf("GetWorkspaceByID: %v", err)
	}
	if _, err := s.GetWorkspaceByID("missing"); err == nil {
		t.Fatal("expected not-found for unknown workspace id")
	}
	ws, err := s.ListWorkspaces(o.ID)
	if err != nil || len(ws) != 1 {
		t.Fatalf("ListWorkspaces: %v %d", err, len(ws))
	}
	// Update (lock fields must survive an update untouched).
	if ok, err := s.TryLockWorkspace(w.ID, "run-1"); err != nil || !ok {
		t.Fatalf("TryLockWorkspace: %v %v", ok, err)
	}
	w.Name = "Web App v2"
	w.VCSRepo = "example/web"
	if err := s.UpdateWorkspace(w); err != nil {
		t.Fatalf("UpdateWorkspace: %v", err)
	}
	gotW, err = s.GetWorkspaceByID(w.ID)
	if err != nil || gotW.Name != "Web App v2" || gotW.VCSRepo != "example/web" || gotW.LockedBy != "run-1" {
		t.Fatalf("UpdateWorkspace mismatch: %v %+v", err, gotW)
	}
	if err := s.UnlockWorkspace(w.ID, "run-1"); err != nil {
		t.Fatalf("UnlockWorkspace: %v", err)
	}
	if err := s.DeleteWorkspace(w.ID); err != nil {
		t.Fatalf("DeleteWorkspace: %v", err)
	}
	if _, err := s.GetWorkspaceByID(w.ID); err == nil {
		t.Fatal("workspace should be gone after delete")
	}
	if err := s.DeleteWorkspace(w.ID); err == nil {
		t.Fatal("expected error deleting missing workspace")
	}
}

func TestVariableEncryptionAndMasking(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	secret := "top-secret-value-123"
	if _, err := s.SetVariable(w.ID, "", "API_TOKEN", secret, true, "env"); err != nil {
		t.Fatalf("SetVariable sensitive: %v", err)
	}
	if _, err := s.SetVariable(w.ID, "", "REGION", "us-east-1", false, "terraform"); err != nil {
		t.Fatalf("SetVariable plain: %v", err)
	}
	// Raw storage must not contain either plaintext (all values encrypted).
	var enc []byte
	if err := s.db.QueryRow(`SELECT value_enc FROM variables WHERE key = 'API_TOKEN'`).Scan(&enc); err != nil {
		t.Fatalf("raw query: %v", err)
	}
	if bytes.Contains(enc, []byte(secret)) {
		t.Fatal("sensitive value stored in plaintext")
	}
	vars, err := s.ListVariables(w.ID)
	if err != nil || len(vars) != 2 {
		t.Fatalf("ListVariables: %v %d", err, len(vars))
	}
	byKey := map[string]*model.Variable{}
	for _, v := range vars {
		byKey[v.Key] = v
	}
	if byKey["API_TOKEN"].DisplayValue != "***" || !byKey["API_TOKEN"].Sensitive {
		t.Fatalf("sensitive masking failed: %+v", byKey["API_TOKEN"])
	}
	if byKey["REGION"].DisplayValue != "us-east-1" || byKey["REGION"].Sensitive {
		t.Fatalf("non-sensitive display failed: %+v", byKey["REGION"])
	}
	if byKey["API_TOKEN"].Value != "" {
		t.Fatal("ListVariables must not populate Value")
	}
	pt, sens, err := s.GetVariablePlaintext(w.ID, "API_TOKEN")
	if err != nil || pt != secret || !sens {
		t.Fatalf("GetVariablePlaintext: %v %q %v", err, pt, sens)
	}
	if _, _, err := s.GetVariablePlaintext(w.ID, "MISSING"); err == nil {
		t.Fatal("expected error for missing variable")
	}
	// Upsert overwrites.
	if _, err := s.SetVariable(w.ID, "", "REGION", "eu-west-1", false, "terraform"); err != nil {
		t.Fatalf("SetVariable upsert: %v", err)
	}
	vars, _ = s.ListVariables(w.ID)
	if len(vars) != 2 || byKey["REGION"] == nil {
		t.Fatalf("upsert changed count: %d", len(vars))
	}
	pt, _, _ = s.GetVariablePlaintext(w.ID, "REGION")
	if pt != "eu-west-1" {
		t.Fatalf("upsert did not overwrite: %q", pt)
	}
	// Variable sets.
	vs, err := s.CreateVariableSet(o.ID, "shared")
	if err != nil {
		t.Fatalf("CreateVariableSet: %v", err)
	}
	if _, err := s.SetVariable("", vs.ID, "SHARED_KEY", "shared-val", false, "env"); err != nil {
		t.Fatalf("SetVariable in set: %v", err)
	}
	sets, err := s.ListVariableSets(o.ID)
	if err != nil || len(sets) != 1 || sets[0].ID != vs.ID {
		t.Fatalf("ListVariableSets: %v %+v", err, sets)
	}
	if _, err := s.SetVariable("", "", "ORPHAN", "x", false, "env"); err == nil {
		t.Fatal("expected error for variable with neither workspace nor set")
	}
}

func TestStateVersionAutoIncrementAndEncryption(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	if _, err := s.LatestStateVersion(w.ID); err == nil {
		t.Fatal("expected error with no state versions")
	}
	sv1, err := s.CreateStateVersion(w.ID, []byte(`{"version":4,"resources":[]}`))
	if err != nil {
		t.Fatalf("CreateStateVersion: %v", err)
	}
	if sv1.Version != 1 {
		t.Fatalf("expected version 1, got %d", sv1.Version)
	}
	sv2, err := s.CreateStateVersion(w.ID, []byte(`{"version":4,"resources":[{"type":"aws_instance"}]}`))
	if err != nil {
		t.Fatalf("CreateStateVersion 2: %v", err)
	}
	if sv2.Version != 2 {
		t.Fatalf("expected version 2, got %d", sv2.Version)
	}
	var enc []byte
	if err := s.db.QueryRow(`SELECT data_enc FROM state_versions WHERE version = 2`).Scan(&enc); err != nil {
		t.Fatalf("raw query: %v", err)
	}
	if bytes.Contains(enc, []byte("aws_instance")) {
		t.Fatal("state stored in plaintext")
	}
	latest, err := s.LatestStateVersion(w.ID)
	if err != nil || latest.Version != 2 || !bytes.Contains(latest.Data, []byte("aws_instance")) {
		t.Fatalf("LatestStateVersion: %v %+v", err, latest)
	}
	all, err := s.ListStateVersions(w.ID)
	if err != nil || len(all) != 2 || all[0].Version != 1 || all[1].Version != 2 {
		t.Fatalf("ListStateVersions: %v %+v", err, all)
	}
	if !bytes.Equal(all[0].Data, []byte(`{"version":4,"resources":[]}`)) {
		t.Fatalf("state round-trip failed: %q", all[0].Data)
	}
}

func TestTryLockAtomicity(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	ok, err := s.TryLockWorkspace(w.ID, "holder-a")
	if err != nil || !ok {
		t.Fatalf("first lock: %v %v", ok, err)
	}
	ok, err = s.TryLockWorkspace(w.ID, "holder-b")
	if err != nil || ok {
		t.Fatalf("second lock must fail: %v %v", ok, err)
	}
	if err := s.UnlockWorkspace(w.ID, "holder-b"); err == nil {
		t.Fatal("unlock by wrong holder must fail")
	}
	if err := s.UnlockWorkspace(w.ID, "holder-a"); err != nil {
		t.Fatalf("unlock by holder: %v", err)
	}
	ok, err = s.TryLockWorkspace(w.ID, "holder-b")
	if err != nil || !ok {
		t.Fatalf("lock after unlock: %v %v", ok, err)
	}
	if _, err := s.TryLockWorkspace("missing", "h"); err == nil {
		t.Fatal("expected error locking missing workspace")
	}
}

func TestClaimQueuedRunAtomicity(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	if claimed, err := s.ClaimQueuedRun(); err != nil || claimed != nil {
		t.Fatalf("empty claim: %v %+v", err, claimed)
	}
	plan, err := s.CreateRun(&model.Run{WorkspaceID: w.ID, Type: model.RunPlan, Trigger: model.TriggerCLI, Status: model.StatusQueued})
	if err != nil {
		t.Fatalf("CreateRun plan: %v", err)
	}
	apply, err := s.CreateRun(&model.Run{WorkspaceID: w.ID, Type: model.RunApply, Trigger: model.TriggerCLI, Status: model.StatusQueued, PlanRunID: plan.ID})
	if err != nil {
		t.Fatalf("CreateRun apply: %v", err)
	}
	drift, err := s.CreateRun(&model.Run{WorkspaceID: w.ID, Type: model.RunDrift, Trigger: model.TriggerSchedule, Status: model.StatusQueued})
	if err != nil {
		t.Fatalf("CreateRun drift: %v", err)
	}
	destroy, err := s.CreateRun(&model.Run{WorkspaceID: w.ID, Type: model.RunDestroy, Trigger: model.TriggerCLI, Status: model.StatusQueued})
	if err != nil {
		t.Fatalf("CreateRun destroy: %v", err)
	}
	claimed, err := s.ClaimQueuedRun()
	if err != nil || claimed == nil || claimed.ID != plan.ID || claimed.Status != model.StatusPlanning {
		t.Fatalf("claim 1 (plan->planning): %v %+v", err, claimed)
	}
	claimed, err = s.ClaimQueuedRun()
	if err != nil || claimed == nil || claimed.ID != apply.ID || claimed.Status != model.StatusApplying {
		t.Fatalf("claim 2 (apply->applying): %v %+v", err, claimed)
	}
	claimed, err = s.ClaimQueuedRun()
	if err != nil || claimed == nil || claimed.ID != drift.ID || claimed.Status != model.StatusPlanning {
		t.Fatalf("claim 3 (drift->planning): %v %+v", err, claimed)
	}
	claimed, err = s.ClaimQueuedRun()
	if err != nil || claimed == nil || claimed.ID != destroy.ID || claimed.Status != model.StatusApplying {
		t.Fatalf("claim 4 (destroy->applying): %v %+v", err, claimed)
	}
	claimed, err = s.ClaimQueuedRun()
	if err != nil || claimed != nil {
		t.Fatalf("claim 5 must be nil: %v %+v", err, claimed)
	}
	// A re-queued run is claimable again; a claimed run is not double-claimed.
	got, err := s.GetRun(plan.ID)
	if err != nil || got.Status != model.StatusPlanning {
		t.Fatalf("GetRun after claim: %v %+v", err, got)
	}
}

func TestRunCRUDAndLog(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	r, err := s.CreateRun(&model.Run{
		WorkspaceID: w.ID, Type: model.RunPlan, Trigger: model.TriggerAPI,
		Plan:   &model.PlanSummary{Add: 1, Resources: []model.ResourceChange{{Address: "aws_instance.web", Type: "aws_instance", Action: "create"}}},
		Policy: &model.PolicyResult{Result: model.PolicyPass, Messages: []string{"ok"}},
		Cost:   &model.CostEstimate{MonthlyUSD: 8, Note: "estimate from static price table, not a cloud bill"},
	})
	if err != nil {
		t.Fatalf("CreateRun: %v", err)
	}
	if r.Status != model.StatusQueued {
		t.Fatalf("default status must be queued, got %q", r.Status)
	}
	if err := s.AppendRunLog(r.ID, "planning..."); err != nil {
		t.Fatalf("AppendRunLog: %v", err)
	}
	if err := s.AppendRunLog(r.ID, "done"); err != nil {
		t.Fatalf("AppendRunLog 2: %v", err)
	}
	got, err := s.GetRun(r.ID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.Log != "planning...\ndone\n" {
		t.Fatalf("log mismatch: %q", got.Log)
	}
	if got.Plan == nil || got.Plan.Add != 1 || got.Plan.Resources[0].Address != "aws_instance.web" {
		t.Fatalf("plan round-trip failed: %+v", got.Plan)
	}
	if got.Policy == nil || got.Policy.Result != model.PolicyPass {
		t.Fatalf("policy round-trip failed: %+v", got.Policy)
	}
	if got.Cost == nil || got.Cost.MonthlyUSD != 8 {
		t.Fatalf("cost round-trip failed: %+v", got.Cost)
	}
	got.Status = model.StatusApplied
	if err := s.UpdateRun(got); err != nil {
		t.Fatalf("UpdateRun: %v", err)
	}
	got, _ = s.GetRun(r.ID)
	if got.Status != model.StatusApplied || got.FinishedAt == nil {
		t.Fatalf("terminal update must set finished_at: %+v", got)
	}
	if err := s.UpdateRun(&model.Run{ID: "missing", WorkspaceID: w.ID, Type: model.RunPlan}); err == nil {
		t.Fatal("expected error updating missing run")
	}
	if err := s.AppendRunLog("missing", "x"); err == nil {
		t.Fatal("expected error appending log to missing run")
	}
	runs, err := s.ListRuns(w.ID, 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns: %v %d", err, len(runs))
	}
	if _, err := s.GetRun("missing"); err == nil {
		t.Fatal("expected error for missing run")
	}
}

func TestAgentKeyCreateAuthenticate(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	plaintext, rec, err := s.CreateAgentKey(o.ID, w.ID, []string{model.ScopePlan, model.ScopeStateRead})
	if err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}
	if !strings.HasPrefix(plaintext, "fiak_") || len(plaintext) != 5+32 {
		t.Fatalf("plaintext key shape wrong: %q (len %d)", plaintext, len(plaintext))
	}
	if _, err := hex.DecodeString(plaintext[5:]); err != nil {
		t.Fatalf("key suffix not hex: %v", err)
	}
	if rec.Prefix != plaintext[:11] {
		t.Fatalf("prefix mismatch: %q vs %q", rec.Prefix, plaintext[:11])
	}
	if rec.Hash != "" {
		t.Fatal("returned record must not carry the hash")
	}
	// Hash at rest: stored value is SHA-256 hex of the plaintext, never the plaintext.
	var storedHash string
	if err := s.db.QueryRow(`SELECT hash FROM agent_keys WHERE id = ?`, rec.ID).Scan(&storedHash); err != nil {
		t.Fatalf("raw query: %v", err)
	}
	sum := sha256.Sum256([]byte(plaintext))
	if storedHash != hex.EncodeToString(sum[:]) {
		t.Fatal("stored hash is not SHA-256 of the plaintext key")
	}
	if storedHash == plaintext {
		t.Fatal("stored hash equals plaintext")
	}
	auth, err := s.AuthenticateKey(plaintext)
	if err != nil || auth.ID != rec.ID || auth.Prefix != rec.Prefix {
		t.Fatalf("AuthenticateKey: %v %+v", err, auth)
	}
	if len(auth.Scopes) != 2 || auth.Scopes[0] != model.ScopePlan {
		t.Fatalf("scopes round-trip failed: %v", auth.Scopes)
	}
	if _, err := s.AuthenticateKey("fiak_" + strings.Repeat("0", 32)); err == nil {
		t.Fatal("wrong key must fail authentication")
	}
	if _, err := s.AuthenticateKey("not-a-key"); err == nil {
		t.Fatal("garbage key must fail authentication")
	}
}

func TestAuditAppendList(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	other := mustWorkspace(t, s, o.ID, "Other")
	if err := s.AppendAudit(&model.AuditEntry{Actor: "local", Action: "workspace.create", WorkspaceID: w.ID, Detail: "created"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if err := s.AppendAudit(&model.AuditEntry{Actor: "local", Action: "run.plan", WorkspaceID: w.ID, Detail: "planned"}); err != nil {
		t.Fatalf("AppendAudit 2: %v", err)
	}
	if err := s.AppendAudit(&model.AuditEntry{Actor: "local", Action: "workspace.create", WorkspaceID: other.ID, Detail: "other"}); err != nil {
		t.Fatalf("AppendAudit 3: %v", err)
	}
	entries, err := s.ListAudit(w.ID, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("ListAudit filtered: %v %d", err, len(entries))
	}
	if entries[0].Action != "run.plan" {
		t.Fatalf("expected newest first, got %q", entries[0].Action)
	}
	all, err := s.ListAudit("", 10)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListAudit all: %v %d", err, len(all))
	}
	limited, err := s.ListAudit("", 1)
	if err != nil || len(limited) != 1 {
		t.Fatalf("ListAudit limit: %v %d", err, len(limited))
	}
	if err := s.AppendAudit(&model.AuditEntry{Actor: "local"}); err == nil {
		t.Fatal("expected error for audit entry without action")
	}
}

func TestPolicyModuleDrift(t *testing.T) {
	s := newTestStore(t)
	o := mustOrg(t, s, "Acme", "acme")
	w := mustWorkspace(t, s, o.ID, "WS")
	ps, err := s.CreatePolicySet(o.ID, w.ID, "guardrails", []byte(`{"deny_destroy":true}`))
	if err != nil {
		t.Fatalf("CreatePolicySet: %v", err)
	}
	sets, err := s.ListPolicySets(o.ID)
	if err != nil || len(sets) != 1 || sets[0].ID != ps.ID || string(sets[0].RulesJSON) != `{"deny_destroy":true}` {
		t.Fatalf("ListPolicySets: %v %+v", err, sets)
	}
	mod, err := s.CreateModule(&model.Module{Namespace: "acme", Name: "vpc", Provider: "aws", Version: "1.0.0", Readme: "hi"}, []byte("tarball-bytes"))
	if err != nil {
		t.Fatalf("CreateModule: %v", err)
	}
	if _, err := s.CreateModule(&model.Module{Namespace: "acme", Name: "vpc", Provider: "aws", Version: "1.0.0"}, []byte("dup")); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected duplicate module error, got %v", err)
	}
	gotMod, blob, err := s.GetModule("acme", "vpc", "aws", "1.0.0")
	if err != nil || gotMod.ID != mod.ID || !bytes.Equal(blob, []byte("tarball-bytes")) {
		t.Fatalf("GetModule: %v %+v %q", err, gotMod, blob)
	}
	if _, _, err := s.GetModule("acme", "vpc", "aws", "9.9.9"); err == nil {
		t.Fatal("expected error for missing module version")
	}
	mods, err := s.ListModules()
	if err != nil || len(mods) != 1 {
		t.Fatalf("ListModules: %v %d", err, len(mods))
	}
	if _, err := s.LatestDriftReport(w.ID); err == nil {
		t.Fatal("expected error with no drift reports")
	}
	dr, err := s.CreateDriftReport(&model.DriftReport{WorkspaceID: w.ID, Drifted: true, Summary: &model.PlanSummary{Add: 1}})
	if err != nil {
		t.Fatalf("CreateDriftReport: %v", err)
	}
	latest, err := s.LatestDriftReport(w.ID)
	if err != nil || latest.ID != dr.ID || !latest.Drifted || latest.Summary == nil || latest.Summary.Add != 1 {
		t.Fatalf("LatestDriftReport: %v %+v", err, latest)
	}
	var _ store.Store = s
}
