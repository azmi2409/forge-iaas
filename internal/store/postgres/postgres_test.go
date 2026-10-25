package postgres

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/azmi2409/forge-iaas/internal/model"
	"github.com/azmi2409/forge-iaas/internal/store"
)

var testKey = bytes.Repeat([]byte("k"), 32)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	dsn := os.Getenv("FIAAS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("FIAAS_TEST_DATABASE_URL not set; skipping Postgres tests")
	}
	s, err := New(dsn, testKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewRequires32ByteKey(t *testing.T) {
	if _, err := New("postgres://localhost:5432/postgres?sslmode=disable", nil); err == nil {
		t.Fatal("expected error for nil key")
	}
	if _, err := New("postgres://localhost:5432/postgres?sslmode=disable", []byte("short")); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestStoreConformance(t *testing.T) {
	s := newTestStore(t)

	o, err := s.CreateOrganization("PG Acme", "pg-acme")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	gotOrg, err := s.GetOrganization("pg-acme")
	if err != nil || gotOrg.ID != o.ID {
		t.Fatalf("GetOrganization: %v %+v", err, gotOrg)
	}

	w, err := s.CreateWorkspace(&model.Workspace{OrgID: o.ID, Name: "PG WS", ExecutionMode: "remote"})
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	gotW, err := s.GetWorkspaceByID(w.ID)
	if err != nil || gotW.Slug != "pg-ws" {
		t.Fatalf("GetWorkspaceByID: %v %+v", err, gotW)
	}

	// Variables: sensitive masked on list, plaintext via runner accessor.
	secret := "pg-top-secret-value"
	if _, err := s.SetVariable(w.ID, "", "API_TOKEN", secret, true, "env"); err != nil {
		t.Fatalf("SetVariable: %v", err)
	}
	if _, err := s.SetVariable(w.ID, "", "REGION", "us-east-1", false, "terraform"); err != nil {
		t.Fatalf("SetVariable plain: %v", err)
	}
	vars, err := s.ListVariables(w.ID)
	if err != nil || len(vars) != 2 {
		t.Fatalf("ListVariables: %v %d", err, len(vars))
	}
	for _, v := range vars {
		if v.Key == "API_TOKEN" && v.DisplayValue != "***" {
			t.Fatalf("sensitive not masked: %q", v.DisplayValue)
		}
		if v.Key == "REGION" && v.DisplayValue != "us-east-1" {
			t.Fatalf("plain display wrong: %q", v.DisplayValue)
		}
	}
	pt, sens, err := s.GetVariablePlaintext(w.ID, "API_TOKEN")
	if err != nil || pt != secret || !sens {
		t.Fatalf("GetVariablePlaintext: %v %q %v", err, pt, sens)
	}

	// State versions auto-increment + encryption round-trip.
	sv1, err := s.CreateStateVersion(w.ID, []byte(`{"version":4,"resources":[]}`))
	if err != nil || sv1.Version != 1 {
		t.Fatalf("CreateStateVersion 1: %v %+v", err, sv1)
	}
	sv2, err := s.CreateStateVersion(w.ID, []byte(`{"version":4,"resources":[{"type":"aws_instance"}]}`))
	if err != nil || sv2.Version != 2 {
		t.Fatalf("CreateStateVersion 2: %v %+v", err, sv2)
	}
	latest, err := s.LatestStateVersion(w.ID)
	if err != nil || latest.Version != 2 || !bytes.Contains(latest.Data, []byte("aws_instance")) {
		t.Fatalf("LatestStateVersion: %v %+v", err, latest)
	}

	// Lock atomicity.
	ok, err := s.TryLockWorkspace(w.ID, "holder-a")
	if err != nil || !ok {
		t.Fatalf("first lock: %v %v", ok, err)
	}
	ok, err = s.TryLockWorkspace(w.ID, "holder-b")
	if err != nil || ok {
		t.Fatalf("second lock must fail: %v %v", ok, err)
	}
	if err := s.UnlockWorkspace(w.ID, "holder-a"); err != nil {
		t.Fatalf("unlock: %v", err)
	}

	// Claim: drain any leftover queued runs from earlier test runs in
	// this shared test database, then verify exact claim order.
	for {
		claimed, err := s.ClaimQueuedRun()
		if err != nil {
			t.Fatalf("drain ClaimQueuedRun: %v", err)
		}
		if claimed == nil {
			break
		}
	}
	plan, err := s.CreateRun(&model.Run{WorkspaceID: w.ID, Type: model.RunPlan, Trigger: model.TriggerCLI, Status: model.StatusQueued})
	if err != nil {
		t.Fatalf("CreateRun plan: %v", err)
	}
	apply, err := s.CreateRun(&model.Run{WorkspaceID: w.ID, Type: model.RunApply, Trigger: model.TriggerCLI, Status: model.StatusQueued, PlanRunID: plan.ID})
	if err != nil {
		t.Fatalf("CreateRun apply: %v", err)
	}
	claimed, err := s.ClaimQueuedRun()
	if err != nil || claimed == nil || claimed.ID != plan.ID || claimed.Status != model.StatusPlanning {
		t.Fatalf("claim plan: %v %+v", err, claimed)
	}
	claimed, err = s.ClaimQueuedRun()
	if err != nil || claimed == nil || claimed.ID != apply.ID || claimed.Status != model.StatusApplying {
		t.Fatalf("claim apply: %v %+v", err, claimed)
	}
	claimed, err = s.ClaimQueuedRun()
	if err != nil || claimed != nil {
		t.Fatalf("claim empty: %v %+v", err, claimed)
	}

	// Agent key: shape, authenticate, wrong key fails.
	plaintext, rec, err := s.CreateAgentKey(o.ID, w.ID, []string{model.ScopePlan})
	if err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}
	if !strings.HasPrefix(plaintext, "fiak_") || len(plaintext) != 5+32 {
		t.Fatalf("key shape wrong: %q", plaintext)
	}
	if rec.Hash != "" {
		t.Fatal("returned record must not carry the hash")
	}
	auth, err := s.AuthenticateKey(plaintext)
	if err != nil || auth.ID != rec.ID {
		t.Fatalf("AuthenticateKey: %v %+v", err, auth)
	}
	if _, err := s.AuthenticateKey("fiak_" + strings.Repeat("0", 32)); err == nil {
		t.Fatal("wrong key must fail authentication")
	}

	// Audit append/list (scoped to this workspace).
	if err := s.AppendAudit(&model.AuditEntry{Actor: "local", Action: "run.plan", WorkspaceID: w.ID, Detail: "planned"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	entries, err := s.ListAudit(w.ID, 10)
	if err != nil || len(entries) != 1 || entries[0].Action != "run.plan" {
		t.Fatalf("ListAudit: %v %+v", err, entries)
	}

	// Policy set, module, drift report smoke coverage.
	if _, err := s.CreatePolicySet(o.ID, w.ID, "guardrails", []byte(`{"deny_destroy":true}`)); err != nil {
		t.Fatalf("CreatePolicySet: %v", err)
	}
	if _, err := s.CreateModule(&model.Module{Namespace: "pg", Name: "vpc", Provider: "aws", Version: "1.0.0"}, []byte("tarball")); err != nil {
		t.Fatalf("CreateModule: %v", err)
	}
	if _, _, err := s.GetModule("pg", "vpc", "aws", "1.0.0"); err != nil {
		t.Fatalf("GetModule: %v", err)
	}
	if _, err := s.CreateDriftReport(&model.DriftReport{WorkspaceID: w.ID, Drifted: false}); err != nil {
		t.Fatalf("CreateDriftReport: %v", err)
	}
	if _, err := s.LatestDriftReport(w.ID); err != nil {
		t.Fatalf("LatestDriftReport: %v", err)
	}

	var _ store.Store = s
}
