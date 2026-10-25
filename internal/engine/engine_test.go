package engine

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azmi2409/forge-iaas/internal/model"
)

func writeTF(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testWorkspace(dir string) *model.Workspace {
	return &model.Workspace{ID: "ws-test", OrgID: "org-test", ConfigPath: dir}
}

func parseState(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("state is not valid JSON: %v", err)
	}
	return doc
}

func TestMockPlanApplyDestroyRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
variable "region" {}
resource "aws_instance" "web" {
  instance_type = "t3.micro"
}
resource "aws_s3_bucket" "data" {}
output "x" { value = "hi" }
`)
	eng := NewMockEngine()
	ws := testWorkspace(dir)

	plan, err := eng.Plan(ctx, ws, model.EngineVars{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Add != 2 || plan.Change != 0 || plan.Destroy != 0 {
		t.Fatalf("plan counts = add %d change %d destroy %d, want 2/0/0", plan.Add, plan.Change, plan.Destroy)
	}
	for _, rc := range plan.Resources {
		if rc.Action != "create" {
			t.Fatalf("first plan action for %s = %q, want create", rc.Address, rc.Action)
		}
	}
	if !strings.Contains(string(plan.RawPlanJSON), MockMarker) {
		t.Fatalf("plan RawPlanJSON does not contain mock marker: %s", plan.RawPlanJSON)
	}

	state, err := eng.Apply(ctx, ws, plan, model.EngineVars{})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	doc := parseState(t, state)
	if doc["version"] != float64(4) {
		t.Fatalf("state version = %v, want 4", doc["version"])
	}
	if !strings.Contains(string(state), MockMarker) {
		t.Fatalf("apply state does not contain mock marker")
	}
	resources, _ := doc["resources"].([]any)
	if len(resources) != 2 {
		t.Fatalf("state resources = %d, want 2", len(resources))
	}
	stateStr := string(state)
	for _, id := range []string{"mock-aws_instance-web", "mock-aws_s3_bucket-data"} {
		if !strings.Contains(stateStr, id) {
			t.Fatalf("state missing mock id %s: %s", id, stateStr)
		}
	}

	// Second plan against the applied state: everything is a no-op.
	plan2, err := eng.PlanWithState(ctx, ws, model.EngineVars{}, state)
	if err != nil {
		t.Fatalf("PlanWithState: %v", err)
	}
	if plan2.Add != 0 {
		t.Fatalf("second plan add = %d, want 0", plan2.Add)
	}
	for _, rc := range plan2.Resources {
		if rc.Action != "no-op" {
			t.Fatalf("second plan action for %s = %q, want no-op", rc.Address, rc.Action)
		}
	}

	empty, err := eng.Destroy(ctx, ws, model.EngineVars{})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	emptyDoc := parseState(t, empty)
	emptyRes, _ := emptyDoc["resources"].([]any)
	if len(emptyRes) != 0 {
		t.Fatalf("destroy state resources = %d, want 0", len(emptyRes))
	}
	if !strings.Contains(string(empty), MockMarker) {
		t.Fatalf("destroy state does not contain mock marker")
	}
}

func TestMockIgnoresNonResourceLines(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
# resource "fake" "commented" {}
locals {
  text = "resource \"also\" \"fake\""
}
resource "aws_instance" "real" {}
`)
	plan, err := NewMockEngine().Plan(ctx, testWorkspace(dir), model.EngineVars{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Add != 1 || len(plan.Resources) != 1 || plan.Resources[0].Address != "aws_instance.real" {
		t.Fatalf("plan = %+v, want exactly aws_instance.real", plan.Resources)
	}
}

func TestMockMissingDirErrorsLoudly(t *testing.T) {
	_, err := NewMockEngine().Plan(context.Background(), testWorkspace("/nonexistent-dir-xyz"), model.EngineVars{})
	if err == nil {
		t.Fatal("expected error for missing config dir, got nil")
	}
}

func TestNewFromEnvMock(t *testing.T) {
	t.Setenv("FIAAS_ENGINE", "mock")
	if _, ok := NewFromEnv().(*MockEngine); !ok {
		t.Fatalf("FIAAS_ENGINE=mock did not select MockEngine, got %T", NewFromEnv())
	}
	t.Setenv("FIAAS_ENGINE", "")
	if _, ok := NewFromEnv().(*TofuEngine); !ok {
		t.Fatalf("unset FIAAS_ENGINE did not select TofuEngine, got %T", NewFromEnv())
	}
}

func TestTofuMissingBinaryLoudError(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `resource "aws_instance" "web" {}`)
	eng := NewTofuEngine("fiaas-definitely-missing-binary-xyz")
	ws := testWorkspace(dir)
	if _, err := eng.Plan(ctx, ws, model.EngineVars{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Plan with missing binary: err = %v, want loud 'not found' error", err)
	}
	if _, err := eng.Apply(ctx, ws, nil, model.EngineVars{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Apply with missing binary: err = %v, want loud 'not found' error", err)
	}
	if _, err := eng.Destroy(ctx, ws, model.EngineVars{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Destroy with missing binary: err = %v, want loud 'not found' error", err)
	}
}

func TestTofuDefaultBinaryMissingSkipsWhenPresent(t *testing.T) {
	if _, err := exec.LookPath("tofu"); err == nil {
		t.Skip("tofu binary present; missing-binary case covered by TestTofuMissingBinaryLoudError")
	}
	_, err := NewTofuEngine("tofu").Plan(context.Background(), testWorkspace(t.TempDir()), model.EngineVars{})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Plan with default tofu binary absent: err = %v, want loud 'not found' error", err)
	}
}

func TestBuildEnvAWSProvider(t *testing.T) {
	// Ambient server credentials must NOT leak into a run, and a
	// workspace's own credentials must override them when set.
	t.Setenv("AWS_ACCESS_KEY_ID", "AMBIENT-KEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "AMBIENT-SECRET")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_CA_BUNDLE", "/ca/bundle.pem")
	t.Setenv("MY_UNRELATED", "keep-me")

	envMap := func(env []string) map[string]string {
		m := map[string]string{}
		for _, e := range env {
			k, v, _ := strings.Cut(e, "=")
			m[k] = v
		}
		return m
	}

	// Case 1: workspace sets its own AWS env vars -> they win,
	// terraform vars become TF_VAR_*, unrelated env is inherited.
	got := envMap(buildEnv(model.EngineVars{
		Terraform: map[string]string{"aws_region": "ap-southeast-1"},
		Env:       map[string]string{"AWS_ACCESS_KEY_ID": "WS-KEY", "AWS_SECRET_ACCESS_KEY": "WS-SECRET", "AWS_REGION": "ap-southeast-1"},
	}))
	if got["AWS_ACCESS_KEY_ID"] != "WS-KEY" || got["AWS_SECRET_ACCESS_KEY"] != "WS-SECRET" || got["AWS_REGION"] != "ap-southeast-1" {
		t.Fatalf("workspace AWS env not passed verbatim: %v", got)
	}
	if got["TF_VAR_aws_region"] != "ap-southeast-1" {
		t.Fatalf("terraform var not TF_VAR_-prefixed: %v", got)
	}
	if got["TF_VAR_AWS_ACCESS_KEY_ID"] != "" {
		t.Fatalf("AWS credential leaked into TF_VAR_*: %v", got)
	}
	if got["MY_UNRELATED"] != "keep-me" {
		t.Fatalf("unrelated inherited env dropped: %v", got)
	}

	// Case 2: workspace sets NO AWS vars -> ambient AWS keys are
	// stripped, so the provider fails loudly instead of silently
	// running on the server's credentials.
	got2 := envMap(buildEnv(model.EngineVars{
		Terraform: map[string]string{"bucket_name": "b"},
	}))
	if _, ok := got2["AWS_ACCESS_KEY_ID"]; ok {
		t.Fatalf("ambient AWS_ACCESS_KEY_ID leaked into run env")
	}
	if _, ok := got2["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Fatalf("ambient AWS_SECRET_ACCESS_KEY leaked into run env")
	}
	if _, ok := got2["AWS_REGION"]; ok {
		t.Fatalf("ambient AWS_REGION leaked into run env")
	}
	if got2["TF_VAR_bucket_name"] != "b" {
		t.Fatalf("terraform var missing in stripped case: %v", got2)
	}
	// CA bundle is TLS trust, not account identity: it passes
	// through even when the workspace sets no AWS credentials.
	if got2["AWS_CA_BUNDLE"] != "/ca/bundle.pem" {
		t.Fatalf("AWS_CA_BUNDLE should pass through, got %v", got2)
	}
}
