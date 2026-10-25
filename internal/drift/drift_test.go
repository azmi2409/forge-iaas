package drift

import (
	"testing"

	"github.com/azmi2409/forge-iaas/internal/model"
)

func TestCheckReportDrifted(t *testing.T) {
	dirty := &model.PlanSummary{Add: 1, Change: 0, Destroy: 0}
	r := CheckReport("ws-1", dirty)
	if !r.Drifted {
		t.Fatal("add>0: expected drifted=true")
	}
	if r.WorkspaceID != "ws-1" {
		t.Fatalf("workspace: got %q, want ws-1", r.WorkspaceID)
	}
	if r.Summary != dirty {
		t.Fatal("summary must be the plan itself")
	}

	for _, p := range []*model.PlanSummary{
		{Add: 0, Change: 1, Destroy: 0},
		{Add: 0, Change: 0, Destroy: 1},
	} {
		if r := CheckReport("ws-1", p); !r.Drifted {
			t.Fatalf("plan %+v: expected drifted=true", p)
		}
	}

	clean := &model.PlanSummary{Add: 0, Change: 0, Destroy: 0}
	if r := CheckReport("ws-1", clean); r.Drifted {
		t.Fatal("all-zero plan: expected drifted=false")
	}
	if r := CheckReport("ws-1", nil); r.Drifted || r.Summary == nil {
		t.Fatalf("nil plan: expected clean report with empty summary, got %+v", r)
	}
	// INTERFACES.md surface: Check with no workspace attached.
	if r := Check(clean); r.Drifted {
		t.Fatal("Check(clean): expected drifted=false")
	}
}

func TestCompare(t *testing.T) {
	a := &model.PlanSummary{Add: 1, Resources: []model.ResourceChange{{Address: "aws_instance.web", Action: "create"}}}
	b := &model.PlanSummary{Add: 1, Resources: []model.ResourceChange{{Address: "aws_instance.web", Action: "create"}}}
	if Compare(a, b) {
		t.Fatal("identical plans: expected no difference")
	}
	c := &model.PlanSummary{Add: 1, Resources: []model.ResourceChange{{Address: "aws_instance.web", Action: "update"}}}
	if !Compare(a, c) {
		t.Fatal("different action: expected a difference")
	}
}
