package policy

import (
	"strings"
	"testing"

	"github.com/azmi2409/forge-iaas/internal/model"
)

func set(rules string) *model.PolicySet {
	return &model.PolicySet{Name: "test-set", RulesJSON: []byte(rules)}
}

func plan(resources ...model.ResourceChange) *model.PlanSummary {
	p := &model.PlanSummary{Resources: resources}
	for _, rc := range resources {
		switch rc.Action {
		case "create":
			p.Add++
		case "update":
			p.Change++
		case "delete":
			p.Destroy++
		}
	}
	return p
}

func TestDenyNotInPassAndFail(t *testing.T) {
	s := set(`{"deny": ["resource type aws_instance where instance_type not in [t3.micro, t3.small]"]}`)
	ok := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"instance_type": "t3.small"}})
	if got := Evaluate(ok, []*model.PolicySet{s}); got.Result != model.PolicyPass {
		t.Fatalf("allowed instance type: got %s (%v), want pass", got.Result, got.Messages)
	}
	bad := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"instance_type": "m5.large"}})
	got := Evaluate(bad, []*model.PolicySet{s})
	if got.Result != model.PolicyFail {
		t.Fatalf("disallowed instance type: got %s, want fail", got.Result)
	}
	if !strings.Contains(got.Messages[0], "aws_instance.web") || !strings.Contains(got.Messages[0], "instance_type") {
		t.Fatalf("message must name resource and rule, got %q", got.Messages[0])
	}
	// Other resource types are untouched by the rule.
	other := plan(model.ResourceChange{Address: "aws_s3_bucket.b", Type: "aws_s3_bucket", Action: "create",
		Attributes: map[string]any{"instance_type": "m5.large"}})
	if got := Evaluate(other, []*model.PolicySet{s}); got.Result != model.PolicyPass {
		t.Fatalf("other type: got %s, want pass", got.Result)
	}
}

func TestDenyEqualsAndNotEquals(t *testing.T) {
	eq := set(`{"deny": ["resource type aws_s3_bucket where acl = public-read"]}`)
	bad := plan(model.ResourceChange{Address: "aws_s3_bucket.b", Type: "aws_s3_bucket", Action: "create",
		Attributes: map[string]any{"acl": "public-read"}})
	if got := Evaluate(bad, []*model.PolicySet{eq}); got.Result != model.PolicyFail {
		t.Fatalf("= match: got %s, want fail", got.Result)
	}
	ne := set(`{"deny": ["resource type aws_instance where tenancy != default"]}`)
	bad2 := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"tenancy": "dedicated"}})
	if got := Evaluate(bad2, []*model.PolicySet{ne}); got.Result != model.PolicyFail {
		t.Fatalf("!= match: got %s, want fail", got.Result)
	}
	ok := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"tenancy": "default"}})
	if got := Evaluate(ok, []*model.PolicySet{ne}); got.Result != model.PolicyPass {
		t.Fatalf("!= non-match: got %s, want pass", got.Result)
	}
}

func TestRequireTags(t *testing.T) {
	s := set(`{"require_tags": ["owner", "env"]}`)
	missing := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"tags": map[string]any{"owner": "azmi"}}})
	got := Evaluate(missing, []*model.PolicySet{s})
	if got.Result != model.PolicyFail {
		t.Fatalf("missing tag: got %s, want fail", got.Result)
	}
	if !strings.Contains(got.Messages[0], "aws_instance.web") || !strings.Contains(got.Messages[0], "env") {
		t.Fatalf("message must name resource and tag, got %q", got.Messages[0])
	}
	// Top-level attribute with the tag name also satisfies the rule.
	topLevel := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"owner": "azmi", "env": "prod"}})
	if got := Evaluate(topLevel, []*model.PolicySet{s}); got.Result != model.PolicyPass {
		t.Fatalf("top-level tags: got %s (%v), want pass", got.Result, got.Messages)
	}
	// Absent attributes entirely: missing tag counts as a violation.
	absent := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create"})
	if got := Evaluate(absent, []*model.PolicySet{s}); got.Result != model.PolicyFail {
		t.Fatalf("absent attributes: got %s, want fail", got.Result)
	}
}

func TestDenyDestroy(t *testing.T) {
	s := set(`{"deny_destroy": true}`)
	destroy := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "delete"})
	if got := Evaluate(destroy, []*model.PolicySet{s}); got.Result != model.PolicyFail {
		t.Fatalf("destroy plan: got %s, want fail", got.Result)
	}
	// Destroy count without a delete action listed still fails.
	countOnly := &model.PlanSummary{Destroy: 2}
	if got := Evaluate(countOnly, []*model.PolicySet{s}); got.Result != model.PolicyFail {
		t.Fatalf("destroy count: got %s, want fail", got.Result)
	}
	create := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create"})
	if got := Evaluate(create, []*model.PolicySet{s}); got.Result != model.PolicyPass {
		t.Fatalf("create-only plan: got %s, want pass", got.Result)
	}
}

func TestMaxMonthlyCost(t *testing.T) {
	s := set(`{"max_monthly_cost_usd": 20}`)
	under := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"instance_type": "t3.micro"}}) // 8
	if got := Evaluate(under, []*model.PolicySet{s}); got.Result != model.PolicyPass {
		t.Fatalf("under budget: got %s (%v), want pass", got.Result, got.Messages)
	}
	over := plan(
		model.ResourceChange{Address: "aws_instance.a", Type: "aws_instance", Action: "create",
			Attributes: map[string]any{"instance_type": "t3.medium"}}, // 32
	)
	if got := Evaluate(over, []*model.PolicySet{s}); got.Result != model.PolicyFail {
		t.Fatalf("over budget: got %s, want fail", got.Result)
	}
}

func TestAllowedRegions(t *testing.T) {
	s := set(`{"allowed_regions": ["ap-southeast-1", "ap-southeast-2"]}`)
	bad := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"region": "us-east-1"}})
	if got := Evaluate(bad, []*model.PolicySet{s}); got.Result != model.PolicyFail {
		t.Fatalf("disallowed region: got %s, want fail", got.Result)
	}
	ok := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"region": "ap-southeast-1"}})
	if got := Evaluate(ok, []*model.PolicySet{s}); got.Result != model.PolicyPass {
		t.Fatalf("allowed region: got %s, want pass", got.Result)
	}
	// No region attribute: no violation.
	none := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create"})
	if got := Evaluate(none, []*model.PolicySet{s}); got.Result != model.PolicyPass {
		t.Fatalf("no region attr: got %s, want pass", got.Result)
	}
}

func TestUnknownDenyFormIsAdvisoryNotPass(t *testing.T) {
	s := set(`{"deny": ["resource type aws_instance where instance_type matches t3.*"]}`)
	p := plan(model.ResourceChange{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
		Attributes: map[string]any{"instance_type": "t3.micro"}})
	got := Evaluate(p, []*model.PolicySet{s})
	if got.Result != model.PolicyAdvisory {
		t.Fatalf("unknown form: got %s, want advisory", got.Result)
	}
	if len(got.Messages) == 0 {
		t.Fatal("unknown form: expected an advisory message, got none")
	}
	// Unparsable rules JSON is advisory too, never a silent pass.
	broken := &model.PolicySet{Name: "broken", RulesJSON: []byte(`{not json`)}
	if got := Evaluate(p, []*model.PolicySet{broken}); got.Result != model.PolicyAdvisory {
		t.Fatalf("unparsable rules: got %s, want advisory", got.Result)
	}
}

func TestCostTableAndNote(t *testing.T) {
	cases := []struct {
		rc   model.ResourceChange
		want float64
	}{
		{model.ResourceChange{Type: "aws_instance", Action: "create", Attributes: map[string]any{"instance_type": "t3.micro"}}, 8},
		{model.ResourceChange{Type: "aws_instance", Action: "create", Attributes: map[string]any{"instance_type": "t3.small"}}, 16},
		{model.ResourceChange{Type: "aws_instance", Action: "create", Attributes: map[string]any{"instance_type": "t3.medium"}}, 32},
		{model.ResourceChange{Type: "aws_s3_bucket", Action: "create"}, 2},
		{model.ResourceChange{Type: "aws_lambda_function", Action: "create"}, 5},
		{model.ResourceChange{Type: "aws_instance", Action: "create"}, 5}, // no instance_type: type default
	}
	for _, tc := range cases {
		est := Estimate(&model.PlanSummary{Resources: []model.ResourceChange{tc.rc}})
		if est.MonthlyUSD != tc.want {
			t.Errorf("type %s attrs %v: got %.2f, want %.2f", tc.rc.Type, tc.rc.Attributes, est.MonthlyUSD, tc.want)
		}
		if est.Note != CostNote || !strings.Contains(est.Note, "not a cloud bill") {
			t.Errorf("note must state estimate, not a bill; got %q", est.Note)
		}
	}
	// Nil plan: zero cost, note still set.
	if est := Estimate(nil); est.MonthlyUSD != 0 || est.Note == "" {
		t.Errorf("nil plan: got %+v", est)
	}
}
