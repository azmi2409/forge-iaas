// Package policy evaluates JSON policy rules against a plan summary
// and estimates monthly cost from a static price table.
//
// v1 rules are JSON rules only (model.PolicyRules). This package does
// NOT support Sentinel or OPA — those are explicitly deferred in
// CONTRACT.md. Unknown deny-rule forms produce an advisory message,
// never a silent pass.
package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// CostNote is always set on every CostEstimate: the figure is an
// estimate from a static table, not a cloud bill.
const CostNote = "estimate from static price table, not a cloud bill"

// Static monthly prices (USD) from docs/INTERFACES.md.
var instancePrices = map[string]float64{
	"t3.micro":  8,
	"t3.small":  16,
	"t3.medium": 32,
}

const (
	s3BucketPrice    = 2
	defaultTypePrice = 5
)

// resourceCost returns the static monthly USD cost of one resource
// change: for aws_instance the instance_type attribute selects the
// price; every other type uses its type default, and unknown types
// (or an aws_instance with an unrecognized/missing instance_type)
// fall back to the default unknown-type price.
func resourceCost(rc model.ResourceChange) float64 {
	switch rc.Type {
	case "aws_instance":
		if v, ok := rc.Attributes["instance_type"]; ok {
			if s, ok := v.(string); ok {
				if p, ok := instancePrices[s]; ok {
					return p
				}
			}
		}
		return defaultTypePrice
	case "aws_s3_bucket":
		return s3BucketPrice
	default:
		return defaultTypePrice
	}
}

// Estimate computes a monthly cost estimate for a plan. MonthlyUSD is
// the summed static price of every resource in the plan; DeltaUSD is
// the net change from non-no-op actions (creates/updates add, deletes
// subtract). Note is always the static-table disclaimer.
func Estimate(plan *model.PlanSummary) model.CostEstimate {
	est := model.CostEstimate{Note: CostNote}
	if plan == nil {
		return est
	}
	for _, rc := range plan.Resources {
		c := resourceCost(rc)
		est.MonthlyUSD += c
		switch rc.Action {
		case "create", "update":
			est.DeltaUSD += c
		case "delete":
			est.DeltaUSD -= c
		}
	}
	return est
}

// Evaluate checks a plan against every policy set. The result is
// "fail" if any hard violation exists, "advisory" if only
// unknown-form rules (or unparsable rule sets) were seen, and "pass"
// otherwise. Every message names the policy set, the rule, and —
// where a resource is involved — the resource address.
func Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult {
	if plan == nil {
		plan = &model.PlanSummary{}
	}
	var hard, advisory []string
	cost := Estimate(plan)

	for _, set := range sets {
		if set == nil {
			continue
		}
		var rules model.PolicyRules
		if len(set.RulesJSON) == 0 {
			continue
		}
		if err := json.Unmarshal(set.RulesJSON, &rules); err != nil {
			advisory = append(advisory, fmt.Sprintf(
				"policy %q: rules could not be parsed (%v); treated as advisory, not a pass", set.Name, err))
			continue
		}
		for _, rule := range rules.Deny {
			h, a := evalDeny(set.Name, rule, plan)
			hard = append(hard, h...)
			advisory = append(advisory, a...)
		}
		for _, tag := range rules.RequireTags {
			for _, rc := range plan.Resources {
				if !hasTag(rc, tag) {
					hard = append(hard, fmt.Sprintf(
						"policy %q require_tags: resource %s is missing required tag %q",
						set.Name, rc.Address, tag))
				}
			}
		}
		if rules.DenyDestroy {
			if plan.Destroy > 0 || hasDelete(plan) {
				addr := firstDeleteAddress(plan)
				if addr != "" {
					hard = append(hard, fmt.Sprintf(
						"policy %q deny_destroy: plan destroys resource %s (%d destroy actions)",
						set.Name, addr, plan.Destroy))
				} else {
					hard = append(hard, fmt.Sprintf(
						"policy %q deny_destroy: plan destroys %d resource(s)",
						set.Name, plan.Destroy))
				}
			}
		}
		if rules.MaxMonthlyCostUSD > 0 && cost.MonthlyUSD > rules.MaxMonthlyCostUSD {
			hard = append(hard, fmt.Sprintf(
				"policy %q max_monthly_cost_usd: estimated monthly cost %.2f USD exceeds budget %.2f USD",
				set.Name, cost.MonthlyUSD, rules.MaxMonthlyCostUSD))
		}
		if len(rules.AllowedRegions) > 0 {
			allowed := map[string]bool{}
			for _, r := range rules.AllowedRegions {
				allowed[r] = true
			}
			for _, rc := range plan.Resources {
				if v, ok := rc.Attributes["region"]; ok {
					if s, ok := v.(string); ok && s != "" && !allowed[s] {
						hard = append(hard, fmt.Sprintf(
							"policy %q allowed_regions: resource %s is in region %q, which is not allowed",
							set.Name, rc.Address, s))
					}
				}
			}
		}
	}

	switch {
	case len(hard) > 0:
		return model.PolicyResult{Result: model.PolicyFail, Messages: hard}
	case len(advisory) > 0:
		return model.PolicyResult{Result: model.PolicyAdvisory, Messages: advisory}
	default:
		return model.PolicyResult{Result: model.PolicyPass, Messages: nil}
	}
}

func hasDelete(plan *model.PlanSummary) bool {
	for _, rc := range plan.Resources {
		if rc.Action == "delete" {
			return true
		}
	}
	return false
}

func firstDeleteAddress(plan *model.PlanSummary) string {
	for _, rc := range plan.Resources {
		if rc.Action == "delete" {
			return rc.Address
		}
	}
	return ""
}

// hasTag reports whether a resource carries the tag key: either in a
// "tags" map attribute, or as a top-level attribute of that name.
func hasTag(rc model.ResourceChange, tag string) bool {
	if raw, ok := rc.Attributes["tags"]; ok {
		switch tags := raw.(type) {
		case map[string]any:
			if _, ok := tags[tag]; ok {
				return true
			}
		case map[string]string:
			if _, ok := tags[tag]; ok {
				return true
			}
		}
	}
	_, ok := rc.Attributes[tag]
	return ok
}

// Deny-rule contract forms (see CONTRACT.md):
//
//	resource type X where ATTR not in [a, b]
//	resource type X where ATTR = Y
//	resource type X where ATTR != Y
var (
	denyNotInRe = regexp.MustCompile(`(?i)^\s*resource\s+type\s+(\S+)\s+where\s+(\S+)\s+not\s+in\s*\[\s*(.*?)\s*\]\s*$`)
	denyEqRe    = regexp.MustCompile(`(?i)^\s*resource\s+type\s+(\S+)\s+where\s+(\S+)\s*(=|!=)\s*(\S+)\s*$`)
)

// evalDeny evaluates one deny string. A resource whose attribute
// matches the rule is a hard violation. An unrecognized form yields
// an advisory message, never a silent pass.
func evalDeny(setName, rule string, plan *model.PlanSummary) (hard, advisory []string) {
	if m := denyNotInRe.FindStringSubmatch(rule); m != nil {
		resType, attr := m[1], m[2]
		allowed := map[string]bool{}
		for _, item := range strings.Split(m[3], ",") {
			item = strings.TrimSpace(item)
			item = strings.Trim(item, `"'`)
			if item != "" {
				allowed[item] = true
			}
		}
		for _, rc := range plan.Resources {
			if rc.Type != resType {
				continue
			}
			v, ok := rc.Attributes[attr]
			if !ok {
				continue // attribute absent: cannot prove a match
			}
			s := stringify(v)
			if !allowed[s] {
				hard = append(hard, fmt.Sprintf(
					"policy %q deny rule %q: resource %s has %s=%s, which is not in [%s]",
					setName, rule, rc.Address, attr, s, m[3]))
			}
		}
		return hard, nil
	}
	if m := denyEqRe.FindStringSubmatch(rule); m != nil {
		resType, attr, op, want := m[1], m[2], m[3], strings.Trim(m[4], `"'`)
		for _, rc := range plan.Resources {
			if rc.Type != resType {
				continue
			}
			v, ok := rc.Attributes[attr]
			if !ok {
				continue
			}
			s := stringify(v)
			violates := (op == "=" && s == want) || (op == "!=" && s != want)
			if violates {
				hard = append(hard, fmt.Sprintf(
					"policy %q deny rule %q: resource %s has %s=%s",
					setName, rule, rc.Address, attr, s))
			}
		}
		return hard, nil
	}
	return nil, []string{fmt.Sprintf(
		"policy %q deny rule %q: unrecognized rule form; treated as advisory, not a pass",
		setName, rule)}
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
