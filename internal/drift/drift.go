// Package drift builds drift reports from a plan summary. A drift
// run never applies anything: it re-plans and compares, and the
// report records whether the plan differs from the latest state.
package drift

import (
	"time"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// Check is the INTERFACES.md surface: a report for a plan, with no
// workspace attached (the caller fills WorkspaceID, e.g. via
// CheckReport, before persisting).
func Check(plan *model.PlanSummary) *model.DriftReport {
	return CheckReport("", plan)
}

// CheckReport is the required surface: it builds a DriftReport for
// workspace wsID. Drifted is true exactly when the plan adds, changes,
// or destroys anything (add+change+destroy > 0); Summary is the plan
// itself.
func CheckReport(wsID string, plan *model.PlanSummary) *model.DriftReport {
	if plan == nil {
		plan = &model.PlanSummary{}
	}
	return &model.DriftReport{
		WorkspaceID: wsID,
		Drifted:     plan.Add+plan.Change+plan.Destroy > 0,
		Summary:     plan,
		CreatedAt:   time.Now().UTC(),
	}
}

// Compare reports whether two plan summaries differ: any difference
// in add/change/destroy counts, or in the set of resource addresses
// and their actions, counts as a difference. It is a convenience
// helper; CheckReport is the canonical drift surface.
func Compare(a, b *model.PlanSummary) bool {
	if a == nil {
		a = &model.PlanSummary{}
	}
	if b == nil {
		b = &model.PlanSummary{}
	}
	if a.Add != b.Add || a.Change != b.Change || a.Destroy != b.Destroy {
		return true
	}
	if len(a.Resources) != len(b.Resources) {
		return true
	}
	actions := map[string]string{}
	for _, rc := range a.Resources {
		actions[rc.Address] = rc.Action
	}
	for _, rc := range b.Resources {
		if act, ok := actions[rc.Address]; !ok || act != rc.Action {
			return true
		}
	}
	return false
}
