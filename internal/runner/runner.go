// Package runner executes queued runs per the canonical run flow in
// docs/INTERFACES.md:
//
//	plan run    -> planning -> Plan -> policy+cost -> awaiting_approval
//	             (policy fail -> failed, error/message stored, no apply)
//	apply run   -> lock -> Apply (linked plan's PlanSummary if present,
//	             else fresh Plan) -> new StateVersion -> applied
//	destroy run -> policy re-evaluated (deny_destroy -> failed) ->
//	             lock -> Destroy -> new StateVersion -> applied
//	drift run   -> fresh Plan -> DriftReport (drifted = add+change+
//	             destroy > 0) -> applied. A drift run NEVER applies
//	             anything; "applied" here means the drift check itself
//	             completed successfully (documented choice: there is
//	             no separate "drifted/clean" run status in the model).
//
// The runner never panics out of RunOnce: a panic is recovered and
// recorded as a failed run. Sensitive variable values are never
// logged; every log line passes through model.RedactText with the
// sensitive values as a second line of defence.
package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/azmi2409/forge-iaas/internal/engine"
	"github.com/azmi2409/forge-iaas/internal/model"
)

// Store is the small duck-typed interface the runner needs from a
// store implementation. It is declared here so the runner does not
// import any concrete store package.
type Store interface {
	GetWorkspaceByID(id string) (*model.Workspace, error)
	GetRun(id string) (*model.Run, error)
	UpdateRun(r *model.Run) error
	AppendRunLog(id, line string) error
	ClaimQueuedRun() (*model.Run, error)
	TryLockWorkspace(id, holder string) (bool, error)
	UnlockWorkspace(id, holder string) error
	LatestStateVersion(wsID string) (*model.StateVersion, error)
	CreateStateVersion(wsID string, data []byte) (*model.StateVersion, error)
	ListPolicySets(orgID string) ([]*model.PolicySet, error)
	GetVariablePlaintext(wsID, key string) (string, bool, error)
	ListVariables(wsID string) ([]*model.Variable, error)
	CreateRun(r *model.Run) (*model.Run, error)
	CreateDriftReport(r *model.DriftReport) (*model.DriftReport, error)
}

// PolicyEvaluator evaluates a plan against policy sets.
type PolicyEvaluator interface {
	Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult
}

// CostEstimator estimates the monthly cost of a plan.
type CostEstimator interface {
	Estimate(plan *model.PlanSummary) model.CostEstimate
}

// Runner executes queued runs one at a time.
type Runner struct {
	store  Store
	engine engine.Engine
	policy PolicyEvaluator
	cost   CostEstimator
}

// New returns a Runner. Any of policy/cost may be nil only if the
// caller never runs plan flows; plan/destroy flows treat a nil
// evaluator as pass / zero estimate respectively.
func New(store Store, eng engine.Engine, policy PolicyEvaluator, cost CostEstimator) *Runner {
	return &Runner{store: store, engine: eng, policy: policy, cost: cost}
}

// planWithState is the duck-typed state-aware plan method offered by
// the mock engine (and any engine that supports it).
type planWithState interface {
	PlanWithState(ctx context.Context, ws *model.Workspace, vars model.EngineVars, state []byte) (*model.PlanSummary, error)
}

func (r *Runner) log(runID string, secrets []string, format string, args ...any) {
	line := model.RedactText(fmt.Sprintf(format, args...), secrets...)
	// A logging failure must never fail the run itself.
	_ = r.store.AppendRunLog(runID, line)
}

func finishAtNow(r *model.Run) {
	now := time.Now().UTC()
	r.FinishedAt = &now
	r.UpdatedAt = now
}

// failRun records a terminal failure on the run (redacted) and logs
// it. It returns an error describing the failure for RunOnce.
func (r *Runner) failRun(run *model.Run, secrets []string, errMsg string) error {
	errMsg = model.RedactText(errMsg, secrets...)
	run.Status = model.StatusFailed
	run.Error = errMsg
	finishAtNow(run)
	r.log(run.ID, secrets, "run failed: %s", errMsg)
	_ = r.store.UpdateRun(run)
	return fmt.Errorf("run %s failed: %s", run.ID, errMsg)
}

// loadVars returns the workspace variables for the engine,
// partitioned by category, plus the sensitive plaintexts (for log
// redaction only — never logged). Variables are resolved via
// GetVariablePlaintext (runner-only); ListVariables alone only
// yields masked display values.
//
// The partition is the AWS-provider fix: category "env" variables
// (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, …) go to
// EngineVars.Env and reach tofu as raw environment, while
// "terraform" variables (and legacy variables with no category)
// become TF_VAR_* for HCL variable blocks. Flattening them, as the
// runner previously did, silently broke every provider that
// authenticates via environment.
func (r *Runner) loadVars(wsID string) (model.EngineVars, []string) {
	vars := model.EngineVars{Terraform: map[string]string{}, Env: map[string]string{}}
	var secrets []string
	list, err := r.store.ListVariables(wsID)
	if err != nil {
		return vars, secrets
	}
	put := func(v *model.Variable, plain string) {
		if v.Category == "env" {
			vars.Env[v.Key] = plain
		} else {
			vars.Terraform[v.Key] = plain
		}
		if v.Sensitive && plain != "" {
			secrets = append(secrets, plain)
		}
	}
	for _, v := range list {
		if plain, found, err := r.store.GetVariablePlaintext(wsID, v.Key); err == nil && found {
			put(v, plain)
			continue
		}
		// Fall back to the display value only for non-sensitive
		// variables; sensitive values never come from DisplayValue.
		if !v.Sensitive && v.DisplayValue != "" && v.DisplayValue != "***" {
			put(v, v.DisplayValue)
		}
	}
	return vars, secrets
}

// planFor runs a plan, preferring the state-aware method so the
// engine can report no-ops for resources already in state. A missing
// or unreadable prior state is not fatal: it just means the plan
// reports everything as new (first-plan rule).
func (r *Runner) planFor(ctx context.Context, ws *model.Workspace, vars model.EngineVars, secrets []string, runID string) (*model.PlanSummary, error) {
	if ps, ok := r.engine.(planWithState); ok {
		var state []byte
		if sv, err := r.store.LatestStateVersion(ws.ID); err == nil && sv != nil {
			state = sv.Data
		} else if err != nil {
			r.log(runID, secrets, "no prior state readable; planning as first plan")
		}
		return ps.PlanWithState(ctx, ws, vars, state)
	}
	return r.engine.Plan(ctx, ws, vars)
}

// policySetsFor returns the policy sets applicable to a workspace:
// org-wide sets plus sets scoped to this workspace.
func (r *Runner) policySetsFor(ws *model.Workspace) []*model.PolicySet {
	sets, err := r.store.ListPolicySets(ws.OrgID)
	if err != nil {
		return nil
	}
	var out []*model.PolicySet
	for _, s := range sets {
		if s.WorkspaceID == "" || s.WorkspaceID == ws.ID {
			out = append(out, s)
		}
	}
	return out
}

func (r *Runner) evaluatePolicy(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult {
	if r.policy == nil {
		return model.PolicyResult{Result: model.PolicyPass}
	}
	return r.policy.Evaluate(plan, sets)
}

func (r *Runner) estimateCost(plan *model.PlanSummary) *model.CostEstimate {
	if r.cost == nil {
		return &model.CostEstimate{Note: "estimate from static price table, not a cloud bill"}
	}
	est := r.cost.Estimate(plan)
	return &est
}

// RunOnce claims one queued run and executes it per the canonical
// flow. It returns nil when the run reaches a successful terminal
// state (awaiting_approval or applied) and an error when the run
// ends failed or when claiming itself fails. It never panics.
func (r *Runner) RunOnce(ctx context.Context) (err error) {
	var run *model.Run
	var locked bool
	var lockHolder string
	defer func() {
		if rec := recover(); rec != nil {
			// Best effort: release any held lock, then record the
			// failure. This deferred handler never panics itself.
			func() {
				defer func() { _ = recover() }()
				if locked && run != nil {
					_ = r.store.UnlockWorkspace(run.WorkspaceID, lockHolder)
				}
				if run != nil {
					run.Status = model.StatusFailed
					run.Error = fmt.Sprintf("runner panic recovered: %v", rec)
					finishAtNow(run)
					_ = r.store.UpdateRun(run)
				}
			}()
			err = fmt.Errorf("runner panic recovered: %v", rec)
		}
	}()

	run, err = r.store.ClaimQueuedRun()
	if err != nil {
		return fmt.Errorf("claim queued run: %w", err)
	}
	if run == nil {
		return nil // nothing queued
	}

	switch run.Type {
	case model.RunPlan:
		return r.executePlan(ctx, run)
	case model.RunApply:
		return r.executeApply(ctx, run, &locked, &lockHolder)
	case model.RunDestroy:
		return r.executeDestroy(ctx, run, &locked, &lockHolder)
	case model.RunDrift:
		return r.executeDrift(ctx, run)
	default:
		return r.failRun(run, nil, fmt.Sprintf("unknown run type %q", run.Type))
	}
}

// executePlan implements: planning -> Plan -> policy+cost ->
// awaiting_approval, or failed on policy fail. No workspace lock is
// taken for plan runs (canonical flow).
func (r *Runner) executePlan(ctx context.Context, run *model.Run) error {
	ws, err := r.store.GetWorkspaceByID(run.WorkspaceID)
	if err != nil {
		return r.failRun(run, nil, fmt.Sprintf("get workspace: %v", err))
	}
	vars, secrets := r.loadVars(ws.ID)
	run.Status = model.StatusPlanning
	run.UpdatedAt = time.Now().UTC()
	_ = r.store.UpdateRun(run)
	r.log(run.ID, secrets, "planning workspace %s", ws.ID)

	plan, err := r.planFor(ctx, ws, vars, secrets, run.ID)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("plan: %v", err))
	}
	run.Plan = plan
	run.Status = model.StatusPolicy
	run.UpdatedAt = time.Now().UTC()
	_ = r.store.UpdateRun(run)

	policy := r.evaluatePolicy(plan, r.policySetsFor(ws))
	run.Policy = &policy
	run.Cost = r.estimateCost(plan)
	r.log(run.ID, secrets, "plan complete: add=%d change=%d destroy=%d policy=%s",
		plan.Add, plan.Change, plan.Destroy, policy.Result)
	if policy.Result == model.PolicyFail {
		msg := strings.Join(policy.Messages, "; ")
		if msg == "" {
			msg = "policy evaluation failed"
		}
		return r.failRun(run, secrets, "policy fail: "+msg)
	}
	run.Status = model.StatusAwaitingApproval
	run.Error = ""
	finishAtNow(run)
	// awaiting_approval is not a finished run, so clear FinishedAt:
	// the run is still open until approve/discard.
	run.FinishedAt = nil
	run.UpdatedAt = time.Now().UTC()
	if err := r.store.UpdateRun(run); err != nil {
		return fmt.Errorf("update run: %w", err)
	}
	r.log(run.ID, secrets, "plan awaiting approval")
	return nil
}

// acquireLock tries the atomic workspace lock. On failure the run is
// marked failed (never silently re-queued forever) and an error is
// returned. locked/lockHolder report the outcome to the caller.
func (r *Runner) acquireLock(run *model.Run, secrets []string, locked *bool, lockHolder *string) error {
	holder := "run:" + run.ID
	ok, err := r.store.TryLockWorkspace(run.WorkspaceID, holder)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("workspace lock error: %v", err))
	}
	if !ok {
		return r.failRun(run, secrets, "workspace lock error: workspace is already locked by another run")
	}
	*locked = true
	*lockHolder = holder
	return nil
}

func (r *Runner) releaseLock(run *model.Run, secrets []string, locked *bool, lockHolder *string) {
	if *locked {
		if err := r.store.UnlockWorkspace(run.WorkspaceID, *lockHolder); err != nil {
			r.log(run.ID, secrets, "warning: failed to release workspace lock: %v", err)
		}
		*locked = false
	}
}

// executeApply implements: applying -> lock -> Apply (linked plan's
// summary if present, else fresh Plan) -> new StateVersion ->
// applied. Lock failure marks the run failed, not re-queued.
func (r *Runner) executeApply(ctx context.Context, run *model.Run, locked *bool, lockHolder *string) error {
	ws, err := r.store.GetWorkspaceByID(run.WorkspaceID)
	if err != nil {
		return r.failRun(run, nil, fmt.Sprintf("get workspace: %v", err))
	}
	vars, secrets := r.loadVars(ws.ID)
	run.Status = model.StatusApplying
	run.UpdatedAt = time.Now().UTC()
	_ = r.store.UpdateRun(run)

	var plan *model.PlanSummary
	if run.PlanRunID != "" {
		if planRun, err := r.store.GetRun(run.PlanRunID); err == nil && planRun != nil && planRun.Plan != nil {
			plan = planRun.Plan
			r.log(run.ID, secrets, "applying linked plan run %s", run.PlanRunID)
		} else if err != nil {
			r.log(run.ID, secrets, "linked plan run %s unreadable; planning fresh", run.PlanRunID)
		}
	}
	if plan == nil {
		fresh, err := r.planFor(ctx, ws, vars, secrets, run.ID)
		if err != nil {
			return r.failRun(run, secrets, fmt.Sprintf("fresh plan before apply: %v", err))
		}
		plan = fresh
		run.Plan = plan
	}

	if err := r.acquireLock(run, secrets, locked, lockHolder); err != nil {
		return err
	}
	defer r.releaseLock(run, secrets, locked, lockHolder)

	r.log(run.ID, secrets, "applying: add=%d change=%d destroy=%d", plan.Add, plan.Change, plan.Destroy)
	newState, err := r.engine.Apply(ctx, ws, plan, vars)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("apply: %v", err))
	}
	sv, err := r.store.CreateStateVersion(ws.ID, newState)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("create state version: %v", err))
	}
	run.StateVersion = sv.Version
	run.Status = model.StatusApplied
	run.Error = ""
	finishAtNow(run)
	if err := r.store.UpdateRun(run); err != nil {
		return fmt.Errorf("update run: %w", err)
	}
	r.log(run.ID, secrets, "applied; new state version %d", sv.Version)
	return nil
}

// executeDestroy re-evaluates policy before destroying (deny_destroy
// -> failed, without taking the lock), then mirrors apply: lock ->
// Destroy -> new StateVersion -> applied.
func (r *Runner) executeDestroy(ctx context.Context, run *model.Run, locked *bool, lockHolder *string) error {
	ws, err := r.store.GetWorkspaceByID(run.WorkspaceID)
	if err != nil {
		return r.failRun(run, nil, fmt.Sprintf("get workspace: %v", err))
	}
	vars, secrets := r.loadVars(ws.ID)
	run.Status = model.StatusApplying
	run.UpdatedAt = time.Now().UTC()
	_ = r.store.UpdateRun(run)

	plan, err := r.planFor(ctx, ws, vars, secrets, run.ID)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("plan before destroy: %v", err))
	}
	run.Plan = plan
	policy := r.evaluatePolicy(plan, r.policySetsFor(ws))
	run.Policy = &policy
	run.Cost = r.estimateCost(plan)
	if policy.Result == model.PolicyFail {
		msg := strings.Join(policy.Messages, "; ")
		if msg == "" {
			msg = "policy evaluation failed"
		}
		_ = r.store.UpdateRun(run)
		return r.failRun(run, secrets, "policy fail: "+msg)
	}

	if err := r.acquireLock(run, secrets, locked, lockHolder); err != nil {
		return err
	}
	defer r.releaseLock(run, secrets, locked, lockHolder)

	r.log(run.ID, secrets, "destroying workspace %s", ws.ID)
	newState, err := r.engine.Destroy(ctx, ws, vars)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("destroy: %v", err))
	}
	sv, err := r.store.CreateStateVersion(ws.ID, newState)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("create state version: %v", err))
	}
	run.StateVersion = sv.Version
	run.Status = model.StatusApplied
	run.Error = ""
	finishAtNow(run)
	if err := r.store.UpdateRun(run); err != nil {
		return fmt.Errorf("update run: %w", err)
	}
	r.log(run.ID, secrets, "destroyed; new state version %d", sv.Version)
	return nil
}

// executeDrift runs a fresh plan, stores a DriftReport, and marks
// the run applied (drift runs complete as applied: they succeeded
// and applied nothing). Drift never takes the workspace lock and
// never calls Apply/Destroy.
func (r *Runner) executeDrift(ctx context.Context, run *model.Run) error {
	ws, err := r.store.GetWorkspaceByID(run.WorkspaceID)
	if err != nil {
		return r.failRun(run, nil, fmt.Sprintf("get workspace: %v", err))
	}
	vars, secrets := r.loadVars(ws.ID)
	run.Status = model.StatusPlanning
	run.UpdatedAt = time.Now().UTC()
	_ = r.store.UpdateRun(run)

	plan, err := r.planFor(ctx, ws, vars, secrets, run.ID)
	if err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("drift plan: %v", err))
	}
	run.Plan = plan
	drifted := plan.Add+plan.Change+plan.Destroy > 0
	if _, err := r.store.CreateDriftReport(&model.DriftReport{
		WorkspaceID: ws.ID,
		Drifted:     drifted,
		Summary:     plan,
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		return r.failRun(run, secrets, fmt.Sprintf("create drift report: %v", err))
	}
	// Drift runs "complete" as applied: the check succeeded. There
	// is no separate drifted/clean run status in the model, and a
	// drift run must never be confused with an infra apply — the
	// DriftReport, not the run status, carries the drift verdict.
	run.Status = model.StatusApplied
	run.Error = ""
	finishAtNow(run)
	if err := r.store.UpdateRun(run); err != nil {
		return fmt.Errorf("update run: %w", err)
	}
	r.log(run.ID, secrets, "drift check complete: drifted=%v add=%d change=%d destroy=%d", drifted, plan.Add, plan.Change, plan.Destroy)
	return nil
}

// RunLoop polls RunOnce every interval until ctx is done.
func (r *Runner) RunLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Errors are already recorded on the run (or were
			// claim errors with no run to mark); keep polling.
			_ = r.RunOnce(ctx)
		}
	}
}
