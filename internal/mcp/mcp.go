// Package mcp implements the forge-iaas MCP server (see CONTRACT.md):
// exactly the 15 tools workspace_list, workspace_create, workspace_get,
// run_plan, run_get, run_approve, run_discard, state_read_redacted,
// drift_check, variable_set, module_publish, module_get, policy_check,
// cost_estimate, audit_list.
//
// Auth mirrors the REST API: fiak_ keys with the same scope rules
// (run_approve rejects plan-scoped keys; state reads need
// state:read-redacted). For stdio mode the key comes from the
// FIAAS_AGENT_KEY environment variable (or the Options.AgentKey set by
// the caller); for Streamable HTTP it comes from the request's
// Authorization header, resolved per request. A tool call may also
// pass "agent_key" as an argument, which is authenticated for that
// call only and never echoed back.
//
// Every tool result states the approval gate in plain language, and
// state is returned ONLY via model.RedactedStateView. This package
// never executes runs: it only creates run records, exactly like the
// API package. Policy evaluation and cost estimation are delegated to
// the PolicyEvaluator / CostEstimator interfaces below (wired by the
// coordinator to internal/policy); when they are nil, policy_check
// and cost_estimate return a clear "not wired" tool error instead of
// a fabricated pass or price.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// Store is the duck-typed subset of internal/store that MCP needs.
// Method names and signatures match docs/INTERFACES.md exactly.
type Store interface {
	AuthenticateKey(plaintext string) (*model.AgentKey, error)
	CreateOrganization(name, slug string) (*model.Organization, error)
	GetOrganization(idOrSlug string) (*model.Organization, error)
	ListOrganizations() ([]*model.Organization, error)
	CreateWorkspace(w *model.Workspace) (*model.Workspace, error)
	GetWorkspace(idOrSlug string) (*model.Workspace, error)
	ListWorkspaces(orgID string) ([]*model.Workspace, error)
	CreateRun(r *model.Run) (*model.Run, error)
	GetRun(id string) (*model.Run, error)
	UpdateRun(r *model.Run) error
	SetVariable(wsID, setID, key, plaintext string, sensitive bool, category string) (*model.Variable, error)
	ListVariables(wsID string) ([]*model.Variable, error)
	LatestStateVersion(wsID string) (*model.StateVersion, error)
	CreateModule(m *model.Module, tarball []byte) (*model.Module, error)
	ListModules() ([]*model.Module, error)
	CreatePolicySet(orgID, wsID, name string, rules []byte) (*model.PolicySet, error)
	ListPolicySets(orgID string) ([]*model.PolicySet, error)
	AppendAudit(e *model.AuditEntry) error
	ListAudit(wsID string, limit int) ([]*model.AuditEntry, error)
	LatestDriftReport(wsID string) (*model.DriftReport, error)
}

// PolicyEvaluator evaluates a plan against policy sets. Signature
// matches docs/INTERFACES.md (runner/policy sections).
type PolicyEvaluator interface {
	Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult
}

// CostEstimator estimates a plan's monthly cost. Signature matches
// docs/INTERFACES.md (runner/policy sections).
type CostEstimator interface {
	Estimate(plan *model.PlanSummary) model.CostEstimate
}

// Options configures a Server.
type Options struct {
	// AgentKey is an already-authenticated key record (see
	// Authenticate). When nil, stdio mode falls back to the
	// FIAAS_AGENT_KEY environment variable.
	AgentKey *model.AgentKey
	// AllowAnon, when true, treats keyless callers as actor "local"
	// with all scopes (dev/E2E only).
	AllowAnon bool
	// Policy, when set, backs policy_check. Nil => tool error.
	Policy PolicyEvaluator
	// Cost, when set, backs cost_estimate. Nil => tool error.
	Cost CostEstimator
}

// Server is the forge-iaas MCP server bound to one store and one
// acting key (per-request servers are built by Handler).
type Server struct {
	store Store
	opts  Options
	sdk   *sdk.Server
}

// NewServer builds an MCP Server. It does not start any transport;
// use RunStdio for stdio mode or Handler for Streamable HTTP.
func NewServer(store Store, opts Options) *Server {
	s := &Server{store: store, opts: opts}
	srv := sdk.NewServer(&sdk.Implementation{Name: "forge-iaas", Version: "v1"}, nil)
	s.sdk = srv
	s.registerTools()
	return s
}

// SDK returns the underlying SDK server (for in-memory tests).
func (s *Server) SDK() *sdk.Server { return s.sdk }

// Authenticate resolves a plaintext key via the store.
func (s *Server) Authenticate(plaintext string) (*model.AgentKey, error) {
	return s.store.AuthenticateKey(plaintext)
}

// RunStdio serves MCP over stdin/stdout. The acting key is
// opts.AgentKey when set, else FIAAS_AGENT_KEY from the environment,
// else (AllowAnon only) the local actor. Keyless + !AllowAnon still
// starts the server, but every tool call fails with an
// unauthenticated error, so a misconfigured client fails loudly
// instead of silently acting as someone else.
func (s *Server) RunStdio(ctx context.Context) error {
	if s.opts.AgentKey == nil {
		if envKey := strings.TrimSpace(os.Getenv("FIAAS_AGENT_KEY")); envKey != "" {
			rec, err := s.store.AuthenticateKey(envKey)
			if err != nil {
				return fmt.Errorf("FIAAS_AGENT_KEY authentication failed: %w", err)
			}
			s.opts.AgentKey = rec
		}
	}
	return s.sdk.Run(ctx, &sdk.StdioTransport{})
}

// Handler returns a Streamable HTTP handler mountable at /mcp. The
// acting key is resolved per request from the Authorization header;
// an unauthenticated request still gets a server, but its tools all
// fail with unauthenticated errors (unless AllowAnon).
func (s *Server) Handler() http.Handler {
	return sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		opts := s.opts
		opts.AgentKey = nil
		if key := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); key != "" {
			if rec, err := s.store.AuthenticateKey(key); err == nil {
				opts.AgentKey = rec
			}
		}
		return NewServer(s.store, opts).sdk
	}, nil)
}

// ---------------------------------------------------------------- auth

type actor struct {
	name   string
	scopes []string
	orgID  string
	wsID   string
	anon   bool
}

func (a *actor) hasScope(scope string) bool {
	for _, sc := range a.scopes {
		if sc == model.ScopeAdmin || sc == scope {
			return true
		}
	}
	return false
}

func (a *actor) hasAnyScope(scopes ...string) bool {
	for _, sc := range scopes {
		if a.hasScope(sc) {
			return true
		}
	}
	return false
}

func localActor() *actor {
	return &actor{name: "local", anon: true, scopes: []string{
		model.ScopePlan, model.ScopeApply, model.ScopeDestroy,
		model.ScopeStateRead, model.ScopeRegistryPublish, model.ScopeAdmin,
	}}
}

func actorFromRecord(rec *model.AgentKey) *actor {
	return &actor{name: rec.Prefix, scopes: rec.Scopes, orgID: rec.OrgID, wsID: rec.WorkspaceID}
}

// resolveActor determines the acting key for one tool call: a per-call
// "agent_key" argument wins, then the server's bound key, then the
// local actor when AllowAnon. Otherwise an error.
func (s *Server) resolveActor(args map[string]any) (*actor, error) {
	if raw, ok := args["agent_key"]; ok {
		if key, ok := raw.(string); ok && strings.TrimSpace(key) != "" {
			rec, err := s.store.AuthenticateKey(strings.TrimSpace(key))
			if err != nil {
				return nil, fmt.Errorf("unauthenticated: invalid agent key")
			}
			return actorFromRecord(rec), nil
		}
	}
	if s.opts.AgentKey != nil {
		return actorFromRecord(s.opts.AgentKey), nil
	}
	if s.opts.AllowAnon {
		return localActor(), nil
	}
	return nil, fmt.Errorf("unauthenticated: no agent key (set FIAAS_AGENT_KEY, pass agent_key, or run with AllowAnon)")
}

func checkWorkspaceScope(a *actor, ws *model.Workspace) error {
	if a.anon {
		return nil
	}
	if a.wsID != "" && a.wsID != ws.ID {
		return fmt.Errorf("forbidden: key is scoped to a different workspace")
	}
	if a.orgID != "" && a.orgID != ws.OrgID {
		return fmt.Errorf("forbidden: key is scoped to a different organization")
	}
	return nil
}

func (s *Server) audit(a *actor, action, wsID, runID, detail string) {
	_ = s.store.AppendAudit(&model.AuditEntry{
		Actor: a.name, Action: action, WorkspaceID: wsID, RunID: runID,
		Detail: detail, CreatedAt: time.Now(),
	})
}

// approvalGate renders the approval gate for a run in plain language.
// Every tool result that touches a run includes this text.
func approvalGate(run *model.Run) string {
	switch run.Status {
	case model.StatusAwaitingApproval:
		if run.Policy != nil && run.Policy.Result == model.PolicyAdvisory {
			return "Approval gate: plan is awaiting approval, but its policy result is advisory — approving requires an override note and an apply-scoped key. A plan-scoped key can never approve."
		}
		if run.Policy != nil && run.Policy.Result == model.PolicyFail {
			return "Approval gate: plan FAILED policy — apply is blocked. Fix the plan or policy; approval will not proceed."
		}
		return "Approval gate: plan is awaiting approval — approve it with an apply-scoped key to apply. A plan-scoped key can never approve, and nothing is applied until the runner executes the apply run."
	case model.StatusQueued, model.StatusPlanning, model.StatusPolicy:
		return "Approval gate: run is still " + run.Status + " — it has not reached approval yet, and nothing has been applied. Wait for it to reach awaiting_approval, then approve with an apply-scoped key."
	case model.StatusApplied:
		return "Approval gate: already applied — no further approval is needed or possible for this run."
	case model.StatusDiscarded, model.StatusCanceled, model.StatusFailed:
		return "Approval gate: run ended as " + run.Status + " — it will never apply."
	default:
		return "Approval gate: run status is " + run.Status + " — nothing has been applied unless the status is applied."
	}
}

// ---------------------------------------------------------------- tool plumbing

type toolFunc func(ctx context.Context, a *actor, args map[string]any) (string, error)

func (s *Server) registerTools() {
	tools := []struct {
		name string
		desc string
		fn   toolFunc
	}{
		{"workspace_list", "List workspaces in an organization. Read-only; nothing is applied.", s.toolWorkspaceList},
		{"workspace_create", "Create a workspace in an organization. Requires plan or admin scope.", s.toolWorkspaceCreate},
		{"workspace_get", "Get one workspace by id or slug. Read-only.", s.toolWorkspaceGet},
		{"run_plan", "Create a plan run for a workspace. Requires plan or admin scope. Planning never applies anything.", s.toolRunPlan},
		{"run_get", "Get one run with its plan summary, policy, and cost (redacted).", s.toolRunGet},
		{"run_approve", "Approve a plan run, creating a queued apply run. Requires apply or admin scope; plan-scoped keys are rejected. Advisory policy requires override_note.", s.toolRunApprove},
		{"run_discard", "Discard a planned run so it will never apply. Requires plan or admin scope.", s.toolRunDiscard},
		{"state_read_redacted", "Read the latest state of a workspace, redacted to resource type/name/address only. Requires state:read-redacted or admin scope. Never returns attribute values.", s.toolStateReadRedacted},
		{"drift_check", "Queue a drift-check run for a workspace. Requires plan or admin scope. A drift check never applies anything.", s.toolDriftCheck},
		{"variable_set", "Set a workspace variable. Sensitive values are masked in every response and never echoed back. Requires plan or admin scope.", s.toolVariableSet},
		{"module_publish", "Publish a module version to the registry. Requires registry:publish or admin scope.", s.toolModulePublish},
		{"module_get", "Get a module version from the registry. Read-only.", s.toolModuleGet},
		{"policy_check", "Evaluate a run's plan against the organization's policy sets. Requires a wired PolicyEvaluator.", s.toolPolicyCheck},
		{"cost_estimate", "Estimate a run's plan monthly cost from the static price table (not a cloud bill). Requires a wired CostEstimator.", s.toolCostEstimate},
		{"audit_list", "List audit entries, optionally filtered by workspace. Read-only; entries are already redacted.", s.toolAuditList},
	}
	for _, t := range tools {
		fn := t.fn
		s.sdk.AddTool(&sdk.Tool{
			Name:        t.name,
			Description: t.desc,
			InputSchema: map[string]any{
				"type": "object", "properties": map[string]any{},
			},
		}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			args := map[string]any{}
			if len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
					return toolError(fmt.Sprintf("invalid arguments: %v", err)), nil
				}
			}
			a, err := s.resolveActor(args)
			if err != nil {
				return toolError(err.Error()), nil
			}
			delete(args, "agent_key") // never echo or forward the key
			text, err := fn(ctx, a, args)
			if err != nil {
				return toolError(err.Error()), nil
			}
			return &sdk.CallToolResult{
				Content: []sdk.Content{&sdk.TextContent{Text: text}},
			}, nil
		})
	}
}

func toolError(msg string) *sdk.CallToolResult {
	return &sdk.CallToolResult{
		IsError: true,
		Content: []sdk.Content{&sdk.TextContent{Text: "error: " + msg}},
	}
}

func argStr(args map[string]any, name string) string {
	if v, ok := args[name]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprint(v)
	}
	return ""
}

func argBool(args map[string]any, name string) bool {
	if v, ok := args[name]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (s *Server) resolveWorkspace(a *actor, idOrSlug string) (*model.Workspace, error) {
	if idOrSlug == "" {
		return nil, fmt.Errorf("workspace is required")
	}
	ws, err := s.store.GetWorkspace(idOrSlug)
	if err != nil || ws == nil {
		return nil, fmt.Errorf("workspace not found: %s", idOrSlug)
	}
	if err := checkWorkspaceScope(a, ws); err != nil {
		return nil, err
	}
	return ws, nil
}

func redactedRun(run *model.Run) *model.Run {
	if run == nil {
		return nil
	}
	cp := *run
	if run.Plan != nil {
		plan := *run.Plan
		res := make([]model.ResourceChange, 0, len(run.Plan.Resources))
		for _, rc := range run.Plan.Resources {
			rc.Attributes = model.RedactAttributes(rc.Attributes)
			res = append(res, rc)
		}
		plan.Resources = res
		plan.RawPlanJSON = nil
		cp.Plan = &plan
	}
	return &cp
}

func isTerminal(st string) bool {
	switch st {
	case model.StatusApplied, model.StatusFailed, model.StatusDiscarded, model.StatusCanceled:
		return true
	}
	return false
}

// ---------------------------------------------------------------- tools

func (s *Server) toolWorkspaceList(_ context.Context, a *actor, args map[string]any) (string, error) {
	orgArg := argStr(args, "org")
	var out []*model.Workspace
	if orgArg != "" {
		org, err := s.store.GetOrganization(orgArg)
		if err != nil || org == nil {
			return "", fmt.Errorf("organization not found: %s", orgArg)
		}
		if !a.anon && a.orgID != "" && a.orgID != org.ID {
			return "", fmt.Errorf("forbidden: key is scoped to a different organization")
		}
		out, err = s.store.ListWorkspaces(org.ID)
		if err != nil {
			return "", err
		}
	} else {
		orgs, err := s.store.ListOrganizations()
		if err != nil {
			return "", err
		}
		for _, org := range orgs {
			ws, err := s.store.ListWorkspaces(org.ID)
			if err != nil {
				return "", err
			}
			out = append(out, ws...)
		}
	}
	if out == nil {
		out = []*model.Workspace{}
	}
	return "Workspaces listed (read-only; listing changes nothing, and no run is created or applied).\n" + mustJSON(out), nil
}

func (s *Server) toolWorkspaceCreate(_ context.Context, a *actor, args map[string]any) (string, error) {
	if !a.hasAnyScope(model.ScopePlan) {
		return "", fmt.Errorf("forbidden: requires plan or admin scope")
	}
	orgArg := argStr(args, "org")
	name := argStr(args, "name")
	if orgArg == "" || name == "" {
		return "", fmt.Errorf("org and name are required")
	}
	org, err := s.store.GetOrganization(orgArg)
	if err != nil || org == nil {
		return "", fmt.Errorf("organization not found: %s", orgArg)
	}
	if !a.anon && a.orgID != "" && a.orgID != org.ID {
		return "", fmt.Errorf("forbidden: key is scoped to a different organization")
	}
	slug := argStr(args, "slug")
	if slug == "" {
		slug = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", "-"))
	}
	mode := argStr(args, "execution_mode")
	if mode == "" {
		mode = "remote"
	}
	ws, err := s.store.CreateWorkspace(&model.Workspace{
		OrgID: org.ID, Name: name, Slug: slug,
		VCSRepo: argStr(args, "vcs_repo"), VCSBranch: argStr(args, "vcs_branch"),
		WorkDir: argStr(args, "work_dir"), ConfigPath: argStr(args, "config_path"),
		ExecutionMode: mode, AutoApply: argBool(args, "auto_apply"),
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		return "", err
	}
	s.audit(a, "workspace.create", ws.ID, "", "created workspace "+ws.Slug+" via MCP")
	return fmt.Sprintf("Workspace created: %s (id %s).\nApproval gate: creating a workspace applies nothing. Create a plan run with run_plan, then approve it with an apply-scoped key to apply.\n%s",
		ws.Slug, ws.ID, mustJSON(ws)), nil
}

func (s *Server) toolWorkspaceGet(_ context.Context, a *actor, args map[string]any) (string, error) {
	ws, err := s.resolveWorkspace(a, argStr(args, "workspace"))
	if err != nil {
		return "", err
	}
	return "Workspace (read-only; no change made).\n" + mustJSON(ws), nil
}

func (s *Server) toolRunPlan(_ context.Context, a *actor, args map[string]any) (string, error) {
	if !a.hasAnyScope(model.ScopePlan) {
		return "", fmt.Errorf("forbidden: requires plan or admin scope")
	}
	ws, err := s.resolveWorkspace(a, argStr(args, "workspace"))
	if err != nil {
		return "", err
	}
	run, err := s.store.CreateRun(&model.Run{
		WorkspaceID: ws.ID, Type: model.RunPlan, Trigger: model.TriggerMCP,
		Status: model.StatusQueued, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		return "", err
	}
	s.audit(a, "run.create", ws.ID, run.ID, "created plan run via MCP")
	return fmt.Sprintf("Plan run queued: %s (workspace %s).\nApproval gate: this plan will not apply anything until it reaches awaiting_approval and is approved with an apply-scoped key. A plan-scoped key can never approve.\n%s",
		run.ID, ws.Slug, mustJSON(redactedRun(run))), nil
}

func (s *Server) toolRunGet(_ context.Context, a *actor, args map[string]any) (string, error) {
	id := argStr(args, "run_id")
	if id == "" {
		return "", fmt.Errorf("run_id is required")
	}
	run, err := s.store.GetRun(id)
	if err != nil || run == nil {
		return "", fmt.Errorf("run not found: %s", id)
	}
	ws, werr := s.store.GetWorkspace(run.WorkspaceID)
	if werr == nil && ws != nil {
		if err := checkWorkspaceScope(a, ws); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("Run %s (type %s, status %s).\n%s\n%s",
		run.ID, run.Type, run.Status, approvalGate(run), mustJSON(redactedRun(run))), nil
}

func (s *Server) toolRunApprove(_ context.Context, a *actor, args map[string]any) (string, error) {
	// Scope first: a plan-scoped key is rejected even for a bad run id.
	if !a.hasAnyScope(model.ScopeApply) {
		return "", fmt.Errorf("forbidden: requires apply or admin scope; plan-scoped keys cannot approve")
	}
	id := argStr(args, "run_id")
	if id == "" {
		return "", fmt.Errorf("run_id is required")
	}
	plan, err := s.store.GetRun(id)
	if err != nil || plan == nil {
		return "", fmt.Errorf("run not found: %s", id)
	}
	ws, werr := s.store.GetWorkspace(plan.WorkspaceID)
	if werr == nil && ws != nil {
		if err := checkWorkspaceScope(a, ws); err != nil {
			return "", err
		}
	}
	if plan.Type != model.RunPlan {
		return "", fmt.Errorf("only plan runs can be approved")
	}
	if isTerminal(plan.Status) {
		return "", fmt.Errorf("run is already %s", plan.Status)
	}
	note := argStr(args, "override_note")
	if plan.Policy != nil {
		switch plan.Policy.Result {
		case model.PolicyFail:
			return "", fmt.Errorf("policy failed; apply is blocked")
		case model.PolicyAdvisory:
			if strings.TrimSpace(note) == "" {
				return "", fmt.Errorf("advisory policy requires an override_note")
			}
		}
	}
	apply, err := s.store.CreateRun(&model.Run{
		WorkspaceID: plan.WorkspaceID, Type: model.RunApply, Trigger: model.TriggerMCP,
		Status: model.StatusQueued, PlanRunID: plan.ID, OverrideNote: note,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		return "", err
	}
	s.audit(a, "run.approve", plan.WorkspaceID, plan.ID,
		"approved plan run via MCP; apply run "+apply.ID+" queued")
	return fmt.Sprintf("Approved: plan run %s -> apply run %s queued.\nApproval gate: the apply run is queued, not yet applied — the runner must execute it, and the workspace lock guarantees only one apply runs at a time. A plan-scoped key could never have performed this approval.\n%s",
		plan.ID, apply.ID, mustJSON(redactedRun(apply))), nil
}

func (s *Server) toolRunDiscard(_ context.Context, a *actor, args map[string]any) (string, error) {
	if !a.hasAnyScope(model.ScopePlan) {
		return "", fmt.Errorf("forbidden: requires plan or admin scope")
	}
	id := argStr(args, "run_id")
	if id == "" {
		return "", fmt.Errorf("run_id is required")
	}
	run, err := s.store.GetRun(id)
	if err != nil || run == nil {
		return "", fmt.Errorf("run not found: %s", id)
	}
	ws, werr := s.store.GetWorkspace(run.WorkspaceID)
	if werr == nil && ws != nil {
		if err := checkWorkspaceScope(a, ws); err != nil {
			return "", err
		}
	}
	if isTerminal(run.Status) {
		return "", fmt.Errorf("run is already %s", run.Status)
	}
	run.Status = model.StatusDiscarded
	run.UpdatedAt = time.Now()
	if err := s.store.UpdateRun(run); err != nil {
		return "", err
	}
	s.audit(a, "run.discard", run.WorkspaceID, run.ID, "discarded run via MCP")
	return fmt.Sprintf("Run %s discarded.\nApproval gate: a discarded run will never apply.\n%s",
		run.ID, mustJSON(redactedRun(run))), nil
}

func (s *Server) toolStateReadRedacted(_ context.Context, a *actor, args map[string]any) (string, error) {
	if !a.hasAnyScope(model.ScopeStateRead) {
		return "", fmt.Errorf("forbidden: requires state:read-redacted or admin scope")
	}
	ws, err := s.resolveWorkspace(a, argStr(args, "workspace"))
	if err != nil {
		return "", err
	}
	sv, err := s.store.LatestStateVersion(ws.ID)
	if err != nil || sv == nil {
		return "", fmt.Errorf("no state version yet for workspace %s", ws.Slug)
	}
	// The ONLY state view ever returned: addresses/types, no values.
	view := model.RedactedStateView(sv.Data)
	view["workspace_id"] = ws.ID
	view["state_version"] = sv.Version
	return fmt.Sprintf("Redacted state for workspace %s (state version %d). This view contains resource types, names, and addresses ONLY — no attribute values, ever.\nApproval gate: reading state changes nothing and applies nothing.\n%s",
		ws.Slug, sv.Version, mustJSON(view)), nil
}

func (s *Server) toolDriftCheck(_ context.Context, a *actor, args map[string]any) (string, error) {
	if !a.hasAnyScope(model.ScopePlan) {
		return "", fmt.Errorf("forbidden: requires plan or admin scope")
	}
	ws, err := s.resolveWorkspace(a, argStr(args, "workspace"))
	if err != nil {
		return "", err
	}
	run, err := s.store.CreateRun(&model.Run{
		WorkspaceID: ws.ID, Type: model.RunDrift, Trigger: model.TriggerMCP,
		Status: model.StatusQueued, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		return "", err
	}
	s.audit(a, "run.create", ws.ID, run.ID, "created drift run via MCP")
	latest, _ := s.store.LatestDriftReport(ws.ID)
	return fmt.Sprintf("Drift-check run queued: %s (workspace %s).\nApproval gate: a drift check never applies anything — it only reports differences. Latest stored report: %s.\n%s",
		run.ID, ws.Slug, mustJSON(latest), mustJSON(redactedRun(run))), nil
}

func (s *Server) toolVariableSet(_ context.Context, a *actor, args map[string]any) (string, error) {
	if !a.hasAnyScope(model.ScopePlan) {
		return "", fmt.Errorf("forbidden: requires plan or admin scope")
	}
	ws, err := s.resolveWorkspace(a, argStr(args, "workspace"))
	if err != nil {
		return "", err
	}
	key := argStr(args, "key")
	value := argStr(args, "value")
	if key == "" {
		return "", fmt.Errorf("key is required")
	}
	sensitive := argBool(args, "sensitive")
	category := argStr(args, "category")
	if category == "" {
		category = "terraform"
	}
	v, err := s.store.SetVariable(ws.ID, "", key, value, sensitive, category)
	if err != nil {
		return "", err
	}
	// Audit and result NEVER contain the value.
	s.audit(a, "variable.set", ws.ID, "", "set variable "+key+" via MCP (sensitive="+fmt.Sprint(sensitive)+")")
	display := v.DisplayValue
	if sensitive {
		display = "***"
	}
	out := map[string]any{"key": v.Key, "value": display, "sensitive": v.Sensitive, "category": v.Category}
	return fmt.Sprintf("Variable %s set on workspace %s (value masked in this response when sensitive).\nApproval gate: setting a variable applies nothing; it takes effect on the next plan/apply run, which still requires approval with an apply-scoped key.\n%s",
		key, ws.Slug, mustJSON(out)), nil
}

func (s *Server) toolModulePublish(_ context.Context, a *actor, args map[string]any) (string, error) {
	if !a.hasAnyScope(model.ScopeRegistryPublish) {
		return "", fmt.Errorf("forbidden: requires registry:publish or admin scope")
	}
	ns, name, provider, version := argStr(args, "namespace"), argStr(args, "name"), argStr(args, "provider"), argStr(args, "version")
	if ns == "" || name == "" || provider == "" || version == "" {
		return "", fmt.Errorf("namespace, name, provider, and version are required")
	}
	mod, err := s.store.CreateModule(&model.Module{
		Namespace: ns, Name: name, Provider: provider, Version: version,
		Readme: argStr(args, "readme"), CreatedAt: time.Now(),
	}, nil)
	if err != nil {
		return "", err
	}
	s.audit(a, "module.publish", "", "", "published module "+ns+"/"+name+" v"+version+" via MCP")
	return fmt.Sprintf("Module published: fiaas/%s/%s v%s.\nApproval gate: publishing a module applies nothing to any workspace; workspaces consume it only through a plan + apply-scoped approval.\n%s",
		ns, name, version, mustJSON(mod)), nil
}

func (s *Server) toolModuleGet(_ context.Context, a *actor, args map[string]any) (string, error) {
	ns, name, version := argStr(args, "namespace"), argStr(args, "name"), argStr(args, "version")
	if ns == "" || name == "" || version == "" {
		return "", fmt.Errorf("namespace, name, and version are required")
	}
	mods, err := s.store.ListModules()
	if err != nil {
		return "", err
	}
	for _, m := range mods {
		if m.Namespace == ns && m.Name == name && m.Version == version {
			return fmt.Sprintf("Module fiaas/%s/%s v%s (read-only; fetching a module applies nothing).\n%s",
				ns, name, version, mustJSON(m)), nil
		}
	}
	return "", fmt.Errorf("module not found: %s/%s v%s", ns, name, version)
}

func (s *Server) loadPlanForEval(args map[string]any) (*model.PlanSummary, []*model.PolicySet, error) {
	runID := argStr(args, "run_id")
	if runID == "" {
		return nil, nil, fmt.Errorf("run_id is required (policy_check/cost_estimate evaluate a run's stored plan)")
	}
	run, err := s.store.GetRun(runID)
	if err != nil || run == nil {
		return nil, nil, fmt.Errorf("run not found: %s", runID)
	}
	if run.Plan == nil {
		return nil, nil, fmt.Errorf("run %s has no plan yet (it may still be queued)", runID)
	}
	ws, err := s.store.GetWorkspace(run.WorkspaceID)
	if err != nil || ws == nil {
		return nil, nil, fmt.Errorf("workspace for run not found")
	}
	sets, err := s.store.ListPolicySets(ws.OrgID)
	if err != nil {
		return nil, nil, err
	}
	return run.Plan, sets, nil
}

func (s *Server) toolPolicyCheck(_ context.Context, a *actor, args map[string]any) (string, error) {
	if s.opts.Policy == nil {
		return "", fmt.Errorf("policy evaluator not wired (coordinator must connect internal/policy); no result is fabricated")
	}
	plan, sets, err := s.loadPlanForEval(args)
	if err != nil {
		return "", err
	}
	res := s.opts.Policy.Evaluate(plan, sets)
	return fmt.Sprintf("Policy result: %s. Messages: %v.\nApproval gate: a fail result blocks apply entirely; an advisory result requires an override note plus an apply-scoped key; a pass still requires an apply-scoped approval before anything is applied.\n%s",
		res.Result, res.Messages, mustJSON(res)), nil
}

func (s *Server) toolCostEstimate(_ context.Context, a *actor, args map[string]any) (string, error) {
	if s.opts.Cost == nil {
		return "", fmt.Errorf("cost estimator not wired (coordinator must connect internal/policy); no price is fabricated")
	}
	plan, _, err := s.loadPlanForEval(args)
	if err != nil {
		return "", err
	}
	est := s.opts.Cost.Estimate(plan)
	return fmt.Sprintf("Cost estimate: $%.2f/month (delta $%.2f). Note: %s.\nApproval gate: an estimate is not a bill and not an approval — applying still requires an apply-scoped key.\n%s",
		est.MonthlyUSD, est.DeltaUSD, est.Note, mustJSON(est)), nil
}

func (s *Server) toolAuditList(_ context.Context, a *actor, args map[string]any) (string, error) {
	wsID := argStr(args, "workspace")
	if wsID != "" {
		ws, err := s.resolveWorkspace(a, wsID)
		if err != nil {
			return "", err
		}
		wsID = ws.ID
	} else if !a.anon && a.wsID != "" {
		wsID = a.wsID
	}
	entries, err := s.store.ListAudit(wsID, 100)
	if err != nil {
		return "", err
	}
	if entries == nil {
		entries = []*model.AuditEntry{}
	}
	return "Audit log (read-only; entries are already redacted, and reading them changes nothing).\n" + mustJSON(entries), nil
}
