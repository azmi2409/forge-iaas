# INTERFACES — frozen wiring contract for the MVP build

All builders import `github.com/azmi2409/forge-iaas/internal/model`.
Do NOT redefine model types. Do NOT edit go.mod (deps already present:
cobra, pgx/v5, modelcontextprotocol/go-sdk, yaml.v3, modernc.org/sqlite,
robfig/cron/v3). Do NOT edit another builder's package directory.

## Canonical run flow (every builder must follow this)

1. Client creates a plan run: workspace -> run{type: plan, status: queued}.
2. Runner claims it (one run per workspace at a time, state lock held
   only for apply/destroy, NOT for plan), runs Plan, evaluates policy
   + cost, stores PlanSummary (redacted) + PolicyResult + CostEstimate.
   Status -> awaiting_approval, unless policy fail -> failed.
3. Approve (API/MCP/CLI, apply-scoped key or admin/local only):
   plan-scoped keys are REJECTED. Advisory policy requires an
   override note. Approve creates a NEW run{type: apply,
   plan_run_id: <plan id>, status: queued} and returns both ids.
4. Runner claims the apply run, acquires the workspace lock (atomic:
   second concurrent apply must fail with a lock error, never apply
   twice), applies, writes a new StateVersion (version = previous + 1),
   status -> applied, lock released. On failure: status -> failed,
   lock released, error stored.
5. Destroy runs are the same shape as apply, with type destroy,
   destroy scope required, and policy DenyDestroy -> failed.
6. Drift: drift_check creates run{type: drift, status: queued};
   runner re-plans and compares to latest state; DriftReport
   {drifted: len(plan.add+change+destroy) > 0} is stored and returned.
   A drift run never applies anything.

## Store (internal/store) — owned by the store builder

Interface (exact method names; implement in SQLite + Postgres):

```
Migrate() error; Close() error
CreateOrganization(name, slug) (*model.Organization, error)
GetOrganization(idOrSlug) (*model.Organization, error)
ListOrganizations() ([]*model.Organization, error)
CreateProject(orgID, name, slug) (*model.Project, error)
ListProjects(orgID) ([]*model.Project, error)
CreateWorkspace(w *model.Workspace) (*model.Workspace, error)
GetWorkspace(idOrSlug) (*model.Workspace, error)
GetWorkspaceByID(id) (*model.Workspace, error)
ListWorkspaces(orgID string) ([]*model.Workspace, error)
UpdateWorkspace(w *model.Workspace) error
DeleteWorkspace(id string) error
TryLockWorkspace(id, holder string) (bool, error)   // atomic, only if unlocked
UnlockWorkspace(id, holder string) error
SetVariable(wsID, setID, key, plaintext string, sensitive bool, category string) (*model.Variable, error)
ListVariables(wsID string) ([]*model.Variable, error) // DisplayValue only; sensitive -> "***"
GetVariablePlaintext(wsID, key string) (string, bool, error) // runner ONLY, never via API
CreateVariableSet(orgID, name string) (*model.VariableSet, error)
ListVariableSets(orgID string) ([]*model.VariableSet, error)
CreateStateVersion(wsID string, data []byte) (*model.StateVersion, error) // version auto-increments, data encrypted
LatestStateVersion(wsID string) (*model.StateVersion, error)
ListStateVersions(wsID string) ([]*model.StateVersion, error)
CreateRun(r *model.Run) (*model.Run, error)
GetRun(id string) (*model.Run, error)
UpdateRun(r *model.Run) error
AppendRunLog(id, line string) error
ClaimQueuedRun() (*model.Run, error) // oldest queued run, atomically -> planning/applying; nil if none
ListRuns(wsID string, limit int) ([]*model.Run, error)
CreatePolicySet(orgID, wsID, name string, rules []byte) (*model.PolicySet, error)
ListPolicySets(orgID string) ([]*model.PolicySet, error)
CreateModule(m *model.Module, tarball []byte) (*model.Module, error)
GetModule(ns, name, provider, version string) (*model.Module, []byte, error)
ListModules() ([]*model.Module, error)
CreateAgentKey(orgID, wsID string, scopes []string) (plaintextKey string, rec *model.AgentKey, err error) // fiak_ + 32 hex chars, SHA256 hash at rest
AuthenticateKey(plaintext string) (*model.AgentKey, error)
AppendAudit(e *model.AuditEntry) error
ListAudit(wsID string, limit int) ([]*model.AuditEntry, error)
CreateDriftReport(r *model.DriftReport) (*model.DriftReport, error)
LatestDriftReport(wsID string) (*model.DriftReport, error)
```

Crypto: AES-256-GCM, key from FIAAS_MASTER_KEY (32 raw bytes or
base64 of 32). If unset, generate an ephemeral key, print a warning
to stderr, and continue (stored secrets will not survive restarts).
Export `MasterKeyFromEnv() (key []byte, ephemeral bool, err error)`
and `Encrypt/Decrypt` helpers in internal/store.
Postgres: pgx/v5, DSN from FIAAS_DATABASE_URL; tests skip when
FIAAS_TEST_DATABASE_URL is unset. SQLite: modernc.org/sqlite, WAL,
busy_timeout 5000.

## Engine (internal/engine) — owned by the engine builder

```
type Engine interface {
  Plan(ctx, ws *model.Workspace, vars model.EngineVars) (*model.PlanSummary, error)
  Apply(ctx, ws *model.Workspace, plan *model.PlanSummary, vars model.EngineVars) (newState []byte, err error)
  Destroy(ctx, ws *model.Workspace, vars model.EngineVars) (newState []byte, err error)
}
NewMockEngine() Engine  // parses .tf files for `resource "TYPE" "NAME"` lines only; NEVER touches real clouds; every output/log says "MOCK ENGINE — no real infrastructure"
NewTofuEngine(bin string) Engine // execs `tofu init` + `tofu plan -json` (parse resource_changes) + `tofu apply -auto-approve` / destroy; if bin missing, Plan/Apply return a loud error, never a fake success
```

Variables are partitioned (model.EngineVars, since the 2026-10-25
AWS fix): Terraform variables -> TF_VAR_<key>; env variables ->
verbatim process environment. The AWS provider is the reason: it
reads AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION from
env, not from TF_VAR_*. Ambient AWS keys in the server process
environment are stripped unless the workspace sets them explicitly,
so a run can never silently use the server's credentials. See
examples/aws-basic/ for the working AWS workspace.

Mock plan: each resource block = 1 create (if no prior state) else
no-op; mock apply: state JSON version 4 with those resources and
mock ids `mock-<type>-<name>`; mock destroy: empty resources state.
Mock must be selected ONLY when env FIAAS_ENGINE=mock (or in tests);
production default is tofu.

## Runner (internal/runner) — owned by the engine builder

```
New(store StoreIface, engine Engine, policy PolicyEvaluator, cost CostEstimator) *Runner
RunOnce(ctx) error  // claim one queued run, execute per flow above, never panic
RunLoop(ctx, interval) // poll until ctx done
```

StoreIface / PolicyEvaluator / CostEstimator are small interfaces
declared IN the runner package (duck-typed against store/policy
packages) so the runner does not import their concrete packages.
PolicyEvaluator: `Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult`.
CostEstimator: `Estimate(plan *model.PlanSummary) model.CostEstimate`.

## Policy + cost (internal/policy) — owned by the policy builder

```
Evaluate(plan *model.PlanSummary, sets []*model.PolicySet) model.PolicyResult
Estimate(plan *model.PlanSummary) model.CostEstimate
```

Rules (PolicyRules JSON in model): deny strings of the contract form
`resource type X where ATTR not in [...]` and `resource type X where
ATTR = Y` (parse these two forms; unknown forms -> advisory message,
never silent pass); require_tags (resource attributes must contain
each tag key — mock/tofu attributes may be absent, in which case a
missing tag counts as a violation, stated in the message); deny_destroy
blocks destroy runs; max_monthly_cost_usd vs Estimate; allowed_regions
vs a `region` attribute if present. Fail if any hard violation;
advisory if only unknown-form rules triggered; else pass.
Cost: static table (USD/month): aws_instance t3.micro 8, t3.small 16,
t3.medium 32, aws_s3_bucket 2, default unknown type 5; Note field
always set to the estimate disclaimer in model.CostEstimate.

## Registry (internal/registry) — owned by the policy builder

```
ValidateVersion(v string) error // semver X.Y.Z
Publish(store, ns, name, provider, version, readme string, tarball []byte) (*model.Module, error) // rejects duplicate version
Get / List via the store; source string form: "fiaas/<ns>/<name>" (documented, not enforced by tofu)
```

## Drift (internal/drift) — owned by the policy builder

```
Check(plan *model.PlanSummary) *model.DriftReport // drifted = add+change+destroy > 0
```

## API (internal/api) — owned by the API builder

`net/http` handlers, exact paths from CONTRACT.md, JSON in/out,
errors `{"error": "..."}`. Auth: header `Authorization: Bearer fiak_…`
validated via store.AuthenticateKey; scope check per endpoint
(plan endpoints need plan|admin, approve needs apply|admin,
destroy needs destroy|admin, state read needs state:read-redacted|
admin, registry publish needs registry:publish|admin).
No key + server AllowAnon=false -> 401. No key + AllowAnon=true ->
actor "local", all scopes (dev/E2E only, log a warning at startup).
Every mutating handler appends a redacted audit entry. The API
package must NOT import engine/runner concrete packages: it only
creates run records; the runner (in-process in `serve`, or external
via `fiaas runner`) executes them. `serve` starts an in-process
runner loop.
Serve also mounts: MCP at /mcp (Streamable HTTP, via internal/mcp),
dashboard at / (via internal/dashboard), /healthz.

## MCP (internal/mcp) — owned by the API builder

modelcontextprotocol/go-sdk, tools exactly as CONTRACT.md:
workspace_list, workspace_create, workspace_get, run_plan, run_get,
run_approve, run_discard, state_read_redacted, drift_check,
variable_set, module_publish, module_get, policy_check, cost_estimate,
audit_list. Each tool result states the approval gate in plain
language (e.g. "plan awaiting approval; approve with an apply-scoped
key to apply"). state_read_redacted uses model.RedactedStateView
only. Tool auth: same fiak_ scopes as API; tools receive the key
from the MCP session metadata / env FIAAS_AGENT_KEY for stdio mode.
Stdio server must be runnable as `fiaas mcp` against a store file
(FIAAS_DB_PATH / FIAAS_DATABASE_URL), NOT requiring a running server.

## CLI (cmd/fiaas) — owned by the API builder

cobra, exact commands from CONTRACT.md, --json everywhere.
`fiaas login --server <url> --key <fiak_…>` stores server+key in
~/.config/fiaas/config.json with 0600. `fiaas key create --org …`
operates directly on the store (local DB) and prints the key ONCE.
`fiaas serve [--addr] [--allow-anon]`, `fiaas runner [--server]`
(polling against a remote server is out of scope for v1: runner
mode runs against the LOCAL store file, same as serve's in-process
runner, and documents that remote polling is deferred — do NOT fake
remote polling), `fiaas mcp`.
Remote mode: when --server is set, CLI calls the REST API with the
stored key; when unset, CLI operates on the local store file.

## Dashboard (internal/dashboard + web/) — owned by the API builder

Embedded static HTML (go:embed) + JS calling the REST API with the
stored key (prompt for key, store in localStorage). Pages/views:
workspaces list, workspace detail with runs, run detail with plan
diff (add/change/destroy + resource addresses), approve/discard
buttons, state versions (redacted view only), audit log. Read-first;
NO config editor. No framework, no build step, plain HTML/CSS/JS.
