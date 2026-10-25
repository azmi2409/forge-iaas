# CONTRACT — forge-iaas v1 (source of truth for the MVP build)

## Identity

- Repo: `azmi2409/forge-iaas` (public, MIT) — SHELVED: do not announce
  or share until the user approves, per the forge-* rule.
- Binary: `fiaas`. Server: `fiaas serve`. MCP: `fiaas mcp` (stdio) and
  `/mcp` on the server (Streamable HTTP).
- Language: Go, single binary, zero non-stdlib deps where practical
  (same discipline as forge-ci). SQLite default, Postgres prod.
- Execution engine: the OpenTofu binary (`tofu`), invoked by the runner.
  forge-iaas does NOT parse HCL or speak the provider protocol itself
  in v1. If `tofu` is absent, runs fail loudly; a mock engine exists
  only for tests and demos (never for real applies).

## Core model

- Organization → Project → Workspace. A workspace has: VCS source
  (repo + branch + working directory) or uploaded config, variables,
  variable sets, execution mode (remote | local), auto-apply flag
  (default false), and a state lock.
- Run: `plan | apply | destroy | drift` with trigger
  (`vcs | api | cli | mcp | schedule | manual`), status
  (`queued | planning | policy | awaiting_approval | applying |
  applied | failed | discarded | canceled`), plan summary, policy
  result, cost estimate, logs, and the state version it produced.
- State version: immutable, numbered per workspace, encrypted at rest,
  redacted on read (sensitive values replaced, never returned to
  agents or the UI by default).
- Variable: `key, value, sensitive, category (terraform|env)`.
  Sensitive values are encrypted (AES-256-GCM, `FIAAS_MASTER_KEY`)
  and masked in every log/API response.
- Module (registry): `namespace/name/provider`, semver versions,
  source tarball, README; consumed as `source = "fiaas/<ns>/<name>"`.
- Policy set: JSON rules scoped org-wide or per-workspace, e.g.
  `{deny: ["resource type aws_instance where instance_type not in [t3.micro, t3.small]"], require_tags: ["owner"], deny_destroy: true, max_monthly_cost_usd: 500}`.
  Result: `pass | advisory | fail`. Fail blocks apply; advisory
  requires an explicit override note.
- Agent key: `fiak_…`, scoped per organization/workspace and per
  action (`plan`, `apply`, `destroy`, `state:read-redacted`,
  `registry:publish`). Apply/destroy scopes are never implied by
  a plan scope. Keys are hashed at rest; only the prefix is shown
  after creation.

## REST API (v1)

| Method | Path | Description |
|---|---|---|
| GET/POST | `/api/v1/organizations` | list / create |
| GET/POST | `/api/v1/organizations/{org}/workspaces` | list / create |
| GET/PUT/DELETE | `/api/v1/workspaces/{id}` | get / update / delete |
| POST | `/api/v1/workspaces/{id}/runs` | `{type: plan\|apply\|destroy, trigger}` → `202 {run_id, status}` |
| GET | `/api/v1/runs/{id}` | run + plan summary + policy + cost (redacted) |
| POST | `/api/v1/runs/{id}/approve` | human or apply-scoped key; requires policy pass |
| POST | `/api/v1/runs/{id}/discard` | discard a planned run |
| POST | `/api/v1/runs/{id}/cancel` | cancel a queued/running run |
| GET | `/api/v1/workspaces/{id}/state` | latest state version, redacted |
| GET | `/api/v1/workspaces/{id}/state/versions` | version history |
| GET/POST | `/api/v1/workspaces/{id}/variables` | list / set (sensitive encrypted) |
| GET/POST | `/api/v1/registry/modules` | list / publish |
| GET | `/api/v1/registry/modules/{ns}/{name}/{version}` | module detail |
| GET/POST | `/api/v1/organizations/{org}/policies` | list / create policy set |
| GET | `/api/v1/workspaces/{id}/drift` | latest drift report |
| GET | `/api/v1/audit?workspace=` | audit log (who, what, run, result) |
| GET | `/healthz` | `{"ok": true}` |
| POST | `/webhook/vcs` | VCS push/PR → speculative plan (apply never auto-runs) |

Errors are `{"error": "..."}`. Every mutating response includes the
run or resource id the caller acts on next.

## MCP tools (v1)

`workspace_list, workspace_create, workspace_get, run_plan,
run_get, run_approve, run_discard, state_read_redacted, drift_check,
variable_set, module_publish, module_get, policy_check, cost_estimate,
audit_list`

Rules: `run_plan` is the only tool a plan-scoped key may call for
execution. `run_approve` rejects plan-scoped keys. `state_read_redacted`
never returns sensitive values. Every tool result states the approval
gate status for the next step in plain language.

## CLI (v1)

```
fiaas init <name>                 # scaffold a workspace config dir
fiaas login --server <url>        # store server + agent key (hashed file, 0600)
fiaas workspace list|create|get
fiaas run plan|apply|destroy <workspace> [--wait]
fiaas run approve|discard <run-id>
fiaas state show <workspace>      # redacted
fiaas variable set <workspace> KEY=VALUE [--sensitive]
fiaas module publish <dir>
fiaas drift <workspace>
fiaas serve [--addr :8080]        # API + runner queue + web UI + MCP
fiaas runner [--server <url>]     # polling runner, no inbound ports
fiaas mcp                         # MCP over stdio
```

Every command accepts `--json`.

## Config

| Env | Default | Description |
|---|---|---|
| `FIAAS_DB_PATH` | `./forge-iaas.db` | SQLite file (when `FIAAS_DATABASE_URL` unset) |
| `FIAAS_DATABASE_URL` | — | Postgres DSN (switches storage backend) |
| `FIAAS_MASTER_KEY` | — | 32 raw bytes or base64(32 bytes); encrypts variables + state at rest |
| `FIAAS_ADDR` | `:8080` | `fiaas serve` listen address |
| `FIAAS_TOFU_BIN` | `tofu` | OpenTofu binary path for the runner |

Without `FIAAS_MASTER_KEY` the server uses an ephemeral key and warns
on stderr — stored secrets will not survive restarts.

## Verification gates (MVP is not done until all pass)

1. `go build ./...`, `go vet ./...`, `go test ./... -count=1` green.
2. End-to-end with the mock engine: workspace → plan → approve →
   apply → state version 2 → drift clean, all via CLI + MCP.
3. End-to-end with a real `tofu` binary (if available on the build
   machine) against a no-cloud mock config: plan produces a real
   plan summary; no real cloud account is required for MVP sign-off.
4. Security checks: sensitive variable never appears in logs, API,
   MCP output, or audit entries; plan-scoped key cannot approve;
   two concurrent runs on one workspace cannot both apply (lock).
5. CI green on the pushed repo.

## Deferred (explicit, not silent gaps)

Web UI beyond a minimal run/state dashboard; Sentinel/OPA language;
real price feeds; no-code provisioning; SSO/SCIM; multi-server;
Terragrunt/Pulumi/CFN engines; OIDC dynamic credentials; state
import from existing Terraform Cloud workspaces.
