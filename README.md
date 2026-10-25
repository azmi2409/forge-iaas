# forge-iaas

**An agent-ready, open-source Terraform + Terraform Cloud clone.
Self-hosted, MIT licensed, single Go binary.**

forge-iaas is the control plane Terraform Cloud provides — organizations,
workspaces, remote runs, versioned + locked state, variables, policy,
a private module registry, drift detection, and an audit trail — built
so AI agents are first-class operators, not an afterthought.

If you are an AI agent reading this: start at
[Your first run via MCP](#your-first-run-via-mcp).

## The one design decision that matters

forge-iaas does **not** reimplement the Terraform engine. That would be
a multi-year trap, and it would duplicate work the open-source community
already did.

Instead, the runner executes the **OpenTofu** binary (`tofu`) — MPL 2.0,
Linux Foundation governed, HCL / provider / state compatible with
Terraform — and forge-iaas owns everything around it: queueing, state,
policy, approvals, registry, drift, and agent access. This is the TACOS
pattern (Spacelift / Scalr / env0 / Atlantis), minus the SaaS pricing
and minus the Terraform-only lock-in.

Terraform moved to BSL 1.1 in August 2023; OpenTofu is the truly open
fork. forge-iaas is MIT and clean-room: the feature set in
[`docs/REA.md`](docs/REA.md) was mapped from public docs, no
HashiCorp source was accessed, and no Terraform trademark is claimed.

## Concepts

- **Organization → Project → Workspace.** A workspace is one collection
  of infrastructure: config + state + variables + run history.
- **Run.** `plan | apply | destroy | drift`, with a recorded trigger
  (VCS, API, CLI, MCP, schedule, manual) and a status. One run per
  workspace at a time; the state lock enforces it.
- **Plan is the default.** A run plans, runs policy + cost checks,
  then waits for approval. Apply and destroy are separate scopes and
  are never implied by a plan.
- **State versions.** Immutable, numbered, encrypted at rest, redacted
  on read. State is written only by a successful apply (or import).
- **Agent keys (`fiak_…`).** Scoped per org/workspace and per action
  (`plan`, `apply`, `destroy`, `state:read-redacted`,
  `registry:publish`). An agent never receives raw cloud credentials
  or unredacted state — the runner holds credentials; the agent gets
  a redacted plan diff.

## Your first run via MCP

Connect the MCP server (stdio: `fiaas mcp`; HTTP: `/mcp` on
`fiaas serve`), then:

```
1. workspace_list              → see your workspaces
2. workspace_create {name}     → a workspace (config via upload or VCS)
3. run_plan {workspace_id}     → queued plan run
4. run_get {run_id}            → plan summary (redacted), policy, cost
5. run_approve {run_id}        → only with an apply-scoped key, after policy passes
6. state_read_redacted {workspace_id}  → what actually exists now
7. drift_check {workspace_id}  → has real infra drifted from config?
```

## CLI reference

Every command accepts `--json`.

```
fiaas init <name>                 # scaffold a workspace config dir
fiaas login --server <url>        # store server + agent key (0600 file)
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

## REST API

See [`docs/CONTRACT.md`](docs/CONTRACT.md) for the full v1 surface:
workspaces, runs (+approve/discard/cancel), redacted state + versions,
variables, registry, policies, drift, audit log, VCS webhook
(speculative plan only — a push never auto-applies).

## Configuration

| Env | Default | Description |
|---|---|---|
| `FIAAS_DB_PATH` | `./forge-iaas.db` | SQLite file (when `FIAAS_DATABASE_URL` unset) |
| `FIAAS_DATABASE_URL` | — | Postgres DSN (switches storage backend) |
| `FIAAS_MASTER_KEY` | — | 32 raw bytes or base64(32 bytes); encrypts variables + state at rest |
| `FIAAS_ADDR` | `:8080` | `fiaas serve` listen address |
| `FIAAS_TOFU_BIN` | `tofu` | OpenTofu binary path for the runner |

Without `FIAAS_MASTER_KEY` the server uses an ephemeral key and warns
on stderr — stored secrets will not survive restarts.

### Security threat model (honest version)

Variables and state are encrypted with AES-256-GCM before hitting the
DB and decrypted only in memory at run time. This protects backups and
at-rest files. It does **not** protect against anyone who can read
process memory or the `FIAAS_MASTER_KEY` value itself. Agents are
isolated by scoped keys and redaction, not by trust — a plan-scoped key
cannot approve, and no key returns sensitive state values.

## Development

```sh
go build ./...
go vet ./...
go test ./... -count=1
```

Postgres conformance tests run when `FIAAS_TEST_DATABASE_URL` is set,
otherwise they skip.

## Status

MVP DONE locally (2026-10-24, all 8 components in
[`docs/TODO.md`](docs/TODO.md)): control plane + storage, engine
adapter, runner, policy + cost, registry, drift, API + CLI + MCP,
and a minimal dashboard. `go build`, `go vet`, and `go test ./...`
are green, and the mock-engine E2E (`scripts/e2e-mock.sh`) passes:
workspace → plan → approve → apply → state v2 → MCP drift clean,
with a plan-scoped key correctly rejected (403) on approve.

NOT pushed to GitHub and NOT announced — push is a separate
approval. Real-OpenTofu E2E is still open: no `tofu` binary exists
on the build machine, so the tofu engine fails loudly instead of
fabricating a plan; no real cloud account is required for sign-off.

## Not yet (deferred deliberately)

- Own HCL parser / provider protocol — OpenTofu does this.
- Sentinel language — simple JSON rules first, OPA/Rego hook later.
- Real cloud price feeds — static price-table cost stub in v1.
- No-code provisioning UI, SSO/SCIM, multi-server scale-out,
  Terragrunt / Pulumi / CloudFormation engines, OIDC dynamic
  credentials, Terraform Cloud state import.

## License

MIT — see [LICENSE](LICENSE).
