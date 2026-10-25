# TODO — forge-iaas MVP (8 components)

Status 2026-10-25: MVP BUILT (all 8 components), unit tests green,
CLI E2E with the mock engine green through state version 2 + drift
clean + plan-key 403. PUSHED to github.com/azmi2409/forge-iaas
2026-10-25 (public, NOT announced — shelved rule still stands).

- [x] 0. REA: Terraform + Terraform Cloud feature inventory, OpenTofu
      fork analysis, TACOS pattern, agent-ready differentiation
- [x] 1. Core domain + storage: orgs, projects, workspaces, variables /
      variable sets (AES-256-GCM), state versions + locking, audit log.
      SQLite default, Postgres prod. (`internal/store/`)
- [x] 2. Config + engine adapter: workspace config ingestion (local
      config dir; git clone is via the workspace's VCS fields, runner
      executes in ConfigPath), run queue, OpenTofu runner invocation,
      plan parsing into the redacted summary. Mock engine for
      tests/demo, clearly labeled, never for real applies.
      (`internal/engine/`)
- [x] 3. Runner: polling agent (no inbound ports; remote polling is
      deferred — `fiaas runner` works against the local store file,
      `fiaas serve` runs it in-process), log streaming, state upload
      on successful apply, failure reporting. (`internal/runner/`)
- [x] 4. Policy + cost: JSON rule engine (deny rules, required tags,
      deny-destroy, budget cap, allowed regions), advisory vs fail,
      cost-estimate stub from a static price table, always labeled
      as an estimate. (`internal/policy/`)
- [x] 5. Registry: private module registry (publish, semver, get).
      Provider mirror stub is deferred (registry stores modules;
      no provider mirroring in v1). (`internal/registry/`)
- [x] 6. Drift + health: manual/MCP drift check, drift report,
      workspace explorer (resource inventory from redacted state).
      Scheduled drift (cron) is deferred — drift runs are created
      on demand via MCP/CLI. (`internal/drift/`, MCP `drift_check`)
- [x] 7. API + CLI + MCP: REST per CONTRACT.md, `fiaas` CLI, MCP
      server (stdio + Streamable HTTP at /mcp), scoped agent keys
      `fiak_…`. (`internal/api/`, `internal/mcp/`, `cmd/fiaas/`)
- [x] 8. Web dashboard (minimal): workspaces, runs, plan diff,
      approve/discard, state versions, audit log. Read-first; no
      config editor in v1. (`internal/dashboard/`, `web/`)
- [~] 9. Verification gates: unit tests green (`go test ./...`),
      CLI + MCP E2E (mock) green, security checks green (see
      below). OPEN: (a) real-`tofu` E2E — no `tofu` binary on this
      machine, tofu engine returns a loud error instead of a fake
      plan; (b) CI workflow added 2026-10-25 and pushed with the
      MVP (CI run on GitHub pending at push time). MCP stdio note: the first scripted
      MCP run only *appeared* to hang — the probe script waited
      for a reply to `notifications/initialized`, which by
      protocol never gets one. Fixed in `scripts/e2e-mock.sh`
      (notifications are send-only) and the full run then passed,
      including `workspace_list`, `state_read_redacted` (state
      version 2), and `drift_check`.
- [ ] 10. Launch: NOT announced/shared until the user approves
      (forge-* shelved rule).

## Verification evidence (2026-10-24, local)

- `go build ./...`, `go vet ./...`, `go test ./... -count=1`:
  all packages ok (see coordinator report for exact output).
- CLI E2E script `scripts/e2e-mock.sh` (mock engine, serve +
  CLI remote): org -> workspace -> sensitive variable -> plan
  (add 2) -> approve -> apply -> state v1 -> plan (no-op)
  -> approve -> apply -> state v2 (redacted view: 2 resources)
  -> plan-scoped key approve -> HTTP 403 -> drift clean.
  The script's MCP section hung and was killed for debugging;
  the CLI/API portion above is from its captured log.
- Security: sensitive variable value absent from variables list
  and audit output in the E2E run; plan-scoped approve rejected
  403 in API tests and in the live E2E; workspace-lock atomicity
  covered by store + runner unit tests (apply with a held lock
  fails, lock untouched).

## Deferred (from CONTRACT.md, still deferred)

Sentinel/OPA language, real price feeds, no-code provisioning,
SSO/SCIM, multi-server scale-out, Terragrunt/Pulumi/CFN engines,
OIDC dynamic credentials, Terraform Cloud state import, remote
runner polling, scheduled drift, provider mirror.
