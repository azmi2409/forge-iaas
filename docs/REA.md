# REA — Terraform + Terraform Cloud (reverse-engineering analysis, 2026-10-24)

Source: public docs, guides, and competitor comparisons surveyed 2026-10-24.
No Terraform / HashiCorp source was accessed; this is a behavioral analysis
only. Clean-room clone: we copy observable behavior, not code.

## The two products being cloned

Terraform (the engine) and Terraform Cloud — now HCP Terraform — (the
control plane) are different layers, and forge-iaas must clone both jobs,
not just one:

- **Engine job:** take declarative config, compare it to real infra via
  state, show a plan, apply it.
- **Control-plane job:** give teams a shared place to run that engine
  remotely, with locked/versioned state, variables, approvals, policy,
  a module registry, drift detection, and an audit trail.

## Terraform core — feature inventory (what we clone)

| Feature | Behavior |
|---|---|
| HCL config | Declarative `.tf` files: `terraform`, `provider`, `resource`, `data`, `variable`, `output`, `module` blocks; `count` / `for_each`, references like `aws_vpc.main.id` |
| Workflow | `init` (download providers, set up backend) → `fmt` / `validate` → `plan` (dry run, `-out` saved plan, `-destroy`, `-target`) → `apply` (saved plan, no re-prompt) → `destroy` → `import` (bring existing infra under management) → `output` / `show` / `state list|show` / `graph` |
| State | `terraform.tfstate` maps config addresses to real object IDs; it is the source of truth. Contains sensitive values, so encryption + access control are critical. Remote backends (S3, GCS, Azure Blob, Terraform Cloud) + state locking against concurrent runs |
| Providers | Plugins that talk to cloud/SaaS APIs. Registry hosts 4,000+ providers, 15,000+ modules (AWS 1,000+ resource types, Azure 600+, GCP, Kubernetes, GitHub, Cloudflare, Datadog, Helm) |
| Modules | Reusable, versioned (semver) packages of config; verified modules from cloud partners, community modules for VPC/EKS/AKS patterns |
| Variables / outputs | Inputs with types/defaults, `.tfvars` files, `-var` / `-var-file`; outputs exported after apply, consumable cross-workspace |
| Drift | Real infra diverging from config/state is detected by a fresh plan |

## Terraform Cloud — feature inventory (what we clone)

| Feature | Behavior |
|---|---|
| Organizations / workspaces | Workspace = one collection of infra (replaces a local working directory): config + state + variables + run history. Org dashboard lists workspaces + run statuses |
| Remote execution | Runs execute on disposable machines in the platform's cloud by default; agents run them on your own / private infra instead. Workspace execution mode can be remote or local (local still uses remote state) |
| Runs | Plan → policy check → cost estimate → apply, with trigger recorded (VCS, API, manual), status, and logs. One run per workspace at a time; queue otherwise |
| VCS-driven runs | Push / PR to a connected repo triggers a speculative plan; merge triggers apply (subject to approval) |
| Remote state | Central, versioned state history, locking, cross-workspace data sharing, audit trail of who changed what and how a run was triggered |
| Variables / variable sets | Secure variable storage; sets shared across workspaces; sensitive values masked |
| Private module registry | Publish versioned modules privately; workspaces consume them by source + version; test-integrated publishing, deprecation (paid tiers) |
| Policy as code | Sentinel (proprietary) policy sets scoped org-wide or per-workspace: hard fail / advisory / soft fail with override. OPA added later. Cost estimation feeds policy (e.g. budget caps, allowed instance sizes, allowed regions) |
| Run tasks | Pre/post-plan hooks to external services |
| Drift / health | Scheduled drift detection + health assessments, workspace explorer / resource inventory |
| Access | RBAC (org + workspace roles), SSO, audit logs, OIDC dynamic cloud credentials (paid tiers) |
| No-code provisioning | Provision from a module via form inputs, no HCL written by the requester (paid tiers) |
| Pricing shape (2026, from comparisons — verify before quoting) | Historically Free / $20/user Team / $70/user Team & Governance + $500 per extra concurrency / Business; newer tiers Free / Standard / Plus / Premium, RUM-based (Resources Under Management). Free tier reportedly ended Mar 2026. The RUM + per-user + concurrency pricing is itself a pain point competitors attack |

## The fork that changes the strategy

- Aug 2023: HashiCorp moved Terraform from MPL 2.0 to **BSL 1.1**
  (source-available; bars building competing commercial offerings).
- Jan 2024: **OpenTofu** shipped as the community fork, MPL 2.0,
  Linux Foundation / CNCF governed, full HCL + provider + state
  compatibility back to Terraform 1.5. Divergences since: native
  client-side state encryption (1.7), early variable evaluation (1.8),
  provider `for_each` + `-exclude` (1.9), OCI registry support (1.10).
  Feb 2025: IBM completed the $6.4B HashiCorp acquisition.
- Consequence for forge-iaas: **do not reimplement the engine.**
  Orchestrate the OpenTofu binary (truly open, same HCL/providers/state)
  as the execution engine, and build the control plane ourselves.
  That is also what Spacelift / Scalr / env0 / Atlantis do — the
  TACOS (Terraform Automation and Collaboration Software) pattern —
  except Atlantis is self-host-only with no built-in policy, and the
  SaaS TACOS tools are not MIT self-hosted.

## Competitor gaps (where we win)

| Competitor | Gap forge-iaas exploits |
|---|---|
| Terraform Cloud / HCP Terraform | Terraform-only (no OpenTofu), RUM pricing, policy + drift + audit gated to paid tiers, no agent-first API |
| Spacelift / env0 / Scalr | Multi-engine and strong, but SaaS-priced, not MIT self-hosted; agent access is a bolt-on (Spacelift MCP is the closest) |
| Atlantis | Free + self-hosted, but Terraform/OpenTofu only, no policy engine, no registry, no state UI — PR comments as the interface |
| Pulumi Cloud | Code-first (TS/Python/Go), not HCL; different audience |
| GitHub Actions / GitLab CI | Pipeline-only: no IaC-aware state, locking, drift, or registry |

## What Terraform Cloud does NOT have (our differentiation)

- **Agents as first-class operators.** No scoped agent login, no MCP
  server, no agent-safe plan summary. forge-iaas: agent API keys
  (`fiak_…`), one operator model (`kind: human|agent`), MCP tools for
  the whole run lifecycle, and an approval gate that is *not* bypassable
  by the agent token itself.
- **Agent-safe execution by default.** Agents never receive raw cloud
  credentials or unredacted state. The runner holds credentials; the
  agent gets a redacted plan diff (add/change/destroy counts + resource
  addresses, secrets masked) and must request apply through the gate.
  Plan is the default; apply/destroy are separate, explicitly granted
  scopes.
- **Truly open + self-hosted.** MIT, single Go binary, SQLite default /
  Postgres prod, docker-compose, Coolify-ready — no RUM, no per-user
  seat meter, no policy/drift paywall.
- **OpenTofu-native, not Terraform-locked.** HCL written for
  Terraform/OpenTofu runs via the OpenTofu binary; provider and state
  formats stay compatible with both.

## Architecture pattern (TACOS, industry standard)

- Control plane (API + web UI + queue) — authoritative for orgs,
  workspaces, variables, state versions, runs, policies, registry,
  audit log.
- Runner (polling agent, no inbound ports) — claims queued runs,
  checks out config, runs `tofu init/plan/apply`, streams logs,
  uploads new state version. Same pattern as Terraform Cloud Agents
  and Spacelift workers.
- State is never edited by hand in MVP: it is written only by a
  successful apply (or import), versioned, locked per workspace,
  encrypted at rest (AES-256-GCM, same pattern as forge-workflow
  credentials), redacted on read.
- Policy runs between plan and apply: plan JSON → rule evaluation →
  pass / advisory / hard fail. Cost estimate is a policy input, not
  a billing feature, in MVP.

## Non-goals for MVP (explicit)

Own HCL parser or provider protocol (OpenTofu binary does this);
Sentinel language itself (simple JSON rules first, OPA/Rego hook
later); real cloud price feeds (static price table stub for cost
estimate); no-code provisioning UI; SSO/SCIM; multi-server scale-out;
Terragrunt / Pulumi / CloudFormation engines (adapter interface only);
dynamic OIDC cloud credentials (static runner credentials first,
OIDC deferred).
