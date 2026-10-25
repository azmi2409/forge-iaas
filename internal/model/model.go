// Package model holds the shared domain types for forge-iaas.
// This package is FROZEN by the coordinator: sub-builders must import
// these types, not redefine their own copies.
package model

import "time"

// Run types.
const (
	RunPlan    = "plan"
	RunApply   = "apply"
	RunDestroy = "destroy"
	RunDrift   = "drift"
)

// Run statuses (see CONTRACT.md; "approved" is an internal transient
// state used only between approve and the apply run being queued —
// the API never reports a plan run as "approved", it reports the
// linked apply run id instead).
const (
	StatusQueued           = "queued"
	StatusPlanning         = "planning"
	StatusPolicy           = "policy"
	StatusAwaitingApproval = "awaiting_approval"
	StatusApplying         = "applying"
	StatusApplied          = "applied"
	StatusFailed           = "failed"
	StatusDiscarded        = "discarded"
	StatusCanceled         = "canceled"
)

// Triggers.
const (
	TriggerVCS      = "vcs"
	TriggerAPI      = "api"
	TriggerCLI      = "cli"
	TriggerMCP      = "mcp"
	TriggerSchedule = "schedule"
	TriggerManual   = "manual"
)

// Policy results.
const (
	PolicyPass     = "pass"
	PolicyAdvisory = "advisory"
	PolicyFail     = "fail"
)

// Agent-key scopes. Apply/destroy are never implied by plan.
const (
	ScopePlan            = "plan"
	ScopeApply           = "apply"
	ScopeDestroy         = "destroy"
	ScopeStateRead       = "state:read-redacted"
	ScopeRegistryPublish = "registry:publish"
	ScopeAdmin           = "admin"
)

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type Project struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

type Workspace struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"org_id"`
	ProjectID     string     `json:"project_id,omitempty"`
	Name          string     `json:"name"`
	Slug          string     `json:"slug"`
	VCSRepo       string     `json:"vcs_repo,omitempty"`
	VCSBranch     string     `json:"vcs_branch,omitempty"`
	WorkDir       string     `json:"work_dir,omitempty"`
	ConfigPath    string     `json:"config_path,omitempty"` // local dir with .tf files (upload / clone target)
	ExecutionMode string     `json:"execution_mode"`        // "remote" | "local"
	AutoApply     bool       `json:"auto_apply"`
	LockedBy      string     `json:"locked_by,omitempty"`
	LockedAt      *time.Time `json:"locked_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type Variable struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	SetID       string `json:"set_id,omitempty"`
	Key         string `json:"key"`
	// Value is the PLAINTEXT only in memory for the runner. It must
	// never be serialized to API/MCP/audit/log output when Sensitive.
	Value string `json:"-"`
	// DisplayValue is what API/MCP may return: plaintext for
	// non-sensitive, "***" for sensitive.
	DisplayValue string `json:"value"`
	Sensitive    bool   `json:"sensitive"`
	Category     string `json:"category"` // "terraform" | "env"
}

// EngineVars is the variable set handed to an execution engine,
// partitioned by category. This split is what makes cloud providers
// work: a "terraform" variable becomes TF_VAR_<key> for HCL
// `variable` blocks, while an "env" variable is passed through
// verbatim as process environment — which is exactly how the AWS
// provider discovers credentials and region (AWS_ACCESS_KEY_ID,
// AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, AWS_REGION /
// AWS_DEFAULT_REGION). Before this type existed the runner flattened
// everything into one map and the tofu engine TF_VAR_-prefixed all
// of it, so an AWS credential stored as an env variable never
// reached the provider at all.
//
// EngineVars is in-memory only and must never be serialized to
// API/MCP/audit/log output: Env may hold raw credentials.
type EngineVars struct {
	Terraform map[string]string // -> TF_VAR_<key>
	Env       map[string]string // -> <key> verbatim
}

// AllValues returns every variable value (both partitions), for log
// and error redaction. Callers must treat the result as secret.
func (v EngineVars) AllValues() []string {
	out := make([]string, 0, len(v.Terraform)+len(v.Env))
	for _, s := range v.Terraform {
		if s != "" {
			out = append(out, s)
		}
	}
	for _, s := range v.Env {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

type VariableSet struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// StateVersion is immutable. Data is the raw state JSON, encrypted
// at rest; Redacted() returns the safe view (addresses/types only).
type StateVersion struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	Version     int       `json:"version"`
	Data        []byte    `json:"-"` // raw state JSON, encrypted at rest in the store
	CreatedAt   time.Time `json:"created_at"`
}

// ResourceChange is one entry of a plan summary. Attributes are
// already redacted: sensitive keys are replaced, never returned.
type ResourceChange struct {
	Address    string         `json:"address"`
	Type       string         `json:"type"`
	Action     string         `json:"action"` // "create" | "update" | "delete" | "no-op"
	Attributes map[string]any `json:"attributes,omitempty"`
}

type PlanSummary struct {
	Add       int              `json:"add"`
	Change    int              `json:"change"`
	Destroy   int              `json:"destroy"`
	Resources []ResourceChange `json:"resources"`
	// RawPlanJSON is internal (tofu plan JSON / mock plan); never
	// serialized to API/MCP output without redaction.
	RawPlanJSON []byte `json:"-"`
}

type CostEstimate struct {
	MonthlyUSD float64 `json:"monthly_usd"`
	DeltaUSD   float64 `json:"delta_usd"`
	Note       string  `json:"note"` // always: "estimate from static price table, not a cloud bill"
}

type PolicyResult struct {
	Result   string   `json:"result"` // pass | advisory | fail
	Messages []string `json:"messages"`
}

type Run struct {
	ID           string        `json:"id"`
	WorkspaceID  string        `json:"workspace_id"`
	Type         string        `json:"type"` // plan | apply | destroy | drift
	Trigger      string        `json:"trigger"`
	Status       string        `json:"status"`
	PlanRunID    string        `json:"plan_run_id,omitempty"` // apply runs link back to their plan run
	Plan         *PlanSummary  `json:"plan,omitempty"`
	Policy       *PolicyResult `json:"policy,omitempty"`
	Cost         *CostEstimate `json:"cost,omitempty"`
	OverrideNote string        `json:"override_note,omitempty"`
	Log          string        `json:"log,omitempty"`
	StateVersion int           `json:"state_version,omitempty"`
	Error        string        `json:"error,omitempty"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	FinishedAt   *time.Time    `json:"finished_at,omitempty"`
}

type PolicySet struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	WorkspaceID string    `json:"workspace_id,omitempty"` // empty = org-wide
	Name        string    `json:"name"`
	RulesJSON   []byte    `json:"rules"`
	CreatedAt   time.Time `json:"created_at"`
}

// PolicyRules is the JSON shape stored in PolicySet.RulesJSON.
// Deny entries use the contract form, e.g.
// "resource type aws_instance where instance_type not in [t3.micro, t3.small]"
// plus the structured fields below, which are equivalent and easier
// to evaluate deterministically.
type PolicyRules struct {
	Deny              []string `json:"deny,omitempty"`
	RequireTags       []string `json:"require_tags,omitempty"`
	DenyDestroy       bool     `json:"deny_destroy,omitempty"`
	MaxMonthlyCostUSD float64  `json:"max_monthly_cost_usd,omitempty"`
	AllowedRegions    []string `json:"allowed_regions,omitempty"`
}

type Module struct {
	ID        string    `json:"id"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	Version   string    `json:"version"` // semver, no leading "v" required
	Readme    string    `json:"readme,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AgentKey struct {
	ID          string    `json:"id"`
	Prefix      string    `json:"prefix"` // e.g. "fiak_abc123" shown once at creation, then prefix only
	Hash        string    `json:"-"`
	OrgID       string    `json:"org_id"`
	WorkspaceID string    `json:"workspace_id,omitempty"`
	Scopes      []string  `json:"scopes"`
	CreatedAt   time.Time `json:"created_at"`
}

type AuditEntry struct {
	ID          string    `json:"id"`
	Actor       string    `json:"actor"` // key prefix, "local", or "system"
	Action      string    `json:"action"`
	WorkspaceID string    `json:"workspace_id,omitempty"`
	RunID       string    `json:"run_id,omitempty"`
	Detail      string    `json:"detail"` // MUST already be redacted by the caller
	CreatedAt   time.Time `json:"created_at"`
}

type DriftReport struct {
	ID          string       `json:"id"`
	WorkspaceID string       `json:"workspace_id"`
	Drifted     bool         `json:"drifted"`
	Summary     *PlanSummary `json:"summary,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
}
