// Package api implements the forge-iaas v1 REST API (see CONTRACT.md).
//
// It is deliberately decoupled from the real store: it codes against the
// small Store interface below (duck-typed against the method names in
// docs/INTERFACES.md, section "Store"). The coordinator wires this
// interface to internal/store when that package lands; the API package
// itself never imports engine/runner and never executes runs — it only
// creates run records. Execution is supplied by the serve command via
// Options.RunLoop (see StartRunner hook below).
//
// Security invariants enforced here:
//   - Sensitive variable values are never returned (DisplayValue only,
//     "***" for sensitive) and never appear in audit entries.
//   - State is returned ONLY via model.RedactedStateView (resource
//     type/name/address, no attribute values). State version history
//     returns metadata only, never raw state bytes.
//   - Plan summaries returned here have sensitive attributes redacted.
//   - Plan-scoped keys can never approve (apply scope or admin only).
//   - A webhook VCS event creates a SPECULATIVE plan run only; it never
//     auto-applies, even if the workspace has auto_apply set.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// Store is the duck-typed subset of internal/store that the API needs.
// Method names and signatures match docs/INTERFACES.md exactly so the
// coordinator can wire the real store with a one-line adapter (or
// directly, since the real store implements a superset of this).
type Store interface {
	AuthenticateKey(plaintext string) (*model.AgentKey, error)
	CreateOrganization(name, slug string) (*model.Organization, error)
	GetOrganization(idOrSlug string) (*model.Organization, error)
	ListOrganizations() ([]*model.Organization, error)
	CreateWorkspace(w *model.Workspace) (*model.Workspace, error)
	GetWorkspace(idOrSlug string) (*model.Workspace, error)
	ListWorkspaces(orgID string) ([]*model.Workspace, error)
	UpdateWorkspace(w *model.Workspace) error
	DeleteWorkspace(id string) error
	CreateRun(r *model.Run) (*model.Run, error)
	GetRun(id string) (*model.Run, error)
	UpdateRun(r *model.Run) error
	ListRuns(wsID string, limit int) ([]*model.Run, error)
	SetVariable(wsID, setID, key, plaintext string, sensitive bool, category string) (*model.Variable, error)
	ListVariables(wsID string) ([]*model.Variable, error)
	LatestStateVersion(wsID string) (*model.StateVersion, error)
	ListStateVersions(wsID string) ([]*model.StateVersion, error)
	CreateModule(m *model.Module, tarball []byte) (*model.Module, error)
	GetModule(ns, name, provider, version string) (*model.Module, []byte, error)
	ListModules() ([]*model.Module, error)
	CreatePolicySet(orgID, wsID, name string, rules []byte) (*model.PolicySet, error)
	ListPolicySets(orgID string) ([]*model.PolicySet, error)
	CreateAgentKey(orgID, wsID string, scopes []string) (string, *model.AgentKey, error)
	AppendAudit(e *model.AuditEntry) error
	ListAudit(wsID string, limit int) ([]*model.AuditEntry, error)
	LatestDriftReport(wsID string) (*model.DriftReport, error)
}

// RunLoop is the execution hook the serve command supplies: a function
// that polls the store and executes queued runs until ctx is done.
// The API package never runs executions itself; when RunLoop is nil,
// runs stay queued until an external `fiaas runner` picks them up.
type RunLoop func(ctx context.Context) error

// Options configures a Server.
type Options struct {
	// AllowAnon, when true, treats requests without a key as actor
	// "local" with all scopes (dev/E2E only). NewServer logs a warning
	// in this mode. When false (default), keyless requests get 401.
	AllowAnon bool
	// RunLoop, when set, is started by Start (see below).
	RunLoop RunLoop
}

// Server is the forge-iaas API server.
type Server struct {
	store Store
	opts  Options
	mux   *http.ServeMux
}

// NewServer builds a Server. Pass opts.AllowAnon=true only for local
// dev/E2E; it logs a warning to the standard logger at construction.
func NewServer(store Store, opts Options) *Server {
	if opts.AllowAnon {
		log.Printf("WARNING: forge-iaas API running with AllowAnon=true: " +
			"unauthenticated requests act as \"local\" with all scopes; " +
			"do not use outside local development")
	}
	s := &Server{store: store, opts: opts, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the HTTP handler serving every CONTRACT.md route.
func (s *Server) Handler() http.Handler { return s.mux }

// Start runs opts.RunLoop (if set) until ctx is done. The HTTP server
// itself is the caller's responsibility (see cmd/fiaas serve, which
// composes this handler with the MCP and dashboard handlers).
func (s *Server) Start(ctx context.Context) error {
	if s.opts.RunLoop == nil {
		return nil
	}
	return s.opts.RunLoop(ctx)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("POST /webhook/vcs", s.handleWebhookVCS)

	m.HandleFunc("GET /api/v1/organizations", s.handleListOrgs)
	m.HandleFunc("POST /api/v1/organizations", s.handleCreateOrg)
	m.HandleFunc("GET /api/v1/organizations/{org}/workspaces", s.handleListWorkspaces)
	m.HandleFunc("POST /api/v1/organizations/{org}/workspaces", s.handleCreateWorkspace)
	m.HandleFunc("GET /api/v1/organizations/{org}/policies", s.handleListPolicies)
	m.HandleFunc("POST /api/v1/organizations/{org}/policies", s.handleCreatePolicy)

	m.HandleFunc("GET /api/v1/workspaces/{id}", s.handleGetWorkspace)
	m.HandleFunc("PUT /api/v1/workspaces/{id}", s.handleUpdateWorkspace)
	m.HandleFunc("DELETE /api/v1/workspaces/{id}", s.handleDeleteWorkspace)
	m.HandleFunc("POST /api/v1/workspaces/{id}/runs", s.handleCreateRun)
	// Convenience (not in CONTRACT.md, additive only): list runs of a
	// workspace for the dashboard/CLI workspace-detail views.
	m.HandleFunc("GET /api/v1/workspaces/{id}/runs", s.handleListRuns)
	m.HandleFunc("GET /api/v1/workspaces/{id}/state", s.handleGetState)
	m.HandleFunc("GET /api/v1/workspaces/{id}/state/versions", s.handleListStateVersions)
	m.HandleFunc("GET /api/v1/workspaces/{id}/variables", s.handleListVariables)
	m.HandleFunc("POST /api/v1/workspaces/{id}/variables", s.handleSetVariable)
	m.HandleFunc("GET /api/v1/workspaces/{id}/drift", s.handleGetDrift)

	m.HandleFunc("GET /api/v1/runs/{id}", s.handleGetRun)
	m.HandleFunc("POST /api/v1/runs/{id}/approve", s.handleApproveRun)
	m.HandleFunc("POST /api/v1/runs/{id}/discard", s.handleDiscardRun)
	m.HandleFunc("POST /api/v1/runs/{id}/cancel", s.handleCancelRun)

	m.HandleFunc("GET /api/v1/registry/modules", s.handleListModules)
	m.HandleFunc("POST /api/v1/registry/modules", s.handlePublishModule)
	m.HandleFunc("GET /api/v1/registry/modules/{ns}/{name}/{version}", s.handleGetModule)

	m.HandleFunc("GET /api/v1/audit", s.handleListAudit)
}

// ---------------------------------------------------------------- auth

type actor struct {
	name   string // key prefix, or "local"
	scopes []string
	orgID  string
	wsID   string
	anon   bool
}

type actorKey struct{}

func actorFromContext(ctx context.Context) *actor {
	if a, ok := ctx.Value(actorKey{}).(*actor); ok {
		return a
	}
	return &actor{name: "anonymous"}
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

// authenticate resolves the request's actor. Keyless + AllowAnon=false
// yields 401; keyless + AllowAnon=true yields actor "local" with all
// scopes; an unrecognised key yields 401.
func (s *Server) authenticate(r *http.Request) (*actor, bool) {
	key := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if key == "" {
		if s.opts.AllowAnon {
			return &actor{name: "local", anon: true, scopes: []string{
				model.ScopePlan, model.ScopeApply, model.ScopeDestroy,
				model.ScopeStateRead, model.ScopeRegistryPublish, model.ScopeAdmin,
			}}, true
		}
		return nil, false
	}
	rec, err := s.store.AuthenticateKey(key)
	if err != nil || rec == nil {
		return nil, false
	}
	return &actor{name: rec.Prefix, scopes: rec.Scopes, orgID: rec.OrgID, wsID: rec.WorkspaceID}, true
}

// withAuth wraps a handler with authentication. The actor is stored in
// the request context for the handler.
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := s.authenticate(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthorized: missing or invalid agent key")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, a)))
	}
}

// requireScope enforces that the actor holds one of the given scopes.
func requireScope(a *actor, scopes ...string) bool { return a.hasAnyScope(scopes...) }

// checkWorkspaceScope rejects keys scoped to a different workspace or
// organization than the workspace being accessed. Unscoped keys (empty
// org/ws) are unrestricted.
func checkWorkspaceScope(a *actor, ws *model.Workspace) bool {
	if a.anon {
		return true
	}
	if a.wsID != "" && a.wsID != ws.ID {
		return false
	}
	if a.orgID != "" && a.orgID != ws.OrgID {
		return false
	}
	return true
}

// audit appends a REDACTED audit entry. Details passed here must never
// contain secret values; callers build them from ids/names only.
// Audit failures never fail the request itself.
func (s *Server) audit(a *actor, action, wsID, runID, detail string) {
	_ = s.store.AppendAudit(&model.AuditEntry{
		Actor: a.name, Action: action, WorkspaceID: wsID, RunID: runID,
		Detail: detail, CreatedAt: time.Now(),
	})
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugRe.ReplaceAllString(s, "-")
	return strings.Trim(s, "-")
}

func maskVariables(vars []*model.Variable) []*model.Variable {
	out := make([]*model.Variable, 0, len(vars))
	for _, v := range vars {
		if v == nil {
			continue
		}
		cp := *v
		cp.Value = "" // plaintext never leaves the server
		if cp.Sensitive {
			cp.DisplayValue = "***"
		}
		out = append(out, &cp)
	}
	return out
}

// redactedRun returns a copy of r whose plan attributes are redacted.
func redactedRun(r *model.Run) *model.Run {
	if r == nil {
		return nil
	}
	cp := *r
	if r.Plan != nil {
		plan := *r.Plan
		res := make([]model.ResourceChange, 0, len(r.Plan.Resources))
		for _, rc := range r.Plan.Resources {
			rc.Attributes = model.RedactAttributes(rc.Attributes)
			res = append(res, rc)
		}
		plan.Resources = res
		plan.RawPlanJSON = nil
		cp.Plan = &plan
	}
	return &cp
}

func (s *Server) resolveOrg(r *http.Request) (*model.Organization, bool) {
	org, err := s.store.GetOrganization(r.PathValue("org"))
	if err != nil || org == nil {
		return nil, false
	}
	return org, true
}

func (s *Server) resolveWorkspace(r *http.Request) (*model.Workspace, bool) {
	ws, err := s.store.GetWorkspace(r.PathValue("id"))
	if err != nil || ws == nil {
		return nil, false
	}
	return ws, true
}

// ---------------------------------------------------------------- health + webhook

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleWebhookVCS creates a SPECULATIVE plan run only. It NEVER
// auto-applies — not even when the workspace has auto_apply=true.
// This endpoint is intentionally unauthenticated (VCS providers sign
// webhooks out of band); signature verification is deferred in v1, so
// treat a webhook plan run as untrusted input: it can only queue a
// plan, and applying still requires an apply-scoped approval.
func (s *Server) handleWebhookVCS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		WorkspaceID string `json:"workspace_id"`
		Workspace   string `json:"workspace"`
		Repository  string `json:"repository"`
		Ref         string `json:"ref"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	id := body.WorkspaceID
	if id == "" {
		id = body.Workspace
	}
	if id == "" {
		writeErr(w, http.StatusBadRequest, "workspace_id is required")
		return
	}
	ws, err := s.store.GetWorkspace(id)
	if err != nil || ws == nil {
		writeErr(w, http.StatusNotFound, "workspace not found")
		return
	}
	run, err := s.store.CreateRun(&model.Run{
		WorkspaceID: ws.ID, Type: model.RunPlan, Trigger: model.TriggerVCS,
		Status: model.StatusQueued, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(&actor{name: "webhook"}, "webhook.vcs.plan", ws.ID, run.ID,
		"speculative plan queued from VCS event; never auto-applies")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id": run.ID, "status": run.Status, "speculative": true,
		"note": "speculative plan only — applying requires an apply-scoped approval",
	})
}

// ---------------------------------------------------------------- organizations

func (s *Server) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		orgs, err := s.store.ListOrganizations()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if orgs == nil {
			orgs = []*model.Organization{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": orgs})
	})(w, r)
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		var body struct {
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Name == "" {
			writeErr(w, http.StatusBadRequest, "name is required")
			return
		}
		slug := body.Slug
		if slug == "" {
			slug = slugify(body.Name)
		}
		org, err := s.store.CreateOrganization(body.Name, slug)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "organization.create", "", "", "created organization "+org.Slug)
		writeJSON(w, http.StatusCreated, org)
	})(w, r)
}

// ---------------------------------------------------------------- workspaces

func (s *Server) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		org, ok := s.resolveOrg(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "organization not found")
			return
		}
		if !a.anon && a.orgID != "" && a.orgID != org.ID {
			writeErr(w, http.StatusForbidden, "key is scoped to a different organization")
			return
		}
		ws, err := s.store.ListWorkspaces(org.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ws == nil {
			ws = []*model.Workspace{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"workspaces": ws})
	})(w, r)
}

func (s *Server) handleCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopePlan) {
			writeErr(w, http.StatusForbidden, "requires plan or admin scope")
			return
		}
		org, ok := s.resolveOrg(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "organization not found")
			return
		}
		if !a.anon && a.orgID != "" && a.orgID != org.ID {
			writeErr(w, http.StatusForbidden, "key is scoped to a different organization")
			return
		}
		var body struct {
			Name          string `json:"name"`
			Slug          string `json:"slug"`
			VCSRepo       string `json:"vcs_repo"`
			VCSBranch     string `json:"vcs_branch"`
			WorkDir       string `json:"work_dir"`
			ConfigPath    string `json:"config_path"`
			ExecutionMode string `json:"execution_mode"`
			AutoApply     bool   `json:"auto_apply"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Name == "" {
			writeErr(w, http.StatusBadRequest, "name is required")
			return
		}
		slug := body.Slug
		if slug == "" {
			slug = slugify(body.Name)
		}
		mode := body.ExecutionMode
		if mode == "" {
			mode = "remote"
		}
		if mode != "remote" && mode != "local" {
			writeErr(w, http.StatusBadRequest, "execution_mode must be remote or local")
			return
		}
		ws, err := s.store.CreateWorkspace(&model.Workspace{
			OrgID: org.ID, Name: body.Name, Slug: slug,
			VCSRepo: body.VCSRepo, VCSBranch: body.VCSBranch,
			WorkDir: body.WorkDir, ConfigPath: body.ConfigPath,
			ExecutionMode: mode, AutoApply: body.AutoApply,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "workspace.create", ws.ID, "", "created workspace "+ws.Slug)
		writeJSON(w, http.StatusCreated, ws)
	})(w, r)
}

func (s *Server) handleGetWorkspace(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		writeJSON(w, http.StatusOK, ws)
	})(w, r)
}

func (s *Server) handleUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopePlan) {
			writeErr(w, http.StatusForbidden, "requires plan or admin scope")
			return
		}
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		var body struct {
			Name          *string `json:"name"`
			Slug          *string `json:"slug"`
			VCSRepo       *string `json:"vcs_repo"`
			VCSBranch     *string `json:"vcs_branch"`
			WorkDir       *string `json:"work_dir"`
			ConfigPath    *string `json:"config_path"`
			ExecutionMode *string `json:"execution_mode"`
			AutoApply     *bool   `json:"auto_apply"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Name != nil {
			ws.Name = *body.Name
		}
		if body.Slug != nil {
			ws.Slug = *body.Slug
		}
		if body.VCSRepo != nil {
			ws.VCSRepo = *body.VCSRepo
		}
		if body.VCSBranch != nil {
			ws.VCSBranch = *body.VCSBranch
		}
		if body.WorkDir != nil {
			ws.WorkDir = *body.WorkDir
		}
		if body.ConfigPath != nil {
			ws.ConfigPath = *body.ConfigPath
		}
		if body.ExecutionMode != nil {
			if *body.ExecutionMode != "remote" && *body.ExecutionMode != "local" {
				writeErr(w, http.StatusBadRequest, "execution_mode must be remote or local")
				return
			}
			ws.ExecutionMode = *body.ExecutionMode
		}
		if body.AutoApply != nil {
			ws.AutoApply = *body.AutoApply
		}
		ws.UpdatedAt = time.Now()
		if err := s.store.UpdateWorkspace(ws); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "workspace.update", ws.ID, "", "updated workspace "+ws.Slug)
		writeJSON(w, http.StatusOK, ws)
	})(w, r)
}

func (s *Server) handleDeleteWorkspace(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopeAdmin) {
			writeErr(w, http.StatusForbidden, "requires admin scope")
			return
		}
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		if err := s.store.DeleteWorkspace(ws.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "workspace.delete", ws.ID, "", "deleted workspace "+ws.Slug)
		writeJSON(w, http.StatusOK, map[string]any{"id": ws.ID, "deleted": true})
	})(w, r)
}

// ---------------------------------------------------------------- runs

func scopeForRunType(runType string) string {
	switch runType {
	case model.RunApply:
		return model.ScopeApply
	case model.RunDestroy:
		return model.ScopeDestroy
	default: // plan, drift
		return model.ScopePlan
	}
}

func (s *Server) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		var body struct {
			Type    string `json:"type"`
			Trigger string `json:"trigger"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		runType := body.Type
		if runType == "" {
			runType = model.RunPlan
		}
		switch runType {
		case model.RunPlan, model.RunApply, model.RunDestroy, model.RunDrift:
		default:
			writeErr(w, http.StatusBadRequest, "type must be plan, apply, destroy, or drift")
			return
		}
		if !requireScope(a, scopeForRunType(runType)) {
			writeErr(w, http.StatusForbidden, "requires "+scopeForRunType(runType)+" or admin scope")
			return
		}
		trigger := body.Trigger
		if trigger == "" {
			trigger = model.TriggerAPI
		}
		run, err := s.store.CreateRun(&model.Run{
			WorkspaceID: ws.ID, Type: runType, Trigger: trigger,
			Status: model.StatusQueued, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "run.create", ws.ID, run.ID, "created "+runType+" run")
		writeJSON(w, http.StatusAccepted, map[string]any{
			"run_id": run.ID, "status": run.Status, "type": run.Type,
			"workspace_id": ws.ID,
		})
	})(w, r)
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		runs, err := s.store.ListRuns(ws.ID, 50)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]*model.Run, 0, len(runs))
		for _, rn := range runs {
			out = append(out, redactedRun(rn))
		}
		writeJSON(w, http.StatusOK, map[string]any{"runs": out})
	})(w, r)
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		run, err := s.store.GetRun(r.PathValue("id"))
		if err != nil || run == nil {
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
		ws, werr := s.store.GetWorkspace(run.WorkspaceID)
		if werr == nil && ws != nil && !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		writeJSON(w, http.StatusOK, redactedRun(run))
	})(w, r)
}

func isTerminalRunStatus(st string) bool {
	switch st {
	case model.StatusApplied, model.StatusFailed, model.StatusDiscarded, model.StatusCanceled:
		return true
	}
	return false
}

// approveRun implements the shared approval gate: plan-scoped keys are
// rejected by the caller (scope check); a failed policy blocks apply;
// an advisory policy requires an override note. On success it creates
// a NEW apply run linked to the plan run and returns it. The plan run
// itself is left untouched (the API never reports a plan run as
// "approved"; callers act on the linked apply run id).
func approveRun(store Store, plan *model.Run, overrideNote, trigger string) (*model.Run, int, string) {
	if plan.Type != model.RunPlan {
		return nil, http.StatusConflict, "only plan runs can be approved"
	}
	if isTerminalRunStatus(plan.Status) {
		return nil, http.StatusConflict, "run is already " + plan.Status
	}
	if plan.Policy != nil {
		switch plan.Policy.Result {
		case model.PolicyFail:
			return nil, http.StatusConflict, "policy failed; apply is blocked"
		case model.PolicyAdvisory:
			if strings.TrimSpace(overrideNote) == "" {
				return nil, http.StatusBadRequest, "advisory policy requires an override_note"
			}
		}
	}
	apply, err := store.CreateRun(&model.Run{
		WorkspaceID: plan.WorkspaceID, Type: model.RunApply,
		Trigger: trigger, Status: model.StatusQueued, PlanRunID: plan.ID,
		OverrideNote: overrideNote, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	if err != nil {
		return nil, http.StatusInternalServerError, err.Error()
	}
	return apply, 0, ""
}

func (s *Server) handleApproveRun(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		// Scope check FIRST: a plan-scoped key is rejected even for a
		// nonexistent run id, so scope can never be probed around.
		if !requireScope(a, model.ScopeApply) {
			writeErr(w, http.StatusForbidden, "requires apply or admin scope; plan-scoped keys cannot approve")
			return
		}
		plan, err := s.store.GetRun(r.PathValue("id"))
		if err != nil || plan == nil {
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
		if ws, werr := s.store.GetWorkspace(plan.WorkspaceID); werr == nil && ws != nil && !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		var body struct {
			OverrideNote string `json:"override_note"`
		}
		// Body is optional (policy-pass approvals need no note); only
		// parse it when present.
		if r.ContentLength != 0 {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		apply, code, msg := approveRun(s.store, plan, body.OverrideNote, model.TriggerAPI)
		if code != 0 {
			writeErr(w, code, msg)
			return
		}
		s.audit(a, "run.approve", plan.WorkspaceID, plan.ID,
			"approved plan run; apply run "+apply.ID+" queued")
		writeJSON(w, http.StatusOK, map[string]any{
			"run_id": plan.ID, "apply_run_id": apply.ID, "status": apply.Status,
		})
	})(w, r)
}

func (s *Server) handleDiscardRun(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopePlan) {
			writeErr(w, http.StatusForbidden, "requires plan or admin scope")
			return
		}
		run, err := s.store.GetRun(r.PathValue("id"))
		if err != nil || run == nil {
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
		if ws, werr := s.store.GetWorkspace(run.WorkspaceID); werr == nil && ws != nil && !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		if isTerminalRunStatus(run.Status) {
			writeErr(w, http.StatusConflict, "run is already "+run.Status)
			return
		}
		run.Status = model.StatusDiscarded
		run.UpdatedAt = time.Now()
		if err := s.store.UpdateRun(run); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "run.discard", run.WorkspaceID, run.ID, "discarded run")
		writeJSON(w, http.StatusOK, map[string]any{"run_id": run.ID, "status": run.Status})
	})(w, r)
}

func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		run, err := s.store.GetRun(r.PathValue("id"))
		if err != nil || run == nil {
			writeErr(w, http.StatusNotFound, "run not found")
			return
		}
		// Cancel needs the scope matching the run's type (an apply run
		// cannot be cancelled with a plan-scoped key).
		if !requireScope(a, scopeForRunType(run.Type)) {
			writeErr(w, http.StatusForbidden, "requires "+scopeForRunType(run.Type)+" or admin scope")
			return
		}
		if ws, werr := s.store.GetWorkspace(run.WorkspaceID); werr == nil && ws != nil && !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		switch run.Status {
		case model.StatusQueued, model.StatusPlanning, model.StatusPolicy,
			model.StatusAwaitingApproval, model.StatusApplying:
		default:
			writeErr(w, http.StatusConflict, "run in status "+run.Status+" cannot be cancelled")
			return
		}
		run.Status = model.StatusCanceled
		run.UpdatedAt = time.Now()
		if err := s.store.UpdateRun(run); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "run.cancel", run.WorkspaceID, run.ID, "cancelled run")
		writeJSON(w, http.StatusOK, map[string]any{"run_id": run.ID, "status": run.Status})
	})(w, r)
}

// ---------------------------------------------------------------- state

func (s *Server) handleGetState(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopeStateRead) {
			writeErr(w, http.StatusForbidden, "requires state:read-redacted or admin scope")
			return
		}
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		sv, err := s.store.LatestStateVersion(ws.ID)
		if err != nil || sv == nil {
			writeErr(w, http.StatusNotFound, "no state version yet")
			return
		}
		// The ONLY state view ever returned: addresses/types, no values.
		view := model.RedactedStateView(sv.Data)
		view["workspace_id"] = ws.ID
		view["state_version_id"] = sv.ID
		view["state_version"] = sv.Version
		writeJSON(w, http.StatusOK, view)
	})(w, r)
}

func (s *Server) handleListStateVersions(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopeStateRead) {
			writeErr(w, http.StatusForbidden, "requires state:read-redacted or admin scope")
			return
		}
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		versions, err := s.store.ListStateVersions(ws.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Metadata only: never raw state bytes.
		out := make([]map[string]any, 0, len(versions))
		for _, sv := range versions {
			out = append(out, map[string]any{
				"id": sv.ID, "workspace_id": sv.WorkspaceID,
				"version": sv.Version, "created_at": sv.CreatedAt,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": out})
	})(w, r)
}

// ---------------------------------------------------------------- variables

func (s *Server) handleListVariables(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		vars, err := s.store.ListVariables(ws.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"variables": maskVariables(vars)})
	})(w, r)
}

func (s *Server) handleSetVariable(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopePlan) {
			writeErr(w, http.StatusForbidden, "requires plan or admin scope")
			return
		}
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		var body struct {
			Key       string `json:"key"`
			Value     string `json:"value"`
			Sensitive bool   `json:"sensitive"`
			Category  string `json:"category"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Key == "" {
			writeErr(w, http.StatusBadRequest, "key is required")
			return
		}
		category := body.Category
		if category == "" {
			category = "terraform"
		}
		if category != "terraform" && category != "env" {
			writeErr(w, http.StatusBadRequest, "category must be terraform or env")
			return
		}
		v, err := s.store.SetVariable(ws.ID, "", body.Key, body.Value, body.Sensitive, category)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Audit NEVER records the value.
		s.audit(a, "variable.set", ws.ID, "",
			"set variable "+body.Key+" (sensitive="+fmt.Sprint(body.Sensitive)+")")
		masked := maskVariables([]*model.Variable{v})
		writeJSON(w, http.StatusCreated, masked[0])
	})(w, r)
}

// ---------------------------------------------------------------- registry

var semverRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

func normalizeVersion(v string) (string, error) {
	m := semverRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return "", errors.New("version must be semver X.Y.Z")
	}
	return m[1] + "." + m[2] + "." + m[3], nil
}

func (s *Server) handleListModules(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		mods, err := s.store.ListModules()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if mods == nil {
			mods = []*model.Module{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"modules": mods})
	})(w, r)
}

func (s *Server) handlePublishModule(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopeRegistryPublish) {
			writeErr(w, http.StatusForbidden, "requires registry:publish or admin scope")
			return
		}
		var body struct {
			Namespace     string `json:"namespace"`
			Name          string `json:"name"`
			Provider      string `json:"provider"`
			Version       string `json:"version"`
			Readme        string `json:"readme"`
			TarballBase64 string `json:"tarball_base64"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Namespace == "" || body.Name == "" || body.Provider == "" {
			writeErr(w, http.StatusBadRequest, "namespace, name, and provider are required")
			return
		}
		version, err := normalizeVersion(body.Version)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		var tarball []byte
		if body.TarballBase64 != "" {
			tarball, err = base64.StdEncoding.DecodeString(body.TarballBase64)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "tarball_base64 is not valid base64")
				return
			}
		}
		mod, err := s.store.CreateModule(&model.Module{
			Namespace: body.Namespace, Name: body.Name, Provider: body.Provider,
			Version: version, Readme: body.Readme, CreatedAt: time.Now(),
		}, tarball)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") ||
				strings.Contains(strings.ToLower(err.Error()), "exists") {
				writeErr(w, http.StatusConflict, err.Error())
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "module.publish", "", "",
			"published module "+mod.Namespace+"/"+mod.Name+" v"+mod.Version)
		writeJSON(w, http.StatusCreated, mod)
	})(w, r)
}

func (s *Server) handleGetModule(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		ns, name, version := r.PathValue("ns"), r.PathValue("name"), r.PathValue("version")
		version, err := normalizeVersion(version)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// Filter ListModules rather than GetModule(ns,name,"",version):
		// the CONTRACT path carries no provider segment, so the provider
		// is unknown here and must not be guessed.
		mods, err := s.store.ListModules()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, m := range mods {
			if m.Namespace == ns && m.Name == name && m.Version == version {
				writeJSON(w, http.StatusOK, map[string]any{
					"module": m,
					"source": "fiaas/" + ns + "/" + name,
				})
				return
			}
		}
		writeErr(w, http.StatusNotFound, "module not found")
	})(w, r)
}

// ---------------------------------------------------------------- policies

func policyOutput(p *model.PolicySet) map[string]any {
	var rules any
	if len(p.RulesJSON) > 0 {
		var decoded any
		if err := json.Unmarshal(p.RulesJSON, &decoded); err == nil {
			rules = decoded
		} else {
			rules = string(p.RulesJSON)
		}
	}
	return map[string]any{
		"id": p.ID, "org_id": p.OrgID, "workspace_id": p.WorkspaceID,
		"name": p.Name, "rules": rules, "created_at": p.CreatedAt,
	}
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		org, ok := s.resolveOrg(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "organization not found")
			return
		}
		if !a.anon && a.orgID != "" && a.orgID != org.ID {
			writeErr(w, http.StatusForbidden, "key is scoped to a different organization")
			return
		}
		sets, err := s.store.ListPolicySets(org.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		out := make([]map[string]any, 0, len(sets))
		for _, p := range sets {
			out = append(out, policyOutput(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": out})
	})(w, r)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		if !requireScope(a, model.ScopeAdmin) {
			writeErr(w, http.StatusForbidden, "requires admin scope")
			return
		}
		org, ok := s.resolveOrg(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "organization not found")
			return
		}
		if !a.anon && a.orgID != "" && a.orgID != org.ID {
			writeErr(w, http.StatusForbidden, "key is scoped to a different organization")
			return
		}
		var body struct {
			Name        string          `json:"name"`
			WorkspaceID string          `json:"workspace_id"`
			Rules       json.RawMessage `json:"rules"`
		}
		if !decodeJSON(w, r, &body) {
			return
		}
		if body.Name == "" {
			writeErr(w, http.StatusBadRequest, "name is required")
			return
		}
		if len(body.Rules) == 0 {
			writeErr(w, http.StatusBadRequest, "rules are required")
			return
		}
		ps, err := s.store.CreatePolicySet(org.ID, body.WorkspaceID, body.Name, []byte(body.Rules))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(a, "policy.create", body.WorkspaceID, "", "created policy set "+ps.Name)
		writeJSON(w, http.StatusCreated, policyOutput(ps))
	})(w, r)
}

// ---------------------------------------------------------------- drift + audit

func (s *Server) handleGetDrift(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		ws, ok := s.resolveWorkspace(r)
		if !ok {
			writeErr(w, http.StatusNotFound, "workspace not found")
			return
		}
		if !checkWorkspaceScope(a, ws) {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace or organization")
			return
		}
		rep, err := s.store.LatestDriftReport(ws.ID)
		if err != nil || rep == nil {
			writeErr(w, http.StatusNotFound, "no drift report yet")
			return
		}
		writeJSON(w, http.StatusOK, rep)
	})(w, r)
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	s.withAuth(func(w http.ResponseWriter, r *http.Request) {
		a := actorFromContext(r.Context())
		wsID := r.URL.Query().Get("workspace")
		if wsID != "" && !a.anon && a.wsID != "" && a.wsID != wsID {
			writeErr(w, http.StatusForbidden, "key is scoped to a different workspace")
			return
		}
		entries, err := s.store.ListAudit(wsID, 100)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if entries == nil {
			entries = []*model.AuditEntry{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
	})(w, r)
}
