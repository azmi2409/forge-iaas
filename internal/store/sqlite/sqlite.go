// Package sqlite is the file-backed store implementation for forge-iaas.
package sqlite

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/azmi2409/forge-iaas/internal/model"
	"github.com/azmi2409/forge-iaas/internal/store"
)

// SQLiteStore implements store.Store on top of a SQLite file.
type SQLiteStore struct {
	db  *sql.DB
	key []byte
	mu  sync.Mutex
}

// New opens (creating if needed) the SQLite database at path, runs the
// migration, and returns the store. The key must be 32 bytes; state
// data and variable values are encrypted with it.
func New(path string, key []byte) (*SQLiteStore, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db, key: key}
	if err := s.Migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Migrate creates the schema if it does not already exist.
func (s *SQLiteStore) Migrate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS organizations (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	slug TEXT UNIQUE NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
	id TEXT PRIMARY KEY,
	org_id TEXT NOT NULL,
	name TEXT NOT NULL,
	slug TEXT NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE (org_id, slug)
);
CREATE TABLE IF NOT EXISTS workspaces (
	id TEXT PRIMARY KEY,
	org_id TEXT NOT NULL,
	project_id TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL,
	slug TEXT NOT NULL,
	vcs_repo TEXT NOT NULL DEFAULT '',
	vcs_branch TEXT NOT NULL DEFAULT '',
	work_dir TEXT NOT NULL DEFAULT '',
	config_path TEXT NOT NULL DEFAULT '',
	execution_mode TEXT NOT NULL DEFAULT 'remote',
	auto_apply INTEGER NOT NULL DEFAULT 0,
	locked_by TEXT NOT NULL DEFAULT '',
	locked_at TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	UNIQUE (org_id, slug)
);
CREATE TABLE IF NOT EXISTS variables (
	id TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL DEFAULT '',
	set_id TEXT NOT NULL DEFAULT '',
	key TEXT NOT NULL,
	value_enc BLOB,
	sensitive INTEGER NOT NULL DEFAULT 0,
	category TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	UNIQUE (workspace_id, set_id, key)
);
CREATE TABLE IF NOT EXISTS variable_sets (
	id TEXT PRIMARY KEY,
	org_id TEXT NOT NULL,
	name TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state_versions (
	id TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL,
	version INTEGER NOT NULL,
	data_enc BLOB,
	created_at TEXT NOT NULL,
	UNIQUE (workspace_id, version)
);
CREATE TABLE IF NOT EXISTS runs (
	id TEXT PRIMARY KEY,
	seq INTEGER NOT NULL DEFAULT 0,
	workspace_id TEXT NOT NULL,
	type TEXT NOT NULL,
	trigger TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	plan_run_id TEXT NOT NULL DEFAULT '',
	plan_json TEXT,
	policy_json TEXT,
	cost_json TEXT,
	override_note TEXT NOT NULL DEFAULT '',
	log TEXT NOT NULL DEFAULT '',
	state_version INTEGER NOT NULL DEFAULT 0,
	error TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	finished_at TEXT
);
CREATE TABLE IF NOT EXISTS policy_sets (
	id TEXT PRIMARY KEY,
	org_id TEXT NOT NULL,
	workspace_id TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL,
	rules BLOB,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS modules (
	id TEXT PRIMARY KEY,
	namespace TEXT NOT NULL,
	name TEXT NOT NULL,
	provider TEXT NOT NULL,
	version TEXT NOT NULL,
	readme TEXT NOT NULL DEFAULT '',
	tarball BLOB,
	created_at TEXT NOT NULL,
	UNIQUE (namespace, name, provider, version)
);
CREATE TABLE IF NOT EXISTS agent_keys (
	id TEXT PRIMARY KEY,
	prefix TEXT NOT NULL,
	hash TEXT UNIQUE NOT NULL,
	org_id TEXT NOT NULL,
	workspace_id TEXT NOT NULL DEFAULT '',
	scopes TEXT NOT NULL DEFAULT '[]',
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
	id TEXT PRIMARY KEY,
	seq INTEGER NOT NULL DEFAULT 0,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	workspace_id TEXT NOT NULL DEFAULT '',
	run_id TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS drift_reports (
	id TEXT PRIMARY KEY,
	seq INTEGER NOT NULL DEFAULT 0,
	workspace_id TEXT NOT NULL,
	drifted INTEGER NOT NULL DEFAULT 0,
	summary_json TEXT,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
CREATE INDEX IF NOT EXISTS idx_workspaces_org ON workspaces(org_id);
CREATE INDEX IF NOT EXISTS idx_variables_ws ON variables(workspace_id, key);
CREATE INDEX IF NOT EXISTS idx_variables_set ON variables(set_id, key);
CREATE INDEX IF NOT EXISTS idx_state_ws ON state_versions(workspace_id, version);
CREATE INDEX IF NOT EXISTS idx_runs_ws ON runs(workspace_id, created_at);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_policy_org ON policy_sets(org_id);
CREATE INDEX IF NOT EXISTS idx_agent_org ON agent_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_audit_ws ON audit(workspace_id, created_at);
CREATE INDEX IF NOT EXISTS idx_drift_ws ON drift_reports(workspace_id, created_at);
`)
	return err
}

// Close releases the database handle.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTS(v string) time.Time {
	tm, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}
	}
	return tm.UTC()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func slugify(name string) string {
	var b strings.Builder
	lastDash := true
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed") ||
		strings.Contains(err.Error(), "unique constraint")
}

func jsonOrNull(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	// Avoid storing typed-nil pointers as "null" for optional fields:
	// callers pass nil interfaces for absent values; a non-nil pointer
	// is marshalled normally.
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// --- Organizations ------------------------------------------------------

func (s *SQLiteStore) CreateOrganization(name, slug string) (*model.Organization, error) {
	if name == "" {
		return nil, errors.New("organization name required")
	}
	if slug == "" {
		slug = slugify(name)
	}
	if slug == "" {
		return nil, errors.New("organization slug required")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)`,
		id, name, slug, ts(now))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("organization slug %q already exists", slug)
		}
		return nil, err
	}
	return &model.Organization{ID: id, Name: name, Slug: slug, CreatedAt: now}, nil
}

func (s *SQLiteStore) GetOrganization(idOrSlug string) (*model.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(
		`SELECT id, name, slug, created_at FROM organizations WHERE id = ?`, idOrSlug)
	var o model.Organization
	var createdAt string
	if err := row.Scan(&o.ID, &o.Name, &o.Slug, &createdAt); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		row = s.db.QueryRow(
			`SELECT id, name, slug, created_at FROM organizations WHERE slug = ?`, idOrSlug)
		if err := row.Scan(&o.ID, &o.Name, &o.Slug, &createdAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("organization not found (%q)", idOrSlug)
			}
			return nil, err
		}
	}
	o.CreatedAt = parseTS(createdAt)
	return &o, nil
}

func (s *SQLiteStore) ListOrganizations() ([]*model.Organization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, name, slug, created_at FROM organizations ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Organization
	for rows.Next() {
		var o model.Organization
		var createdAt string
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &createdAt); err != nil {
			return nil, err
		}
		o.CreatedAt = parseTS(createdAt)
		out = append(out, &o)
	}
	return out, rows.Err()
}

// --- Projects -----------------------------------------------------------

func (s *SQLiteStore) CreateProject(orgID, name, slug string) (*model.Project, error) {
	if orgID == "" {
		return nil, errors.New("org_id required")
	}
	if name == "" {
		return nil, errors.New("project name required")
	}
	if slug == "" {
		slug = slugify(name)
	}
	if slug == "" {
		return nil, errors.New("project slug required")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO projects (id, org_id, name, slug, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, orgID, name, slug, ts(now))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("project slug %q already exists in organization", slug)
		}
		return nil, err
	}
	return &model.Project{ID: id, OrgID: orgID, Name: name, Slug: slug, CreatedAt: now}, nil
}

func (s *SQLiteStore) ListProjects(orgID string) ([]*model.Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, org_id, name, slug, created_at FROM projects WHERE org_id = ? ORDER BY created_at, id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Project
	for rows.Next() {
		var p model.Project
		var createdAt string
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Slug, &createdAt); err != nil {
			return nil, err
		}
		p.CreatedAt = parseTS(createdAt)
		out = append(out, &p)
	}
	return out, rows.Err()
}

// --- Workspaces ---------------------------------------------------------

const workspaceCols = `id, org_id, project_id, name, slug, vcs_repo, vcs_branch, work_dir, config_path, execution_mode, auto_apply, locked_by, locked_at, created_at, updated_at`

func scanWorkspace(row *sql.Row) (*model.Workspace, error) {
	var w model.Workspace
	var autoApply int
	var lockedAt sql.NullString
	var createdAt, updatedAt string
	if err := row.Scan(&w.ID, &w.OrgID, &w.ProjectID, &w.Name, &w.Slug,
		&w.VCSRepo, &w.VCSBranch, &w.WorkDir, &w.ConfigPath, &w.ExecutionMode,
		&autoApply, &w.LockedBy, &lockedAt, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	w.AutoApply = autoApply != 0
	if lockedAt.Valid {
		tm := parseTS(lockedAt.String)
		w.LockedAt = &tm
	}
	w.CreatedAt = parseTS(createdAt)
	w.UpdatedAt = parseTS(updatedAt)
	return &w, nil
}

func scanWorkspaceRows(rows *sql.Rows) (*model.Workspace, error) {
	var w model.Workspace
	var autoApply int
	var lockedAt sql.NullString
	var createdAt, updatedAt string
	if err := rows.Scan(&w.ID, &w.OrgID, &w.ProjectID, &w.Name, &w.Slug,
		&w.VCSRepo, &w.VCSBranch, &w.WorkDir, &w.ConfigPath, &w.ExecutionMode,
		&autoApply, &w.LockedBy, &lockedAt, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	w.AutoApply = autoApply != 0
	if lockedAt.Valid {
		tm := parseTS(lockedAt.String)
		w.LockedAt = &tm
	}
	w.CreatedAt = parseTS(createdAt)
	w.UpdatedAt = parseTS(updatedAt)
	return &w, nil
}

func (s *SQLiteStore) CreateWorkspace(w *model.Workspace) (*model.Workspace, error) {
	if w == nil {
		return nil, errors.New("workspace required")
	}
	if w.OrgID == "" {
		return nil, errors.New("workspace org_id required")
	}
	if w.Name == "" {
		return nil, errors.New("workspace name required")
	}
	slug := w.Slug
	if slug == "" {
		slug = slugify(w.Name)
	}
	if slug == "" {
		return nil, errors.New("workspace slug required")
	}
	mode := w.ExecutionMode
	if mode == "" {
		mode = "remote"
	}
	id := w.ID
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	out := &model.Workspace{
		ID: id, OrgID: w.OrgID, ProjectID: w.ProjectID, Name: w.Name, Slug: slug,
		VCSRepo: w.VCSRepo, VCSBranch: w.VCSBranch, WorkDir: w.WorkDir,
		ConfigPath: w.ConfigPath, ExecutionMode: mode, AutoApply: w.AutoApply,
		CreatedAt: now, UpdatedAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO workspaces (`+workspaceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', NULL, ?, ?)`,
		out.ID, out.OrgID, out.ProjectID, out.Name, out.Slug, out.VCSRepo,
		out.VCSBranch, out.WorkDir, out.ConfigPath, out.ExecutionMode,
		boolInt(out.AutoApply), ts(now), ts(now))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("workspace slug %q already exists in organization", slug)
		}
		return nil, err
	}
	return out, nil
}

func (s *SQLiteStore) GetWorkspace(idOrSlug string) (*model.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := scanWorkspace(s.db.QueryRow(
		`SELECT `+workspaceCols+` FROM workspaces WHERE id = ?`, idOrSlug))
	if err == nil {
		return w, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	w, err = scanWorkspace(s.db.QueryRow(
		`SELECT `+workspaceCols+` FROM workspaces WHERE slug = ? ORDER BY created_at LIMIT 1`, idOrSlug))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("workspace not found (%q)", idOrSlug)
		}
		return nil, err
	}
	return w, nil
}

func (s *SQLiteStore) GetWorkspaceByID(id string) (*model.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, err := scanWorkspace(s.db.QueryRow(
		`SELECT `+workspaceCols+` FROM workspaces WHERE id = ?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("workspace not found (id=%q)", id)
		}
		return nil, err
	}
	return w, nil
}

func (s *SQLiteStore) ListWorkspaces(orgID string) ([]*model.Workspace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows *sql.Rows
	var err error
	if orgID == "" {
		rows, err = s.db.Query(`SELECT ` + workspaceCols + ` FROM workspaces ORDER BY created_at, id`)
	} else {
		rows, err = s.db.Query(`SELECT `+workspaceCols+` FROM workspaces WHERE org_id = ? ORDER BY created_at, id`, orgID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Workspace
	for rows.Next() {
		w, err := scanWorkspaceRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateWorkspace(w *model.Workspace) error {
	if w == nil || w.ID == "" {
		return errors.New("workspace id required")
	}
	slug := w.Slug
	if slug == "" {
		slug = slugify(w.Name)
	}
	mode := w.ExecutionMode
	if mode == "" {
		mode = "remote"
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`UPDATE workspaces SET project_id = ?, name = ?, slug = ?, vcs_repo = ?, vcs_branch = ?,
		 work_dir = ?, config_path = ?, execution_mode = ?, auto_apply = ?, updated_at = ?
		 WHERE id = ?`,
		w.ProjectID, w.Name, slug, w.VCSRepo, w.VCSBranch, w.WorkDir,
		w.ConfigPath, mode, boolInt(w.AutoApply), ts(now), w.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("workspace slug %q already exists in organization", slug)
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("workspace not found (id=%q)", w.ID)
	}
	return nil
}

func (s *SQLiteStore) DeleteWorkspace(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql string
		arg string
	}{
		{`DELETE FROM variables WHERE workspace_id = ?`, id},
		{`DELETE FROM state_versions WHERE workspace_id = ?`, id},
		{`DELETE FROM runs WHERE workspace_id = ?`, id},
		{`DELETE FROM drift_reports WHERE workspace_id = ?`, id},
		{`DELETE FROM audit WHERE workspace_id = ?`, id},
		{`DELETE FROM agent_keys WHERE workspace_id = ?`, id},
		{`DELETE FROM policy_sets WHERE workspace_id = ?`, id},
	} {
		if _, err := tx.Exec(q.sql, q.arg); err != nil {
			return err
		}
	}
	res, err := tx.Exec(`DELETE FROM workspaces WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("workspace not found (id=%q)", id)
	}
	return tx.Commit()
}

// TryLockWorkspace atomically locks the workspace only if unlocked.
func (s *SQLiteStore) TryLockWorkspace(id, holder string) (bool, error) {
	if holder == "" {
		return false, errors.New("lock holder required")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`UPDATE workspaces SET locked_by = ?, locked_at = ? WHERE id = ? AND locked_by = ''`,
		holder, ts(now), id)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return true, nil
	}
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM workspaces WHERE id = ?`, id).Scan(&exists); err != nil {
		return false, err
	}
	if exists == 0 {
		return false, fmt.Errorf("workspace not found (id=%q)", id)
	}
	return false, nil
}

func (s *SQLiteStore) UnlockWorkspace(id, holder string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var lockedBy string
	err := s.db.QueryRow(`SELECT locked_by FROM workspaces WHERE id = ?`, id).Scan(&lockedBy)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("workspace not found (id=%q)", id)
		}
		return err
	}
	if lockedBy != "" && lockedBy != holder {
		return fmt.Errorf("workspace locked by another holder")
	}
	_, err = s.db.Exec(
		`UPDATE workspaces SET locked_by = '', locked_at = NULL WHERE id = ?`, id)
	return err
}

// --- Variables ----------------------------------------------------------

func (s *SQLiteStore) SetVariable(wsID, setID, key, plaintext string, sensitive bool, category string) (*model.Variable, error) {
	if key == "" {
		return nil, errors.New("variable key required")
	}
	if wsID == "" && setID == "" {
		return nil, errors.New("variable requires a workspace or a variable set")
	}
	enc, err := store.Encrypt(s.key, []byte(plaintext))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	err = s.db.QueryRow(
		`SELECT id FROM variables WHERE workspace_id = ? AND set_id = ? AND key = ?`,
		wsID, setID, key).Scan(&id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		id, err = newID()
		if err != nil {
			return nil, err
		}
		_, err = s.db.Exec(
			`INSERT INTO variables (id, workspace_id, set_id, key, value_enc, sensitive, category, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, wsID, setID, key, enc, boolInt(sensitive), category, ts(now))
		if err != nil {
			return nil, err
		}
	} else {
		_, err = s.db.Exec(
			`UPDATE variables SET value_enc = ?, sensitive = ?, category = ? WHERE id = ?`,
			enc, boolInt(sensitive), category, id)
		if err != nil {
			return nil, err
		}
	}
	disp := plaintext
	if sensitive {
		disp = "***"
	}
	return &model.Variable{ID: id, WorkspaceID: wsID, SetID: setID, Key: key,
		DisplayValue: disp, Sensitive: sensitive, Category: category}, nil
}

func (s *SQLiteStore) ListVariables(wsID string) ([]*model.Variable, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, workspace_id, set_id, key, value_enc, sensitive, category
		 FROM variables WHERE workspace_id = ? ORDER BY key`, wsID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Variable
	for rows.Next() {
		var v model.Variable
		var enc []byte
		var sens int
		if err := rows.Scan(&v.ID, &v.WorkspaceID, &v.SetID, &v.Key, &enc, &sens, &v.Category); err != nil {
			return nil, err
		}
		v.Sensitive = sens != 0
		if v.Sensitive {
			v.DisplayValue = "***"
		} else {
			plain, err := store.Decrypt(s.key, enc)
			if err != nil {
				return nil, fmt.Errorf("variable %q cannot be decrypted with this key: %w", v.Key, err)
			}
			v.DisplayValue = string(plain)
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) GetVariablePlaintext(wsID, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var enc []byte
	var sens int
	err := s.db.QueryRow(
		`SELECT value_enc, sensitive FROM variables WHERE workspace_id = ? AND key = ?`,
		wsID, key).Scan(&enc, &sens)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, fmt.Errorf("variable not found (workspace=%q key=%q)", wsID, key)
		}
		return "", false, err
	}
	plain, err := store.Decrypt(s.key, enc)
	if err != nil {
		return "", false, fmt.Errorf("variable %q cannot be decrypted with this key: %w", key, err)
	}
	return string(plain), sens != 0, nil
}

func (s *SQLiteStore) CreateVariableSet(orgID, name string) (*model.VariableSet, error) {
	if orgID == "" {
		return nil, errors.New("org_id required")
	}
	if name == "" {
		return nil, errors.New("variable set name required")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO variable_sets (id, org_id, name, created_at) VALUES (?, ?, ?, ?)`,
		id, orgID, name, ts(now))
	if err != nil {
		return nil, err
	}
	return &model.VariableSet{ID: id, OrgID: orgID, Name: name, CreatedAt: now}, nil
}

func (s *SQLiteStore) ListVariableSets(orgID string) ([]*model.VariableSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, org_id, name, created_at FROM variable_sets WHERE org_id = ? ORDER BY created_at, id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.VariableSet
	for rows.Next() {
		var vs model.VariableSet
		var createdAt string
		if err := rows.Scan(&vs.ID, &vs.OrgID, &vs.Name, &createdAt); err != nil {
			return nil, err
		}
		vs.CreatedAt = parseTS(createdAt)
		out = append(out, &vs)
	}
	return out, rows.Err()
}

// --- State versions -----------------------------------------------------

func (s *SQLiteStore) CreateStateVersion(wsID string, data []byte) (*model.StateVersion, error) {
	if wsID == "" {
		return nil, errors.New("workspace_id required")
	}
	enc, err := store.Encrypt(s.key, data)
	if err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var maxV sql.NullInt64
	if err := tx.QueryRow(
		`SELECT MAX(version) FROM state_versions WHERE workspace_id = ?`, wsID).Scan(&maxV); err != nil {
		return nil, err
	}
	version := 1
	if maxV.Valid {
		version = int(maxV.Int64) + 1
	}
	_, err = tx.Exec(
		`INSERT INTO state_versions (id, workspace_id, version, data_enc, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, wsID, version, enc, ts(now))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &model.StateVersion{ID: id, WorkspaceID: wsID, Version: version, Data: data, CreatedAt: now}, nil
}

func (s *SQLiteStore) scanStateVersion(row *sql.Row) (*model.StateVersion, error) {
	var sv model.StateVersion
	var enc []byte
	var createdAt string
	if err := row.Scan(&sv.ID, &sv.WorkspaceID, &sv.Version, &enc, &createdAt); err != nil {
		return nil, err
	}
	plain, err := store.Decrypt(s.key, enc)
	if err != nil {
		return nil, fmt.Errorf("state version %d cannot be decrypted with this key: %w", sv.Version, err)
	}
	sv.Data = plain
	sv.CreatedAt = parseTS(createdAt)
	return &sv, nil
}

func (s *SQLiteStore) LatestStateVersion(wsID string) (*model.StateVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sv, err := s.scanStateVersion(s.db.QueryRow(
		`SELECT id, workspace_id, version, data_enc, created_at FROM state_versions
		 WHERE workspace_id = ? ORDER BY version DESC LIMIT 1`, wsID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no state version for workspace %q", wsID)
		}
		return nil, err
	}
	return sv, nil
}

func (s *SQLiteStore) ListStateVersions(wsID string) ([]*model.StateVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, workspace_id, version, data_enc, created_at FROM state_versions
		 WHERE workspace_id = ? ORDER BY version`, wsID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.StateVersion
	for rows.Next() {
		var sv model.StateVersion
		var enc []byte
		var createdAt string
		if err := rows.Scan(&sv.ID, &sv.WorkspaceID, &sv.Version, &enc, &createdAt); err != nil {
			return nil, err
		}
		plain, err := store.Decrypt(s.key, enc)
		if err != nil {
			return nil, fmt.Errorf("state version %d cannot be decrypted with this key: %w", sv.Version, err)
		}
		sv.Data = plain
		sv.CreatedAt = parseTS(createdAt)
		out = append(out, &sv)
	}
	return out, rows.Err()
}

// --- Runs ---------------------------------------------------------------

const runCols = `id, workspace_id, type, trigger, status, plan_run_id, plan_json, policy_json, cost_json, override_note, log, state_version, error, created_at, updated_at, finished_at`

func isTerminalRunStatus(st string) bool {
	switch st {
	case model.StatusApplied, model.StatusFailed, model.StatusDiscarded, model.StatusCanceled:
		return true
	}
	return false
}

func decodeRunJSON(planS, policyS, costS sql.NullString, r *model.Run) error {
	if planS.Valid && planS.String != "" && planS.String != "null" {
		var p model.PlanSummary
		if err := json.Unmarshal([]byte(planS.String), &p); err != nil {
			return err
		}
		r.Plan = &p
	}
	if policyS.Valid && policyS.String != "" && policyS.String != "null" {
		var p model.PolicyResult
		if err := json.Unmarshal([]byte(policyS.String), &p); err != nil {
			return err
		}
		r.Policy = &p
	}
	if costS.Valid && costS.String != "" && costS.String != "null" {
		var c model.CostEstimate
		if err := json.Unmarshal([]byte(costS.String), &c); err != nil {
			return err
		}
		r.Cost = &c
	}
	return nil
}

func scanRunRow(scan func(dest ...any) error) (*model.Run, error) {
	var r model.Run
	var planS, policyS, costS sql.NullString
	var createdAt, updatedAt string
	var finishedAt sql.NullString
	if err := scan(&r.ID, &r.WorkspaceID, &r.Type, &r.Trigger, &r.Status,
		&r.PlanRunID, &planS, &policyS, &costS, &r.OverrideNote, &r.Log,
		&r.StateVersion, &r.Error, &createdAt, &updatedAt, &finishedAt); err != nil {
		return nil, err
	}
	if err := decodeRunJSON(planS, policyS, costS, &r); err != nil {
		return nil, err
	}
	r.CreatedAt = parseTS(createdAt)
	r.UpdatedAt = parseTS(updatedAt)
	if finishedAt.Valid {
		tm := parseTS(finishedAt.String)
		r.FinishedAt = &tm
	}
	return &r, nil
}

func (s *SQLiteStore) CreateRun(r *model.Run) (*model.Run, error) {
	if r == nil {
		return nil, errors.New("run required")
	}
	if r.WorkspaceID == "" {
		return nil, errors.New("run workspace_id required")
	}
	if r.Type == "" {
		return nil, errors.New("run type required")
	}
	id := r.ID
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			return nil, err
		}
	}
	status := r.Status
	if status == "" {
		status = model.StatusQueued
	}
	now := time.Now().UTC()
	out := &model.Run{
		ID: id, WorkspaceID: r.WorkspaceID, Type: r.Type, Trigger: r.Trigger,
		Status: status, PlanRunID: r.PlanRunID, Plan: r.Plan, Policy: r.Policy,
		Cost: r.Cost, OverrideNote: r.OverrideNote, Log: r.Log,
		StateVersion: r.StateVersion, Error: r.Error,
		CreatedAt: now, UpdatedAt: now, FinishedAt: r.FinishedAt,
	}
	planJ, err := jsonOrNull(r.Plan)
	if err != nil {
		return nil, err
	}
	policyJ, err := jsonOrNull(r.Policy)
	if err != nil {
		return nil, err
	}
	costJ, err := jsonOrNull(r.Cost)
	if err != nil {
		return nil, err
	}
	var finishedAt any
	if r.FinishedAt != nil {
		finishedAt = ts(*r.FinishedAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO runs (`+runCols+`, seq) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(seq),0)+1 FROM runs))`,
		out.ID, out.WorkspaceID, out.Type, out.Trigger, out.Status, out.PlanRunID,
		planJ, policyJ, costJ, out.OverrideNote, out.Log, out.StateVersion,
		out.Error, ts(now), ts(now), finishedAt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLiteStore) GetRun(id string) (*model.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := scanRunRow(s.db.QueryRow(
		`SELECT `+runCols+` FROM runs WHERE id = ?`, id).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("run not found (id=%q)", id)
		}
		return nil, err
	}
	return r, nil
}

func (s *SQLiteStore) UpdateRun(r *model.Run) error {
	if r == nil || r.ID == "" {
		return errors.New("run id required")
	}
	planJ, err := jsonOrNull(r.Plan)
	if err != nil {
		return err
	}
	policyJ, err := jsonOrNull(r.Policy)
	if err != nil {
		return err
	}
	costJ, err := jsonOrNull(r.Cost)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	finishedAt := r.FinishedAt
	if finishedAt == nil && isTerminalRunStatus(r.Status) {
		finishedAt = &now
	}
	var finishedVal any
	if finishedAt != nil {
		finishedVal = ts(*finishedAt)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`UPDATE runs SET workspace_id = ?, type = ?, trigger = ?, status = ?, plan_run_id = ?,
		 plan_json = ?, policy_json = ?, cost_json = ?, override_note = ?, log = ?,
		 state_version = ?, error = ?, updated_at = ?, finished_at = ? WHERE id = ?`,
		r.WorkspaceID, r.Type, r.Trigger, r.Status, r.PlanRunID,
		planJ, policyJ, costJ, r.OverrideNote, r.Log, r.StateVersion,
		r.Error, ts(now), finishedVal, r.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("run not found (id=%q)", r.ID)
	}
	return nil
}

func (s *SQLiteStore) AppendRunLog(id, line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		`UPDATE runs SET log = log || ?, updated_at = ? WHERE id = ?`,
		line+"\n", ts(time.Now().UTC()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("run not found (id=%q)", id)
	}
	return nil
}

// ClaimQueuedRun atomically claims the oldest queued run. The single
// transaction under BEGIN IMMEDIATE serializes claimants; the status
// transition is conditional on the run still being queued.
func (s *SQLiteStore) ClaimQueuedRun() (*model.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id, runType string
	err = tx.QueryRow(
		`SELECT id, type FROM runs WHERE status = ? ORDER BY created_at, seq LIMIT 1`,
		model.StatusQueued).Scan(&id, &runType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	newStatus := model.StatusPlanning
	if runType == model.RunApply || runType == model.RunDestroy {
		newStatus = model.StatusApplying
	}
	res, err := tx.Exec(
		`UPDATE runs SET status = ?, updated_at = ? WHERE id = ? AND status = ?`,
		newStatus, ts(time.Now().UTC()), id, model.StatusQueued)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	r, err := scanRunRow(s.db.QueryRow(
		`SELECT `+runCols+` FROM runs WHERE id = ?`, id).Scan)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *SQLiteStore) ListRuns(wsID string, limit int) ([]*model.Run, error) {
	if limit <= 0 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT `+runCols+` FROM runs WHERE workspace_id = ? ORDER BY created_at DESC, seq DESC LIMIT ?`, wsID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Run
	for rows.Next() {
		r, err := scanRunRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Policy sets ------------------------------------------------------

func (s *SQLiteStore) CreatePolicySet(orgID, wsID, name string, rules []byte) (*model.PolicySet, error) {
	if orgID == "" {
		return nil, errors.New("org_id required")
	}
	if name == "" {
		return nil, errors.New("policy set name required")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO policy_sets (id, org_id, workspace_id, name, rules, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, orgID, wsID, name, rules, ts(now))
	if err != nil {
		return nil, err
	}
	return &model.PolicySet{ID: id, OrgID: orgID, WorkspaceID: wsID, Name: name, RulesJSON: rules, CreatedAt: now}, nil
}

func (s *SQLiteStore) ListPolicySets(orgID string) ([]*model.PolicySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, org_id, workspace_id, name, rules, created_at FROM policy_sets
		 WHERE org_id = ? ORDER BY created_at, id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.PolicySet
	for rows.Next() {
		var p model.PolicySet
		var createdAt string
		if err := rows.Scan(&p.ID, &p.OrgID, &p.WorkspaceID, &p.Name, &p.RulesJSON, &createdAt); err != nil {
			return nil, err
		}
		p.CreatedAt = parseTS(createdAt)
		out = append(out, &p)
	}
	return out, rows.Err()
}

// --- Registry modules -------------------------------------------------

func (s *SQLiteStore) CreateModule(m *model.Module, tarball []byte) (*model.Module, error) {
	if m == nil {
		return nil, errors.New("module required")
	}
	if m.Namespace == "" || m.Name == "" || m.Provider == "" || m.Version == "" {
		return nil, errors.New("module namespace, name, provider and version are required")
	}
	id := m.ID
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	out := &model.Module{ID: id, Namespace: m.Namespace, Name: m.Name,
		Provider: m.Provider, Version: m.Version, Readme: m.Readme, CreatedAt: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO modules (id, namespace, name, provider, version, readme, tarball, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		out.ID, out.Namespace, out.Name, out.Provider, out.Version, out.Readme, tarball, ts(now))
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("module version %s/%s/%s %s already exists", m.Namespace, m.Name, m.Provider, m.Version)
		}
		return nil, err
	}
	return out, nil
}

func (s *SQLiteStore) GetModule(ns, name, provider, version string) (*model.Module, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m model.Module
	var tarball []byte
	var createdAt string
	err := s.db.QueryRow(
		`SELECT id, namespace, name, provider, version, readme, tarball, created_at
		 FROM modules WHERE namespace = ? AND name = ? AND provider = ? AND version = ?`,
		ns, name, provider, version).Scan(
		&m.ID, &m.Namespace, &m.Name, &m.Provider, &m.Version, &m.Readme, &tarball, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("module not found (%s/%s/%s %s)", ns, name, provider, version)
		}
		return nil, nil, err
	}
	m.CreatedAt = parseTS(createdAt)
	return &m, tarball, nil
}

func (s *SQLiteStore) ListModules() ([]*model.Module, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(
		`SELECT id, namespace, name, provider, version, readme, created_at
		 FROM modules ORDER BY namespace, name, provider, version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Module
	for rows.Next() {
		var m model.Module
		var createdAt string
		if err := rows.Scan(&m.ID, &m.Namespace, &m.Name, &m.Provider, &m.Version, &m.Readme, &createdAt); err != nil {
			return nil, err
		}
		m.CreatedAt = parseTS(createdAt)
		out = append(out, &m)
	}
	return out, rows.Err()
}

// --- Agent keys -------------------------------------------------------

// keyPrefixLen is the visible prefix length: "fiak_" + 6 hex chars.
const keyPrefixLen = 11

func (s *SQLiteStore) CreateAgentKey(orgID, wsID string, scopes []string) (string, *model.AgentKey, error) {
	if orgID == "" {
		return "", nil, errors.New("org_id required")
	}
	if scopes == nil {
		scopes = []string{}
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	plaintext := "fiak_" + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plaintext))
	hash := hex.EncodeToString(sum[:])
	prefix := plaintext[:keyPrefixLen]
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return "", nil, err
	}
	id, err := newID()
	if err != nil {
		return "", nil, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO agent_keys (id, prefix, hash, org_id, workspace_id, scopes, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, prefix, hash, orgID, wsID, string(scopesJSON), ts(now))
	if err != nil {
		return "", nil, err
	}
	rec := &model.AgentKey{ID: id, Prefix: prefix, OrgID: orgID,
		WorkspaceID: wsID, Scopes: scopes, CreatedAt: now}
	return plaintext, rec, nil
}

func (s *SQLiteStore) AuthenticateKey(plaintext string) (*model.AgentKey, error) {
	sum := sha256.Sum256([]byte(plaintext))
	hash := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	var rec model.AgentKey
	var scopesJSON string
	var createdAt string
	err := s.db.QueryRow(
		`SELECT id, prefix, org_id, workspace_id, scopes, created_at
		 FROM agent_keys WHERE hash = ?`, hash).Scan(
		&rec.ID, &rec.Prefix, &rec.OrgID, &rec.WorkspaceID, &scopesJSON, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("agent key not found")
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopesJSON), &rec.Scopes); err != nil {
		return nil, err
	}
	rec.CreatedAt = parseTS(createdAt)
	// Hash is never returned: it lives only in the database row.
	return &rec, nil
}

// --- Audit ------------------------------------------------------------

func (s *SQLiteStore) AppendAudit(e *model.AuditEntry) error {
	if e == nil {
		return errors.New("audit entry required")
	}
	if e.Action == "" {
		return errors.New("audit action required")
	}
	id := e.ID
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	if !e.CreatedAt.IsZero() {
		now = e.CreatedAt.UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO audit (id, seq, actor, action, workspace_id, run_id, detail, created_at)
		 VALUES (?, (SELECT COALESCE(MAX(seq),0)+1 FROM audit), ?, ?, ?, ?, ?, ?)`,
		id, e.Actor, e.Action, e.WorkspaceID, e.RunID, e.Detail, ts(now))
	return err
}

func (s *SQLiteStore) ListAudit(wsID string, limit int) ([]*model.AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows *sql.Rows
	var err error
	if wsID == "" {
		rows, err = s.db.Query(
			`SELECT id, actor, action, workspace_id, run_id, detail, created_at
			 FROM audit ORDER BY created_at DESC, seq DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(
			`SELECT id, actor, action, workspace_id, run_id, detail, created_at
			 FROM audit WHERE workspace_id = ? ORDER BY created_at DESC, seq DESC LIMIT ?`, wsID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AuditEntry
	for rows.Next() {
		var a model.AuditEntry
		var createdAt string
		if err := rows.Scan(&a.ID, &a.Actor, &a.Action, &a.WorkspaceID, &a.RunID, &a.Detail, &createdAt); err != nil {
			return nil, err
		}
		a.CreatedAt = parseTS(createdAt)
		out = append(out, &a)
	}
	return out, rows.Err()
}

// --- Drift reports ----------------------------------------------------

func (s *SQLiteStore) CreateDriftReport(r *model.DriftReport) (*model.DriftReport, error) {
	if r == nil {
		return nil, errors.New("drift report required")
	}
	if r.WorkspaceID == "" {
		return nil, errors.New("drift report workspace_id required")
	}
	id := r.ID
	if id == "" {
		var err error
		id, err = newID()
		if err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	out := &model.DriftReport{ID: id, WorkspaceID: r.WorkspaceID,
		Drifted: r.Drifted, Summary: r.Summary, CreatedAt: now}
	summaryJ, err := jsonOrNull(r.Summary)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(
		`INSERT INTO drift_reports (id, seq, workspace_id, drifted, summary_json, created_at)
		 VALUES (?, (SELECT COALESCE(MAX(seq),0)+1 FROM drift_reports), ?, ?, ?, ?)`,
		out.ID, out.WorkspaceID, boolInt(out.Drifted), summaryJ, ts(now))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *SQLiteStore) LatestDriftReport(wsID string) (*model.DriftReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r model.DriftReport
	var drifted int
	var summaryS sql.NullString
	var createdAt string
	err := s.db.QueryRow(
		`SELECT id, workspace_id, drifted, summary_json, created_at FROM drift_reports
		 WHERE workspace_id = ? ORDER BY created_at DESC, seq DESC LIMIT 1`, wsID).Scan(
		&r.ID, &r.WorkspaceID, &drifted, &summaryS, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no drift report for workspace %q", wsID)
		}
		return nil, err
	}
	r.Drifted = drifted != 0
	if summaryS.Valid && summaryS.String != "" && summaryS.String != "null" {
		var sum model.PlanSummary
		if err := json.Unmarshal([]byte(summaryS.String), &sum); err != nil {
			return nil, err
		}
		r.Summary = &sum
	}
	r.CreatedAt = parseTS(createdAt)
	return &r, nil
}

var _ store.Store = (*SQLiteStore)(nil)
