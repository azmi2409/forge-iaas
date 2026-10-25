// Package store defines the persistence contract for forge-iaas:
// organizations, projects, workspaces, variables, state versions,
// runs, policy sets, registry modules, agent keys, audit entries,
// and drift reports. Implementations: SQLite (default, file-based)
// and Postgres (production). State data and variable values are
// encrypted at rest with AES-256-GCM under FIAAS_MASTER_KEY.
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// Store is the persistence interface. All methods are safe for
// concurrent use. Every method that returns a model value returns a
// redacted-safe view except GetVariablePlaintext and
// LatestStateVersion/ListStateVersions, which are runner-only and
// return decrypted secrets/state by design.
type Store interface {
	// Migrate ensures the schema exists.
	Migrate() error
	// Close releases resources.
	Close() error

	// Organizations -------------------------------------------------
	CreateOrganization(name, slug string) (*model.Organization, error)
	GetOrganization(idOrSlug string) (*model.Organization, error)
	ListOrganizations() ([]*model.Organization, error)

	// Projects ------------------------------------------------------
	CreateProject(orgID, name, slug string) (*model.Project, error)
	ListProjects(orgID string) ([]*model.Project, error)

	// Workspaces ----------------------------------------------------
	CreateWorkspace(w *model.Workspace) (*model.Workspace, error)
	GetWorkspace(idOrSlug string) (*model.Workspace, error)
	GetWorkspaceByID(id string) (*model.Workspace, error)
	ListWorkspaces(orgID string) ([]*model.Workspace, error)
	UpdateWorkspace(w *model.Workspace) error
	DeleteWorkspace(id string) error
	// TryLockWorkspace atomically locks the workspace if unlocked.
	// It returns false (nil error) when already locked.
	TryLockWorkspace(id, holder string) (bool, error)
	UnlockWorkspace(id, holder string) error

	// Variables -----------------------------------------------------
	SetVariable(wsID, setID, key, plaintext string, sensitive bool, category string) (*model.Variable, error)
	// ListVariables returns DisplayValue only; sensitive -> "***".
	ListVariables(wsID string) ([]*model.Variable, error)
	// GetVariablePlaintext is for the runner ONLY, never via API.
	GetVariablePlaintext(wsID, key string) (string, bool, error)
	CreateVariableSet(orgID, name string) (*model.VariableSet, error)
	ListVariableSets(orgID string) ([]*model.VariableSet, error)

	// State versions ------------------------------------------------
	// CreateStateVersion encrypts data; version auto-increments per workspace.
	CreateStateVersion(wsID string, data []byte) (*model.StateVersion, error)
	LatestStateVersion(wsID string) (*model.StateVersion, error)
	ListStateVersions(wsID string) ([]*model.StateVersion, error)

	// Runs ----------------------------------------------------------
	CreateRun(r *model.Run) (*model.Run, error)
	GetRun(id string) (*model.Run, error)
	UpdateRun(r *model.Run) error
	AppendRunLog(id, line string) error
	// ClaimQueuedRun atomically claims the oldest queued run
	// (-> planning for plan/drift runs, -> applying for apply/destroy
	// runs) and returns nil when none are queued.
	ClaimQueuedRun() (*model.Run, error)
	ListRuns(wsID string, limit int) ([]*model.Run, error)

	// Policy sets ---------------------------------------------------
	CreatePolicySet(orgID, wsID, name string, rules []byte) (*model.PolicySet, error)
	ListPolicySets(orgID string) ([]*model.PolicySet, error)

	// Registry modules ----------------------------------------------
	CreateModule(m *model.Module, tarball []byte) (*model.Module, error)
	GetModule(ns, name, provider, version string) (*model.Module, []byte, error)
	ListModules() ([]*model.Module, error)

	// Agent keys ----------------------------------------------------
	// CreateAgentKey returns the plaintext key ONCE; only its SHA-256
	// hash is stored. The returned record carries Prefix only.
	CreateAgentKey(orgID, wsID string, scopes []string) (plaintextKey string, rec *model.AgentKey, err error)
	AuthenticateKey(plaintext string) (*model.AgentKey, error)

	// Audit ---------------------------------------------------------
	AppendAudit(e *model.AuditEntry) error
	ListAudit(wsID string, limit int) ([]*model.AuditEntry, error)

	// Drift ---------------------------------------------------------
	CreateDriftReport(r *model.DriftReport) (*model.DriftReport, error)
	LatestDriftReport(wsID string) (*model.DriftReport, error)
}

// MasterKeyFromEnv reads the encryption key from FIAAS_MASTER_KEY.
// The value may be 32 raw bytes or base64 of 32 bytes. If unset, it
// generates an ephemeral 32-byte key, prints a warning to stderr,
// and returns ephemeral=true (stored secrets will not survive
// restarts). It only errors when a set value is not a valid key.
func MasterKeyFromEnv() (key []byte, ephemeral bool, err error) {
	raw := os.Getenv("FIAAS_MASTER_KEY")
	if raw == "" {
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, false, fmt.Errorf("generating ephemeral master key: %w", err)
		}
		fmt.Fprintln(os.Stderr, "WARNING: FIAAS_MASTER_KEY is not set; using an ephemeral key — stored secrets will not survive restarts")
		return key, true, nil
	}
	if decoded, derr := base64.StdEncoding.DecodeString(raw); derr == nil && len(decoded) == 32 {
		return decoded, false, nil
	}
	if decoded, derr := base64.RawStdEncoding.DecodeString(raw); derr == nil && len(decoded) == 32 {
		return decoded, false, nil
	}
	if len(raw) == 32 {
		return []byte(raw), false, nil
	}
	return nil, false, errors.New("FIAAS_MASTER_KEY must be 32 raw bytes or base64 of 32 bytes")
}

// Encrypt encrypts plaintext with AES-256-GCM; output is nonce|ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
