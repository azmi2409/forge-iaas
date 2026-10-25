// Package registry validates module versions and publishes modules
// through a small duck-typed Store interface, so callers (and tests)
// can supply any store implementation matching the store builder's
// method shapes. No tarball parsing is done here: tarball bytes are
// stored opaquely via the store.
package registry

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// Store is the minimal module-store surface this package needs. It
// mirrors the store builder's signatures in docs/INTERFACES.md.
type Store interface {
	CreateModule(m *model.Module, tarball []byte) (*model.Module, error)
	GetModule(ns, name, provider, version string) (*model.Module, []byte, error)
	ListModules() ([]*model.Module, error)
}

// semverRe is strict X.Y.Z: no leading "v", no pre-release, no build
// metadata, no leading zeroes (per semver).
var semverRe = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// ValidateVersion rejects anything that is not a strict X.Y.Z
// semver version. In v1, pre-release versions are not accepted.
func ValidateVersion(v string) error {
	if v == "" {
		return fmt.Errorf("version must not be empty (expected X.Y.Z)")
	}
	if strings.HasPrefix(v, "v") || strings.HasPrefix(v, "V") {
		return fmt.Errorf("invalid version %q: must not have a leading 'v' (expected X.Y.Z)", v)
	}
	if strings.ContainsAny(v, "-+") {
		return fmt.Errorf("invalid version %q: pre-release and build metadata are not supported in v1 (expected X.Y.Z)", v)
	}
	if !semverRe.MatchString(v) {
		return fmt.Errorf("invalid version %q: expected strict semver X.Y.Z (e.g. 1.2.3)", v)
	}
	return nil
}

// SourceString returns the module source form consumers use:
// "fiaas/<ns>/<name>". It is documented, not enforced by tofu.
func SourceString(ns, name string) string {
	return "fiaas/" + ns + "/" + name
}

// Publish validates the version, rejects a duplicate
// (namespace, name, provider, version), and stores the module with
// its tarball bytes via the store.
func Publish(store Store, ns, name, provider, version, readme string, tarball []byte) (*model.Module, error) {
	if store == nil {
		return nil, fmt.Errorf("registry: store is nil")
	}
	if ns == "" || name == "" || provider == "" {
		return nil, fmt.Errorf("registry: namespace, name, and provider must all be non-empty")
	}
	if err := ValidateVersion(version); err != nil {
		return nil, err
	}
	if existing, _, err := store.GetModule(ns, name, provider, version); err == nil && existing != nil {
		return nil, fmt.Errorf("registry: module %s/%s/%s version %s already exists",
			ns, name, provider, version)
	}
	return store.CreateModule(&model.Module{
		Namespace: ns,
		Name:      name,
		Provider:  provider,
		Version:   version,
		Readme:    readme,
	}, tarball)
}

// Get fetches one module version via the store.
func Get(store Store, ns, name, provider, version string) (*model.Module, []byte, error) {
	if store == nil {
		return nil, nil, fmt.Errorf("registry: store is nil")
	}
	return store.GetModule(ns, name, provider, version)
}

// List returns all modules via the store.
func List(store Store) ([]*model.Module, error) {
	if store == nil {
		return nil, fmt.Errorf("registry: store is nil")
	}
	return store.ListModules()
}
