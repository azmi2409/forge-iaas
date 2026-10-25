package registry

import (
	"errors"
	"testing"

	"github.com/azmi2409/forge-iaas/internal/model"
)

// fakeStore is an in-memory Store for tests.
type fakeStore struct {
	modules map[string]*model.Module
}

func newFakeStore() *fakeStore { return &fakeStore{modules: map[string]*model.Module{}} }

func key(ns, name, provider, version string) string {
	return ns + "/" + name + "/" + provider + "/" + version
}

func (f *fakeStore) CreateModule(m *model.Module, _ []byte) (*model.Module, error) {
	m.ID = "mod-" + key(m.Namespace, m.Name, m.Provider, m.Version)
	f.modules[key(m.Namespace, m.Name, m.Provider, m.Version)] = m
	return m, nil
}

func (f *fakeStore) GetModule(ns, name, provider, version string) (*model.Module, []byte, error) {
	if m, ok := f.modules[key(ns, name, provider, version)]; ok {
		return m, []byte("tarball"), nil
	}
	return nil, nil, errors.New("module not found")
}

func (f *fakeStore) ListModules() ([]*model.Module, error) {
	var out []*model.Module
	for _, m := range f.modules {
		out = append(out, m)
	}
	return out, nil
}

func TestValidateVersion(t *testing.T) {
	for _, v := range []string{"1.2.3", "0.0.1", "10.20.30"} {
		if err := ValidateVersion(v); err != nil {
			t.Errorf("valid %q: unexpected error %v", v, err)
		}
	}
	for _, v := range []string{
		"", "v1.2.3", "1.2", "1.2.3.4", "1.2.3-alpha", "1.2.3+build",
		"01.2.3", "1.02.3", "a.b.c", "1.2.x",
	} {
		if err := ValidateVersion(v); err == nil {
			t.Errorf("invalid %q: expected an error, got nil", v)
		}
	}
}

func TestPublishAndDuplicate(t *testing.T) {
	store := newFakeStore()
	m, err := Publish(store, "hashicorp", "consul", "aws", "1.2.3", "readme", []byte("tb"))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if m.Namespace != "hashicorp" || m.Version != "1.2.3" {
		t.Fatalf("published module mismatch: %+v", m)
	}
	// Same (namespace, name, provider, version) again: rejected.
	if _, err := Publish(store, "hashicorp", "consul", "aws", "1.2.3", "readme2", []byte("tb")); err == nil {
		t.Fatal("duplicate publish: expected an error, got nil")
	}
	// A different version is fine.
	if _, err := Publish(store, "hashicorp", "consul", "aws", "1.2.4", "readme", []byte("tb")); err != nil {
		t.Fatalf("new version publish: %v", err)
	}
	// Invalid version never reaches the store.
	if _, err := Publish(store, "hashicorp", "consul", "aws", "v2.0.0", "readme", []byte("tb")); err == nil {
		t.Fatal("invalid version publish: expected an error, got nil")
	}
	if got, _ := List(store); len(got) != 2 {
		t.Fatalf("list: got %d modules, want 2", len(got))
	}
	if got, _, err := Get(store, "hashicorp", "consul", "aws", "1.2.3"); err != nil || got == nil {
		t.Fatalf("get: %v %+v", err, got)
	}
}

func TestSourceString(t *testing.T) {
	if got := SourceString("hashicorp", "consul"); got != "fiaas/hashicorp/consul" {
		t.Fatalf("source: got %q, want %q", got, "fiaas/hashicorp/consul")
	}
}
