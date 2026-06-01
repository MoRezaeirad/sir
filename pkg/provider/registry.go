// Package provider manages the SIR provider registry: installation, lifecycle
// (enable/disable), invocation routing, and health tracking for all five
// provider kinds (signal, effect, policy, advisory, export).
package provider

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	registrySchemaVersion = "sir.provider_registry.v1"

	// StatusActive means the provider is registered and enabled.
	StatusActive = "active"
	// StatusInactive means registered but disabled (enabled=false).
	StatusInactive = "inactive"
	// StatusFailed means the last health check failed.
	StatusFailed = "failed"

	// HealthHealthy / HealthUnhealthy / HealthUnknown are health check states.
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
	HealthUnknown   = "unknown"

	// Provider kind constants mirror sdk.KindXxx but live here to avoid a
	// dependency on pkg/sdk from pkg/provider (which is imported by pkg/hooks).
	KindSignal   = "signal_provider"
	KindEffect   = "effect_provider"
	KindPolicy   = "policy_provider"
	KindAdvisory = "advisory_provider"
	KindExport   = "export_provider"

	// ExclusiveKinds are provider kinds where at most one provider is active at
	// a time. enable/use/swap enforce this invariant.
	//
	// Non-exclusive kinds (export, advisory) allow multiple active providers.
)

// exclusiveKind reports whether a provider kind enforces the one-active invariant.
func exclusiveKind(kind string) bool {
	switch kind {
	case "policy_provider", "effect_provider":
		return true
	}
	return false
}

// Entry is a registered provider with its runtime state.
type Entry struct {
	RegistryID   string         `json:"registry_id"`
	Name         string         `json:"name"`
	Kind         string         `json:"kind"`
	Version      string         `json:"version"`
	ManifestPath string         `json:"manifest_path"`
	Entrypoint   string         `json:"entrypoint"` // absolute, resolved at install time
	Platforms    []string       `json:"platforms,omitempty"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
	Enabled      bool           `json:"enabled"`
	Health       Health         `json:"health"`
	InstalledAt  time.Time      `json:"installed_at"`
	InstalledBy  string         `json:"installed_by"`
	Config       map[string]string `json:"config,omitempty"` // key=val provider-specific config
}

// Health holds the last health check result for a provider.
type Health struct {
	Status    string    `json:"status"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Errors    int       `json:"errors,omitempty"`
}

// Registry is the on-disk provider registry stored at ~/.sir/providers.json.
type Registry struct {
	SchemaVersion string    `json:"schema_version"`
	Providers     []Entry   `json:"providers"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// path returns the absolute path to the registry file.
func path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".sir", "providers.json"), nil
}

// Load reads ~/.sir/providers.json. Returns an empty registry if the file does
// not exist — a fresh install with no providers registered is not an error.
// Parse errors fail closed.
func Load() (*Registry, error) {
	p, err := path()
	if err != nil {
		return emptyRegistry(), err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyRegistry(), nil
		}
		return emptyRegistry(), fmt.Errorf("read provider registry: %w", err)
	}
	var r Registry
	if err := json.Unmarshal(data, &r); err != nil {
		return emptyRegistry(), fmt.Errorf("parse provider registry: %w", err)
	}
	return &r, nil
}

// Save writes the registry atomically to ~/.sir/providers.json.
func (r *Registry) Save() error {
	p, err := path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create .sir dir: %w", err)
	}
	r.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "providers-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, p); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// Add registers a new provider. Returns an error if a provider with the same
// name is already registered.
func (r *Registry) Add(e Entry) error {
	if _, exists := r.ByName(e.Name); exists {
		return fmt.Errorf("provider %q is already registered (uninstall first to replace)", e.Name)
	}
	if e.RegistryID == "" {
		e.RegistryID = makeRegistryID(e.Name)
	}
	if e.Health.Status == "" {
		e.Health.Status = HealthUnknown
	}
	r.Providers = append(r.Providers, e)
	return nil
}

// Remove unregisters a provider by name. Returns error if not found.
func (r *Registry) Remove(name string) error {
	for i, e := range r.Providers {
		if e.Name == name {
			r.Providers = append(r.Providers[:i], r.Providers[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("provider %q not found", name)
}

// Enable sets Enabled=true for the named provider. If the kind is exclusive,
// all other providers of the same kind are disabled first.
func (r *Registry) Enable(name string) error {
	e, ok := r.ByName(name)
	if !ok {
		return fmt.Errorf("provider %q not found", name)
	}
	if exclusiveKind(e.Kind) {
		for i := range r.Providers {
			if r.Providers[i].Kind == e.Kind && r.Providers[i].Name != name {
				r.Providers[i].Enabled = false
			}
		}
	}
	for i := range r.Providers {
		if r.Providers[i].Name == name {
			r.Providers[i].Enabled = true
			return nil
		}
	}
	return nil
}

// Disable sets Enabled=false for the named provider without removing it.
func (r *Registry) Disable(name string) error {
	for i := range r.Providers {
		if r.Providers[i].Name == name {
			r.Providers[i].Enabled = false
			return nil
		}
	}
	return fmt.Errorf("provider %q not found", name)
}

// Use enables the named provider and (for exclusive kinds) disables all other
// providers of the same kind. Equivalent to Enable for non-exclusive kinds.
func (r *Registry) Use(name string) error {
	return r.Enable(name)
}

// Swap atomically disables oldName and enables newName. Both must exist and
// have the same kind.
func (r *Registry) Swap(oldName, newName string) error {
	old, okOld := r.ByName(oldName)
	nw, okNew := r.ByName(newName)
	if !okOld {
		return fmt.Errorf("provider %q not found", oldName)
	}
	if !okNew {
		return fmt.Errorf("provider %q not found", newName)
	}
	if old.Kind != nw.Kind {
		return fmt.Errorf("providers have different kinds: %s (%s) vs %s (%s)",
			oldName, old.Kind, newName, nw.Kind)
	}
	if err := r.Disable(oldName); err != nil {
		return err
	}
	return r.Enable(newName)
}

// Configure sets a key=value config entry on the named provider.
func (r *Registry) Configure(name, key, value string) error {
	for i := range r.Providers {
		if r.Providers[i].Name == name {
			if r.Providers[i].Config == nil {
				r.Providers[i].Config = make(map[string]string)
			}
			r.Providers[i].Config[key] = value
			return nil
		}
	}
	return fmt.Errorf("provider %q not found", name)
}

// Active returns all enabled providers of the given kind. For exclusive kinds
// there will be at most one; for non-exclusive (export, advisory) there may be
// many.
func (r *Registry) Active(kind string) []Entry {
	var out []Entry
	for _, e := range r.Providers {
		if e.Kind == kind && e.Enabled {
			out = append(out, e)
		}
	}
	return out
}

// ByName looks up a provider by name. Returns (entry, true) if found.
func (r *Registry) ByName(name string) (*Entry, bool) {
	for i := range r.Providers {
		if r.Providers[i].Name == name {
			return &r.Providers[i], true
		}
	}
	return nil, false
}

// UpdateHealth records the result of a health check for the named provider.
func (r *Registry) UpdateHealth(name, status, reason string) {
	for i := range r.Providers {
		if r.Providers[i].Name == name {
			r.Providers[i].Health.Status = status
			r.Providers[i].Health.CheckedAt = time.Now().UTC()
			r.Providers[i].Health.Reason = reason
			if status == HealthUnhealthy {
				r.Providers[i].Health.Errors++
			}
			return
		}
	}
}

// emptyRegistry returns a new empty registry with the current schema version.
func emptyRegistry() *Registry {
	return &Registry{SchemaVersion: registrySchemaVersion}
}

// makeRegistryID derives a stable short ID from the provider name.
func makeRegistryID(name string) string {
	h := sha256.Sum256([]byte(name))
	return fmt.Sprintf("prov_%x", h[:4])
}
