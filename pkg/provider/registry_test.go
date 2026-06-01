package provider

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempRegistry(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func sampleEntry(name, kind string) Entry {
	return Entry{
		Name:        name,
		Kind:        kind,
		Version:     "1.0.0",
		Entrypoint:  "/tmp/fake-provider",
		Enabled:     true,
		InstalledAt: time.Now().UTC(),
		InstalledBy: "test",
	}
}

func TestRegistry_AddAndByName(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	if err := reg.Add(sampleEntry("opa-policy", KindPolicy)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	e, ok := reg.ByName("opa-policy")
	if !ok {
		t.Fatal("ByName: not found after Add")
	}
	if e.Kind != KindPolicy {
		t.Errorf("Kind = %s, want %s", e.Kind, KindPolicy)
	}
	if e.RegistryID == "" {
		t.Error("RegistryID should be set by Add")
	}
}

func TestRegistry_DuplicateNameRejected(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("my-provider", KindPolicy))
	if err := reg.Add(sampleEntry("my-provider", KindPolicy)); err == nil {
		t.Error("Add should reject duplicate name")
	}
}

func TestRegistry_Remove(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("to-remove", KindExport))
	if err := reg.Remove("to-remove"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := reg.ByName("to-remove"); ok {
		t.Error("provider should be gone after Remove")
	}
	if err := reg.Remove("nonexistent"); err == nil {
		t.Error("Remove of nonexistent should return error")
	}
}

func TestRegistry_EnableDisable(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("p1", KindExport))

	if err := reg.Disable("p1"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	e, _ := reg.ByName("p1")
	if e.Enabled {
		t.Error("provider should be disabled")
	}

	if err := reg.Enable("p1"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	e, _ = reg.ByName("p1")
	if !e.Enabled {
		t.Error("provider should be enabled")
	}
}

func TestRegistry_UseExclusiveKind(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("policy-a", KindPolicy))
	_ = reg.Add(sampleEntry("policy-b", KindPolicy))

	// Enable both first.
	_ = reg.Enable("policy-a")
	_ = reg.Enable("policy-b")

	// Use policy-b: policy-a should be disabled (exclusive kind).
	if err := reg.Use("policy-b"); err != nil {
		t.Fatalf("Use: %v", err)
	}
	a, _ := reg.ByName("policy-a")
	b, _ := reg.ByName("policy-b")
	if a.Enabled {
		t.Error("policy-a should be disabled after Use(policy-b)")
	}
	if !b.Enabled {
		t.Error("policy-b should be enabled after Use(policy-b)")
	}
}

func TestRegistry_UseNonExclusiveKind(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("export-a", KindExport))
	_ = reg.Add(sampleEntry("export-b", KindExport))

	_ = reg.Enable("export-a")
	_ = reg.Use("export-b") // non-exclusive: export-a stays enabled

	a, _ := reg.ByName("export-a")
	b, _ := reg.ByName("export-b")
	if !a.Enabled {
		t.Error("export-a should remain enabled (non-exclusive kind)")
	}
	if !b.Enabled {
		t.Error("export-b should be enabled")
	}
}

func TestRegistry_Swap(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("sandbox-old", KindEffect))
	_ = reg.Add(sampleEntry("sandbox-new", KindEffect))
	_ = reg.Enable("sandbox-old")

	if err := reg.Swap("sandbox-old", "sandbox-new"); err != nil {
		t.Fatalf("Swap: %v", err)
	}
	old, _ := reg.ByName("sandbox-old")
	nw, _ := reg.ByName("sandbox-new")
	if old.Enabled {
		t.Error("sandbox-old should be disabled after swap")
	}
	if !nw.Enabled {
		t.Error("sandbox-new should be enabled after swap")
	}
}

func TestRegistry_SwapDifferentKindFails(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("a-policy", KindPolicy))
	_ = reg.Add(sampleEntry("b-effect", KindEffect))
	if err := reg.Swap("a-policy", "b-effect"); err == nil {
		t.Error("Swap of different kinds should fail")
	}
}

func TestRegistry_Active(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("exp1", KindExport))
	_ = reg.Add(sampleEntry("exp2", KindExport))
	e2, _ := reg.ByName("exp2")
	e2.Enabled = false
	for i := range reg.Providers {
		if reg.Providers[i].Name == "exp2" {
			reg.Providers[i].Enabled = false
		}
	}

	active := reg.Active(KindExport)
	if len(active) != 1 || active[0].Name != "exp1" {
		t.Errorf("Active(export) = %v, want [exp1]", active)
	}
}

func TestRegistry_Configure(t *testing.T) {
	tempRegistry(t)
	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("configurable", KindPolicy))
	if err := reg.Configure("configurable", "was-secret-push-origin", "warn"); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	e, _ := reg.ByName("configurable")
	if e.Config["was-secret-push-origin"] != "warn" {
		t.Errorf("Config[was-secret-push-origin] = %q, want %q", e.Config["was-secret-push-origin"], "warn")
	}
}

func TestRegistry_SaveAndLoad(t *testing.T) {
	home := tempRegistry(t)
	sirDir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(sirDir, 0o700); err != nil {
		t.Fatal(err)
	}

	reg := emptyRegistry()
	_ = reg.Add(sampleEntry("persistent", KindExport))
	if err := reg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reg2, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := reg2.ByName("persistent"); !ok {
		t.Error("provider should survive Save/Load round-trip")
	}
}

func TestRegistry_LoadMissingReturnsEmpty(t *testing.T) {
	tempRegistry(t)
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load of missing file should not error, got: %v", err)
	}
	if len(reg.Providers) != 0 {
		t.Error("Load of missing file should return empty registry")
	}
}
