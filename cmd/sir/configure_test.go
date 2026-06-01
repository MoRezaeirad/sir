package main

import (
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

// TestKnownAgentsCatalogHonestyGate enforces the security invariant that
// every knownAgents entry marked supported:true maps to a real adapter in
// agent.Registry(), and that the set of supported IDs exactly matches the
// registry. A mismatch means we claim to protect an agent we cannot hook —
// the one failure mode that makes this feature actively harmful.
func TestKnownAgentsCatalogHonestyGate(t *testing.T) {
	// Build registry ID set.
	registryIDs := make(map[string]bool)
	for _, reg := range agent.Registry() {
		registryIDs[string(reg.ID)] = true
	}

	// Build supported-probe ID set and verify each has a live adapter.
	supportedIDs := make(map[string]bool)
	for _, probe := range knownAgents {
		if !probe.supported {
			continue
		}
		supportedIDs[probe.id] = true

		ag := agent.ForID(agent.AgentID(probe.id))
		if ag == nil {
			t.Errorf("knownAgents probe %q marked supported:true but agent.ForID returns nil — no adapter exists", probe.id)
		}
	}

	// Every registry adapter must have a corresponding supported probe.
	for id := range registryIDs {
		if !supportedIDs[id] {
			t.Errorf("agent.Registry() has adapter %q but no knownAgents probe with supported:true — add it to the catalog", id)
		}
	}

	// Every supported probe must be in the registry.
	for id := range supportedIDs {
		if !registryIDs[id] {
			t.Errorf("knownAgents probe %q marked supported:true but not in agent.Registry() — mark it supported:false or add the adapter", id)
		}
	}
}

// TestSplitDiscovery verifies that splitDiscovery correctly categorizes
// detected-supported, detected-unsupported, and undetected results.
func TestSplitDiscovery(t *testing.T) {
	results := []agentDiscovery{
		{probe: agentProbe{supported: true}, detected: true},
		{probe: agentProbe{supported: true}, detected: false},
		{probe: agentProbe{supported: false}, detected: true},
		{probe: agentProbe{supported: false}, detected: false},
	}

	supported, comingSoon := splitDiscovery(results)

	if len(supported) != 1 {
		t.Errorf("want 1 supported, got %d", len(supported))
	}
	if !supported[0].detected || !supported[0].probe.supported {
		t.Errorf("supported slot should be detected+supported")
	}

	if len(comingSoon) != 1 {
		t.Errorf("want 1 coming-soon, got %d", len(comingSoon))
	}
	if !comingSoon[0].detected || comingSoon[0].probe.supported {
		t.Errorf("coming-soon slot should be detected+unsupported")
	}

	// Undetected agents never appear in either slice.
	for _, d := range supported {
		if !d.detected {
			t.Errorf("undetected agent in supported slice")
		}
	}
	for _, d := range comingSoon {
		if !d.detected {
			t.Errorf("undetected agent in coming-soon slice")
		}
	}
}

// TestKnownAgentsNoDuplicateIDs verifies there are no duplicate IDs in the
// catalog (which would make honesty-gate checks ambiguous).
func TestKnownAgentsNoDuplicateIDs(t *testing.T) {
	seen := make(map[string]bool)
	for _, probe := range knownAgents {
		if seen[probe.id] {
			t.Errorf("duplicate id %q in knownAgents catalog", probe.id)
		}
		seen[probe.id] = true
	}
}
