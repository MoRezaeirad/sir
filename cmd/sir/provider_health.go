package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/sdk"
)

// cmdProviderHealth scans a directory of provider manifests and reports health.
// Note: the PLAN calls for this to be part of `sir doctor`. This subcommand
// keeps the probe logic reusable for that future integration.
//
// Usage: sir provider health [<directory>]
func cmdProviderHealth(args []string) {
	dir := "examples/providers"
	if len(args) > 0 {
		dir = args[0]
	}

	manifests, err := findProviderManifests(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error scanning %s: %v\n", dir, err)
		os.Exit(1)
	}
	if len(manifests) == 0 {
		fmt.Fprintf(os.Stderr, "no provider manifests found in %s\n", dir)
		os.Exit(1)
	}

	fmt.Printf("%-26s %-16s %-10s %s\n", "provider", "kind", "status", "capabilities")
	fmt.Println(strings.Repeat("-", 90))

	anyUnhealthy := false
	for _, mpath := range manifests {
		m, issues := loadAndValidateManifest(mpath)
		if m == nil || len(issues) > 0 {
			fmt.Printf("%-26s %-16s %-10s manifest invalid: %s\n",
				filepath.Base(filepath.Dir(mpath)), "?", "unhealthy", strings.Join(issues, "; "))
			anyUnhealthy = true
			continue
		}

		dir := filepath.Dir(mpath)
		ep := filepath.Join(dir, m.Entrypoint)
		capsRaw, err := queryProviderCapabilities(ep)
		if err != nil {
			fmt.Printf("%-26s %-16s %-10s capabilities query failed: %v\n",
				m.Name, m.Kind, "unhealthy", err)
			anyUnhealthy = true
			continue
		}

		capsLine := summarizeCapabilities(capsRaw)
		fmt.Printf("%-26s %-16s %-10s %s\n", m.Name, m.Kind, "healthy", capsLine)
	}

	if anyUnhealthy {
		os.Exit(1)
	}
}

func findProviderManifests(root string) ([]string, error) {
	var found []string
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join(root, e.Name(), "provider.yaml")
		if _, err := os.Stat(candidate); err == nil {
			found = append(found, candidate)
		}
	}
	return found, nil
}

func summarizeCapabilities(capsRaw []byte) string {
	var resp sdk.CapabilitiesResponse
	if err := json.Unmarshal(capsRaw, &resp); err != nil {
		return "(parse error)"
	}
	caps := resp.Capabilities
	var parts []string

	// Effect provider summary: contain/block availability
	for _, key := range []string{"contain", "block", "record", "nudge"} {
		if v, ok := caps[key]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", key, v))
		}
	}
	// Signal provider summary: reliability + timing
	if rel, ok := caps["signal_reliability"]; ok {
		parts = append(parts, fmt.Sprintf("reliability=%v", rel))
	}
	if timing, ok := caps["timing"]; ok {
		parts = append(parts, fmt.Sprintf("timing=%v", timing))
	}
	// Docker / platform availability notes
	if docker, ok := caps["docker_available"]; ok {
		parts = append(parts, fmt.Sprintf("docker=%v", docker))
	}
	if platform, ok := caps["platform"]; ok {
		parts = append(parts, fmt.Sprintf("platform=%v", platform))
	}

	if len(parts) == 0 {
		return "(no summary available)"
	}
	return strings.Join(parts, "  ")
}
