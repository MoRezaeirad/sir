// Package signal bridges the v1 hook path and v2 signal pipeline.
//
// The evaluation pipeline should be signal-first: hooks are one source of
// declared_intent signals, but eBPF sensors, process monitors, git hooks, and
// runtime observers can also contribute. This package collects signals from all
// registered sources and normalizes them before evaluation so that:
//
//   - If a hook fires:  declared_intent signal at pre_exec → enforces class
//   - If only runtime:  observed_runtime signal → detects class
//   - If no signals:    blind class, no-op beyond ledger
//
// The evaluation path reads from signals, not directly from HookPayload.
package signal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/kernel"
	"github.com/somoore/sir/pkg/sdk"
)

// FromHookPayload converts a v1 HookPayload into a sir.signal.v0 Signal.
//
// This is the canonical bridge from v1 hooks to the v2 signal pipeline.
// All tool classification that was previously scattered across evaluatePayload()
// happens here at signal-emission time, so the evaluation path receives a
// pre-digested signal rather than raw ToolInput.
//
// Source reliability: declared_intent — the hook fires before execution and
// declares what the agent intends to do. Combined with pre_exec timing this
// gives ClassEnforces in hook_gate mode.
func FromHookPayload(payload *agent.HookPayload) sdk.Signal {
	if payload == nil {
		return sdk.Signal{}
	}

	actionType := actionTypeFromTool(payload.ToolName)
	display, sensitivity := classifyTarget(payload.ToolName, payload.ToolInput)

	actorKind := "ai_coding_agent" // PreToolUse is always AI-initiated
	if payload.AgentID == "" {
		actorKind = "human_developer"
	}

	rawInput, _ := json.Marshal(payload.ToolInput)

	return sdk.Signal{
		SchemaVersion: sdk.SchemaSignalV0,
		SignalID:      hookSignalID(payload),
		SignalTime:    time.Now().UTC().Format(time.RFC3339Nano),
		Source: sdk.Source{
			Kind:        sourceKindForAgent(string(payload.AgentID)),
			Reliability: sdk.ReliabilityDeclaredIntent,
			Timing:      sdk.TimingPreExec,
		},
		Session: &sdk.Session{
			SessionID: payload.SessionID,
			SpanID:    payload.ToolUseID,
		},
		ActorClaim: &sdk.ActorClaim{
			Kind: actorKind,
			Name: string(payload.AgentID),
		},
		ActionClaim: map[string]any{
			"type":      actionType,
			"tool_name": payload.ToolName,
			"target": map[string]any{
				"display":     display,
				"sensitivity": sensitivity,
			},
			"raw_input": json.RawMessage(rawInput),
		},
	}
}

// CollectSignals gathers all signals for a single evaluation:
//  1. The hook-derived signal (declared_intent, pre_exec) — always present
//  2. Signals from registered signal_providers in the registry
//
// The hook signal is authoritative for blocking: it fires before execution
// and gives ClassEnforces in hook_gate mode. Signal provider outputs augment
// with additional context (OS-level correlation, process identity, etc.) but
// do not replace the hook signal.
//
// If hook payload is nil (future: evaluation triggered by runtime observer,
// not a hook), only provider signals are collected. Enforceability degrades
// to ClassDetects or ClassBlind depending on signal reliabilities present.
func CollectSignals(payload *agent.HookPayload, projectRoot string) []sdk.Signal {
	var signals []sdk.Signal

	// Hook signal — always first and highest-reliability in the hook path.
	if payload != nil {
		hookSig := FromHookPayload(payload)
		if hookSig.SignalID != "" {
			signals = append(signals, hookSig)
		}
	}

	// Signal providers from registry — contribute corroborating signals.
	// Errors are non-fatal: a missing provider degrades enforceability but
	// never prevents evaluation (fail-open for normal developer workflows).
	providerSignals := invokeSignalProviders(payload, projectRoot)
	signals = append(signals, providerSignals...)

	return kernel.NormalizeSignals(signals)
}

// EnforceabilityForSignals returns the enforceability class for a set of
// signals in hook_gate mode. Used to annotate ledger entries and telemetry.
func EnforceabilityForSignals(signals []sdk.Signal) string {
	result := kernel.AnalyzeEnforceability(kernel.EnforceabilityInput{
		Mode:    kernel.ModeHookGate,
		Signals: signals,
	})
	return result.Class
}

// AttributionConfidence returns the attribution confidence across collected signals.
func AttributionConfidence(signals []sdk.Signal) string {
	return kernel.AttributionConfidence(signals)
}

// ActorKindFromSignals returns the resolved actor kind from the highest-confidence signal.
func ActorKindFromSignals(signals []sdk.Signal) string {
	// Walk signals in order — first (hook signal) has highest reliability.
	for _, s := range signals {
		if s.ActorClaim != nil && s.ActorClaim.Kind != "" {
			return s.ActorClaim.Kind
		}
	}
	// No signal has actor attribution — cannot determine.
	return "unknown"
}

// invokeSignalProviders calls registered signal_provider entries and returns
// their emitted signals. The raw hook payload JSON is forwarded so providers
// can correlate agent events with OS-level observations.
func invokeSignalProviders(payload *agent.HookPayload, projectRoot string) []sdk.Signal {
	_ = projectRoot // reserved for per-project provider scoping

	// Load registry — cached per process (see policy_providers.go singleton).
	// Avoid importing pkg/hooks to prevent circular imports; registry load is
	// self-contained in pkg/provider.
	raw, err := os.ReadFile(registryPath())
	if err != nil {
		return nil // no registry or unreadable — not an error
	}

	var reg struct {
		Providers []struct {
			Name       string `json:"name"`
			Kind       string `json:"kind"`
			Enabled    bool   `json:"enabled"`
			Entrypoint string `json:"entrypoint"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil
	}

	eventJSON, _ := json.Marshal(payload)
	var signals []sdk.Signal

	for _, e := range reg.Providers {
		if !e.Enabled || e.Kind != sdk.KindSignalProvider {
			continue
		}
		sig, err := invokeSignalProvider(e.Entrypoint, eventJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sir: signal provider %s: %v\n", e.Name, err)
			continue
		}
		signals = append(signals, sig...)
	}
	return signals
}

// ─── private helpers ────────────────────────────────────────────────────────

func actionTypeFromTool(toolName string) string {
	switch toolName {
	case "Bash":
		return "shell_exec"
	case "Read":
		return "file_read"
	case "Write", "Edit", "NotebookEdit":
		return "file_write"
	case "WebFetch":
		return "network_fetch"
	case "WebSearch":
		return "network_search"
	case "Agent":
		return "agent_delegation"
	case "Grep":
		return "file_read"
	case "Glob":
		return "file_list"
	default:
		if strings.HasPrefix(toolName, "mcp__") {
			return "mcp_call"
		}
		return "tool_call"
	}
}

func classifyTarget(toolName string, toolInput map[string]any) (display, sensitivity string) {
	switch toolName {
	case "Bash":
		if cmd, ok := toolInput["command"].(string); ok {
			display = truncate(cmd, 200)
			if isSensitiveCommand(cmd) {
				sensitivity = "credential"
			} else if isExternalNetwork(cmd) {
				sensitivity = "external_network"
			} else {
				sensitivity = "low"
			}
		}
	case "Read", "Grep", "Glob":
		if path, ok := toolInput["file_path"].(string); ok {
			display = path
			sensitivity = sensitivityForPath(path)
		}
	case "Write", "Edit":
		if path, ok := toolInput["file_path"].(string); ok {
			display = path
			sensitivity = sensitivityForPath(path)
		}
	case "WebFetch", "WebSearch":
		if url, ok := toolInput["url"].(string); ok {
			display = url
			sensitivity = "external_network"
		} else if query, ok := toolInput["query"].(string); ok {
			display = query
			sensitivity = "external_network"
		}
	default:
		if strings.HasPrefix(toolName, "mcp__") {
			display = toolName
			sensitivity = "low"
		}
	}
	if sensitivity == "" {
		sensitivity = "low"
	}
	return display, sensitivity
}

func isSensitiveCommand(cmd string) bool {
	sensitivePatterns := []string{
		".aws", ".ssh", ".env", "credentials", "id_rsa", "id_ed25519",
		"secret", "token", "password", "passwd", "api_key",
	}
	lower := strings.ToLower(cmd)
	for _, p := range sensitivePatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isExternalNetwork(cmd string) bool {
	networkCommands := []string{"curl", "wget", "fetch", "http", "https", "ftp", "ssh ", "scp ", "rsync "}
	lower := strings.ToLower(cmd)
	for _, c := range networkCommands {
		if strings.Contains(lower, c) {
			return true
		}
	}
	return false
}

func sensitivityForPath(path string) string {
	lp := strings.ToLower(path)
	sensitiveFragments := []string{
		".env", ".aws/", ".ssh/", ".gnupg/", "credentials", "secrets",
		".pem", ".key", ".p12", ".pfx", "id_rsa", "id_ed25519",
	}
	for _, frag := range sensitiveFragments {
		if strings.Contains(lp, frag) {
			return "credential"
		}
	}
	return "low"
}

func sourceKindForAgent(agentID string) string {
	switch agentID {
	case "claude":
		return "claude_hook"
	case "codex":
		return "codex_hook"
	case "gemini":
		return "gemini_hook"
	default:
		return "agent_hook"
	}
}

func hookSignalID(payload *agent.HookPayload) string {
	if payload.ToolUseID != "" {
		return "hook-" + payload.ToolUseID
	}
	return "hook-" + payload.SessionID + "-" + payload.ToolName
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func registryPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home + "/.sir/providers.json"
}
