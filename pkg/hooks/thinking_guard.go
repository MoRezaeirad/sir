package hooks

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// thinkingTranscriptTailBytes bounds how much of the (potentially large)
// transcript tail is scanned for thinking blocks. Recent turns are enough:
// if thinking is active it appears in every turn, and the settings signal
// covers the always-on case regardless of transcript size.
const thinkingTranscriptTailBytes = 1 << 20 // 1 MiB

// thinkingBlockMarkers are the JSON encodings of an extended-thinking content
// block as they appear in a Claude Code transcript. Matching the typed "type"
// field (rather than the bare word) avoids false positives from prose that
// merely mentions thinking.
var thinkingBlockMarkers = [][]byte{
	[]byte(`"type":"thinking"`),
	[]byte(`"type": "thinking"`),
	[]byte(`"type":"redacted_thinking"`),
	[]byte(`"type": "redacted_thinking"`),
}

// thinkingGuardLedgerReason is the concise reason recorded in the ledger when
// an ask is degraded to a deny by the thinking guard. The agent-visible wire
// reason is the fuller FormatThinkingGuardDeny block.
const thinkingGuardLedgerReason = "interactive approval suppressed (Claude thinking-safe): ask degraded to deny"

// thinkingDegradeActive reports whether an interactive ask should be degraded to
// a deny on this invocation: the host is Claude Code and extended thinking is
// active. Computed once per evaluation and stashed on the session so the wire
// guard and the ledger writers agree on a single answer.
func thinkingDegradeActive(ag agent.Agent, payload *HookPayload) bool {
	return ag != nil && ag.ID() == agent.Claude && claudeThinkingActive(payload)
}

// applyThinkingGuard degrades an interactive "ask" to a deny-with-guidance when
// degrade is set. An ask suspends the assistant turn for interactive approval;
// resuming a thinking-enabled turn trips a Claude Code bug ("thinking blocks ...
// cannot be modified", API 400) that wedges the entire conversation. A deny
// keeps the turn linear, so it is safe. This is a Go-side narrowing (ask ->
// deny) and never widens a verdict.
//
// It runs as a post-processing transform on every PreToolUse / PermissionRequest
// return path, mirroring observe mode. Under observe mode the observe downgrade
// (deny -> allow) is registered to run after this and therefore still wins.
func applyThinkingGuard(resp *HookResponse, degrade bool) {
	if resp == nil || !degrade || resp.Decision != policy.VerdictAsk {
		return
	}
	resp.Reason = FormatThinkingGuardDeny(resp.Reason)
	resp.Decision = policy.VerdictDeny
}

// thinkingDegradedLedgerDecision returns the verdict to record in the ledger,
// folding in the thinking-guard degrade (ask -> deny) so the recorded decision
// matches the agent-visible wire decision. Callers still apply observe-mode
// rewriting on top via recordedDecisionFor / appendEvaluationLedgerEntry.
func thinkingDegradedLedgerDecision(state *session.State, decision policy.Verdict) policy.Verdict {
	if state != nil && state.ThinkingGuardActive && decision == policy.VerdictAsk {
		return policy.VerdictDeny
	}
	return decision
}

// claudeThinkingActive reports whether the current Claude Code session has
// extended/interleaved thinking active. Two independent signals are checked,
// either of which is sufficient; the cheaper settings read runs first.
func claudeThinkingActive(payload *HookPayload) bool {
	if payload == nil {
		return false
	}
	if settingsThinkingEnabled(payload.CWD) {
		return true
	}
	return transcriptHasThinking(payload.TranscriptPath)
}

// settingsThinkingEnabled reports whether alwaysThinkingEnabled is set in any
// Claude settings file that applies to this session: project-local settings
// (and its untracked .local override) take precedence over user settings, but
// for a boolean "is thinking on anywhere" any true wins.
func settingsThinkingEnabled(cwd string) bool {
	var candidates []string
	if cwd != "" {
		candidates = append(candidates,
			filepath.Join(cwd, ".claude", "settings.local.json"),
			filepath.Join(cwd, ".claude", "settings.json"),
		)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, filepath.Join(home, ".claude", "settings.json"))
	}
	for _, path := range candidates {
		if settingsFileEnablesThinking(path) {
			return true
		}
	}
	return false
}

func settingsFileEnablesThinking(path string) bool {
	data, err := os.ReadFile(path) // #nosec G304 -- reading the agent's own settings file to detect thinking mode
	if err != nil {
		return false
	}
	var cfg struct {
		AlwaysThinkingEnabled bool `json:"alwaysThinkingEnabled"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false
	}
	return cfg.AlwaysThinkingEnabled
}

// transcriptHasThinking reports whether the tail of the transcript contains an
// extended-thinking content block. This catches thinking that was toggled on
// in-session without persisting to settings.
func transcriptHasThinking(path string) bool {
	if path == "" {
		return false
	}
	f, err := os.Open(path) // #nosec G304 -- reading the agent-provided transcript path to detect thinking mode
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	if fi, err := f.Stat(); err == nil && fi.Size() > thinkingTranscriptTailBytes {
		if _, err := f.Seek(fi.Size()-thinkingTranscriptTailBytes, io.SeekStart); err != nil {
			return false
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, thinkingTranscriptTailBytes))
	if err != nil {
		return false
	}
	for _, marker := range thinkingBlockMarkers {
		if bytes.Contains(data, marker) {
			return true
		}
	}
	return false
}
