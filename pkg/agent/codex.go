// Package agent — Codex adapter.
//
// Codex uses the legacy { decision:"block", reason } response shape for
// PreToolUse/PostToolUse (still accepted on 0.135/0.136), but PermissionRequest
// requires a distinct nested envelope (hookSpecificOutput.decision.behavior),
// handled by codexLifecycleResponse. The adapter is otherwise a thin wrapper
// over the shared base functions driven by codexSpec.
//
// PostInstallFunc (ensureCodexFeatureFlag) is wired at init time from
// cmd/sir/install.go to avoid a pkg/agent → cmd/sir circular import.
package agent

import "encoding/json"

// codexPermissionDecision is the nested decision object Codex 0.135/0.136
// expects inside a PermissionRequest hook's hookSpecificOutput. Only "allow"
// and "deny" are valid behaviors; a deny carries an optional message.
type codexPermissionDecision struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

type codexPermissionHookSpecificOutput struct {
	HookEventName string                  `json:"hookEventName"`
	Decision      codexPermissionDecision `json:"decision"`
}

type codexPermissionResponse struct {
	HookSpecificOutput codexPermissionHookSpecificOutput `json:"hookSpecificOutput"`
}

// codexLifecycleResponse produces Codex's per-event response shape.
//
// PermissionRequest uses the nested hookSpecificOutput.decision.behavior form
// required by codex-cli 0.135/0.136 (verified against the live binary schema
// and the published hooks docs). sir's internal verdicts map as:
//
//	allow            → { behavior: "allow" }
//	deny/block/ask   → { behavior: "deny", message: reason }
//
// Codex has no "ask" behavior for PermissionRequest, so an ask verdict
// fail-closes to deny with the reason carried in the message. All other events
// fall through to the shared legacy formatter (their {decision:"block",reason}
// / {} shapes are unchanged and still honored).
func codexLifecycleResponse(eventName, decision, reason, context string) ([]byte, error) {
	if eventName != "PermissionRequest" {
		return formatLegacyLifecycle(&codexSpec, eventName, decision, reason, context, true)
	}
	behavior := "deny"
	message := reason
	if decision == "allow" {
		behavior = "allow"
		message = ""
	}
	return json.Marshal(codexPermissionResponse{
		HookSpecificOutput: codexPermissionHookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision:      codexPermissionDecision{Behavior: behavior, Message: message},
		},
	})
}

// codexSpec is the pure data declaration for the Codex adapter.
var codexSpec = AgentSpec{
	ID:         Codex,
	Name:       "Codex",
	MinVersion: "0.118.0",
	Capabilities: AgentCapabilities{
		SupportTier:          SupportTierLimited,
		ToolCoverage:         ToolCoveragePartial,
		InteractiveApproval:  false,
		PostureBackstop:      true,
		FileReadIFC:          true,
		FileWriteIFC:         true,
		ShellClassification:  true,
		MCPToolHooks:         true,
		SessionTerminalSweep: true,
		PreToolUse:           true,
		PermissionRequest:    true,
		PostToolUse:          true,
		UserPromptSubmit:     true,
		SessionStart:         true,
		Stop:                 true,
	},

	SupportedSIREvents: []string{
		"PreToolUse",
		"PermissionRequest",
		"PostToolUse",
		"UserPromptSubmit",
		"SessionStart",
		"Stop",
	},
	SupportedWireEvents: []string{
		"PreToolUse",
		"PermissionRequest",
		"PostToolUse",
		"UserPromptSubmit",
		"SessionStart",
		"Stop",
	},

	ConfigFile:               ".codex/hooks.json",
	ConfigDirs:               []string{".codex"},
	BinaryNames:              []string{"codex"},
	RuntimeProxyHosts:        []string{"api.openai.com"},
	RequiredFeatureFlag:      "hooks",
	FeatureFlagEnableCommand: "codex features enable hooks",

	ToolNames: map[string]string{
		"apply_patch": "Edit",
		// NOTE: codex-cli's model-facing shell tool is "exec_command"
		// (unified-exec) on 0.135/0.136, but the PreToolUse *hook payload*
		// normalizes it to tool_name:"Bash" with tool_input.command — verified
		// against a live 0.136 interactive hook (2026-06-01). So no exec_command
		// mapping is needed here; the hook contract is already "Bash".
	},
	EventNames: nil,

	ResponseFormat:         ResponseFormatLegacy,
	HasAskVerdict:          false,
	LegacyDenyLiteral:      "block",
	EmitLegacyPostEnvelope: true,

	ConfigStrategy: ConfigStrategy{
		ManagedSubtreeKey:   "hooks",
		Layout:              ConfigLayoutMatcherGroups,
		CanonicalBackupFile: "hooks-canonical-codex.json",
	},
	TimeoutUnit: "seconds",
	CommandFlag: "--agent codex",

	HookRegistrations: []HookRegistration{
		// The unified-exec shell tool arrives in the PreToolUse hook payload as
		// tool_name:"Bash" (verified against a live 0.136 hook), so the existing
		// Bash matcher covers it — no exec_command alternative is needed.
		{Event: "PreToolUse", Matcher: "Bash|apply_patch|Edit|Write|mcp__.*", Command: "guard evaluate", Timeout: 10},
		{Event: "PermissionRequest", Matcher: ".*", Command: "guard permission-request", Timeout: 10},
		{Event: "PostToolUse", Matcher: "Bash|apply_patch|Edit|Write|mcp__.*", Command: "guard post-evaluate", Timeout: 10},
		{Event: "SessionStart", Matcher: "startup|resume", Command: "guard compact-reinject", Timeout: 5},
		{Event: "UserPromptSubmit", Command: "guard user-prompt", Timeout: 5},
		{Event: "Stop", Command: "guard session-summary", Timeout: 5},
	},

	// FormatLifecycleFunc is wired in init() (below) to codexLifecycleResponse;
	// setting it inline would create an init cycle since the formatter falls
	// back to formatLegacyLifecycle(&codexSpec, ...).

	// PostInstallFunc is wired from cmd/sir/install.go at init time.
	PostInstallFunc: nil,
}

func init() {
	// Wire the lifecycle formatter here to avoid a codexSpec ⇄
	// codexLifecycleResponse initialization cycle.
	codexSpec.FormatLifecycleFunc = codexLifecycleResponse
}

// CodexAgent is the OpenAI Codex CLI adapter.
type CodexAgent struct{}

// compile-time interface assertions
var _ Agent = (*CodexAgent)(nil)
var _ MapBuilder = (*CodexAgent)(nil)

// NewCodexAgent returns a new Codex adapter.
func NewCodexAgent() *CodexAgent { return &CodexAgent{} }

func (c *CodexAgent) ID() AgentID         { return codexSpec.ID }
func (c *CodexAgent) Name() string        { return codexSpec.Name }
func (c *CodexAgent) MinVersion() string  { return codexSpec.MinVersion }
func (c *CodexAgent) GetSpec() *AgentSpec { return &codexSpec }

func (c *CodexAgent) ParsePreToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(&codexSpec, raw)
}
func (c *CodexAgent) ParsePostToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(&codexSpec, raw)
}

func (c *CodexAgent) FormatPreToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPreToolUseResponse(&codexSpec, decision, reason)
}
func (c *CodexAgent) FormatPostToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPostToolUseResponse(&codexSpec, decision, reason)
}
func (c *CodexAgent) FormatLifecycleResponse(eventName, decision, reason, context string) ([]byte, error) {
	return baseFormatLifecycleResponse(&codexSpec, eventName, decision, reason, context)
}

func (c *CodexAgent) SupportedEvents() []string { return codexSpec.SupportedWireEvents }
func (c *CodexAgent) ConfigPath() string        { return baseConfigPath(&codexSpec) }
func (c *CodexAgent) DetectInstallation() bool  { return baseDetectInstallation(&codexSpec) }

func (c *CodexAgent) GenerateHooksConfig(sirBinaryPath, mode string) ([]byte, error) {
	return baseGenerateHooksConfig(&codexSpec, sirBinaryPath, mode)
}
func (c *CodexAgent) GenerateHooksConfigMap(sirBinaryPath, mode string) (map[string]interface{}, error) {
	return baseGenerateHooksConfigMap(&codexSpec, sirBinaryPath, mode)
}
