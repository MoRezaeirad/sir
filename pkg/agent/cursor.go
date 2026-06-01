package agent

import (
	"encoding/json"
	"fmt"
	"strings"
)

var cursorSpec = AgentSpec{
	ID:         Cursor,
	Name:       "Cursor",
	MinVersion: "3.6.21",
	Capabilities: AgentCapabilities{
		SupportTier:          SupportTierNearParity,
		ToolCoverage:         ToolCoveragePartial,
		InteractiveApproval:  false,
		PostureBackstop:      true,
		FileReadIFC:          true,
		FileWriteIFC:         false,
		ShellClassification:  true,
		MCPToolHooks:         true,
		SessionTerminalSweep: true,
		PreToolUse:           true,
		PostToolUse:          true,
		UserPromptSubmit:     true,
		SubagentStart:        true,
		SessionStart:         true,
		Stop:                 true,
		SessionEnd:           true,
	},

	SupportedSIREvents: []string{
		"PreToolUse",
		"PostToolUse",
		"UserPromptSubmit",
		"SubagentStart",
		"SessionStart",
		"Stop",
		"SessionEnd",
	},
	SupportedWireEvents: []string{
		"preToolUse",
		"postToolUse",
		"postToolUseFailure",
		"beforeShellExecution",
		"afterShellExecution",
		"beforeMCPExecution",
		"afterMCPExecution",
		"beforeReadFile",
		"afterFileEdit",
		"subagentStart",
		"beforeSubmitPrompt",
		"sessionStart",
		"preCompact",
		"stop",
		"sessionEnd",
	},

	ConfigFile:        ".cursor/hooks.json",
	ConfigDirs:        []string{".cursor"},
	BinaryNames:       []string{"cursor-agent", "cursor"},
	RuntimeProxyHosts: []string{"api2.cursor.sh", "api3.cursor.sh"},

	ResponseFormat: ResponseFormatCursor,
	HasAskVerdict:  false,

	ConfigStrategy: ConfigStrategy{
		ManagedSubtreeKey:   "hooks",
		Layout:              ConfigLayoutFlatCommands,
		CanonicalBackupFile: "hooks-canonical-cursor.json",
	},
	TimeoutUnit: "milliseconds",
	CommandFlag: "--agent cursor",

	HookRegistrations: []HookRegistration{
		{Event: "PreToolUse", WireEvent: "preToolUse", Command: "guard evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PostToolUse", WireEvent: "postToolUse", Command: "guard post-evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PostToolUse", WireEvent: "postToolUseFailure", Command: "guard post-evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PreToolUse", WireEvent: "beforeShellExecution", Command: "guard evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PostToolUse", WireEvent: "afterShellExecution", Command: "guard post-evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PreToolUse", WireEvent: "beforeMCPExecution", Command: "guard evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PostToolUse", WireEvent: "afterMCPExecution", Command: "guard post-evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PreToolUse", WireEvent: "beforeReadFile", Command: "guard evaluate", Timeout: 10000, FailClosed: true},
		{Event: "PostToolUse", WireEvent: "afterFileEdit", Command: "guard post-evaluate", Timeout: 10000, FailClosed: true},
		{Event: "SubagentStart", WireEvent: "subagentStart", Command: "guard subagent-start", Timeout: 10000, FailClosed: true},
		{Event: "UserPromptSubmit", WireEvent: "beforeSubmitPrompt", Command: "guard user-prompt", Timeout: 5000, FailClosed: true},
		{Event: "SessionStart", WireEvent: "sessionStart", Command: "guard compact-reinject", Timeout: 5000, FailClosed: true},
		{Event: "SessionStart", WireEvent: "preCompact", Command: "guard compact-reinject", Timeout: 5000, FailClosed: true},
		{Event: "Stop", WireEvent: "stop", Command: "guard session-summary", Timeout: 5000, FailClosed: true},
		{Event: "SessionEnd", WireEvent: "sessionEnd", Command: "guard session-end", Timeout: 5000, FailClosed: true},
	},
}

type CursorAgent struct{}

var _ Agent = (*CursorAgent)(nil)
var _ MapBuilder = (*CursorAgent)(nil)

func NewCursorAgent() *CursorAgent { return &CursorAgent{} }

func (c *CursorAgent) ID() AgentID         { return cursorSpec.ID }
func (c *CursorAgent) Name() string        { return cursorSpec.Name }
func (c *CursorAgent) MinVersion() string  { return cursorSpec.MinVersion }
func (c *CursorAgent) GetSpec() *AgentSpec { return &cursorSpec }

func (c *CursorAgent) ParsePreToolUse(raw []byte) (*HookPayload, error) {
	return parseCursorHookPayload(raw)
}
func (c *CursorAgent) ParsePostToolUse(raw []byte) (*HookPayload, error) {
	return parseCursorHookPayload(raw)
}

func (c *CursorAgent) FormatPreToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPreToolUseResponse(&cursorSpec, decision, reason)
}
func (c *CursorAgent) FormatPostToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPostToolUseResponse(&cursorSpec, decision, reason)
}
func (c *CursorAgent) FormatLifecycleResponse(eventName, decision, reason, context string) ([]byte, error) {
	if context != "" && decision == "allow" {
		return json.Marshal(map[string]interface{}{
			"agent_message": context,
		})
	}
	return formatCursorPreToolUse(decision, reason)
}

func (c *CursorAgent) SupportedEvents() []string { return cursorSpec.SupportedWireEvents }
func (c *CursorAgent) ConfigPath() string        { return baseConfigPath(&cursorSpec) }
func (c *CursorAgent) DetectInstallation() bool  { return baseDetectInstallation(&cursorSpec) }

func (c *CursorAgent) GenerateHooksConfig(sirBinaryPath, mode string) ([]byte, error) {
	return baseGenerateHooksConfig(&cursorSpec, sirBinaryPath, mode)
}
func (c *CursorAgent) GenerateHooksConfigMap(sirBinaryPath, mode string) (map[string]interface{}, error) {
	return baseGenerateHooksConfigMap(&cursorSpec, sirBinaryPath, mode)
}

type cursorWirePayload struct {
	ConversationID string                 `json:"conversation_id"`
	SessionID      string                 `json:"session_id"`
	HookEventName  string                 `json:"hook_event_name"`
	ToolName       string                 `json:"tool_name"`
	ToolInput      map[string]interface{} `json:"tool_input"`
	ToolUseID      string                 `json:"tool_use_id"`
	CWD            string                 `json:"cwd"`
	TranscriptPath string                 `json:"transcript_path"`

	Command    string          `json:"command"`
	Path       string          `json:"path"`
	FilePath   string          `json:"file_path"`
	ServerName string          `json:"server_name"`
	ToolOutput string          `json:"tool_output"`
	ToolResult json.RawMessage `json:"tool_result"`
	Output     json.RawMessage `json:"output"`
	Result     json.RawMessage `json:"result"`
	Response   json.RawMessage `json:"response"`
	Args       json.RawMessage `json:"args"`
}

func parseCursorHookPayload(raw []byte) (*HookPayload, error) {
	var wire cursorWirePayload
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("unmarshal cursor hook payload: %w", err)
	}
	event := normalizeCursorEvent(wire.HookEventName)
	toolName, toolInput := normalizeCursorTool(wire)
	sessionID := wire.SessionID
	if sessionID == "" {
		sessionID = wire.ConversationID
	}
	return &HookPayload{
		SessionID:      sessionID,
		HookEventName:  event,
		ToolName:       toolName,
		ToolInput:      toolInput,
		ToolUseID:      wire.ToolUseID,
		ToolOutput:     cursorToolOutput(wire),
		CWD:            wire.CWD,
		AgentID:        Cursor,
		TranscriptPath: wire.TranscriptPath,
	}, nil
}

func normalizeCursorEvent(name string) string {
	switch name {
	case "preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile":
		return "PreToolUse"
	case "postToolUse", "postToolUseFailure", "afterShellExecution", "afterMCPExecution", "afterFileEdit":
		return "PostToolUse"
	case "beforeSubmitPrompt":
		return "UserPromptSubmit"
	case "sessionStart", "preCompact":
		return "SessionStart"
	case "subagentStart":
		return "SubagentStart"
	case "stop":
		return "Stop"
	case "sessionEnd":
		return "SessionEnd"
	default:
		return name
	}
}

func normalizeCursorTool(wire cursorWirePayload) (string, map[string]interface{}) {
	input := cloneStringMap(wire.ToolInput)
	switch wire.HookEventName {
	case "beforeShellExecution", "afterShellExecution":
		if wire.Command != "" {
			input["command"] = wire.Command
		}
		return "Bash", input
	case "beforeReadFile":
		if wire.Path != "" {
			input["file_path"] = wire.Path
		}
		if wire.FilePath != "" {
			input["file_path"] = wire.FilePath
		}
		return "Read", input
	case "afterFileEdit":
		if wire.Path != "" {
			input["file_path"] = wire.Path
		}
		if wire.FilePath != "" {
			input["file_path"] = wire.FilePath
		}
		return "Edit", input
	case "beforeMCPExecution", "afterMCPExecution":
		if len(wire.Args) > 0 && string(wire.Args) != "null" {
			var args interface{}
			if err := json.Unmarshal(wire.Args, &args); err == nil {
				input["args"] = args
			}
		}
		return normalizeCursorMCPName(wire.ServerName, wire.ToolName), input
	default:
		return normalizeCursorGenericTool(wire.ToolName), input
	}
}

func cloneStringMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeCursorGenericTool(name string) string {
	switch strings.ToLower(name) {
	case "read", "readfile", "read_file":
		return "Read"
	case "write", "writefile", "write_file":
		return "Write"
	case "edit", "fileedit", "afterfileedit":
		return "Edit"
	case "bash", "shell", "terminal", "runshell", "run_shell_command":
		return "Bash"
	case "webfetch", "web_fetch":
		return "WebFetch"
	case "websearch", "web_search":
		return "WebSearch"
	default:
		return name
	}
}

func normalizeCursorMCPName(server, tool string) string {
	server = strings.TrimSpace(server)
	tool = strings.TrimSpace(tool)
	if server != "" && tool != "" {
		return "mcp__" + server + "__" + tool
	}
	if strings.HasPrefix(tool, "mcp__") {
		return tool
	}
	if strings.HasPrefix(tool, "mcp_") {
		return rewriteMCPName(tool, "mcp_", "_")
	}
	return tool
}

func cursorToolOutput(wire cursorWirePayload) string {
	if wire.ToolOutput != "" {
		return wire.ToolOutput
	}
	for _, raw := range []json.RawMessage{wire.ToolResult, wire.Output, wire.Result, wire.Response} {
		if out := defaultExtractToolOutput(raw); out != "" {
			return out
		}
	}
	return ""
}
