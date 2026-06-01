package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DiscoverServerNames returns the set of MCP server names that are eligible for
// legacy hook-time auto approval across the default sir config surfaces.
// Project-scoped servers stored in global configs are intentionally excluded:
// they are discoverable by DiscoverInventory, but require an explicit approval
// step because a single-workspace MCP addition is too easy to confuse with
// already-trusted global posture.
func DiscoverServerNames(projectRoot string) []string {
	return AutoApprovedServerNames(DiscoverInventory(projectRoot).Servers)
}

// DiscoverInventory returns the inventory for the default sir MCP config
// surfaces.
func DiscoverInventory(projectRoot string) InventoryReport {
	return DiscoverInventoryForScopes(projectRoot, nil)
}

// DiscoverInventoryForScopes returns the inventory limited to the provided
// scope set.
func DiscoverInventoryForScopes(projectRoot string, scopes map[ConfigScope]bool) InventoryReport {
	files := discoverConfigFiles(projectRoot, scopes)
	report := InventoryReport{
		Servers: make([]ServerInventory, 0, len(files)),
		Errors:  make([]InventoryError, 0),
	}
	for _, file := range files {
		servers, err := ReadInventoryFile(file)
		if err != nil {
			report.Errors = append(report.Errors, InventoryError{Path: file.Path, Err: err})
			continue
		}
		report.Servers = append(report.Servers, servers...)
	}
	sort.Slice(report.Servers, func(i, j int) bool {
		if report.Servers[i].SourcePath != report.Servers[j].SourcePath {
			return report.Servers[i].SourcePath < report.Servers[j].SourcePath
		}
		return report.Servers[i].Name < report.Servers[j].Name
	})
	sort.Slice(report.Errors, func(i, j int) bool {
		return report.Errors[i].Path < report.Errors[j].Path
	})
	return report
}

func discoverConfigFiles(projectRoot string, scopes map[ConfigScope]bool) []InventoryFile {
	var files []InventoryFile
	if scopeAllowed(scopes, ConfigProjectLocal) {
		files = append(files, InventoryFile{
			Path:  filepath.Join(projectRoot, ".mcp.json"),
			Label: ".mcp.json",
			Scope: ConfigProjectLocal,
		})
	}
	if scopeAllowed(scopes, ConfigCursorProject) {
		files = append(files, InventoryFile{
			Path:  filepath.Join(projectRoot, ".cursor", "mcp.json"),
			Label: ".cursor/mcp.json",
			Scope: ConfigCursorProject,
		})
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		if scopeAllowed(scopes, ConfigClaudeGlobal) {
			files = append(files,
				InventoryFile{
					Path:  filepath.Join(homeDir, ".claude", "settings.json"),
					Label: "~/.claude/settings.json",
					Scope: ConfigClaudeGlobal,
				},
				InventoryFile{
					Path:        filepath.Join(homeDir, ".claude.json"),
					Label:       "~/.claude.json",
					Scope:       ConfigClaudeGlobal,
					ProjectRoot: projectRoot,
				},
				InventoryFile{
					Path:  filepath.Join(homeDir, ".claude", ".mcp.json"),
					Label: "~/.claude/.mcp.json",
					Scope: ConfigClaudeGlobal,
				},
			)
		}
		if scopeAllowed(scopes, ConfigGeminiGlobal) {
			files = append(files, InventoryFile{
				Path:  filepath.Join(homeDir, ".gemini", "settings.json"),
				Label: "~/.gemini/settings.json",
				Scope: ConfigGeminiGlobal,
			})
		}
		if scopeAllowed(scopes, ConfigCursorGlobal) {
			files = append(files, InventoryFile{
				Path:  filepath.Join(homeDir, ".cursor", "mcp.json"),
				Label: "~/.cursor/mcp.json",
				Scope: ConfigCursorGlobal,
			})
		}
	}
	return files
}

func scopeAllowed(scopes map[ConfigScope]bool, scope ConfigScope) bool {
	if scopes == nil {
		return true
	}
	return scopes[scope]
}

// ReadInventoryFile parses one MCP config file into normalized inventory
// entries.
func ReadInventoryFile(file InventoryFile) ([]ServerInventory, error) {
	data, err := os.ReadFile(file.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var servers []ServerInventory
	rawServers, _ := doc["mcpServers"].(map[string]interface{})
	servers = append(servers, readMCPServerMap(file, rawServers, "", file.Label, false)...)

	if file.Scope == ConfigClaudeGlobal && filepath.Base(file.Path) == ".claude.json" && file.ProjectRoot != "" {
		if projects, _ := doc["projects"].(map[string]interface{}); len(projects) > 0 {
			for _, key := range claudeProjectKeyCandidates(file.ProjectRoot) {
				entry, _ := projects[key].(map[string]interface{})
				if entry == nil {
					continue
				}
				projectServers, _ := entry["mcpServers"].(map[string]interface{})
				servers = append(servers, readMCPServerMap(file, projectServers, key, file.Label+" (project)", true)...)
			}
		}
	}
	return servers, nil
}

func readMCPServerMap(file InventoryFile, rawServers map[string]interface{}, projectKey, sourceLabel string, requiresExplicitApproval bool) []ServerInventory {
	if len(rawServers) == 0 {
		return nil
	}

	names := make([]string, 0, len(rawServers))
	for name := range rawServers {
		names = append(names, name)
	}
	sort.Strings(names)

	servers := make([]ServerInventory, 0, len(names))
	for _, name := range names {
		entry, _ := rawServers[name].(map[string]interface{})
		command, hasCommand := entry["command"].(string)
		args, argsOK := InterfaceSliceToStrings(entry["args"])
		if !argsOK {
			args = nil
		}
		proxy := ProxySpec{}
		if hasCommand {
			proxy = ClassifyProxy(command, args)
			if !proxy.Wrapped {
				if rawArgs, ok := entry["args"].([]interface{}); ok && len(rawArgs) > 0 {
					if first, ok := rawArgs[0].(string); ok && first == "mcp-proxy" && isSirBinaryCommand(command) {
						proxy = ProxySpec{Wrapped: true, SirCommand: command, Malformed: true}
					}
				}
			}
			if !argsOK {
				proxy.Malformed = true
			}
		}
		servers = append(servers, ServerInventory{
			Name:                     name,
			SourcePath:               file.Path,
			SourceLabel:              sourceLabel,
			Scope:                    file.Scope,
			ProjectKey:               projectKey,
			RequiresExplicitApproval: requiresExplicitApproval,
			Command:                  command,
			Args:                     args,
			HasCommand:               hasCommand,
			Proxy:                    proxy,
		})
	}
	return servers
}

func claudeProjectKeyCandidates(projectRoot string) []string {
	var candidates []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		for _, existing := range candidates {
			if existing == path {
				return
			}
		}
		candidates = append(candidates, path)
	}
	add(projectRoot)
	if abs, err := filepath.Abs(projectRoot); err == nil {
		add(abs)
		if realPath, err := filepath.EvalSymlinks(abs); err == nil {
			add(realPath)
		}
	}
	return candidates
}

// InterfaceSliceToStrings converts an `[]interface{}` JSON value into a string
// slice.
func InterfaceSliceToStrings(v interface{}) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	raw, ok := v.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// ClassifyProxy detects whether a command/arg pair is a sir mcp-proxy wrapper.
func ClassifyProxy(command string, args []string) ProxySpec {
	if !isSirBinaryCommand(command) || len(args) == 0 || args[0] != "mcp-proxy" {
		return ProxySpec{}
	}
	allowedHosts, noSandbox, innerCommand, innerArgs, malformed := ParseProxyInvocation(args[1:])
	return ProxySpec{
		Wrapped:      true,
		SirCommand:   command,
		AllowedHosts: allowedHosts,
		NoSandbox:    noSandbox,
		InnerCommand: innerCommand,
		InnerArgs:    innerArgs,
		Malformed:    malformed,
	}
}

func isSirBinaryCommand(command string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(command)))
	base = strings.TrimSuffix(base, ".exe")
	return base == "sir"
}

// ParseProxyInvocation parses sir mcp-proxy flags and the wrapped command.
//
// Recognized leading flags (in any order, may repeat):
//
//	--allow-host HOST      — add HOST to the sandbox allowlist
//	--no-sandbox           — disable sandbox-exec / unshare for this invocation
//
// The leading-flags region ends at the first token that is not one of these
// flags; that token is the wrapped command and everything after it becomes
// its argv. Tokens after the command are NOT scanned — so `--no-sandbox`
// passed as a child-program argument is preserved for the child and does not
// affect sir's sandbox decision. This matches cmd/sir's stripLeadingNoSandboxFlag
// semantics so inventory/AssessProxyRuntime classify the same invocation the
// runtime would actually run.
func ParseProxyInvocation(args []string) (allowedHosts []string, noSandbox bool, command string, commandArgs []string, malformed bool) {
	for i := 0; i < len(args); {
		switch args[i] {
		case "--allow-host":
			if i+1 >= len(args) {
				return allowedHosts, noSandbox, "", nil, true
			}
			allowedHosts = append(allowedHosts, args[i+1])
			i += 2
		case "--no-sandbox":
			noSandbox = true
			i++
		default:
			return allowedHosts, noSandbox, args[i], args[i+1:], false
		}
	}
	return allowedHosts, noSandbox, "", nil, true
}
