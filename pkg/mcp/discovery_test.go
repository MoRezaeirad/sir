package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverInventoryForScopes_ReadsCursorMCPFromTempHome(t *testing.T) {
	home := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cursorPath := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursorPath), 0o755); err != nil {
		t.Fatalf("mkdir cursor config dir: %v", err)
	}
	if err := os.WriteFile(cursorPath, []byte(`{"mcpServers":{"cursor-temp":{"command":"node","args":["cursor-server.js"]}}}`), 0o644); err != nil {
		t.Fatalf("write cursor mcp config: %v", err)
	}

	// These files would be visible to broad discovery but must not be read for
	// a Cursor-only scope.
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"project":{"command":"node"}}}`), 0o644); err != nil {
		t.Fatalf("write project mcp config: %v", err)
	}
	claudePath := filepath.Join(home, ".claude", ".mcp.json")
	if err := os.MkdirAll(filepath.Dir(claudePath), 0o755); err != nil {
		t.Fatalf("mkdir claude config dir: %v", err)
	}
	if err := os.WriteFile(claudePath, []byte(`{"mcpServers":{"claude-global":{"command":"node"}}}`), 0o644); err != nil {
		t.Fatalf("write claude mcp config: %v", err)
	}

	report := DiscoverInventoryForScopes(projectRoot, map[ConfigScope]bool{ConfigCursorGlobal: true})
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected inventory errors: %#v", report.Errors)
	}
	if len(report.Servers) != 1 {
		t.Fatalf("expected exactly the temp HOME cursor server, got %#v", report.Servers)
	}
	server := report.Servers[0]
	if server.Name != "cursor-temp" {
		t.Fatalf("server name = %q, want cursor-temp", server.Name)
	}
	if server.SourcePath != cursorPath {
		t.Fatalf("source path = %q, want temp HOME cursor path %q", server.SourcePath, cursorPath)
	}
	if server.SourceLabel != "~/.cursor/mcp.json" {
		t.Fatalf("source label = %q, want ~/.cursor/mcp.json", server.SourceLabel)
	}
	if server.Scope != ConfigCursorGlobal {
		t.Fatalf("scope = %q, want %q", server.Scope, ConfigCursorGlobal)
	}
	if server.Command != "node" || len(server.Args) != 1 || server.Args[0] != "cursor-server.js" {
		t.Fatalf("unexpected command inventory: command=%q args=%v", server.Command, server.Args)
	}
}

func TestDiscoverInventoryForScopes_ReadsCursorProjectMCP(t *testing.T) {
	home := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cursorProjectPath := filepath.Join(projectRoot, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(cursorProjectPath), 0o755); err != nil {
		t.Fatalf("mkdir project cursor config dir: %v", err)
	}
	if err := os.WriteFile(cursorProjectPath, []byte(`{"mcpServers":{"cursor-project":{"command":"node","args":["project-server.js"]}}}`), 0o644); err != nil {
		t.Fatalf("write project cursor mcp config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"generic-project":{"command":"node"}}}`), 0o644); err != nil {
		t.Fatalf("write generic project mcp config: %v", err)
	}

	report := DiscoverInventoryForScopes(projectRoot, map[ConfigScope]bool{ConfigCursorProject: true})
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected inventory errors: %#v", report.Errors)
	}
	if len(report.Servers) != 1 {
		t.Fatalf("expected exactly the project cursor server, got %#v", report.Servers)
	}
	server := report.Servers[0]
	if server.Name != "cursor-project" {
		t.Fatalf("server name = %q, want cursor-project", server.Name)
	}
	if server.SourcePath != cursorProjectPath {
		t.Fatalf("source path = %q, want project cursor path %q", server.SourcePath, cursorProjectPath)
	}
	if server.SourceLabel != ".cursor/mcp.json" {
		t.Fatalf("source label = %q, want .cursor/mcp.json", server.SourceLabel)
	}
	if server.Scope != ConfigCursorProject {
		t.Fatalf("scope = %q, want %q", server.Scope, ConfigCursorProject)
	}
}

func TestDiscoverInventory_ReadsClaudeProjectLocalMCP(t *testing.T) {
	home := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	claudePath := filepath.Join(home, ".claude.json")
	realRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatalf("realpath project root: %v", err)
	}
	body := `{
  "mcpServers": {
    "global": {"command": "node", "args": ["global.js"]}
  },
  "projects": {
    "` + realRoot + `": {
      "mcpServers": {
        "local": {"command": "node", "args": ["local.js"]}
      }
    },
    "/other/project": {
      "mcpServers": {
        "other": {"command": "node", "args": ["other.js"]}
      }
    }
  }
}`
	if err := os.WriteFile(claudePath, []byte(body), 0o644); err != nil {
		t.Fatalf("write claude config: %v", err)
	}

	report := DiscoverInventoryForScopes(projectRoot, map[ConfigScope]bool{ConfigClaudeGlobal: true})
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected inventory errors: %#v", report.Errors)
	}
	if len(report.Servers) != 2 {
		t.Fatalf("expected top-level and matching project server, got %#v", report.Servers)
	}

	var local *ServerInventory
	for i := range report.Servers {
		if report.Servers[i].Name == "local" {
			local = &report.Servers[i]
			break
		}
	}
	if local == nil {
		t.Fatalf("project-local server missing from inventory: %#v", report.Servers)
	}
	if local.SourcePath != claudePath {
		t.Fatalf("source path = %q, want %q", local.SourcePath, claudePath)
	}
	if local.SourceLabel != "~/.claude.json (project)" {
		t.Fatalf("source label = %q, want project label", local.SourceLabel)
	}
	if local.ProjectKey != realRoot {
		t.Fatalf("project key = %q, want %q", local.ProjectKey, realRoot)
	}
	if !local.RequiresExplicitApproval {
		t.Fatal("project-local Claude MCP server should require explicit approval")
	}
}

func TestDiscoverServerNamesSkipsClaudeProjectLocalAutoApproval(t *testing.T) {
	home := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	realRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatalf("realpath project root: %v", err)
	}
	claudePath := filepath.Join(home, ".claude.json")
	body := `{"projects": {"` + realRoot + `": {"mcpServers": {"local": {"command": "node"}}}}}`
	if err := os.WriteFile(claudePath, []byte(body), 0o644); err != nil {
		t.Fatalf("write claude config: %v", err)
	}

	if names := DiscoverServerNames(projectRoot); len(names) != 0 {
		t.Fatalf("project-local Claude MCP server should not be auto-approved, got %v", names)
	}
}

func TestRewriteDiscoveredServers_RewritesClaudeProjectLocalMCP(t *testing.T) {
	home := t.TempDir()
	projectRoot := t.TempDir()
	realRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		t.Fatalf("realpath project root: %v", err)
	}
	claudePath := filepath.Join(home, ".claude.json")
	body := `{
  "projects": {
    "` + realRoot + `": {
      "mcpServers": {
        "local": {"command": "node", "args": ["local.js"]}
      }
    }
  }
}`
	if err := os.WriteFile(claudePath, []byte(body), 0o644); err != nil {
		t.Fatalf("write claude config: %v", err)
	}
	servers, err := ReadInventoryFile(InventoryFile{
		Path:        claudePath,
		Label:       "~/.claude.json",
		Scope:       ConfigClaudeGlobal,
		ProjectRoot: projectRoot,
	})
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected one project-local server, got %#v", servers)
	}

	results, err := RewriteDiscoveredServers(servers, "/tmp/sir")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(results) != 1 || len(results[0].Servers) != 1 || results[0].Servers[0] != "local" {
		t.Fatalf("unexpected rewrite result: %#v", results)
	}

	data, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatalf("read rewritten config: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse rewritten config: %v", err)
	}
	projects := doc["projects"].(map[string]interface{})
	project := projects[realRoot].(map[string]interface{})
	mcpServers := project["mcpServers"].(map[string]interface{})
	local := mcpServers["local"].(map[string]interface{})
	if local["command"] != "/tmp/sir" {
		t.Fatalf("command = %#v, want /tmp/sir", local["command"])
	}
	args := local["args"].([]interface{})
	if len(args) != 3 || args[0] != "mcp-proxy" || args[1] != "node" || args[2] != "local.js" {
		t.Fatalf("args = %#v, want mcp-proxy node local.js", args)
	}
}
