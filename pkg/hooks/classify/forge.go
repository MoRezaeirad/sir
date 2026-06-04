package classify

import "strings"

// ClassifyForgePublish reports whether cmd writes to a code-hosting service via
// a forge CLI. It intentionally maps only publish/write subcommands; read-only
// inspection commands such as `gh pr view` and `glab mr list` stay benign.
func ClassifyForgePublish(cmd string) (remoteName string, ok bool) {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) == 0 {
		return "", false
	}

	switch parts[0] {
	case "gh":
		return "github-cli", isGitHubPublish(parts[1:])
	case "glab":
		return "gitlab-cli", isGitLabPublish(parts[1:])
	case "hub":
		return "github-hub", isHubPublish(parts[1:])
	case "tea":
		return "gitea-cli", isTeaPublish(parts[1:])
	default:
		return "", false
	}
}

func isGitHubPublish(args []string) bool {
	args = stripLeadingFlags(args, forgeGlobalValuedFlags())
	if len(args) == 0 {
		return false
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "pr":
		return actionIn(rest, "create", "edit", "comment", "review", "merge", "close", "reopen", "ready", "lock", "unlock")
	case "issue":
		return actionIn(rest, "create", "edit", "comment", "close", "reopen", "pin", "unpin", "lock", "unlock", "transfer")
	case "gist":
		return actionIn(rest, "create", "edit", "delete")
	case "release":
		return actionIn(rest, "create", "upload", "edit", "delete", "undelete")
	case "repo":
		return actionIn(rest, "create", "edit", "delete", "fork", "rename", "archive", "unarchive", "transfer")
	case "api":
		return apiWriteFlags(rest)
	default:
		return false
	}
}

func isGitLabPublish(args []string) bool {
	args = stripLeadingFlags(args, forgeGlobalValuedFlags())
	if len(args) == 0 {
		return false
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "mr", "merge-request", "merge_request":
		return actionIn(rest, "create", "update", "edit", "note", "comment", "merge", "approve", "revoke", "close", "reopen", "delete")
	case "issue":
		return actionIn(rest, "create", "update", "edit", "note", "comment", "close", "reopen", "delete")
	case "snippet":
		return actionIn(rest, "create", "update", "edit", "delete")
	case "release":
		return actionIn(rest, "create", "upload", "update", "edit", "delete")
	case "repo", "project":
		return actionIn(rest, "create", "fork", "update", "edit", "delete", "archive", "unarchive", "transfer")
	case "api":
		return apiWriteFlags(rest)
	default:
		return false
	}
}

func isHubPublish(args []string) bool {
	args = stripLeadingFlags(args, forgeGlobalValuedFlags())
	if len(args) == 0 {
		return false
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "pull-request":
		return true
	case "issue":
		return actionIn(rest, "create", "edit", "comment", "close", "reopen")
	case "release":
		return actionIn(rest, "create", "edit", "delete")
	case "fork", "push":
		return true
	default:
		return false
	}
}

func isTeaPublish(args []string) bool {
	args = stripLeadingFlags(args, forgeGlobalValuedFlags())
	if len(args) == 0 {
		return false
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "pulls", "pull", "prs", "pr":
		return actionIn(rest, "create", "edit", "comment", "close", "reopen", "merge")
	case "issues", "issue":
		return actionIn(rest, "create", "edit", "comment", "close", "reopen")
	case "releases", "release":
		return actionIn(rest, "create", "edit", "delete")
	case "repos", "repo":
		return actionIn(rest, "create", "fork", "edit", "delete")
	case "api":
		return apiWriteFlags(rest)
	default:
		return false
	}
}

func actionIn(args []string, allowed ...string) bool {
	action, ok := firstNonFlag(args, forgeGlobalValuedFlags())
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if action == candidate {
			return true
		}
	}
	return false
}

func apiWriteFlags(args []string) bool {
	for i := 0; i < len(args); i++ {
		token := args[i]
		switch {
		case token == "-X" || token == "--method":
			if i+1 < len(args) && isWriteHTTPMethod(args[i+1]) {
				return true
			}
			i++
		case strings.HasPrefix(token, "-X") && len(token) > 2:
			if isWriteHTTPMethod(token[2:]) {
				return true
			}
		case strings.HasPrefix(token, "--method="):
			if isWriteHTTPMethod(strings.TrimPrefix(token, "--method=")) {
				return true
			}
		case token == "--input" || token == "--field" || token == "--raw-field" || token == "-f" || token == "-F":
			return true
		case strings.HasPrefix(token, "--input=") || strings.HasPrefix(token, "--field=") || strings.HasPrefix(token, "--raw-field="):
			return true
		case strings.HasPrefix(token, "-f") && len(token) > 2:
			return true
		case strings.HasPrefix(token, "-F") && len(token) > 2:
			return true
		}
	}
	return false
}

func isWriteHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.Trim(method, "\"'")) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func firstNonFlag(args []string, valuedFlags map[string]bool) (string, bool) {
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if strings.HasPrefix(token, "-") {
			if flagTakesValue(token, valuedFlags) && !strings.Contains(token, "=") && i+1 < len(args) {
				i++
			}
			continue
		}
		return token, true
	}
	return "", false
}

func stripLeadingFlags(args []string, valuedFlags map[string]bool) []string {
	for len(args) > 0 {
		token := args[0]
		if token == "--" {
			return args[1:]
		}
		if !strings.HasPrefix(token, "-") {
			return args
		}
		args = args[1:]
		if flagTakesValue(token, valuedFlags) && !strings.Contains(token, "=") && len(args) > 0 {
			args = args[1:]
		}
	}
	return args
}

func flagTakesValue(token string, valuedFlags map[string]bool) bool {
	if eq := strings.IndexByte(token, '='); eq >= 0 {
		token = token[:eq]
	}
	return valuedFlags[token]
}

func forgeGlobalValuedFlags() map[string]bool {
	return map[string]bool{
		"-R":         true,
		"--repo":     true,
		"-H":         true,
		"--hostname": true,
		"-c":         true,
		"--config":   true,
		"-C":         true,
		"--cwd":      true,
		"-g":         true,
		"--group":    true,
		"-p":         true,
		"--project":  true,
	}
}
