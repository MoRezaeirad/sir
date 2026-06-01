package hooks

import (
	"os"
	"path/filepath"
	"strings"

	hookclassify "github.com/somoore/sir/pkg/hooks/classify"
	"github.com/somoore/sir/pkg/policy"
)

// sirStateTamper denies an agent write whose resolved target lands inside sir's
// own state or config — `~/.sir/` (the ledger, session state, posture), or the
// `sir.yaml` / `sir-posture` config patterns. The v2 kernel's
// `deny-sir-config-tamper` already denies this; this closes the production
// (mister-core path) parity gap, where `.sir/` was NOT gated.
//
// DENY, not ask: an agent has no legitimate reason to write sir's own
// control-plane state, and silently allowing it lets a prompt-injected agent
// disable the guard before acting. (Contrast `.claude/settings.json`, which is
// agent config and stays a posture ask — the asymmetry is principled.)
//
// Safety: sir's OWN writes (`ledger.Append`, `session.State.Save`) are internal
// Go calls that never pass through agent intent classification, so this can
// never block sir itself. Symlinks are resolved before matching (non-negotiable
// #6) so a `ln -s ~/.sir x` indirection cannot bypass it. Covers Write / Edit /
// apply_patch (mapWrite extracts apply_patch targets, so this catches the
// PreToolUse-bypass vector the file-hash path cannot). Accepted residuals: the
// Bash vector (`echo > ~/.sir/x`, `rm -rf ~/.sir`) and heavy shell obfuscation
// — documented, not silently dropped.
func sirStateTamper(intent Intent, projectRoot string) (string, bool) {
	if intent.Verb != policy.VerbStageWrite && intent.Verb != policy.VerbDeletePosture {
		return "", false
	}
	sirDir := ""
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		// Resolve sir's state dir through the SAME normalization the target uses
		// (clean + EvalSymlinks + case-fold on darwin/windows) so the prefix
		// comparison is apples-to-apples.
		sirDir = hookclassify.ResolveTarget(projectRoot, filepath.Join(home, ".sir"))
	}
	// intent.Target may be a comma-joined list (apply_patch multi-file). Any one
	// landing in sir's state is enough to deny the whole write.
	for _, raw := range strings.Split(intent.Target, ",") {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if sirDir != "" {
			resolved := hookclassify.ResolveTarget(projectRoot, t)
			if resolved == sirDir || strings.HasPrefix(resolved, sirDir+string(filepath.Separator)) {
				return "a write to sir's own state directory (~/.sir)", true
			}
		}
		base := filepath.Base(t)
		if base == "sir.yaml" || strings.Contains(t, "sir-posture") {
			return "a write to a sir configuration file", true
		}
	}
	return "", false
}

// gitSensitiveConfigKeys are git config keys whose rewrite is a dangerous
// transition. Lowercased to match the case-folded normalized command (git config
// section/name are case-insensitive).
var gitSensitiveConfigKeys = map[string]string{ // #nosec G101 -- git config key names, not credentials.
	"credential.helper": "git credential helper",
	"core.hookspath":    "git hooks path (core.hooksPath)",
}

// gitConfigSensitiveAsk asks before an agent rewrites git's credential helper or
// hooks path — the config-form of credential theft (a malicious helper leaks
// credentials on every git operation) and of hook redirection (pointing
// core.hooksPath at attacker-controlled scripts).
//
// ASK, not deny: husky v5+ and lefthook legitimately run
// `git config core.hooksPath …` on install, so a deny would break the most
// common git-hook frameworks — exactly the workflow-breakage sir exists to
// avoid, and consistent with the `.git/hooks/*` file floor (also ask).
// credential.helper is higher-severity, so the reason is loud, but it is a
// dangerous transition, not a non-bypassable floor.
//
// Detects the common shapes: `git config [--global|--local|--add|--replace-all]
// credential.helper|core.hooksPath <value>` (a SET) and inline
// `git -c credential.helper=…|core.hooksPath=… <cmd>`. Read forms (--get/--list)
// are excluded. It self-guards on verb risk so it never preempts a stricter gate
// (e.g. `git -c credential.helper=… push` is handled by the push gate). Accepted
// residuals: heavy obfuscation, env-var indirection, and a direct write to
// `.git/config` (which stays non-posture so routine git is quiet) — documented.
func gitConfigSensitiveAsk(payload *HookPayload, intent Intent) (string, bool) {
	if payload == nil || payload.ToolName != "Bash" {
		return "", false
	}
	// Never preempt a higher-risk verb that already gates this command.
	if hookclassify.VerbRisk(intent.Verb) > hookclassify.VerbRisk(policy.VerbExecuteDryRun) {
		return "", false
	}
	cmd, _ := payload.ToolInput["command"].(string)
	if strings.TrimSpace(cmd) == "" {
		return "", false
	}
	norm := strings.ToLower(hookclassify.NormalizeCommand(cmd))
	if !strings.Contains(norm, "git") {
		return "", false
	}
	tokens := strings.Fields(norm)

	// Inline config: `git -c key=value <cmd>`.
	for i, tok := range tokens {
		if tok != "-c" || i+1 >= len(tokens) {
			continue
		}
		kv := tokens[i+1]
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			if pretty, ok := gitSensitiveConfigKeys[kv[:eq]]; ok {
				return pretty + " (inline -c)", true
			}
		}
	}

	// `git config` SET form.
	if !containsTokenCV(tokens, "config") {
		return "", false
	}
	if containsAnyCV(tokens, "--get", "--get-all", "--get-regexp", "--list", "-l") {
		return "", false // read, not a write
	}
	writeFlag := containsAnyCV(tokens, "--add", "--replace-all", "--global", "--local", "--system", "--file")
	for i, tok := range tokens {
		pretty, ok := gitSensitiveConfigKeys[tok]
		if !ok {
			continue
		}
		// A non-flag value token after the key, or an explicit write flag, = SET.
		if (i+1 < len(tokens) && !strings.HasPrefix(tokens[i+1], "-")) || writeFlag {
			return pretty, true
		}
	}
	return "", false
}

func containsTokenCV(tokens []string, want string) bool {
	for _, t := range tokens {
		if t == want {
			return true
		}
	}
	return false
}

func containsAnyCV(tokens []string, wants ...string) bool {
	for _, w := range wants {
		if containsTokenCV(tokens, w) {
			return true
		}
	}
	return false
}
