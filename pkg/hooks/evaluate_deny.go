package hooks

import (
	"fmt"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// formatDenyReason produces human-readable block messages with causal chain.
func formatDenyReason(originalReason string, intent Intent, state *session.State, ag agent.Agent) string {
	secretSince := state.SecretSessionSince
	if !state.SecretSession {
		secretSince = time.Time{}
	}
	agentName := "Claude"
	if ag != nil {
		agentName = AgentDisplayName(string(ag.ID()))
	}
	switch intent.Verb {
	case policy.VerbNetExternal:
		return FormatBlockNetExternal(agentName, intent.Target, secretSince)
	case policy.VerbPushRemote:
		// FormatBlockPush suggests `sir allow-remote <remote>`, which only makes
		// sense for a real git remote. Forge-publish CLIs (gh/glab/hub/tea) carry
		// a synthetic RemoteName like "github-cli" that is never a git remote and
		// is excluded from remote auto-approval, so that hint is a dead end for
		// them in any session. Route forge publishes — and all non-secret push
		// denials — to the generic block, which surfaces the real reason plus
		// `sir doctor`/`sir why`. Only a secret-session deny on a genuine git
		// remote reaches FormatBlockPush.
		if !state.SecretSession || intent.IsForgePublish {
			return FormatBlock(
				fmt.Sprintf("%s: %s", intent.Verb, intent.Target),
				originalReason,
				"sir doctor                       (diagnose the block)\n       sir why                          (explain the most recent decision)",
			)
		}
		remote := intent.RemoteName
		if remote == "" {
			remote = "origin"
		}
		return FormatBlockPush(agentName, remote, secretSince)
	case policy.VerbDnsLookup:
		return FormatBlockDNS(agentName, intent.Target, secretSince)
	}
	return FormatBlock(
		fmt.Sprintf("%s: %s", intent.Verb, intent.Target),
		originalReason,
		"sir doctor                       (diagnose the block)\n       sir why                          (explain the most recent decision)",
	)
}
