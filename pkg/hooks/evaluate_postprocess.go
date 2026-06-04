package hooks

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func applyCoreEvaluationResult(coreResp *core.Response, intent Intent, labels core.Label, state *session.State, ag agent.Agent) *HookResponse {
	hookResp := &HookResponse{
		Decision: coreResp.Decision,
		Reason:   coreResp.Reason,
	}

	if coreResp.Decision == policy.VerdictAllow || coreResp.Decision == policy.VerdictAsk {
		if intent.IsSensitive && intent.Verb == policy.VerbReadRef {
			if coreResp.Decision == policy.VerdictAllow {
				state.MarkSecretSession()
			}
			if coreResp.Decision == policy.VerdictAsk {
				hookResp.Reason = FormatAskSensitive(intent.Target, string(state.ApprovalScope))
				fmt.Fprintf(os.Stderr, "\n  Note: approving this will block external network requests\n")
				fmt.Fprintf(os.Stderr, "  until the agent finishes responding (turn-scoped by default).\n")
				fmt.Fprintf(os.Stderr, "  To clear now: sir unlock\n\n")
			}
		}
		if labels.Trust == "verified_origin" || labels.Provenance == "external_package" {
			state.MarkUntrustedRead()
		}
	}

	if coreResp.Decision == policy.VerdictDeny {
		hookResp.Reason = formatDenyReason(coreResp.Reason, intent, state, ag)
		// Secret-context egress denied by the oracle is the canonical exfil
		// shape; mark it Floor so observe mode never downgrades it to allow
		// (OBSERVE-1). Clean-session egress denies are NOT floor — they carry no
		// secret and remain observe-downgradable.
		if isSecretExfilFloor(intent, state, labels) {
			hookResp.Floor = true
		}
	}

	// An authoritative PDP verdict is FINAL on the wire — observe mode must not
	// downgrade an authoritative deny/ask to allow. Observe mode exists for the
	// NATIVE policy rollout; an operator who explicitly configured an
	// authoritative provider opted that provider in as the decision, so its
	// deny/ask is a real enforced decision, not a "would-block" to observe past.
	// (applyThinkingGuard only tightens ask→deny, fail-safe, so needs no guard.)
	if coreResp.AuthoritativeActive {
		hookResp.Floor = true
	}
	return hookResp
}

// isSecretExfilFloor reports whether a denied verb is a secret-bearing egress —
// the transition that observe mode must keep enforced. It is true only for the
// hard exfil sinks (external egress, DNS, push to an unapproved remote) while
// the session carries secret context or the target is secret-derived.
func isSecretExfilFloor(intent Intent, state *session.State, labels core.Label) bool {
	switch intent.Verb {
	case policy.VerbNetExternal, policy.VerbDnsLookup, policy.VerbPushRemote:
	default:
		return false
	}
	return state.SecretSession || labels.Sensitivity == "secret"
}

func overlayPendingInjectionWarning(hookResp *HookResponse, pendingInjectionDetail string) {
	if pendingInjectionDetail == "" {
		return
	}
	injectionWarning := fmt.Sprintf("sir WARNING: A previous tool response contained suspicious patterns. %s", pendingInjectionDetail)
	switch hookResp.Decision {
	case policy.VerdictDeny:
		hookResp.Reason += "\n\n  Additionally: " + injectionWarning
	case policy.VerdictAllow:
		hookResp.Decision = policy.VerdictAsk
		hookResp.Reason = injectionWarning + "\n\n  This action would normally be allowed, but requires approval due to the suspicious activity."
	case policy.VerdictAsk:
		hookResp.Reason = injectionWarning + "\n\n  " + hookResp.Reason
	}
}
