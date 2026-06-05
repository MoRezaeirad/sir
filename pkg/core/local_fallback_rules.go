package core

import (
	"encoding/json"
	"fmt"

	"github.com/somoore/sir/pkg/policy"
)

func localEvaluatePreflight(req *Request) *Response {
	if req.Session.DenyAll {
		return &Response{
			Decision: policy.VerdictDeny,
			Reason:   "session in deny-all mode - security configuration was modified unexpectedly",
		}
	}
	if hasDerivedSecret(req.Intent.DerivedLabels) {
		switch req.Intent.Verb {
		case policy.VerbStageWrite, policy.VerbCommit, policy.VerbPushOrigin, policy.VerbNetAllowlisted:
			return &Response{Decision: policy.VerdictAsk, Reason: "This action touches a file derived from sensitive data and requires approval."}
		case policy.VerbPushRemote, policy.VerbNetExternal, policy.VerbDnsLookup:
			return &Response{Decision: policy.VerdictDeny, Reason: "This action would send a file derived from sensitive data to an untrusted sink."}
		}
	}
	if req.Intent.IsPosture && isWriteVerb(req.Intent.Verb) {
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("This file controls security settings. Approve to let the agent edit it. (%s)", req.Intent.Target)}
	}
	if req.Intent.IsSensitive && req.Intent.Verb == policy.VerbReadRef {
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("This file may contain credentials. Approve to let the agent read it. (%s)", req.Intent.Target)}
	}
	return nil
}

func localEvaluateDelegation(req *Request) *Response {
	if req.Intent.Verb != policy.VerbDelegate {
		return nil
	}
	if req.Session.SecretSession {
		return &Response{Decision: policy.VerdictDeny, Reason: "Delegation blocked — your session contains credentials."}
	}
	if req.Session.RecentlyReadUntrusted {
		return &Response{Decision: policy.VerdictAsk, Reason: "Untrusted content was read recently. Delegation requires approval."}
	}
	if len(req.LeaseJSON) > 0 {
		var leaseData struct {
			AllowDelegation bool `json:"allow_delegation"`
		}
		if err := json.Unmarshal(req.LeaseJSON, &leaseData); err != nil {
			return &Response{Decision: policy.VerdictDeny, Reason: "Delegation denied — lease could not be parsed. Run `sir doctor` to investigate."}
		}
		if !leaseData.AllowDelegation {
			return &Response{Decision: policy.VerdictDeny, Reason: "Delegation is not allowed by your security policy."}
		}
	}
	return &Response{Decision: policy.VerdictAllow, Reason: "Delegation allowed by your security policy."}
}

func localEvaluateCommandRisk(req *Request) *Response {
	switch req.Intent.Verb {
	case policy.VerbRunEphemeral:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("npx downloads and runs remote code. Approve to proceed. (%s)", req.Intent.Target)}
	case policy.VerbDangerousShell:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("This shell command can destructively modify files, disks, permissions, or repository state. Approve to proceed. (%s)", req.Intent.Target)}
	case policy.VerbMcpUnapproved:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("This tool comes from a server sir hasn't seen before (%s). Approve this call once, or add the server to your MCP config and re-run `sir install` to refresh approved MCP servers.", req.Intent.Target)}
	case policy.VerbMcpNetworkUnapproved:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("An MCP tool was called with a URL whose host is not in your approved_hosts list (%s). Approve this call, or run `sir allow-host <host>` to approve the destination. Note: this only sees URLs passed as tool arguments — a malicious MCP can still reach the network on its own.", req.Intent.Target)}
	case policy.VerbMcpOnboarding:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("MCP server %q is within its onboarding window. Approving surfaces early activity; once the session call threshold or wall-clock window is crossed, this gate stops firing. Friction, not a security block.", req.Intent.Target)}
	case policy.VerbMcpBinaryDrift:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("MCP command binary for %q changed since you approved it. Approve once to continue, or run `sir mcp revoke` and re-approve after confirming the new binary is intended.", req.Intent.Target)}
	case policy.VerbEnvRead:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("Environment variables may contain credentials. Approve to proceed. (%s)", req.Intent.Target)}
	case policy.VerbPersistence:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("This can create scheduled tasks that outlive your session. (%s)", req.Intent.Target)}
	case policy.VerbSudo:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("This runs with sudo. Approve to proceed. (%s)", req.Intent.Target)}
	case policy.VerbSirSelf:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("This command modifies sir itself. Only you should do this. (%s)", req.Intent.Target)}
	case policy.VerbDeletePosture:
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("Delete/link targeting a security settings file requires approval. (%s)", req.Intent.Target)}
	case policy.VerbMcpCredentialLeak:
		return &Response{Decision: policy.VerdictDeny, Reason: fmt.Sprintf("Credential pattern detected in MCP tool arguments. Blocked. (%s)", req.Intent.Target)}
	case policy.VerbCredentialDetected, policy.VerbElicitationHarvest, policy.VerbMcpInjectionDetected:
		// Detection/alert verbs that the fallback previously had no case for —
		// they fell through to the permissive default (allow), while Rust
		// (default_unknown_verb_result) returns at least ask. This gates them so
		// the fallback is never more permissive than the oracle.
		//
		// The Rust oracle returns ASK for these verbs even with a labeled flow
		// (the safe-direction differential test confirms the fallback is never
		// looser). This branch is INTENTIONALLY STRICTER than the oracle: it
		// returns DENY when a label carries secret/restricted sensitivity or
		// untrusted trust, and ASK otherwise — never allow. Stricter-than-oracle
		// is permitted on the degraded fallback path (deny ≤ ask); the invariant
		// is only that Go must not be looser than Rust.
		if detectionVerbDenies(req.Intent.Labels, req.Intent.DerivedLabels) {
			return &Response{Decision: policy.VerdictDeny, Reason: fmt.Sprintf("Detection signal carries sensitive or untrusted data; flow blocked. (%s)", req.Intent.Target)}
		}
		return &Response{Decision: policy.VerdictAsk, Reason: fmt.Sprintf("A security detection signal was raised and needs your review. (%s)", req.Intent.Target)}
	}
	return nil
}

// detectionVerbDenies reports whether the combined labels would fail the IFC flow
// check that Rust applies to the detection/alert verbs (credential_detected,
// elicitation_harvest, mcp_injection_detected). Any secret/restricted sensitivity
// or untrusted trust makes Rust deny; otherwise it asks.
func detectionVerbDenies(labels, derived []Label) bool {
	for _, label := range labels {
		if labelIsSensitiveOrUntrusted(label) {
			return true
		}
	}
	for _, label := range derived {
		if labelIsSensitiveOrUntrusted(label) {
			return true
		}
	}
	return false
}

func labelIsSensitiveOrUntrusted(label Label) bool {
	return label.Sensitivity == "secret" || label.Sensitivity == "restricted" || label.Trust == "untrusted"
}
