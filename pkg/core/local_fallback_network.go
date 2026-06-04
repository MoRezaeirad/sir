package core

import (
	"encoding/json"
	"fmt"

	"github.com/somoore/sir/pkg/policy"
)

// forbiddenVerbs returns the lease's forbidden_verbs, parsed STRUCTURALLY (so
// the key is matched as a real object key, never a substring of some value) and
// cached on the request so repeated verb checks and repeated evaluations of the
// same request never re-parse. ok is false when the lease cannot be parsed —
// the caller must then fail closed (treat the verb as forbidden). Parsing only
// the forbidden_verbs field keeps the cold parse cheap; the cache keeps the hot
// path a slice scan with no parsing at all.
func (r *Request) forbiddenVerbs() (verbs []policy.Verb, ok bool) {
	if !r.forbiddenParsed {
		r.forbiddenParsed = true
		if len(r.LeaseJSON) > 0 {
			var ld struct {
				Forbidden []policy.Verb `json:"forbidden_verbs"`
			}
			if err := json.Unmarshal(r.LeaseJSON, &ld); err != nil {
				r.forbiddenParseErr = true
			} else {
				r.forbiddenVerbCache = ld.Forbidden
			}
		}
	}
	return r.forbiddenVerbCache, !r.forbiddenParseErr
}

// leaseForbidsVerb reports whether the request's lease lists verb in
// forbidden_verbs (the Go-fallback mirror of the Rust lease.is_verb_forbidden).
// Fail closed: a lease that cannot be parsed is treated as forbidding the verb,
// so a corrupted/tampered lease can never silently downgrade a hard deny to an
// ask on the degraded fallback path.
func leaseForbidsVerb(req *Request, verb policy.Verb) bool {
	verbs, ok := req.forbiddenVerbs()
	if !ok {
		return true // unparseable lease — fail closed (forbidden)
	}
	for _, v := range verbs {
		if v == verb {
			return true
		}
	}
	return false
}

func localEvaluateNetwork(req *Request, effectiveLabels []Label) *Response {
	switch req.Intent.Verb {
	case policy.VerbNetExternal:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		if req.Session.SecretSession {
			return &Response{Decision: policy.VerdictDeny, Reason: "This session may contain credentials. Network requests to external hosts are blocked."}
		}
		if leaseForbidsVerb(req, policy.VerbNetExternal) {
			return &Response{Decision: policy.VerdictDeny, Reason: "Network requests to external hosts are blocked by your security policy."}
		}
		if req.Session.RecentlyReadUntrusted || req.Session.UntrustedContentThisTurn {
			return untrustedEgressDeny("External network request")
		}
		// NET-1: clean session, not forbidden (personal/team) -> approval prompt.
		return &Response{Decision: policy.VerdictAsk, Reason: "External network request requires approval."}
	case policy.VerbPushRemote:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		if req.Session.SecretSession {
			return &Response{Decision: policy.VerdictDeny, Reason: "This session may contain credentials. Push to unapproved remotes is blocked."}
		}
		if req.Session.RecentlyReadUntrusted || req.Session.UntrustedContentThisTurn {
			return untrustedPublishResponse(policy.VerbPushRemote)
		}
		return &Response{Decision: policy.VerdictAsk, Reason: "Git push to unapproved remote requires approval."}
	case policy.VerbPushOrigin:
		if req.Session.SecretSession {
			return &Response{Decision: policy.VerdictAsk, Reason: "This session may contain credentials. Push to approved remote requires approval."}
		}
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		// High-water mark: the turn-scoped secret flag has cleared but the
		// session held a secret earlier. Mirror the oracle — re-prompt instead
		// of silently allowing (taint is monotonic across turns).
		if req.Session.WasSecret {
			return &Response{Decision: policy.VerdictAsk, Reason: "This session previously contained credentials. Push to approved remote requires approval."}
		}
		if req.Session.RecentlyReadUntrusted || req.Session.UntrustedContentThisTurn {
			return untrustedPublishResponse(policy.VerbPushOrigin)
		}
	case policy.VerbNetAllowlisted:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		return &Response{
			Decision: policy.VerdictAsk,
			Reason:   fmt.Sprintf("Network request to %s. This host is in your security policy but still requires approval.", req.Intent.Target),
		}
	case policy.VerbDnsLookup:
		if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
			return denyFlowResponse()
		}
		if req.Session.SecretSession {
			return &Response{Decision: policy.VerdictDeny, Reason: "DNS lookup blocked — your session contains credentials."}
		}
		if leaseForbidsVerb(req, policy.VerbDnsLookup) {
			return &Response{Decision: policy.VerdictDeny, Reason: "DNS lookup (outbound request) not allowed by your security policy."}
		}
		if req.Session.RecentlyReadUntrusted || req.Session.UntrustedContentThisTurn {
			return untrustedEgressDeny("DNS lookup")
		}
		// NET-2: clean session, not forbidden (personal/team) -> approval prompt.
		return &Response{Decision: policy.VerdictAsk, Reason: "DNS lookup (outbound request) requires approval."}
	}
	return nil
}

func denyFlowResponse() *Response {
	return &Response{
		Decision: policy.VerdictDeny,
		Reason:   "Data labels on this action exceed the trust level of the destination.",
	}
}

// untrustedEgressDeny mirrors mister-core's integrity-flow egress wall (P0.3):
// untrusted content ingested this session (detected MCP injection, or
// external-package-provenance read) must not silently drive outbound egress —
// the exfiltration leg of the lethal trifecta. Reached only after the
// secret-session and forbidden-lease deny branches, so it strictly tightens the
// clean-session Ask into a Deny and never widens a deny. Kept byte-for-byte in
// step with policy_guards.rs::untrusted_egress_deny for Go<->Rust parity.
func untrustedEgressDeny(action string) *Response {
	reason := "External network egress blocked — untrusted content was ingested this session (possible prompt injection); outbound requests are held. Verify intent, then `sir unlock`."
	if action == "DNS lookup" {
		reason = "DNS lookup blocked — untrusted content was ingested this session (possible prompt injection); outbound requests are held. Verify intent, then `sir unlock`."
	}
	return &Response{Decision: policy.VerdictDeny, Reason: reason}
}

func untrustedPublishResponse(verb policy.Verb) *Response {
	reason := "Code-host publish blocked — untrusted content was ingested this session (possible prompt injection); outbound publish is held. Verify intent, then `sir unlock`."
	decision := policy.VerdictDeny
	if verb == policy.VerbPushOrigin {
		decision = policy.VerdictAsk
		reason = "Code-host publish after untrusted content requires approval. Verify intent, then `sir unlock`."
	}
	return &Response{Decision: decision, Reason: reason}
}
