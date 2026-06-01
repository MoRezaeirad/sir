package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/sdk"
)

// Evaluate is the pure decision function. It takes explicit, complete input
// and returns deterministic output. No clocks, no global state, no IO.
//
// This is the function ported to Rust sir-core. Both implementations must
// agree on the six parity fields: verdict, decision_class, enforceability,
// attribution, policy_rules, effects.
//
// What is NOT here: decision_id, timestamp (Go stamps those), friction
// (stateful, orchestrator-managed), ledger writes (Go's job).
func Evaluate(in EvaluationInput) EvaluationOutput {
	normalized := NormalizeSignals(in.Signals)

	enforceability := AnalyzeEnforceability(EnforceabilityInput{
		Mode:                 in.Mode,
		Signals:              normalized,
		EvasionFlags:         in.Evasion,
		ProviderCapabilities: in.ProviderCapabilities,
		ProviderEnforcement:  in.ProviderEnforcement,
		EnforcedActions:      in.ProviderEnforcedActions,
	})
	attribution := AttributionConfidence(normalized)
	actionType := PrimaryActionType(normalized)
	sensitivity := PrimarySensitivity(normalized)
	labels := Labelize(actionType, sensitivity, normalized)
	// Apply resolved actor kind from orchestrator. When the orchestrator has
	// fused a shell signal with agent-session evidence and resolved the actor
	// to ai_coding_agent, policy rules that key on ai_agent_actor can fire.
	// This keeps Evaluate() pure: resolution happens above, threaded via input.
	if in.ResolvedActorKind == "ai_coding_agent" {
		labels = appendUnique(labels, "ai_agent_actor")
	}
	labels = ApplyDangerousShellLabel(labels, normalized)
	labels = ApplyCICDLabel(labels, normalized)
	labels = ApplyGitHookTamperLabel(labels, normalized)
	labels = ApplySIRTamperLabel(labels, normalized)

	action := AttributedAction{
		ActionID:       actionID(in.CaseID),
		Mode:           in.Mode,
		Signals:        normalized,
		Enforceability: enforceability,
		Attribution:    attribution,
		ActionType:     actionType,
		Sensitivity:    sensitivity,
		Labels:         labels,
		EvasionFlags:   in.Evasion,
	}

	// priorTaint carries cross-action taint from previous evaluations.
	policy := EvaluatePolicy(action, in.PriorTaint)

	verdict := policy.Verdict
	effects := policy.Effects
	rules := policy.Rules

	// Low-confidence escalation (CORRELATION spec).
	prevVerdict := verdict
	verdict, rules = applyLowConfidenceEscalation(verdict, rules, attribution, sensitivity)

	// Advisory policy-verdict composition. Runs AFTER all native floors and
	// low-confidence escalation, mirroring mister-core's compose_policy_verdicts.
	// Advisory verdicts can only escalate allow->ask; they never widen a deny and
	// cannot bypass the developer-workflow floor. With no verdicts this is a no-op,
	// reproducing the pre-provider baseline exactly (parity-critical).
	var providerRules []string
	verdict, providerRules = composePolicyVerdicts(in.PolicyVerdicts, verdict, in.PriorTaint, actionType)
	rules = append(rules, providerRules...)

	// When any escalation promoted allow -> ask, add a prompt effect so the
	// developer is notified. Without this the ask verdict has no prompt (silent UX).
	if prevVerdict == VerdictAllow && verdict == VerdictAsk {
		effects = append([]PlannedEffect{{Type: "prompt", Required: false, FailClosed: false}}, effects...)
	}

	// Compute new taint produced by this action.
	newTaint := computeNewTaint(action)

	return EvaluationOutput{
		Verdict:        verdict,
		DecisionClass:  resolveDecisionClass(verdict, enforceability.Class),
		Enforceability: enforceability.Class,
		Attribution:    attribution,
		SpoofingRisk:   ComputeSpoofingRisk(in.Evasion, normalized),
		PolicyRules:    rules,
		Effects:        effects,
		ActionType:     actionType,
		Sensitivity:    sensitivity,
		NewTaint:       newTaint,
		ProviderRules:  providerRules,
	}
}

// cleanDeveloperWorkflowActions is the set of action types protected by the
// developer-workflow floor: on a clean session (no credential taint), an
// advisory provider cannot escalate these. Mirrors mister-core's
// is_clean_developer_workflow verb set, expressed in v2 action-type vocabulary.
// Push is deliberately NOT included — it remains escalatable (matches v1, where
// push_origin is not floored).
var cleanDeveloperWorkflowActions = map[string]bool{
	"file_read":   true,
	"file_write":  true,
	"file_list":   true,
	"run_tests":   true,
	"search_code": true,
	"vcs_status":  true,
	"vcs_diff":    true,
	"vcs_commit":  true,
}

// isCleanDeveloperWorkflow reports whether this action is a clean-session
// developer workflow that advisory providers must not escalate. The floor lifts
// the moment the session carries credential taint.
func isCleanDeveloperWorkflow(priorTaint []string, actionType string) bool {
	if hasLabel(priorTaint, "credential_access") {
		return false
	}
	return cleanDeveloperWorkflowActions[actionType]
}

// composePolicyVerdicts folds advisory policy-provider verdicts into the base
// verdict. Returns the (possibly escalated) verdict and the provider rule IDs
// that contributed. Pure and deterministic — Go and Rust implement this
// identically so the harness parity check exercises the production decision path.
//
// Rules:
//  1. Developer-workflow floor: a clean-session allow on a protected action type
//     is returned unchanged — no advisory verdict can escalate it.
//  2. Otherwise an advisory ask/deny verdict escalates allow->ask.
//  3. A deny is never widened; an advisory verdict cannot lower a native deny.
func composePolicyVerdicts(verdicts []PolicyVerdict, base string, priorTaint []string, actionType string) (string, []string) {
	verdict := base
	var providerRules []string

	if verdict == VerdictAllow && isCleanDeveloperWorkflow(priorTaint, actionType) {
		return verdict, providerRules
	}

	for _, pv := range verdicts {
		if !pv.IsAdvisory {
			continue
		}
		if (pv.Verdict == VerdictAsk || pv.Verdict == VerdictDeny) && verdict == VerdictAllow {
			verdict = VerdictAsk
			tag := "policy:" + pv.Provider
			if len(pv.RulesMatched) > 0 {
				tag += ":" + strings.Join(pv.RulesMatched, ",")
			}
			providerRules = append(providerRules, tag)
		}
	}
	return verdict, providerRules
}

// computeNewTaint returns taint labels this action adds to the session.
// The orchestrator merges these into its taint store after evaluation.
func computeNewTaint(action AttributedAction) []string {
	if action.Sensitivity == "credential" {
		return []string{"credential_access"}
	}
	return nil
}

// Process is the stateful orchestrator wrapper around Evaluate.
// It threads prior taint in, applies new taint out, stamps id+time, ledgers.
func Process(caseID, mode string, signals []sdk.Signal, evasion EvasionFlags) Decision {
	// Build evaluation input — thread prior session taint in.
	scope, _ := TaintScopeFromSignals(signals)
	priorTaint := collectSessionTaint(scope)

	out := Evaluate(EvaluationInput{
		CaseID:     caseID,
		Mode:       mode,
		Signals:    signals,
		Evasion:    evasion,
		PriorTaint: priorTaint,
	})

	// Apply friction bounding (stateful — stays in orchestrator).
	verdict := CheckFriction(scope, out.Verdict, nil)

	// Apply new taint from this evaluation.
	for _, t := range out.NewTaint {
		Taint(scope, "session", t, out.Attribution)
	}

	// Explanation (not a parity field — Go-only for UX).
	normalized := NormalizeSignals(signals)
	enf := AnalyzeEnforceability(EnforceabilityInput{Mode: mode, Signals: normalized, EvasionFlags: evasion})
	explanation := RedactExplanation(buildExplanation(AttributedAction{
		ActionType: out.ActionType, Sensitivity: out.Sensitivity,
		Mode: mode, Signals: normalized, Labels: collectLabels(out),
	}, verdict, out.PolicyRules, enf, out.Effects))

	ts := time.Now().UTC().Format(time.RFC3339)
	id := decisionID(caseID, ts)

	return Decision{
		DecisionID:     id,
		Timestamp:      ts,
		Mode:           mode,
		Verdict:        verdict,
		DecisionClass:  out.DecisionClass,
		PolicyRules:    out.PolicyRules,
		Effects:        out.Effects,
		Enforceability: out.Enforceability,
		Attribution:    out.Attribution,
		ActionType:     out.ActionType,
		Sensitivity:    out.Sensitivity,
		Explanation:    explanation,
	}
}

// collectSessionTaint reads prior taint from the global taint store for a scope.
func collectSessionTaint(scope string) []string {
	globalTaint.mu.Lock()
	defer globalTaint.mu.Unlock()
	var labels []string
	for _, e := range globalTaint.entries {
		if e.Scope == scope || scope == "" {
			labels = appendUnique(labels, e.TaintKind)
		}
	}
	return labels
}

// collectLabels extracts labels from EvaluationOutput for explanation building.
func collectLabels(out EvaluationOutput) []string {
	var labels []string
	if out.Sensitivity == "credential" {
		labels = append(labels, "credential_access")
	}
	if out.Sensitivity == "external_network" {
		labels = append(labels, "external_egress")
	}
	return labels
}

func actionID(caseID string) string {
	sum := sha256.Sum256([]byte(caseID))
	return "act-" + hex.EncodeToString(sum[:])[:8]
}

func decisionID(caseID, ts string) string {
	sum := sha256.Sum256([]byte(caseID + ts))
	return "dec-" + hex.EncodeToString(sum[:])[:12]
}

// Explain formats a LedgerEntry as a human-readable decision explanation.
func Explain(entry LedgerEntry) string {
	d := entry.Decision
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Decision:       %s\n", strings.ToUpper(d.Verdict)))
	b.WriteString(fmt.Sprintf("Timestamp:      %s\n", d.Timestamp))
	b.WriteString(fmt.Sprintf("Mode:           %s\n", d.Mode))
	if entry.CaseID != "" {
		b.WriteString(fmt.Sprintf("Case:           %s\n", entry.CaseID))
	}
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("Action type:    %s\n", d.ActionType))
	b.WriteString(fmt.Sprintf("Sensitivity:    %s\n", d.Sensitivity))
	b.WriteString(fmt.Sprintf("Enforceability: %s -- %s\n", d.Enforceability, enforcementGuarantee(d.Mode)))
	b.WriteString(fmt.Sprintf("Attribution:    %s\n", d.Attribution))

	nativeRules := NativePolicyRules(d.PolicyRules)
	if len(nativeRules) > 0 {
		b.WriteString("\nNative SIR policy:\n")
		for _, r := range nativeRules {
			b.WriteString(fmt.Sprintf("  %s\n", r))
		}
	} else {
		b.WriteString("\nNative SIR policy:\n  none\n")
	}

	if len(d.ProviderPolicyEvidence) > 0 {
		b.WriteString("Policy provider verdicts:\n")
		for _, ev := range d.ProviderPolicyEvidence {
			b.WriteString(fmt.Sprintf("  %s: %s\n", ev.Provider, ev.Verdict))
			for _, rule := range ev.RulesMatched {
				b.WriteString(fmt.Sprintf("    rule: %s\n", rule))
			}
			if ev.Reason != "" {
				b.WriteString(fmt.Sprintf("    reason: %s\n", ev.Reason))
			}
			used := "no"
			if ev.Used {
				used = "yes"
			}
			b.WriteString(fmt.Sprintf("    used: %s\n", used))
		}
	}

	if len(d.ProviderEvidence) > 0 {
		b.WriteString("Provider failures:\n")
		for _, ev := range d.ProviderEvidence {
			status := ev.Status
			if status == "" {
				status = "failed"
			}
			b.WriteString(fmt.Sprintf("  %s: %s\n", ev.Provider, status))
			if ev.Reason != "" {
				b.WriteString(fmt.Sprintf("    reason: %s\n", ev.Reason))
			}
			if ev.Behavior != "" {
				b.WriteString(fmt.Sprintf("    behavior: %s\n", ev.Behavior))
			}
		}
	}

	if d.DeveloperWorkflowFloor != "" {
		b.WriteString("Developer workflow floor:\n")
		b.WriteString(fmt.Sprintf("  %s\n", d.DeveloperWorkflowFloor))
	}

	if len(d.Effects) > 0 {
		b.WriteString("\nEffects planned:\n")
		for _, e := range d.Effects {
			req := ""
			if e.Required {
				req = " (required"
				if e.FailClosed {
					req += ", fail_closed"
				}
				req += ")"
			}
			b.WriteString(fmt.Sprintf("  %s%s\n", e.Type, req))
		}
	}

	b.WriteString("Final decision:\n")
	b.WriteString(fmt.Sprintf("  %s\n", d.Verdict))
	b.WriteString(fmt.Sprintf("\n%s\n", d.Explanation))
	return b.String()
}

func buildExplanation(action AttributedAction, verdict string, rules []string, enf EnforceabilityResult, effects []PlannedEffect) string {
	display := DisplayTarget(action.Signals)
	if display == "" {
		display = action.ActionType
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("SIR %s this because:", verdictVerb(verdict)))
	if len(rules) > 0 {
		parts = append(parts, fmt.Sprintf("  Policy rule '%s' matched.", rules[0]))
	}
	if display != "" {
		parts = append(parts, fmt.Sprintf("  Target: %s (sensitivity: %s)", display, action.Sensitivity))
	}
	parts = append(parts, fmt.Sprintf("  Enforceability: %s (%s)", enf.Class, enf.Reason))
	if enf.Class != ClassEnforces && verdict == VerdictDeny {
		parts = append(parts, "  Note: SIR can deny cooperatively but cannot block without a pre-exec hook or sandbox provider.")
	}
	// Surface required-effect downgrade at decision time, not only in the ledger.
	// When a policy requires block/contain but the active mode can only detect,
	// developers need to see this explicitly so they can act on it.
	unavail := UnavailableRequiredEffects(action.Mode, effects)
	if len(unavail) > 0 {
		parts = append(parts, "  DOWNGRADE: required effect(s) unavailable in "+action.Mode+" mode:")
		for _, u := range unavail {
			parts = append(parts, "    - "+u)
		}
		parts = append(parts, "  Run 'sir status' for the enforcement truth in this mode.")
	}
	return strings.Join(parts, "\n")
}

func resolveDecisionClass(verdict, enforceabilityClass string) string {
	switch verdict {
	case VerdictDeny:
		return DecisionClassDenyNow
	case VerdictAsk:
		if enforceabilityClass == ClassEnforces {
			return DecisionClassBlockAndWait
		}
		return DecisionClassRecordPostHoc
	default:
		return DecisionClassProceedAndReconcile
	}
}

func applyLowConfidenceEscalation(verdict string, rules []string, attribution, sensitivity string) (string, []string) {
	if attribution != ConfLow && attribution != ConfUnknown {
		return verdict, rules
	}
	if sensitivity == "credential" || sensitivity == "high" || sensitivity == "critical" {
		if verdict == VerdictAllow {
			rules = append(rules, "low-confidence-escalation")
			return VerdictAsk, rules
		}
	}
	return verdict, rules
}

func verdictVerb(verdict string) string {
	switch verdict {
	case VerdictDeny:
		return "DENIED"
	case VerdictAsk:
		return "ASKED about"
	default:
		return "ALLOWED"
	}
}

func enforcementGuarantee(mode string) string {
	switch mode {
	case ModeObserve:
		return "records only"
	case ModeAdvise:
		return "explains only"
	case ModeHookGate:
		return "cooperative hooks only"
	case ModeOSObserved:
		return "post-hoc detection"
	case ModeMediated:
		return "pre-exec when span intact"
	case ModeContained:
		return "provider-backed enforcement"
	case ModeManaged:
		return "signed policy + provider health"
	}
	return "unknown"
}
