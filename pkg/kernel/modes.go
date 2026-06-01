package kernel

// ModeEnforcementGuarantee describes the bare-laptop enforcement guarantee of
// each protection mode. This is the canonical truth used by both:
//   - `sir harness run` (enforcement scorecard)
//   - `sir status` (what the active mode can and cannot enforce right now)
//
// Changing this map is a breaking change to the enforcement contract.
var ModeEnforcementGuarantee = map[string]string{
	ModeObserve:    "records only — no enforcement; telemetry baseline",
	ModeAdvise:     "explains only — no enforcement; useful for UX feedback",
	ModeHookGate:   "enforces on cooperative hook surfaces; blind to detached children, stripped spans, missing hooks",
	ModeOSObserved: "detects post-hoc via OS sensor; cannot prevent; attribution may be weak",
	ModeMediated:   "enforces when SIR launches/proxies the process; detects on residue when span severed",
	ModeContained:  "enforces via sandbox/effect provider; requires an active provider to be meaningful",
	ModeManaged:    "enforces via signed policy + provider health; enterprise-grade; requires infrastructure",
}

// ModeEnforcementLimits describes what the active mode CANNOT enforce.
// These are the honest limits surfaced to the user in `sir status`.
var ModeEnforcementLimits = map[string]string{
	ModeObserve:    "blind to all actions; records nothing without signals",
	ModeAdvise:     "cannot prevent any action; advisory only",
	ModeHookGate:   "blind to detached children (setsid/nohup/disown), script-file exfil (python script.py), stripped spans (env -u SIR_SPAN_ID), and missing hooks",
	ModeOSObserved: "cannot prevent actions; post-hoc detection only; cannot attribute to specific agents without span context",
	ModeMediated:   "blind to detached children that escape the mediated process tree",
	ModeContained:  "requires an active effect provider — without one, falls back to detection-only",
	ModeManaged:    "requires signed policy and provider health — without both, fails closed (deny-all)",
}

// ModeCanBlock returns true if the mode is capable of pre-exec blocking.
// hook_gate can block cooperatively; mediated/contained/managed can block
// with provider support. observe/advise/os_observed cannot block.
func ModeCanBlock(mode string) bool {
	switch mode {
	case ModeHookGate, ModeMediated, ModeContained, ModeManaged:
		return true
	}
	return false
}

// UnavailableRequiredEffects returns a human-readable list of required effects
// that the active mode cannot fulfill. This powers the decision-time downgrade
// surface so developers see which guarantees are degraded, not just what was
// decided.
func UnavailableRequiredEffects(mode string, effects []PlannedEffect) []string {
	var unavailable []string
	for _, e := range effects {
		if !e.Required {
			continue
		}
		switch e.Type {
		case "block", "contain":
			if !ModeCanBlock(mode) {
				unavailable = append(unavailable, e.Type+" (mode="+mode+": detection-only, no pre-exec block)")
			}
		}
	}
	return unavailable
}
