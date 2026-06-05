package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/sdk"
)

// Ensure policy import is used via PolicyVerdict in toVerdicts.
var _ = policy.PolicyVerdict{}

const (
	policyTimeout   = 200 * time.Millisecond
	advisoryTimeout = 250 * time.Millisecond // slightly slower than policy; risk scoring is heavier
	effectTimeout   = 5 * time.Second
	healthTimeout   = 3 * time.Second

	// authoritativePolicyTimeout is the budget for an AUTHORITATIVE policy
	// provider (PDP delegation). It is larger than the 200ms advisory budget
	// because an authoritative provider's verdict IS the decision (a timeout
	// fails closed to ask/deny, so a too-tight budget re-introduces friction —
	// the very thing PDP exists to reduce). It is still CAPPED so a hung provider
	// becomes a fast fail-closed ask rather than a hang. Authoritative providers
	// are expected to run WARM (a localhost sidecar/daemon, not a cold spawn per
	// call); under that expectation p50 is well under this cap. See
	// docs/research/pdp-provider-delegation.md (latency).
	authoritativePolicyTimeout = 1 * time.Second
)

// AdvisoryRisk is the normalized risk assessment returned by an advisory_provider.
type AdvisoryRisk struct {
	Provider string
	Level    string // "low" | "medium" | "high" | "critical"
	Reason   string
}

// advisoryRequest is the wire format sent to an advisory_provider on stdin.
// Schema: sir.advisory_request.v0
type advisoryRequest struct {
	Op              string   `json:"op"`
	SchemaVersion   string   `json:"schema_version"`
	Action          string   `json:"action"`
	Target          string   `json:"target,omitempty"`
	ResolvedActor   string   `json:"resolved_actor,omitempty"`
	AttributionConf string   `json:"attribution_confidence,omitempty"`
	Taint           []string `json:"taint,omitempty"`
	Enforceability  string   `json:"enforceability,omitempty"`
	Mode            string   `json:"mode,omitempty"`
}

// advisoryResponse is the wire format received from an advisory_provider on stdout.
// Schema: sir.advisory_signal.v0
type advisoryResponse struct {
	SchemaVersion string `json:"schema_version"`
	Provider      string `json:"provider"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason,omitempty"`
	IsAdvisory    bool   `json:"is_advisory"`
}

// policyRequest is the wire format sent to a policy_provider on stdin.
// Fields are flattened at the top level so policy providers can read them
// without needing to unwrap a nested object. This matches the schema described
// in docs/providers.md (sir.policy_request.v0).
type policyRequest struct {
	Op              string   `json:"op"`
	SchemaVersion   string   `json:"schema_version"`
	Action          string   `json:"action"`
	Target          string   `json:"target,omitempty"`
	ResolvedActor   string   `json:"resolved_actor,omitempty"`
	AttributionConf string   `json:"attribution_confidence,omitempty"`
	Taint           []string `json:"taint,omitempty"`
	Enforceability  string   `json:"enforceability,omitempty"`
	Mode            string   `json:"mode,omitempty"`

	// Additive session/integrity signals (schema string stays v0; see
	// InvokePolicy and policy.PolicyRequest). omitempty → invisible to v0
	// providers on a clean session. See pdp-provider-delegation.md §2b.
	SessionSecret            bool `json:"session_secret,omitempty"`
	SessionWasSecret         bool `json:"session_was_secret,omitempty"`
	SessionUntrustedRead     bool `json:"session_untrusted_read,omitempty"`
	SessionUntrustedThisTurn bool `json:"session_untrusted_this_turn,omitempty"`
}

// policyResponse is the wire format received from a policy_provider on stdout.
// Matches sir.policy_verdict.v0 schema exactly.
type policyResponse struct {
	SchemaVersion string   `json:"schema_version"`
	Provider      string   `json:"provider"`
	Verdict       string   `json:"verdict"`
	RulesMatched  []string `json:"rules_matched,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	IsAdvisory    bool     `json:"is_advisory"`
}

// InvokePolicy spawns the provider process, sends a PolicyRequest, and returns
// the resulting PolicyVerdicts. Times out after 200ms (advisory budget).
// Provider errors are returned to the caller; hook collection records them as
// non-fatal failures and evaluation falls back to native floors.
func InvokePolicy(e Entry, req policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
	return invokePolicyWithTimeout(e, req, policyTimeout)
}

// InvokePolicyAuthoritative is InvokePolicy with the larger authoritative budget
// (the provider's verdict IS the decision, so a timeout fails closed). Used only
// for an authoritative policy_provider; advisory providers keep the 200ms budget.
func InvokePolicyAuthoritative(e Entry, req policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
	return invokePolicyWithTimeout(e, req, authoritativePolicyTimeout)
}

func invokePolicyWithTimeout(e Entry, req policy.PolicyRequest, timeout time.Duration) ([]policy.PolicyVerdict, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	payload, err := json.Marshal(policyRequest{
		Op: "evaluate",
		// Schema string stays v0: the new session/integrity fields below are
		// ADDITIVE and omitempty, so a strict v0 provider (the bundled packs
		// advertise schema_version_supported: sir.policy_request.v0) sees only
		// extra optional keys it can ignore and keeps working unchanged. Bumping
		// the version string would break those providers — their verdicts would
		// vanish and advisory escalation would silently stop until every pack is
		// upgraded. v1-aware providers detect the new fields by presence, not by
		// the version string.
		SchemaVersion:   "sir.policy_request.v0",
		Action:          req.Action,
		Target:          req.Target,
		ResolvedActor:   req.ResolvedActor,
		AttributionConf: req.AttributionConf,
		Taint:           req.Taint,
		Enforceability:  req.Enforceability,
		Mode:            req.Mode,

		SessionSecret:            req.SessionSecret,
		SessionWasSecret:         req.SessionWasSecret,
		SessionUntrustedRead:     req.SessionUntrustedRead,
		SessionUntrustedThisTurn: req.SessionUntrustedThisTurn,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal policy request: %w", err)
	}

	out, stderr, err := runProviderWithStderr(ctx, e.Entrypoint, payload)
	if err != nil {
		return nil, fmt.Errorf("policy provider %s: %w", e.Name, err)
	}
	if len(strings.TrimSpace(string(out))) == 0 {
		if err := emptyOutputProviderError(stderr); err != nil {
			return nil, fmt.Errorf("policy provider %s: %w", e.Name, err)
		}
	}
	return parsePolicyVerdicts(e.Name, out)
}

// parsePolicyVerdicts decodes a policy provider's stdout into verdicts.
//
// Empty stdout is the SDK's documented quiet "no verdict / allow by default"
// signal: run_policy_provider writes nothing when evaluate returns None or a
// policy matched nothing. It is fail-open (no advisory verdict; native floors
// apply), NOT a parse error. The invocation layer separately treats empty stdout
// plus stderr as a provider failure so missing dependencies are surfaced instead
// of disappearing as deliberate silence. A provider may return a single verdict
// object or an array.
func parsePolicyVerdicts(name string, out []byte) ([]policy.PolicyVerdict, error) {
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, nil
	}
	if strings.HasPrefix(line, "[") {
		var resps []policyResponse
		if err := json.Unmarshal([]byte(line), &resps); err != nil {
			return nil, fmt.Errorf("policy provider %s: unmarshal response: %w", name, err)
		}
		return toVerdicts(resps), nil
	}
	var resp policyResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return nil, fmt.Errorf("policy provider %s: unmarshal response: %w", name, err)
	}
	return toVerdicts([]policyResponse{resp}), nil
}

// InvokeEffect spawns the provider process, sends an EffectRequest, and
// returns the EffectResult. Times out after 5s. Required effects fail closed
// (caller checks EffectResult.Status); optional effects fail open.
func InvokeEffect(e Entry, req sdk.EffectRequest) (sdk.EffectResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), effectTimeout)
	defer cancel()

	payload, err := json.Marshal(req)
	if err != nil {
		return sdk.EffectResult{}, fmt.Errorf("marshal effect request: %w", err)
	}

	out, err := runProvider(ctx, e.Entrypoint, payload)
	if err != nil {
		return sdk.EffectResult{
			SchemaVersion: sdk.SchemaEffectResV0,
			EffectID:      req.EffectID,
			Status:        sdk.EffectFailed,
			Reason:        err.Error(),
		}, fmt.Errorf("effect provider %s: %w", e.Name, err)
	}

	var result sdk.EffectResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
		return sdk.EffectResult{
			SchemaVersion: sdk.SchemaEffectResV0,
			EffectID:      req.EffectID,
			Status:        sdk.EffectFailed,
			Reason:        "invalid JSON response: " + err.Error(),
		}, fmt.Errorf("effect provider %s: unmarshal: %w", e.Name, err)
	}
	return result, nil
}

// InvokeAdvisory spawns the advisory_provider process, sends an advisory
// request, and returns the AdvisoryRisk assessment. Times out after 250ms.
// Provider errors are returned to the caller; hook collection records them as
// non-fatal failures and continues evaluation.
func InvokeAdvisory(e Entry, req policy.PolicyRequest) (*AdvisoryRisk, error) {
	ctx, cancel := context.WithTimeout(context.Background(), advisoryTimeout)
	defer cancel()

	payload, err := json.Marshal(advisoryRequest{
		Op:              "assess",
		SchemaVersion:   "sir.advisory_request.v0",
		Action:          req.Action,
		Target:          req.Target,
		ResolvedActor:   req.ResolvedActor,
		AttributionConf: req.AttributionConf,
		Taint:           req.Taint,
		Enforceability:  req.Enforceability,
		Mode:            req.Mode,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal advisory request: %w", err)
	}

	out, stderr, err := runProviderWithStderr(ctx, e.Entrypoint, payload)
	if err != nil {
		return nil, fmt.Errorf("advisory provider %s: %w", e.Name, err)
	}

	// Empty stdout without stderr = no risk assessment (fail open), same SDK
	// contract as policy providers. Stderr-only output is a provider failure,
	// not deliberate quiet.
	line := strings.TrimSpace(string(out))
	if line == "" {
		if err := emptyOutputProviderError(stderr); err != nil {
			return nil, fmt.Errorf("advisory provider %s: %w", e.Name, err)
		}
		return nil, nil
	}
	var resp advisoryResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return nil, fmt.Errorf("advisory provider %s: unmarshal: %w", e.Name, err)
	}

	level := normalizeRiskLevel(resp.RiskLevel)
	provider := resp.Provider
	if provider == "" {
		provider = e.Name // auto-normalize missing provider name
	}
	return &AdvisoryRisk{Provider: provider, Level: level, Reason: resp.Reason}, nil
}

// normalizeRiskLevel maps any risk level string to a canonical value.
// Unknown levels default to "low" (fail-open — never escalate on bad data).
func normalizeRiskLevel(level string) string {
	switch level {
	case "low", "medium", "high", "critical":
		return level
	default:
		return "low"
	}
}

// ContainmentProof is the result of a real containment verification: the
// provider was asked to demonstrate (not declare) containment, and this records
// whether the boundary actually held.
type ContainmentProof struct {
	Provider string         `json:"provider"`
	Verified bool           `json:"verified"`
	Reason   string         `json:"reason,omitempty"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// VerifyContainment asks an effect provider to actually demonstrate containment
// by sending {"op":"verify_containment"} and reading its proof. A provider that
// really enforces runs a contained action and confirms the boundary held (e.g.
// network egress failed inside a --network=none jail). Used by the CLI and CI to
// justify an enforcement:real claim — enforces requires demonstrated capability.
//
// Timeout is generous (containment spins up a real container).
func VerifyContainment(e Entry) (ContainmentProof, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := runProvider(ctx, e.Entrypoint, []byte(`{"op":"verify_containment"}`))
	if err != nil {
		return ContainmentProof{Provider: e.Name, Verified: false, Reason: err.Error()}, err
	}
	var resp struct {
		Verified bool           `json:"verified"`
		Reason   string         `json:"reason"`
		Evidence map[string]any `json:"evidence"`
		Network  string         `json:"network"`
		Image    string         `json:"image"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &resp); err != nil {
		return ContainmentProof{Provider: e.Name, Verified: false, Reason: "invalid proof JSON: " + err.Error()}, err
	}
	ev := resp.Evidence
	if ev == nil {
		ev = map[string]any{}
	}
	if resp.Network != "" {
		ev["network"] = resp.Network
	}
	if resp.Image != "" {
		ev["image"] = resp.Image
	}
	return ContainmentProof{Provider: e.Name, Verified: resp.Verified, Reason: resp.Reason, Evidence: ev}, nil
}

// HighestAdvisoryRisk returns the most severe AdvisoryRisk from a slice,
// or nil if the slice is empty.
func HighestAdvisoryRisk(risks []*AdvisoryRisk) *AdvisoryRisk {
	var best *AdvisoryRisk
	rank := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
	for _, r := range risks {
		if r == nil {
			continue
		}
		if best == nil || rank[r.Level] > rank[best.Level] {
			best = r
		}
	}
	return best
}

// HealthCheck spawns the provider, sends {"op":"capabilities"}, and returns
// whether the provider is healthy. Non-destructive.
func HealthCheck(e Entry) (healthy bool, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()

	out, err := runProvider(ctx, e.Entrypoint, []byte(`{"op":"capabilities"}`))
	if err != nil {
		return false, err.Error()
	}
	var resp sdk.CapabilitiesResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &resp); err != nil {
		return false, "invalid capabilities response: " + err.Error()
	}
	if resp.SchemaVersion != sdk.SchemaCapabilitiesV0 {
		return false, fmt.Sprintf("wrong schema_version: %s", resp.SchemaVersion)
	}
	return true, ""
}

// runProvider spawns entrypoint, writes payload to stdin, reads one line from
// stdout, and returns it. The context deadline is forwarded to the subprocess
// via SIGKILL on expiry.
func runProvider(ctx context.Context, entrypoint string, payload []byte) ([]byte, error) {
	out, _, err := runProviderWithStderr(ctx, entrypoint, payload)
	return out, err
}

// runProviderWithStderr is the provider process primitive. Stderr is returned
// so policy/advisory callers can distinguish a quiet no-op from a provider that
// could not emit a verdict.
func runProviderWithStderr(ctx context.Context, entrypoint string, payload []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, entrypoint)
	cmd.Stdin = strings.NewReader(string(payload) + "\n")
	cmd.Env = append(os.Environ(), sdkPythonPath(entrypoint))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, []byte(stderr.String()), fmt.Errorf("timed out")
		}
		return nil, []byte(stderr.String()), fmt.Errorf("process error: %w", err)
	}
	return out, []byte(stderr.String()), nil
}

func emptyOutputProviderError(stderr []byte) error {
	if len(strings.TrimSpace(string(stderr))) == 0 {
		return nil
	}
	lower := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(lower, "timed out") || strings.Contains(lower, "timeout"):
		return fmt.Errorf("timed out")
	case strings.Contains(lower, "not found") || strings.Contains(lower, "no such file"):
		return fmt.Errorf("unavailable dependency not found")
	default:
		return fmt.Errorf("reported an error without a verdict")
	}
}

// sdkPythonPath returns the PYTHONPATH env entry that makes Python providers
// able to `import sir_sdk` without any pip install or manual PYTHONPATH. See
// sdk.SDKPythonPath for the resolution model (absolute paths, vendored-beside-
// entrypoint first); shared so the signal-provider spawn path stays in sync.
func sdkPythonPath(entrypoint string) string {
	return sdk.SDKPythonPath(entrypoint)
}

// toVerdicts normalizes raw provider responses into canonical PolicyVerdicts.
// This is the adapter layer: whatever a provider returns (as long as it has a
// non-empty verdict field), SIR normalizes it:
//   - Missing Provider: filled from the registry entry name by the caller.
//   - Missing RulesMatched: empty slice (not nil).
//   - Missing Reason: empty string (harmless).
//   - IsAdvisory: always forced to true — advisory is non-negotiable.
//   - Unknown verdict strings: dropped (only allow/ask/deny are valid).
func toVerdicts(resps []policyResponse) []policy.PolicyVerdict {
	out := make([]policy.PolicyVerdict, 0, len(resps))
	for _, r := range resps {
		v := r.Verdict
		if v != "allow" && v != "ask" && v != "deny" {
			continue // unknown verdict string — drop rather than propagate
		}
		rules := r.RulesMatched
		if rules == nil {
			rules = []string{}
		}
		out = append(out, policy.PolicyVerdict{
			Provider:     r.Provider, // may be empty; caller fills from entry.Name
			Verdict:      v,
			RulesMatched: rules,
			Reason:       r.Reason,
			IsAdvisory:   true, // always true — policy providers are advisory only
		})
	}
	return out
}
