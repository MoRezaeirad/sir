package sdk

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
)

// CapabilitiesFunc returns this provider's capabilities when SIR queries {"op":"capabilities"}.
type CapabilitiesFunc func() CapabilitiesResponse

// EffectFunc handles an effect request from SIR and returns the result.
type EffectFunc func(req EffectRequest) EffectResult

// EmitFunc converts a native source event (shell command, hook payload, etc.)
// into a SIR signal. Returns nil to silently drop the event.
type EmitFunc func(event map[string]any) *Signal

// RunSignalProvider runs the stdio-JSON loop for a signal_provider.
//
// Protocol:
//   - {"op":"capabilities"} → respond with capabilities.
//   - Any other JSON object → treat as a native source event; call emit and
//     write the returned sir.signal.v0 to stdout. Nil return is a no-op.
func RunSignalProvider(caps CapabilitiesFunc, emit EmitFunc) {
	runSignalLoop(os.Stdin, os.Stdout, caps, emit)
}

// RunEffectProvider runs the stdio-JSON loop for an effect_provider.
// It responds to capabilities queries and dispatches effect requests.
func RunEffectProvider(caps CapabilitiesFunc, handle EffectFunc) {
	runEffectLoop(os.Stdin, os.Stdout, caps, handle)
}

func runSignalLoop(r io.Reader, w io.Writer, caps CapabilitiesFunc, emit EmitFunc) {
	enc := json.NewEncoder(w)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		if msg["op"] == "capabilities" {
			_ = enc.Encode(caps())
			continue
		}
		if emit != nil {
			if sig := emit(msg); sig != nil {
				_ = enc.Encode(sig)
			}
		}
	}
}

func runEffectLoop(r io.Reader, w io.Writer, caps CapabilitiesFunc, handle EffectFunc) {
	enc := json.NewEncoder(w)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		if msg["op"] == "capabilities" {
			_ = enc.Encode(caps())
			continue
		}
		if sv, _ := msg["schema_version"].(string); sv == SchemaEffectReqV0 && handle != nil {
			var req EffectRequest
			if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
				continue
			}
			_ = enc.Encode(handle(req))
		}
	}
}
