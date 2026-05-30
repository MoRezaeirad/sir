package hooks

import (
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/secretscan"
	"github.com/somoore/sir/pkg/session"
)

// captureSecretFingerprints records salted one-way fingerprints of any secret
// VALUES present in a tool output that entered the model context, so a later
// verbatim re-emission of that value can be recognized. Raw values are never
// stored. Called at PostToolUse when a sensitive read was approved or a
// credential was detected in the output.
func captureSecretFingerprints(output string, state *session.State) {
	if output == "" {
		return
	}
	salt := state.SecretSalt() // generates+persists on first use; Save() follows
	fps := secretscan.FingerprintSecrets(output, salt)
	if len(fps) == 0 {
		return
	}
	m := make(map[string]int, len(fps))
	for _, fp := range fps {
		m[fp.Hash] = fp.Len
	}
	state.AddSecretFingerprints(m)
}

// outboundVerbs are the actions that could carry a secret out of the machine or
// persist it where it can later be pushed.
func isOutboundVerb(verb policy.Verb) bool {
	switch verb {
	case policy.VerbNetExternal, policy.VerbNetAllowlisted, policy.VerbDnsLookup,
		policy.VerbPushOrigin, policy.VerbPushRemote, policy.VerbStageWrite, policy.VerbCommit:
		return true
	}
	return false
}

// outboundSecretLeak reports whether an outbound/persisting action's payload
// contains the verbatim value of a secret that earlier entered context this
// session (context-laundering). It returns a short reason. Catches copy-paste
// exfiltration even though the bytes are agent-authored; does NOT catch a
// paraphrased or transformed secret.
func outboundSecretLeak(payload *HookPayload, intent Intent, state *session.State) (string, bool) {
	if !isOutboundVerb(intent.Verb) {
		return "", false
	}
	fpMap := state.SecretFingerprintsCopy()
	if len(fpMap) == 0 {
		return "", false
	}
	salt := state.FingerprintSaltBytes()
	if salt == nil {
		return "", false
	}
	text := outboundPayloadText(payload)
	if text == "" {
		return "", false
	}
	fps := make([]secretscan.SecretFingerprint, 0, len(fpMap))
	for h, n := range fpMap {
		fps = append(fps, secretscan.SecretFingerprint{Hash: h, Len: n})
	}
	if _, leak := secretscan.PayloadLeaksSecret(text, fps, salt); leak {
		return "a secret value read earlier this session appears verbatim in this outbound payload (context-laundering)", true
	}
	return "", false
}

// outboundPayloadText gathers the string fields of a tool input that could carry
// a secret outward (the shell command, file content, request body, …), bounded.
func outboundPayloadText(payload *HookPayload) string {
	const maxBytes = 256 * 1024
	var b []byte
	for _, key := range []string{"command", "content", "new_string", "body", "data", "input", "text", "value"} {
		if v, ok := payload.ToolInput[key].(string); ok && v != "" {
			b = append(b, v...)
			b = append(b, '\n')
			if len(b) >= maxBytes {
				return string(b[:maxBytes])
			}
		}
	}
	return string(b)
}
