package session

import (
	"crypto/rand"
	"encoding/hex"
)

// SecretSalt returns the per-session fingerprint salt, generating and persisting
// one on first use. Mutates state, so the caller must Save() afterward.
func (s *State) SecretSalt() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FingerprintSalt == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		s.FingerprintSalt = hex.EncodeToString(b)
	}
	salt, _ := hex.DecodeString(s.FingerprintSalt)
	return salt
}

// AddSecretFingerprints merges new value fingerprints (digest -> byte length)
// into the session's monotonic set.
func (s *State) AddSecretFingerprints(fps map[string]int) {
	if len(fps) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SecretFingerprints == nil {
		s.SecretFingerprints = make(map[string]int, len(fps))
	}
	for h, n := range fps {
		s.SecretFingerprints[h] = n
	}
}

// SecretFingerprintsCopy returns a copy of the fingerprint set, or nil when
// empty. The matcher (in the hooks layer) builds its query from this.
func (s *State) SecretFingerprintsCopy() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.SecretFingerprints) == 0 {
		return nil
	}
	out := make(map[string]int, len(s.SecretFingerprints))
	for h, n := range s.SecretFingerprints {
		out[h] = n
	}
	return out
}

// FingerprintSaltBytes returns the salt without generating one (nil if unset).
func (s *State) FingerprintSaltBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.FingerprintSalt == "" {
		return nil
	}
	salt, _ := hex.DecodeString(s.FingerprintSalt)
	return salt
}
