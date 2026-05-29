package main

import "testing"

// TestLeaseForProfileGradient (PROFILE-1) pins the personal -> team -> strict ->
// managed friction gradient: each step is monotonically more conservative, and
// raw-secret reads stay deny+redact on EVERY profile (including personal — the
// audit's premise that personal leaves them open was wrong; deny+redact keeps a
// thinking-enabled turn linear and is lower friction than an interactive ask).
func TestLeaseForProfileGradient(t *testing.T) {
	type caps struct {
		denyRawSecrets bool
		autoHosts      bool
		autoRemotes    bool
		reuse          bool
		narrowEnv      bool
		silentHosts    bool
		allowDelegate  bool
	}
	want := map[string]caps{
		"personal": {true, true, true, true, true, true, true},
		"team":     {true, true, true, true, false, true, true},
		"strict":   {true, false, false, false, false, false, false},
		"managed":  {true, false, false, false, false, false, false},
	}
	for profile, w := range want {
		t.Run(profile, func(t *testing.T) {
			l, err := leaseForProfile(profile)
			if err != nil {
				t.Fatalf("leaseForProfile(%q): %v", profile, err)
			}
			got := caps{
				denyRawSecrets: l.DenyRawSecretReads,
				autoHosts:      l.AutoLeaseApprovedHosts,
				autoRemotes:    l.AutoLeaseApprovedRemotes,
				reuse:          l.ReuseSessionApprovals,
				narrowEnv:      l.NarrowEnvReads,
				silentHosts:    l.SilentApprovedHosts,
				allowDelegate:  l.AllowDelegation,
			}
			if got != w {
				t.Errorf("profile %q caps = %+v, want %+v", profile, got, w)
			}
			// Invariant on EVERY profile: raw secret reads are denied+redacted.
			if !l.DenyRawSecretReads {
				t.Errorf("profile %q must keep DenyRawSecretReads (deny+redact)", profile)
			}
		})
	}

	// "default"/"standard" are aliases for personal.
	for _, alias := range []string{"default", "standard"} {
		if l, err := leaseForProfile(alias); err != nil || !l.NarrowEnvReads || !l.DenyRawSecretReads {
			t.Errorf("alias %q should resolve to the personal profile (err=%v)", alias, err)
		}
	}

	if _, err := leaseForProfile("nope"); err == nil {
		t.Error("unknown profile should error")
	}
}
