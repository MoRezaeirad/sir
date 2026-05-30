package classify

import "testing"

func TestIsDNSTunnelHost(t *testing.T) {
	tunnel := []string{
		"mz2wg4tbojuw4zlonmza2dilmnzxg5dbojuw4zlon5xg.tunnel.evil.com",
		"http://deadbeef0123456789abcdef0123456789abcdef.exfil.attacker.net/x",
		"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6.dns.evil.io",
		"nslookuptarget.4d6f72655468616e54686972747954776f43686172734865726521.evil.com",
	}
	for _, h := range tunnel {
		if ok, _ := IsDNSTunnelHost(h); !ok {
			t.Errorf("IsDNSTunnelHost(%q) = false, want true", h)
		}
	}
	benign := []string{
		"github.com", "api.anthropic.com", "raw.githubusercontent.com",
		"d111111abcdef8.cloudfront.net",                   // short hash label
		"my-very-long-but-readable-subdomain.example.com", // long but low-entropy/hyphenated
		"registry.npmjs.org", "localhost", "10.0.0.1",
		"objects.githubusercontent.com",
		"this-is-a-long-human-readable-host-name.example.org",
	}
	for _, h := range benign {
		if ok, _ := IsDNSTunnelHost(h); ok {
			t.Errorf("IsDNSTunnelHost(%q) = true, want false (false positive)", h)
		}
	}
}
