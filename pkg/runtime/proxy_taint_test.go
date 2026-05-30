package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/session"
)

func gateReturning(st *session.State, err error) *postureGate {
	g := newPostureGate("/proj", "/home")
	g.load = func(string, string) (*session.State, error) { return st, err }
	// Point mtime at a path that does not exist so every call re-evaluates
	// (the cache-hit path is covered by TestPostureGate_CachesUntilMtimeChanges).
	g.statePath = func(string, string) string { return "/sir-nonexistent/session.json" }
	return g
}

func TestPostureGate_HardDenyConditions(t *testing.T) {
	cases := []struct {
		name      string
		state     *session.State
		loadErr   error
		wantDeny  bool
		reasonSub string
	}{
		{"clean session allows", &session.State{}, nil, false, ""},
		{"live secret floor denies", &session.State{SecretSession: true}, nil, true, "secret"},
		{"deny-all denies", &session.State{DenyAll: true}, nil, true, "locked"},
		{"untrusted this turn denies", &session.State{UntrustedContentThisTurn: true}, nil, true, "untrusted"},
		{"untrusted read denies", &session.State{RecentlyReadUntrusted: true}, nil, true, "untrusted"},
		// The cross-turn high-water mark is an ASK at the hook layer, which the
		// proxy cannot offer — so it must NOT hard-deny here.
		{"high-water mark alone allows", &session.State{SessionEverSecret: true}, nil, false, ""},
		// Missing shadow state is not taint; genuine corruption fails closed.
		{"missing state allows", nil, os.ErrNotExist, false, ""},
		{"corrupt state fails closed", nil, errors.New("invalid character"), true, "failing closed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := gateReturning(tc.state, tc.loadErr)
			deny, reason := g.externalEgressDenied()
			if deny != tc.wantDeny {
				t.Fatalf("deny=%v, want %v (reason=%q)", deny, tc.wantDeny, reason)
			}
			if tc.reasonSub != "" && !strings.Contains(reason, tc.reasonSub) {
				t.Fatalf("reason %q does not mention %q", reason, tc.reasonSub)
			}
		})
	}
}

func TestPostureGate_NilIsSafe(t *testing.T) {
	var g *postureGate
	if deny, _ := g.externalEgressDenied(); deny {
		t.Fatal("nil gate must never deny")
	}
	var p *LocalProxy
	if deny, _ := p.taintBlocksExternal("evil.example"); deny {
		t.Fatal("nil proxy must never deny")
	}
}

func TestPostureGate_LoopbackNeverBlocked(t *testing.T) {
	p := &LocalProxy{gate: gateReturning(&session.State{SecretSession: true}, nil)}
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if blocked, _ := p.taintBlocksExternal(h); blocked {
			t.Errorf("loopback host %q must not be gated even under taint", h)
		}
	}
	if blocked, _ := p.taintBlocksExternal("evil.example"); !blocked {
		t.Error("external host should be blocked under live secret taint")
	}
}

// TestPostureGate_CachesUntilMtimeChanges confirms the gate only re-reads the
// posture when the file's mtime moves.
func TestPostureGate_CachesUntilMtimeChanges(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/session.json"
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	g := newPostureGate("/proj", "/home")
	g.statePath = func(string, string) string { return path }
	g.load = func(string, string) (*session.State, error) {
		calls++
		return &session.State{}, nil
	}
	g.externalEgressDenied()
	g.externalEgressDenied()
	if calls != 1 {
		t.Fatalf("expected 1 load while mtime stable, got %d", calls)
	}
}

// TestRunProxy_TaintGateBlocksExternalEgress is the end-to-end proof that the
// gate is wired into the request path: an allowlisted NON-loopback host passes
// the gate when the session is clean (and then fails downstream at dial — a
// non-403), but is rejected with 403 before any dial once the shadow session is
// secret-tainted. (A real httptest server can't be used because it binds to
// loopback, which the gate intentionally never blocks.)
func TestRunProxy_TaintGateBlocksExternalEgress(t *testing.T) {
	const allowed = "approved.example" // non-loopback, on the default :80
	resolver := func(_ context.Context, host string) ([]string, error) {
		return []string{"127.0.0.1"}, nil // resolvable so seedAllowlist succeeds
	}
	proxy, err := startLocalProxyWithResolver([]string{allowed}, resolver)
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close()

	home := t.TempDir()
	projectRoot := t.TempDir()
	base := time.Now().Add(-time.Hour)
	writeShadowState(t, home, projectRoot, &session.State{}, base) // clean
	proxy.EnableTaintGate(projectRoot, home)

	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Clean: the gate passes, so the request reaches the dial stage and fails
	// there (no real server) — anything but 403 proves the gate let it through.
	if code := getStatus(t, client, "http://"+allowed+"/"); code == http.StatusForbidden {
		t.Fatalf("clean session: gate blocked an allowlisted host (403)")
	}

	// Taint the shadow session with a distinctly newer mtime so the gate's
	// mtime-keyed cache re-reads it; the same allowlisted host must now 403.
	writeShadowState(t, home, projectRoot, &session.State{SecretSession: true}, base.Add(time.Minute))
	if code := getStatus(t, client, "http://"+allowed+"/"); code != http.StatusForbidden {
		t.Fatalf("tainted session: expected 403, got %d", code)
	}
}

// TestWatchTaintTeardown_ClosesTunnelOnTaint proves an already-open tunnel is
// torn down once the session crosses a hard-deny floor mid-tunnel.
func TestWatchTaintTeardown_ClosesTunnelOnTaint(t *testing.T) {
	p := &LocalProxy{
		gate:         gateReturning(&session.State{SecretSession: true}, nil),
		taintRecheck: 5 * time.Millisecond,
	}
	client, clientPeer := net.Pipe()
	upstream, _ := net.Pipe()
	done := make(chan struct{})
	defer close(done)

	p.watchTaintTeardown(done, client, upstream, "evil.example", "443")

	// Once the watcher fires it closes `client`; the peer's Read then unblocks
	// with an error instead of hanging.
	_ = clientPeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := clientPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the tainted tunnel to be torn down (client closed)")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("watcher did not tear down the tunnel before the deadline")
	}
}

// TestWatchTaintTeardown_LeavesCleanTunnelOpen confirms a clean session's tunnel
// is left running, and that loopback tunnels are never watched.
func TestWatchTaintTeardown_LeavesCleanTunnelOpen(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state *session.State
		host  string
	}{
		{"clean session", &session.State{}, "evil.example"},
		{"loopback never gated", &session.State{SecretSession: true}, "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &LocalProxy{
				gate:         gateReturning(tc.state, nil),
				taintRecheck: 5 * time.Millisecond,
			}
			client, clientPeer := net.Pipe()
			upstream, _ := net.Pipe()
			done := make(chan struct{})
			defer close(done)
			p.watchTaintTeardown(done, client, upstream, tc.host, "443")

			// The tunnel must stay open: a read with a short deadline times out
			// (still connected) rather than returning a closed-pipe error.
			_ = clientPeer.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			_, err := clientPeer.Read(make([]byte, 1))
			ne, ok := err.(net.Error)
			if !ok || !ne.Timeout() {
				t.Fatalf("expected the tunnel to stay open (timeout), got err=%v", err)
			}
		})
	}
}

func writeShadowState(t *testing.T, home, projectRoot string, st *session.State, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(session.StateDirUnder(home, projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	path := session.StatePathUnder(home, projectRoot)
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func getStatus(t *testing.T, client *http.Client, target string) int {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
