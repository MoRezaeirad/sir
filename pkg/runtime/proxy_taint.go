package runtime

import (
	"os"
	"sync"
	"time"

	"github.com/somoore/sir/pkg/session"
)

// postureGate lets the `sir run` local proxy deny external egress under the same
// HARD-deny conditions the hook layer enforces — read from the contained
// agent's live session posture — so a hook-ignoring or hijacked agent cannot
// exfiltrate even though it talks straight to the proxy. This is the
// defense-in-depth value of OS-level containment: the hook layer is advisory,
// the proxy is not.
//
// It mirrors the hook's *hard* denies only:
//   - DenyAll (session locked: hook-integrity violation, corruption);
//   - a live secret floor (a secret is in context this turn);
//   - untrusted content ingested (the integrity-flow egress wall).
//
// It deliberately does NOT deny on the cross-turn high-water mark alone
// (SessionEverSecret): that is an *ask* at the hook layer, and the proxy cannot
// offer an interactive prompt, so hard-denying it here would block egress the
// user already approved. Loopback is never gated (it is not exfil).
type postureGate struct {
	projectRoot string
	stateHome   string // shadow state home the contained agent's hooks write to
	load        func(home, projectRoot string) (*session.State, error)
	statePath   func(home, projectRoot string) string

	mu          sync.Mutex
	evaluated   bool
	cachedMtime time.Time
	deny        bool
	reason      string
}

func newPostureGate(projectRoot, stateHome string) *postureGate {
	return &postureGate{
		projectRoot: projectRoot,
		stateHome:   stateHome,
		load:        session.LoadFromHome,
		statePath:   session.StatePathUnder,
	}
}

// externalEgressDenied reports whether the contained session's live posture
// forbids external egress, and a short operator-facing reason. It is nil-safe
// (a proxy with no gate never adds a deny) and cheap: the posture file is
// re-read only when its mtime changes.
func (g *postureGate) externalEgressDenied() (bool, string) {
	if g == nil {
		return false, ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	mtime, statErr := g.currentMtime()
	if g.evaluated && statErr == nil && mtime.Equal(g.cachedMtime) {
		return g.deny, g.reason
	}
	g.deny, g.reason = g.evaluate()
	g.cachedMtime = mtime
	g.evaluated = true
	return g.deny, g.reason
}

func (g *postureGate) currentMtime() (time.Time, error) {
	info, err := os.Stat(g.statePath(g.stateHome, g.projectRoot))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

func (g *postureGate) evaluate() (bool, string) {
	state, err := g.load(g.stateHome, g.projectRoot)
	if err != nil {
		if os.IsNotExist(err) {
			// No shadow state written yet — no taint signal, so do not add a
			// deny on top of the allowlist the proxy already enforces.
			return false, ""
		}
		// Corrupted posture fails closed: under explicit containment we deny
		// external egress rather than fall back to allowlist-only. This fires
		// only on genuine corruption — exactly when max containment is warranted.
		return true, "session posture unreadable (failing closed)"
	}
	if state == nil {
		return false, ""
	}
	switch {
	case state.DenyAll:
		return true, "session is locked (deny-all)"
	case state.SecretSession:
		return true, "a secret is live in this session"
	case state.UntrustedContentThisTurn || state.RecentlyReadUntrusted:
		return true, "untrusted content was ingested this session"
	}
	return false, ""
}
