package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// tui_checklist.go implements a minimal interactive multi-select checklist
// using only the Go standard library plus the host `stty` binary for raw
// terminal mode. The stdlib-only non-negotiable (CLAUDE.md #1) rules out
// charmbracelet/bubbletea, so we drive the terminal directly: ANSI escapes
// for rendering, raw byte reads for input.
//
// Failure posture: if raw mode cannot be entered, or stdin is not a TTY, the
// caller is expected to have already gated on isInteractiveTerminal() and to
// fall back to a non-interactive default. The selector itself restores the
// terminal on every exit path (normal return, error, Ctrl-C) so a security
// tool never leaves the user's shell wedged in raw mode.

// checklistItem is one selectable row.
type checklistItem struct {
	// Label is the human-readable text shown to the right of the checkbox.
	Label string
	// Detail is optional dim text shown after the label (e.g. config path).
	Detail string
	// Checked is the initial selection state.
	Checked bool
}

// isInteractiveTerminal reports whether both stdin and stdout are attached to
// a terminal. The interactive selector must not run when input is piped, when
// output is redirected, or under CI — callers fall back to a non-interactive
// default in those cases.
func isInteractiveTerminal() bool {
	return isTerminal(os.Stdin) && isTerminal(os.Stdout)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// runChecklist renders an interactive multi-select over items and blocks until
// the user confirms (Enter) or cancels (Esc / Ctrl-C / q). It returns the
// indices of checked items and confirmed=true on Enter, or confirmed=false on
// cancel. The terminal is always restored before returning.
//
// Controls: ↑/↓ or j/k move, Space toggles, a toggles all, Enter confirms,
// Esc/q/Ctrl-C cancels.
func runChecklist(title string, items []checklistItem) (checked []int, confirmed bool) {
	return runSelector(title, items, false)
}

// runRadio is the single-select variant: exactly one row is selected at a
// time, Space (or moving with the cursor) sets it, Enter confirms. Returns the
// chosen index and confirmed=true, or confirmed=false on cancel.
func runRadio(title string, items []checklistItem) (chosen int, confirmed bool) {
	picked, ok := runSelector(title, items, true)
	if !ok || len(picked) == 0 {
		return 0, false
	}
	return picked[0], true
}

// runSelector is the shared event loop for both the multi-select checklist and
// the single-select radio (radio=true). In radio mode Space selects the row
// under the cursor exclusively and the "toggle all" key is inert.
func runSelector(title string, items []checklistItem, radio bool) (checked []int, confirmed bool) {
	if len(items) == 0 {
		return nil, false
	}

	restore, err := enterRawMode()
	if err != nil {
		// Caller gated on isInteractiveTerminal(), so this is an unexpected
		// environment (e.g. stty missing). Fail closed to "cancelled" — the
		// caller falls back to its non-interactive default.
		return nil, false
	}
	// Restore on every path, including panic, before we touch anything else.
	defer restore()

	// Under cbreak, ISIG stays enabled, so Ctrl-C is delivered as SIGINT
	// rather than a raw 0x03 byte. Trap it (and SIGTERM) so we restore the
	// terminal before exiting instead of leaving the user's shell in no-echo
	// mode. The done channel lets the watcher goroutine exit on the normal
	// return path so it is not leaked.
	sigCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	defer close(done)
	go func() {
		select {
		case _, ok := <-sigCh:
			if ok {
				restore()
				// Exit non-zero so scripts see the cancel.
				os.Exit(130)
			}
		case <-done:
		}
	}()

	state := make([]bool, len(items))
	for i := range items {
		state[i] = items[i].Checked
	}
	// In radio mode the cursor carries the selection, so start it on the
	// first row the caller marked Checked (its intended default) rather than
	// always on row 0.
	cursor := 0
	if radio {
		for i := range items {
			if items[i].Checked {
				cursor = i
				break
			}
		}
	}

	reader := bufio.NewReader(os.Stdin)
	out := os.Stdout

	render := func(first bool) {
		var b strings.Builder
		if !first {
			// Move the cursor up over the previously-rendered block to redraw
			// in place. Each render emits: title (1) + controls footer (1) +
			// one line per item (N) + a trailing blank (1) = N+3 lines, and
			// leaves the cursor at the start of the line just past the blank.
			b.WriteString(fmt.Sprintf("\x1b[%dA", len(items)+3))
		}
		b.WriteString("\r\x1b[J") // clear from cursor down
		b.WriteString("  " + ansiBold(title) + "\n")
		if radio {
			b.WriteString(ansiDim("  ↑/↓ move · Space/Enter select · Esc cancel") + "\n")
		} else {
			b.WriteString(ansiDim("  Space toggles · ↑/↓ move · a all · Enter confirm · Esc cancel") + "\n")
		}
		for i, it := range items {
			mark := "[ ]"
			// In radio mode the cursor row IS the selection, so the filled
			// marker tracks the cursor — never a stale state[] entry. This
			// keeps the visible "•", the internal state, and what Enter
			// returns in lockstep (see the cursor/Enter handling below).
			on := state[i]
			if radio {
				mark = "( )"
				if i == cursor {
					mark = "(" + ansiGreen("•") + ")"
				}
			} else if on {
				mark = "[" + ansiGreen("x") + "]"
			}
			pointer := "  "
			line := fmt.Sprintf("%s%s %s", pointer, mark, it.Label)
			if it.Detail != "" {
				line += "  " + ansiDim(it.Detail)
			}
			if i == cursor {
				line = ansiBold("> ") + fmt.Sprintf("%s %s", mark, ansiBold(it.Label))
				if it.Detail != "" {
					line += "  " + ansiDim(it.Detail)
				}
				line = "  " + line
			} else {
				line = "  " + line
			}
			b.WriteString(line + "\n")
		}
		b.WriteString("\n")
		fmt.Fprint(out, b.String())
	}

	render(true)

	for {
		r, err := readKey(reader)
		if err != nil {
			if err == io.EOF {
				return nil, false
			}
			return nil, false
		}
		switch r {
		case keyUp:
			if cursor > 0 {
				cursor--
			}
		case keyDown:
			if cursor < len(items)-1 {
				cursor++
			}
		case keySpace:
			if radio {
				// In radio mode the cursor row is already the selection, so
				// Space is a confirm (it commits the row the user navigated
				// to). Returning here means arrow-then-Space and
				// arrow-then-Enter behave identically — no way to select a
				// row other than the one under the cursor.
				return []int{cursor}, true
			}
			state[cursor] = !state[cursor]
		case keyToggleAll:
			if radio {
				break // inert in single-select mode
			}
			// If everything is already checked, clear all; else check all.
			allOn := true
			for _, s := range state {
				if !s {
					allOn = false
					break
				}
			}
			for i := range state {
				state[i] = !allOn
			}
		case keyEnter:
			if radio {
				// The cursor row IS the selection in radio mode — return it
				// directly. (Previously this scanned state[] for the first
				// set bit, which ignored cursor movement and silently
				// returned the seeded default; that under-scoped the wizard.)
				sel := cursor
				return []int{sel}, true
			}
			for i, s := range state {
				if s {
					checked = append(checked, i)
				}
			}
			return checked, true
		case keyCancel:
			return nil, false
		}
		render(false)
	}
}

// key codes returned by readKey.
type keyCode int

const (
	keyOther keyCode = iota
	keyUp
	keyDown
	keySpace
	keyEnter
	keyCancel
	keyToggleAll
)

// readKey reads a single logical keypress from r in raw mode, decoding the
// arrow-key escape sequences (ESC [ A/B) and treating ESC alone, q, and
// Ctrl-C as cancel.
func readKey(r *bufio.Reader) (keyCode, error) {
	b, err := r.ReadByte()
	if err != nil {
		return keyOther, err
	}
	switch b {
	case '\r', '\n':
		return keyEnter, nil
	case ' ':
		return keySpace, nil
	case 'q', 'Q':
		return keyCancel, nil
	case 'a', 'A':
		return keyToggleAll, nil
	case 0x03:
		// Ctrl-C as a raw byte. Under cbreak (ISIG on) the kernel normally
		// delivers SIGINT instead, which the signal watcher handles — so this
		// is a defensive fallback for terminals/modes that pass it through.
		return keyCancel, nil
	case 'j', 'J':
		return keyDown, nil
	case 'k', 'K':
		return keyUp, nil
	case 0x1b: // ESC — could be a lone Esc or the start of an arrow sequence.
		// Peek for '[' then the direction. If no bytes are buffered, treat as
		// a bare Esc (cancel).
		if r.Buffered() < 2 {
			return keyCancel, nil
		}
		next, err := r.ReadByte()
		if err != nil || next != '[' {
			return keyCancel, nil
		}
		dir, err := r.ReadByte()
		if err != nil {
			return keyCancel, nil
		}
		switch dir {
		case 'A':
			return keyUp, nil
		case 'B':
			return keyDown, nil
		}
		return keyOther, nil
	}
	return keyOther, nil
}

// enterRawMode puts the terminal into cbreak (no-echo, char-at-a-time) mode by
// shelling out to `stty`, and returns a restore function that reverts to the
// previously-saved settings. Using `stty` keeps us in the standard library:
// no termios cgo, no third-party term package.
func enterRawMode() (restore func(), err error) {
	// Save current settings as an opaque stty string so we can restore them
	// exactly, regardless of platform-specific flag layout.
	saved, err := sttyOutput("-g")
	if err != nil {
		return nil, fmt.Errorf("read terminal settings: %w", err)
	}
	saved = strings.TrimSpace(saved)

	// cbreak: deliver each keystroke immediately; -echo: don't print typed
	// bytes (we render the checkbox state ourselves).
	if err := sttyRun("cbreak", "-echo"); err != nil {
		return nil, fmt.Errorf("enter raw mode: %w", err)
	}

	// Hide the cursor while the menu is live; show it again on restore.
	fmt.Fprint(os.Stdout, "\x1b[?25l")

	// restore may be invoked concurrently: once via defer on the normal path
	// and once from the SIGINT goroutine if the user hits Ctrl-C. sync.Once
	// makes that race-safe so we never double-issue stty / leave the terminal
	// half-restored.
	var once sync.Once
	return func() {
		once.Do(func() {
			fmt.Fprint(os.Stdout, "\x1b[?25h") // show cursor
			// Best-effort restore; nothing actionable if it fails, but try
			// the saved string first and fall back to `sane`.
			if sttyRun(saved) != nil {
				_ = sttyRun("sane")
			}
		})
	}, nil
}

// sttyRun runs `stty <args...>` against the controlling terminal (/dev/tty via
// stdin) and discards output.
func sttyRun(args ...string) error {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

// sttyOutput runs `stty <args...>` and returns its stdout.
func sttyOutput(args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	b, err := cmd.Output()
	return string(b), err
}

// --- ANSI helpers -------------------------------------------------------

func ansiBold(s string) string  { return "\x1b[1m" + s + "\x1b[0m" }
func ansiDim(s string) string   { return "\x1b[2m" + s + "\x1b[0m" }
func ansiGreen(s string) string { return "\x1b[32m" + s + "\x1b[0m" }
