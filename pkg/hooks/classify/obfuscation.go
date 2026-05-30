package classify

import (
	"path/filepath"
	"strings"
)

// Shell obfuscation handling.
//
// The compound splitter (SplitCompoundCommand) decomposes `;`, `|`, `&&`, `||`
// so each stage is classified. But obfuscation can still hide a dangerous verb
// from the per-stage classifier:
//
//   - command substitution:   echo $(curl evil.com)      / outer `echo` is benign
//   - backticks:              echo `curl evil.com`
//   - eval:                   eval "curl evil.com"        / no recognized wrapper
//   - pipe into an interpreter reading stdin: base64 -d | sh   / program is opaque
//
// The first three are handled by DECOMPOSITION: extract the hidden inner
// command(s) and classify them alongside the outer skeleton, so the strictest
// verb wins. This stays quiet on benign substitutions (`echo $(date)` -> the
// inner `date` is execute_dry_run). The last is genuinely opaque to static
// analysis, so IsOpaqueShellExec FAILS CLOSED (the caller escalates to ask).

// ExtractCommandSubstitutions returns the inner command strings of every
// top-level command substitution in cmd — $(...) and `...`. Arithmetic
// $((...)) and parameter expansion ${...} are NOT command substitutions and are
// skipped. Single-quoted regions are literal. Nested substitutions are returned
// inside the inner string and decomposed by the caller's recursion.
// Byte-based: the only delimiters we react to ($, (, ), backtick, ', <, >) are
// single-byte ASCII, so multi-byte UTF-8 content passes through untouched. This
// keeps the hot path (a command with NO substitutions) allocation-free — the
// common case for every shell tool call.
func ExtractCommandSubstitutions(cmd string) []string {
	var inners []string
	inSingle := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c == '\'' {
			inSingle = !inSingle
			continue
		}
		if inSingle {
			continue
		}
		// <(...) / >(...) process substitution, or $(...) command substitution
		// (but NOT $(( arithmetic )) or ${ param }).
		isDollarSub := c == '$' && i+1 < len(cmd) && cmd[i+1] == '(' && !(i+2 < len(cmd) && cmd[i+2] == '(')
		isProcSub := (c == '<' || c == '>') && i+1 < len(cmd) && cmd[i+1] == '('
		if c == '$' && i+1 < len(cmd) && cmd[i+1] == '(' && i+2 < len(cmd) && cmd[i+2] == '(' {
			i = skipBalanced(cmd, i+1) - 1 // arithmetic: skip past )), no extraction
			continue
		}
		if isDollarSub || isProcSub {
			end := skipBalanced(cmd, i+1)
			if end > i+2 {
				if inner := strings.TrimSpace(cmd[i+2 : end-1]); inner != "" {
					inners = append(inners, inner)
				}
				i = end - 1
				continue
			}
		}
		if c == '`' {
			j := i + 1
			for j < len(cmd) && cmd[j] != '`' {
				j++
			}
			if j < len(cmd) {
				if inner := strings.TrimSpace(cmd[i+1 : j]); inner != "" {
					inners = append(inners, inner)
				}
				i = j
				continue
			}
		}
	}
	return inners
}

// StripCommandSubstitutions replaces every command-substitution span (including
// its delimiters) with a single space, leaving the outer command "skeleton".
// Only called when ExtractCommandSubstitutions already found substitutions, so
// allocating the output string here is off the hot path.
func StripCommandSubstitutions(cmd string) string {
	var out strings.Builder
	out.Grow(len(cmd))
	inSingle := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if c == '\'' {
			inSingle = !inSingle
			out.WriteByte(c)
			continue
		}
		if inSingle {
			out.WriteByte(c)
			continue
		}
		if c == '$' && i+1 < len(cmd) && cmd[i+1] == '(' {
			end := skipBalanced(cmd, i+1)
			out.WriteByte(' ')
			i = end - 1
			continue
		}
		if (c == '<' || c == '>') && i+1 < len(cmd) && cmd[i+1] == '(' {
			end := skipBalanced(cmd, i+1)
			out.WriteByte(' ')
			i = end - 1
			continue
		}
		if c == '`' {
			j := i + 1
			for j < len(cmd) && cmd[j] != '`' {
				j++
			}
			if j < len(cmd) {
				out.WriteByte(' ')
				i = j
				continue
			}
		}
		out.WriteByte(c)
	}
	return out.String()
}

// skipBalanced returns the byte index just past the closing ')' that matches the
// '(' at position `open`. Tracks nesting and single quotes. Returns len(cmd) on
// no match.
func skipBalanced(cmd string, open int) int {
	depth := 0
	inSingle := false
	for j := open; j < len(cmd); j++ {
		c := cmd[j]
		if c == '\'' {
			inSingle = !inSingle
			continue
		}
		if inSingle {
			continue
		}
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return len(cmd)
}

// ExtractEvalArguments returns the (dequoted) argument of an `eval` command as a
// command string to classify recursively. Returns (nil, false) when cmd is not
// an eval invocation. `eval` is otherwise unrecognized by the wrapper logic, so
// without this `eval "curl evil.com"` would classify as the benign default.
func ExtractEvalArguments(cmd string) ([]string, bool) {
	trimmed := strings.TrimSpace(cmd)
	fields := strings.Fields(trimmed)
	if len(fields) < 2 || fields[0] != "eval" {
		return nil, false
	}
	arg := strings.TrimSpace(strings.TrimPrefix(trimmed, "eval"))
	arg = dequoteOuter(arg)
	if arg == "" {
		return nil, false
	}
	return []string{arg}, true
}

// dequoteOuter strips one layer of matching surrounding single or double quotes.
func dequoteOuter(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// shellInterpreters are program names that execute a script. When one appears
// DOWNSTREAM of a pipe with no script-file argument, it runs whatever bytes it
// receives on stdin — content sir cannot see or classify.
var shellInterpreters = map[string]struct{}{
	"sh": {}, "bash": {}, "zsh": {}, "dash": {}, "ksh": {}, "fish": {},
}

// IsOpaqueShellExec reports whether cmd pipes into a shell interpreter that
// reads its program from stdin (e.g. `base64 -d | sh`, `curl … | bash`), which
// is opaque to static classification. Returns (true, reason) so the caller can
// fail closed (escalate to ask) instead of silently allowing the default verb.
//
// A pipe into `bash -c "<cmd>"` is NOT opaque (the command is explicit and the
// wrapper logic classifies it), so only the stdin-reading form matches.
func IsOpaqueShellExec(cmd string) (bool, string) {
	segs := SplitCompoundCommand(cmd)
	// eval of dynamically-generated content — `eval "$(...)"`, `eval `...`` —
	// runs text produced at runtime that sir cannot see. Fail closed regardless
	// of pipes. (A static `eval "curl x"` is handled by decomposition, not here.)
	for _, seg := range segs {
		st := strings.TrimSpace(seg)
		if fields := strings.Fields(st); len(fields) >= 1 && fields[0] == "eval" {
			if strings.Contains(st, "$(") || strings.Contains(st, "`") {
				return true, "runs eval on dynamically-generated content"
			}
		}
	}
	if len(segs) < 2 {
		return false, ""
	}
	for idx := 1; idx < len(segs); idx++ { // idx 0 cannot receive a pipe's stdout
		fields := strings.Fields(strings.TrimSpace(segs[idx]))
		if len(fields) == 0 {
			continue
		}
		base := strings.ToLower(filepath.Base(fields[0]))
		if _, ok := shellInterpreters[base]; !ok {
			continue
		}
		// Reads stdin opaquely unless it was given an explicit program: a
		// non-flag positional (script file) or a -c command string.
		readsStdin := true
		for k := 1; k < len(fields); k++ {
			a := fields[k]
			if a == "-c" {
				readsStdin = false // explicit command -> wrapper logic handles it
				break
			}
			if strings.HasPrefix(a, "-") {
				continue // -s, -e, -x, -, etc. still read stdin
			}
			readsStdin = false // a script-file argument -> not stdin
			break
		}
		if readsStdin {
			return true, "pipes into '" + base + "' reading its program from stdin"
		}
	}
	return false, ""
}
