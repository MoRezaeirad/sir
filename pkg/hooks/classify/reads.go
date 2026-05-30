package classify

import (
	"strings"

	"github.com/somoore/sir/pkg/lease"
)

var sensitiveReadPrograms = map[string]bool{
	"cat":     true,
	"tac":     true,
	"nl":      true,
	"head":    true,
	"tail":    true,
	"less":    true,
	"more":    true,
	"bat":     true,
	"batcat":  true,
	"xxd":     true,
	"hexdump": true,
	"od":      true,
	"sed":     true,
	"awk":     true,
	"gawk":    true,
	"grep":    true,
	"rg":      true,
	"ag":      true,
	"ack":     true,
	"strings": true,
	"file":    true,
	// Encoders that emit file contents to stdout/stderr — `base64 .env`,
	// `base32 .aws/credentials`, `basenc --base64 .env`, `uuencode .env x` are
	// a classic exfil pipeline leg, indistinguishable from a raw read for our
	// purposes, so they get the same deny + redact treatment.
	"base64":   true,
	"base32":   true,
	"basenc":   true,
	"uuencode": true,
	// Text utilities that read and re-emit a file's contents — `rev .env`,
	// `cut -c1- .env`, `dd if=.env` are extraction legs just like the encoders.
	// (`tr` reads only stdin, so it is covered by the input-redirect detector
	// below rather than this positional list.)
	"rev": true,
	"cut": true,
	"dd":  true,
}

var readProgramFlagsTakingValue = map[string]map[string]bool{
	"cat":     {},
	"tac":     {"s": true},
	"nl":      {"b": true, "d": true, "f": true, "h": true, "i": true, "l": true, "n": true, "p": true, "s": true, "v": true, "w": true},
	"head":    {"c": true, "n": true, "q": true},
	"tail":    {"c": true, "n": true, "F": true},
	"less":    {"b": true, "h": true, "j": true, "k": true, "o": true, "p": true, "t": true, "T": true, "x": true, "y": true, "z": true, "#": true},
	"more":    {"n": true, "p": true, "t": true},
	"bat":     {"l": true, "H": true, "r": true, "m": true, "p": true, "theme": true},
	"batcat":  {"l": true, "H": true, "r": true, "m": true, "p": true},
	"xxd":     {"c": true, "g": true, "l": true, "o": true, "s": true},
	"hexdump": {"e": true, "f": true, "n": true, "s": true},
	"od":      {"A": true, "j": true, "N": true, "S": true, "t": true, "w": true},
	"sed":     {"e": true, "f": true, "i": true},
	"awk":     {"F": true, "f": true, "v": true},
	"gawk":    {"F": true, "f": true, "v": true},
	"grep":    {"A": true, "B": true, "C": true, "D": true, "d": true, "e": true, "f": true, "m": true},
	"rg":      {"A": true, "B": true, "C": true, "e": true, "f": true, "g": true, "t": true, "T": true, "m": true, "max-count": true, "before-context": true, "after-context": true, "context": true, "regexp": true},
	"ag":      {"A": true, "B": true, "C": true, "G": true, "g": true, "m": true},
	"ack":     {"A": true, "B": true, "C": true, "g": true, "m": true},
	"strings": {"n": true, "t": true, "e": true},
	"file":    {"m": true, "P": true},
	// `-w`/`--wrap N` sets the column width; consume its value so the width digit
	// is not mistaken for a positional. NB: `-i` (macOS input file) is left
	// unregistered on purpose — its value IS the file we want to flag, so it must
	// stay a positional rather than be swallowed as a flag argument.
	"base64": {"w": true, "wrap": true},
	"base32": {"w": true, "wrap": true},
	"basenc": {"w": true, "wrap": true},
	// uuencode takes no value-bearing flags relevant to the file positional.
	"uuencode": {},
	"rev":      {},
	// cut's selection flags can be given separately (`cut -c 1-5 file`,
	// `cut -d : -f 1 file`), so consume their value to avoid mistaking it for the
	// file positional.
	"cut": {"b": true, "c": true, "f": true, "d": true},
	// dd uses `if=`/`of=` operands, not flags; handled specially below.
	"dd": {},
}

// DetectSensitiveFileRead checks whether cmd targets a sensitive file.
func DetectSensitiveFileRead(cmd string, l *lease.Lease) (string, bool) {
	normalized := NormalizeCommand(strings.TrimSpace(cmd))
	if normalized == "" {
		return "", false
	}
	fields := strings.Fields(normalized)
	if len(fields) < 2 {
		return "", false
	}
	program := strings.ToLower(fields[0])
	if !sensitiveReadPrograms[program] {
		return "", false
	}
	valueFlags := readProgramFlagsTakingValue[program]

	positionals := make([]string, 0, len(fields)-1)
	skipNext := false
	for _, arg := range fields[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(arg, "--") {
			continue
		}
		if strings.HasPrefix(arg, "-") && len(arg) >= 2 {
			flagBody := arg[1:]
			if flagBody == "-" {
				continue
			}
			// A single-char flag whose value is the next token (e.g. `-w 0`).
			// Bundled forms (`-w0`) carry the value in the same token, so only
			// the bare single-char case consumes the following arg.
			if len(flagBody) == 1 && valueFlags[flagBody] {
				skipNext = true
			}
			continue
		}
		positionals = append(positionals, arg)
	}

	// uuencode's synopsis is `uuencode [-m] [file] decode_pathname`: the trailing
	// operand is only the name embedded in the output header, and stdin is read
	// when no `file` operand is given. So a sensitive *read* exists only in the
	// two-operand form, and only the FIRST operand is the local file. Scanning
	// every positional would falsely flag `echo data | uuencode .env`, where
	// `.env` is the decode name, not a file being read.
	if program == "uuencode" {
		if len(positionals) >= 2 && IsSensitivePathResolved(positionals[0], l) {
			return positionals[0], true
		}
		return "", false
	}

	// dd reads its input from the `if=FILE` operand, not a bare positional, so
	// scan the operands for it (`dd if=.env of=/dev/stdout`, `dd if=.aws/creds`).
	if program == "dd" {
		for _, p := range positionals {
			if path, ok := strings.CutPrefix(p, "if="); ok && IsSensitivePathResolved(path, l) {
				return path, true
			}
		}
		return "", false
	}

	for _, p := range positionals {
		if IsSensitivePathResolved(p, l) {
			return p, true
		}
	}
	return "", false
}

// IsRedirectSensitiveRead reports whether cmd feeds a sensitive file into a
// command via input redirection (`tr a b < .env`, `cmd 0<.env`). The redirect
// reads the file regardless of the program, so this catches stdin-only tools
// (tr, and anything reading from `< secret`) that the program-list classifier
// never sees. It deliberately ignores `<<` (heredoc), `<<<` (here-string),
// `<>` (read-write), and `<(…)` (process substitution).
func IsRedirectSensitiveRead(cmd string, l *lease.Lease) (string, bool) {
	fields := strings.Fields(NormalizeCommand(strings.TrimSpace(cmd)))
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		// Strip an optional leading file-descriptor number (`0<`, `6<`).
		j := 0
		for j < len(tok) && tok[j] >= '0' && tok[j] <= '9' {
			j++
		}
		if j >= len(tok) || tok[j] != '<' {
			continue
		}
		rest := tok[j+1:]
		// Reject <<, <<<, <>, <( — none are a plain file input redirect.
		if strings.HasPrefix(rest, "<") || strings.HasPrefix(rest, ">") || strings.HasPrefix(rest, "(") {
			continue
		}
		target := rest
		if target == "" { // `< file` — the path is the next token
			if i+1 >= len(fields) {
				continue
			}
			target = fields[i+1]
		}
		if IsSensitivePathResolved(target, l) {
			return target, true
		}
	}
	return "", false
}

// interpreterOneLinerPrefixes are interpreters whose -c/-e/-r inline source can
// open files directly, bypassing the argv-based read classifier.
var interpreterOneLinerPrefixes = []string{
	"python ", "python3 ", "python2 ", "node ", "nodejs ",
	"ruby ", "perl ", "php ", "bun ", "deno ", "rscript ",
}

// IsInterpreterSensitiveRead reports whether cmd is an interpreter one-liner
// (e.g. `python -c "open('.env').read()"`, `node -e "fs.readFileSync('.env')"`)
// whose inline source references a sensitive file path, and returns that path.
// This closes the documented residual where a credential file is opened from
// inside interpreter source the shell read-classifier never inspects. It is a
// LITERAL-path heuristic: a dynamically-constructed or obfuscated path is not
// caught (and remains backstopped by the downstream IFC floors).
func IsInterpreterSensitiveRead(cmd string, l *lease.Lease) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	matched := false
	for _, p := range interpreterOneLinerPrefixes {
		if strings.HasPrefix(lower, p) {
			matched = true
			break
		}
	}
	if !matched || !hasInlineCodeFlag(cmd) {
		return "", false
	}
	for _, tok := range interpreterCodeTokens(cmd) {
		if IsSensitivePath(tok, l) {
			return tok, true
		}
	}
	return "", false
}

func hasInlineCodeFlag(cmd string) bool {
	fields := strings.Fields(cmd)
	for i := 1; i < len(fields); i++ {
		part := fields[i]
		if part == "-c" || part == "-e" || part == "-r" || part == "--eval" {
			return true
		}
		// Bundled short flags like `-Sc` / `-e'...'`: last letter is the code flag.
		if strings.HasPrefix(part, "-") && !strings.HasPrefix(part, "--") && len(part) > 2 {
			switch part[len(part)-1] {
			case 'c', 'e', 'r':
				return true
			}
		}
	}
	return false
}

// interpreterCodeTokens splits a command into candidate path tokens on quotes
// and common code delimiters, so a path embedded in interpreter source surfaces
// as its own token for the sensitive-path check.
func interpreterCodeTokens(cmd string) []string {
	return strings.FieldsFunc(cmd, func(r rune) bool {
		switch r {
		case '\'', '"', '(', ')', '[', ']', '{', '}', ',', ';', ' ', '\t', '=', '+', '`', '<', '>':
			return true
		}
		return false
	})
}
