package classify

import (
	"path/filepath"
	"strings"
)

// IsDangerousShellCommand reports whether cmd is a high-blast-radius shell
// operation that should require explicit approval even in a clean session.
func IsDangerousShellCommand(cmd string) bool {
	return isDangerousShellCommand(cmd, 0)
}

func isDangerousShellCommand(cmd string, depth int) bool {
	if depth > 3 {
		return false
	}
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	lower := strings.ToLower(cmd)
	if strings.Contains(lower, ":(){") && strings.Contains(lower, ":|:&") {
		return true
	}

	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return false
	}
	name := commandName(fields[0])

	if inner, ok := windowsShellWrapperInner(name, fields); ok {
		return isDangerousShellCommand(inner, depth+1)
	}

	switch {
	case isDangerousRm(name, fields):
		return true
	case isDangerousPowerShellRemove(name, fields):
		return true
	case isDangerousFind(name, fields):
		return true
	case isDangerousDiskCommand(name, fields):
		return true
	case isDangerousPermissionCommand(name, fields):
		return true
	case isDangerousGitCommand(cmd, fields):
		return true
	case isDangerousRedirection(fields):
		return true
	case isDangerousWindowsCommand(name, fields):
		return true
	case isDangerousMacCommand(name, fields):
		return true
	case isDangerousResourceCommand(name, fields):
		return true
	default:
		return false
	}
}

func commandName(token string) string {
	token = cleanShellToken(token)
	base := filepath.Base(token)
	if idx := strings.LastIndexAny(base, `\/`); idx >= 0 {
		base = base[idx+1:]
	}
	base = strings.ToLower(base)
	return strings.TrimSuffix(base, ".exe")
}

func cleanShellToken(token string) string {
	token = strings.TrimSpace(token)
	token = strings.Trim(token, `"'`)
	token = strings.TrimRight(token, ";,")
	return token
}

func cleanLowerToken(token string) string {
	token = strings.ToLower(cleanShellToken(token))
	token = strings.ReplaceAll(token, `\`, "/")
	return strings.TrimRight(token, ";")
}

func windowsShellWrapperInner(name string, fields []string) (string, bool) {
	switch name {
	case "powershell", "pwsh":
		for i := 1; i < len(fields); i++ {
			arg := strings.ToLower(cleanShellToken(fields[i]))
			if (arg == "-command" || arg == "-c") && i+1 < len(fields) {
				return dequoteOuter(strings.Join(fields[i+1:], " ")), true
			}
		}
	case "cmd":
		for i := 1; i < len(fields); i++ {
			arg := strings.ToLower(cleanShellToken(fields[i]))
			if (arg == "/c" || arg == "/k") && i+1 < len(fields) {
				return dequoteOuter(strings.Join(fields[i+1:], " ")), true
			}
		}
	}
	return "", false
}

func isDangerousRm(name string, fields []string) bool {
	if name != "rm" {
		return false
	}
	if !hasRecursiveFlag(fields[1:]) {
		return false
	}
	for _, f := range fields[1:] {
		if isCriticalDeleteTarget(f) {
			return true
		}
	}
	return false
}

func isDangerousPowerShellRemove(name string, fields []string) bool {
	switch name {
	case "remove-item", "ri":
	default:
		return false
	}
	if !hasRecursiveFlag(fields[1:]) {
		return false
	}
	for _, f := range fields[1:] {
		if isCriticalDeleteTarget(f) {
			return true
		}
	}
	return false
}

func isDangerousFind(name string, fields []string) bool {
	if name != "find" || len(fields) < 2 {
		return false
	}
	criticalStart := false
	for _, f := range fields[1:] {
		if strings.HasPrefix(cleanLowerToken(f), "-") {
			continue
		}
		criticalStart = isCriticalDeleteTarget(f)
		break
	}
	if !criticalStart {
		return false
	}
	for i, f := range fields[1:] {
		tok := cleanLowerToken(f)
		if tok == "-delete" {
			return true
		}
		if tok == "-exec" && containsRmRecursive(fields[i+2:]) {
			return true
		}
	}
	return false
}

func containsRmRecursive(fields []string) bool {
	for i, f := range fields {
		if commandName(f) == "rm" && hasRecursiveFlag(fields[i+1:]) {
			return true
		}
	}
	return false
}

func isDangerousDiskCommand(name string, fields []string) bool {
	if name == "mkfs" || strings.HasPrefix(name, "mkfs.") || name == "mke2fs" ||
		name == "newfs" || name == "wipefs" || name == "blkdiscard" {
		return true
	}
	if name == "dd" {
		for _, f := range fields[1:] {
			tok := cleanLowerToken(f)
			if strings.HasPrefix(tok, "of=") && isDangerousDevicePath(strings.TrimPrefix(tok, "of=")) {
				return true
			}
		}
	}
	if name == "tee" {
		for _, f := range fields[1:] {
			if isDangerousDevicePath(f) {
				return true
			}
		}
	}
	if name == "cp" {
		if target, ok := lastPositionalTarget(fields[1:]); ok && isDangerousDevicePath(target) {
			return true
		}
	}
	if name == "shred" {
		for _, f := range fields[1:] {
			if isDangerousDevicePath(f) {
				return true
			}
		}
	}
	if name == "sgdisk" && containsAnyToken(fields[1:], "--zap-all", "-zap-all") {
		return true
	}
	if name == "parted" && containsAnyToken(fields[1:], "mklabel") {
		return true
	}
	if name == "cryptsetup" && containsAnyToken(fields[1:], "luksformat") {
		return true
	}
	return false
}

func isDangerousPermissionCommand(name string, fields []string) bool {
	switch name {
	case "chmod":
		return hasRecursiveFlag(fields[1:]) && containsWorldWritableMode(fields[1:])
	case "chown", "chgrp":
		if !hasRecursiveFlag(fields[1:]) {
			return false
		}
		for _, f := range fields[1:] {
			if isCriticalDeleteTarget(f) {
				return true
			}
		}
	}
	return false
}

func isDangerousGitCommand(cmd string, fields []string) bool {
	if len(fields) < 2 || commandName(fields[0]) != "git" {
		return false
	}
	if GitSubcommandIs(cmd, "clean") {
		// Accumulate the short-flag letters across every `-`-prefixed token so
		// that separated flags (`git clean -f -d -x`) are treated the same as a
		// combined token (`git clean -fdx`). Both wipe untracked AND ignored
		// files, so requiring f+d+x in a single token would let the equivalent
		// separated form slip past as an ordinary execute_dry_run.
		var hasF, hasD, hasX bool
		for _, f := range fields[1:] {
			tok := cleanLowerToken(f)
			switch {
			case strings.HasPrefix(tok, "--"):
				// Long forms: --force (f), --d is not valid; -x has no long alias.
				switch tok {
				case "--force":
					hasF = true
				}
			case strings.HasPrefix(tok, "-"):
				// Short cluster, e.g. -f, -fd, -fdx.
				hasF = hasF || strings.Contains(tok, "f")
				hasD = hasD || strings.Contains(tok, "d")
				hasX = hasX || strings.Contains(tok, "x")
			}
		}
		if hasF && hasD && hasX {
			return true
		}
	}
	if GitSubcommandIs(cmd, "reset") && containsAnyToken(fields[1:], "--hard") {
		return true
	}
	if GitSubcommandIs(cmd, "checkout") || GitSubcommandIs(cmd, "restore") {
		for _, f := range fields[1:] {
			if isCriticalDeleteTarget(f) {
				return true
			}
		}
	}
	return false
}

func isDangerousRedirection(fields []string) bool {
	for i, f := range fields {
		tok := cleanLowerToken(f)
		if isRedirectToken(tok) && i+1 < len(fields) && isDangerousDevicePath(fields[i+1]) {
			return true
		}
		if strings.Contains(tok, ">") {
			target := tok[strings.LastIndex(tok, ">")+1:]
			if isDangerousDevicePath(target) {
				return true
			}
		}
	}
	return false
}

func isDangerousWindowsCommand(name string, fields []string) bool {
	switch name {
	case "del", "erase":
		return containsAnyToken(fields[1:], "/s") && anyCriticalTarget(fields[1:])
	case "rmdir", "rd":
		return containsAnyToken(fields[1:], "/s") && anyCriticalTarget(fields[1:])
	case "format":
		return anyWindowsDriveTarget(fields[1:])
	case "diskpart", "format-volume", "clear-disk", "initialize-disk", "remove-partition":
		return true
	case "set-partition":
		return containsAnyToken(fields[1:], "-isactive")
	case "icacls":
		return containsAnyToken(fields[1:], "/t") && containsAnyToken(fields[1:], "/grant") &&
			containsEveryoneFullControl(fields[1:])
	case "takeown":
		return containsAnyToken(fields[1:], "/r") && containsAnyToken(fields[1:], "/f") &&
			anyCriticalTarget(fields[1:])
	case "cipher":
		for _, f := range fields[1:] {
			if strings.HasPrefix(cleanLowerToken(f), "/w:") {
				return true
			}
		}
	}
	return false
}

func isDangerousMacCommand(name string, fields []string) bool {
	if name == "diskutil" {
		for i, f := range fields[1:] {
			tok := cleanLowerToken(f)
			switch tok {
			case "erasedisk", "erasevolume", "partitiondisk", "secureerase":
				return true
			case "apfs":
				if i+2 < len(fields) && cleanLowerToken(fields[i+2]) == "deletecontainer" {
					return true
				}
			}
		}
	}
	return name == "asr" && containsAnyToken(fields[1:], "restore") && containsAnyToken(fields[1:], "--erase")
}

func isDangerousResourceCommand(name string, fields []string) bool {
	if name == "kill" && containsAnyToken(fields[1:], "-9") && containsAnyToken(fields[1:], "-1") {
		return true
	}
	return false
}

func hasRecursiveFlag(fields []string) bool {
	for _, f := range fields {
		tok := cleanLowerToken(f)
		switch tok {
		case "-r", "-R", "--recursive", "-recurse", "/s":
			return true
		}
		if strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") && strings.Contains(tok, "r") {
			return true
		}
	}
	return false
}

func containsWorldWritableMode(fields []string) bool {
	for _, f := range fields {
		switch cleanLowerToken(f) {
		// Symbolic modes that grant write to "other" (or everyone), and the
		// numeric modes whose last digit has the world-write bit set. `o+w`
		// and `666` are as dangerous as the previously-covered `a+w`/`777`.
		case "777", "0777", "666", "0666", "a+w", "ugo+w", "o+w", "+w":
			return true
		}
	}
	return false
}

func anyCriticalTarget(fields []string) bool {
	for _, f := range fields {
		if isCriticalDeleteTarget(f) {
			return true
		}
	}
	return false
}

func anyWindowsDriveTarget(fields []string) bool {
	for _, f := range fields {
		if isWindowsDriveRoot(f) {
			return true
		}
	}
	return false
}

func isCriticalDeleteTarget(token string) bool {
	tok := cleanLowerToken(token)
	tok = strings.TrimPrefix(tok, "--")
	switch tok {
	case "", "-", "--":
		return false
	case "/", "/*", "~", "~/", "~/*", "$home", "${home}", "$env:home", "$env:userprofile",
		"%userprofile%", "%systemdrive%", "%homedrive%", "$pwd", "${pwd}", "$env:pwd",
		"$home/*", "${home}/*", "$env:home/*", "$env:userprofile/*", "$pwd/*", "${pwd}/*",
		"$env:pwd/*", ".", "./", "./*", "..", "../", "../*":
		return true
	}
	return isWindowsDriveRoot(tok) || isWindowsEnvRoot(tok)
}

func isWindowsDriveRoot(token string) bool {
	tok := cleanLowerToken(token)
	tok = strings.TrimRight(tok, "/")
	if len(tok) < 2 || tok[1] != ':' {
		return false
	}
	drive := tok[0]
	if drive < 'a' || drive > 'z' {
		return false
	}
	return len(tok) == 2 || tok == string([]byte{drive, ':', '*'}) || tok == string([]byte{drive, ':', '/', '*'})
}

func isWindowsEnvRoot(tok string) bool {
	tok = strings.TrimRight(cleanLowerToken(tok), "/")
	switch tok {
	case "%systemdrive%", "%homedrive%", "%userprofile%":
		return true
	}
	return strings.HasPrefix(tok, "%systemdrive%/") || strings.HasPrefix(tok, "%homedrive%/") ||
		strings.HasPrefix(tok, "%userprofile%/")
}

func isDangerousDevicePath(token string) bool {
	tok := cleanLowerToken(token)
	tok = strings.TrimRight(tok, "/")
	for _, safe := range []string{
		"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
		"/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd", "/dev/tty",
	} {
		if tok == safe || strings.HasPrefix(tok, safe+"/") {
			return false
		}
	}
	for _, prefix := range []string{
		"/dev/sd", "/dev/xvd", "/dev/vd", "/dev/hd", "/dev/nvme",
		"/dev/disk", "/dev/rdisk", "/dev/mapper/", "/dev/dm-", "/dev/md",
	} {
		if strings.HasPrefix(tok, prefix) {
			return true
		}
	}
	return false
}

func isRedirectToken(tok string) bool {
	return tok == ">" || tok == "1>" || tok == ">>" || tok == "1>>"
}

func containsAnyToken(fields []string, wants ...string) bool {
	for _, f := range fields {
		tok := cleanLowerToken(f)
		for _, want := range wants {
			if tok == strings.ToLower(want) {
				return true
			}
		}
	}
	return false
}

func lastPositionalTarget(fields []string) (string, bool) {
	for i := len(fields) - 1; i >= 0; i-- {
		tok := cleanShellToken(fields[i])
		if tok == "" || strings.HasPrefix(tok, "-") {
			continue
		}
		return tok, true
	}
	return "", false
}

func containsEveryoneFullControl(fields []string) bool {
	for _, f := range fields {
		tok := cleanLowerToken(f)
		if tok == "everyone:f" || tok == "everyone:(f)" || tok == "*s-1-1-0:f" || tok == "*s-1-1-0:(f)" {
			return true
		}
	}
	return false
}
