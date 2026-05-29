package hooks

import (
	"path/filepath"
	"strings"
)

// safeEnvVars is a strict ALLOWLIST of environment variables that are provably
// non-secret — process/locale/path metadata that never holds a credential.
// ENV-1 uses an allowlist, never a credential-name denylist: a denylist
// (*_TOKEN/*_KEY/SECRET/…) is trivially bypassed by secret-bearing vars with
// innocuous names (DATABASE_URL, KUBECONFIG, DOCKER_AUTH_CONFIG, registry auth,
// connection strings). Anything not on this list keeps the approval prompt.
var safeEnvVars = map[string]bool{
	"PATH": true, "HOME": true, "PWD": true, "OLDPWD": true, "SHELL": true,
	"USER": true, "LOGNAME": true, "HOSTNAME": true, "HOST": true,
	"LANG": true, "LANGUAGE": true, "LC_ALL": true, "LC_CTYPE": true,
	"TERM": true, "TERM_PROGRAM": true, "COLORTERM": true,
	"TMPDIR": true, "TMP": true, "TEMP": true,
	"EDITOR": true, "VISUAL": true, "PAGER": true,
	"DISPLAY": true, "TZ": true, "COLUMNS": true, "LINES": true,
	"GOPATH": true, "GOROOT": true,
}

// singleSafeEnvVarRead reports the variable name when command is exactly a
// `printenv <VAR>` read of ONE variable on the safe allowlist. It is
// deliberately narrow: bulk dumps (`env`, bare `printenv`, `set`), multiple
// vars, any flags, `echo $VAR`, or any non-allowlisted name all return
// ("", false) so they keep the approval prompt (fail-closed on uncertainty).
func singleSafeEnvVarRead(command string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) != 2 {
		return "", false
	}
	if filepath.Base(fields[0]) != "printenv" {
		return "", false
	}
	name := fields[1]
	if strings.HasPrefix(name, "-") { // a flag, not a var name
		return "", false
	}
	if !safeEnvVars[name] {
		return "", false
	}
	return name, true
}
