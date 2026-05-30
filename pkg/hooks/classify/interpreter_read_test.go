package classify

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

func TestIsInterpreterSensitiveRead(t *testing.T) {
	l := lease.DefaultLease()

	sensitive := []string{
		`python -c "print(open('.env').read())"`,
		`python3 -c "open('.env')"`,
		`node -e "console.log(require('fs').readFileSync('.env','utf8'))"`,
		`ruby -e "puts File.read('.env')"`,
		`perl -e 'open(F, ".env"); print <F>;'`,
	}
	for _, cmd := range sensitive {
		if path, ok := IsInterpreterSensitiveRead(cmd, l); !ok || path == "" {
			t.Errorf("IsInterpreterSensitiveRead(%q) = %q,%v; want a sensitive path", cmd, path, ok)
		}
	}

	benign := []string{
		`python3 -c "print(1+1)"`,
		`node -e "console.log(process.env.PATH)"`, // env var, not the .env file
		`python -c "open('README.md').read()"`,
		`ls -la`,
		`python manage.py runserver`, // a script, not -c inline source
		`echo "open('.env')"`,        // not an interpreter
	}
	for _, cmd := range benign {
		if path, ok := IsInterpreterSensitiveRead(cmd, l); ok {
			t.Errorf("IsInterpreterSensitiveRead(%q) flagged %q (false positive)", cmd, path)
		}
	}
}
