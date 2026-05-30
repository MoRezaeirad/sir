package evidence

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInjectionScannerCorpus scores the heuristic injection scanner
// (ScanMCPResponseForInjection) against a small labelled corpus so the catch
// rate (recall) and false-positive rate (precision) are measured, reproducible,
// and guarded against regression — the P0.2 "measure the heuristic layer" item
// from docs/research/roadmap-to-best.md.
//
// The scanner is intentionally heuristic (~50 patterns); this test does NOT
// demand 100% recall. It records the honest number (paraphrased / multilingual
// payloads in the corpus are expected misses) and asserts conservative floors
// so a future change cannot silently degrade detection or start over-blocking
// benign coding text. The misses are exactly why the turn-scoped integrity-flow
// egress gate exists as a downstream backstop.
func TestInjectionScannerCorpus(t *testing.T) {
	positives := loadCorpus(t, "positive.txt")
	negatives := loadCorpus(t, "negative.txt")
	if len(positives) == 0 || len(negatives) == 0 {
		t.Fatal("corpus is empty — testdata/injection/{positive,negative}.txt missing or all comments")
	}

	detected := func(s string) bool { return len(ScanMCPResponseForInjection(s)) > 0 }

	var tp, fn int
	var missed []string
	for _, p := range positives {
		if detected(p) {
			tp++
		} else {
			fn++
			missed = append(missed, p)
		}
	}
	var fp, tn int
	var falsePos []string
	for _, n := range negatives {
		if detected(n) {
			fp++
			falsePos = append(falsePos, n)
		} else {
			tn++
		}
	}

	recall := ratio(tp, tp+fn)      // catch rate over injections
	precision := ratio(tp, tp+fp)   // 1 - over-block among flagged
	specificity := ratio(tn, tn+fp) // benign-pass rate
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}

	t.Logf("injection scanner on %d positives / %d negatives:", len(positives), len(negatives))
	t.Logf("  recall=%.3f (tp=%d fn=%d)  precision=%.3f (fp=%d)  specificity=%.3f  f1=%.3f",
		recall, tp, fn, precision, fp, specificity, f1)
	for _, m := range missed {
		t.Logf("  MISS (honest residual): %s", truncate(m))
	}
	for _, fpv := range falsePos {
		t.Logf("  FALSE POSITIVE (over-block): %s", truncate(fpv))
	}

	// Floors are conservative regression guards, set below the observed values
	// (run the test to see the current numbers in the log above). Tighten as the
	// scanner improves; never loosen silently.
	const minRecall = 0.55    // it must catch the literal-pattern majority
	const minPrecision = 0.90 // it must almost never flag benign coding text
	if recall < minRecall {
		t.Errorf("recall %.3f below floor %.2f — detection regressed", recall, minRecall)
	}
	if precision < minPrecision {
		t.Errorf("precision %.3f below floor %.2f — scanner is over-blocking benign text", precision, minPrecision)
	}
}

func loadCorpus(t *testing.T, name string) []string {
	t.Helper()
	path := filepath.Join(repoRootFromTest(t), "testdata", "injection", name)
	f, err := os.Open(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("open corpus %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read corpus %s: %v", path, err)
	}
	return out
}

// repoRootFromTest walks up from the test's working dir to the module root
// (the directory containing go.mod), so the corpus path resolves regardless of
// how `go test` is invoked.
func repoRootFromTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found walking up from %s", dir)
		}
		dir = parent
	}
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
