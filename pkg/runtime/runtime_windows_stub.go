//go:build !windows

package runtime

import "fmt"

func runAgentWindows(projectRoot, bin string, opts Options) (int, error) {
	return 0, fmt.Errorf("windows containment mode is not available on this platform")
}
