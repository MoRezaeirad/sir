package main

import (
	"fmt"
	"os"
)

func cmdHarnessCaptureGenerate(args []string) {
	_ = args
	fmt.Fprintln(os.Stderr, "sir harness capture-generate requires Unix process-group APIs")
	os.Exit(1)
}
