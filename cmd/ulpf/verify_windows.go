//go:build windows

package main

import (
	"fmt"
	"io"
)

func runVerify(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, "ulpf verify: the current vault implementation requires Unix flock; run verification in the Linux container")
	return exitFailure
}
