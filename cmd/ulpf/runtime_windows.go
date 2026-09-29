package main

import (
	"fmt"
	"io"
)

func runStart(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, "ulpf: the durable unified runtime requires Unix flock; run it in the Linux container")
	return exitFailure
}
