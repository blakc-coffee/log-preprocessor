package main

import (
	"fmt"
	"io"
)

func runStart(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, "sluice: the durable unified runtime requires Unix flock; run it in the Linux container")
	return exitFailure
}

func runInteractive(_ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, "sluice: the durable runtime requires Unix flock; run it in the Linux container, then use `sluice tui --url ...`")
	return exitFailure
}
