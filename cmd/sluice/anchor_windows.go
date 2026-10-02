package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/dark-14100/sluice/pkg/evidence"
)

func defaultDataDir() string { return "sluice-data" }

func attachAnchor(*evidence.Bundle, string, string) error {
	return errors.New("signed checkpoints need the Unix runtime")
}

func runAnchor(_ []string, _ io.Writer, stderr io.Writer) int {
	fmt.Fprintln(stderr, "sluice anchor: requires the Unix runtime")
	return exitFailure
}
