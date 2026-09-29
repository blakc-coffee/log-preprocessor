//go:build !windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
)

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "vault directory")
	deep := fs.Bool("deep", false, "re-read every record")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "ulpf verify: --dir is required")
		return exitUsage
	}
	v, err := vault.Open(vault.Options{Dir: *dir, ReadOnly: true})
	if err != nil {
		fmt.Fprintf(stderr, "FAIL vault: %v\n", err)
		if errors.Is(err, vault.ErrCorrupt) {
			return exitFailure
		}
		return exitUsage
	}
	defer v.Close()
	report, err := v.VerifyChain(context.Background(), *deep)
	if err != nil {
		fmt.Fprintf(stderr, "FAIL vault: %v\n", err)
		return exitFailure
	}
	if !report.OK {
		fmt.Fprintf(stderr, "FAIL vault: segment=%d reason=%s\n", report.FirstBad, report.Reason)
		return exitFailure
	}
	fmt.Fprintf(stdout, "PASS vault: segments=%d records=%d deep=%v\n", report.Segments, report.Records, *deep)
	return exitOK
}
