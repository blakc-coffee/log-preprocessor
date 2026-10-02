//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The demo is the project's pitch. It must run offline, catch every attack it stages, say so, and
// leave nothing behind. It returns an error, not a pass, if an attack goes undetected.
func TestDemoCatchesEveryAttackAndCleansUp(t *testing.T) {
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "sluice-demo-*"))
	var out bytes.Buffer
	if err := demo(&out, true); err != nil {
		t.Fatalf("demo failed: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"VERIFIED", "CAUGHT: tampering detected", "does not come from that raw log", "signature does not match"} {
		if !strings.Contains(got, want) {
			t.Fatalf("demo output is missing %q:\n%s", want, got)
		}
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "sluice-demo-*"))
	if len(after) != len(before) {
		t.Fatalf("the demo left temporary files behind: %v", after)
	}
}
