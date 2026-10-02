package atomicfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReplacesAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	for _, want := range []string{"one", "two, longer than one"} {
		if err := Write(p, []byte(want), 0o640); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != want {
			t.Fatalf("read %q err %v, want %q", got, err, want)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("a temporary file was left behind: %v", entries)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

// A failed write must leave the previous contents intact.
func TestFailedWriteKeepsOldContents(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	if err := Write(p, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // cannot create the temp file
		t.Skip("cannot make the directory read-only here")
	}
	defer os.Chmod(dir, 0o750)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := Write(p, []byte(strings.Repeat("x", 100)), 0o640); err == nil {
		t.Fatal("expected an error")
	}
	if got, _ := os.ReadFile(p); string(got) != "old" {
		t.Fatalf("old contents lost: %q", got)
	}
}
