package vault

import (
	"os"
	"path/filepath"
	"testing"
)

// A read-only open of a directory that does not exist must fail and must not create it. Run as root
// (CI, containers) the old behaviour silently created the directory and reported an empty vault.
func TestReadOnlyOpenNeverCreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "typo", "vault")
	if _, err := Open(Options{Dir: dir, ReadOnly: true}); err == nil {
		t.Fatal("opening a missing vault read-only must fail")
	}
	if _, err := os.Stat(filepath.Dir(dir)); !os.IsNotExist(err) {
		t.Fatalf("a read-only open created directories: %v", err)
	}
	f := filepath.Join(t.TempDir(), "afile")
	_ = os.WriteFile(f, []byte("x"), 0o600)
	if _, err := Open(Options{Dir: f, ReadOnly: true}); err == nil {
		t.Fatal("a file is not a vault")
	}
}
