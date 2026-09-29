package source_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/source"
)

// TestGlobMatchingNothingIsNotAnError, and its opposite.
//
// A pattern that matches nothing is normal: a log directory may be empty right
// now, and in tail mode files appear later. A literal path is a promise that a
// file is there, so a typo in one must fail by name rather than silently read
// nothing — which is how a source appears healthy while ingesting zero records.
func TestGlobVersusLiteralPaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "real.log"), []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("pattern matching nothing is fine", func(t *testing.T) {
		src, err := source.NewFile(source.FileConfig{
			ID: "g", Paths: []string{filepath.Join(dir, "nothing-*.log")}, Mode: source.ModeOnce,
		})
		if err != nil {
			t.Fatal(err)
		}
		h := start(t, src)
		if err := h.waitRun(); err != nil {
			t.Errorf("a pattern matching no files failed the source: %v", err)
		}
	})

	t.Run("missing literal path is an error", func(t *testing.T) {
		src, err := source.NewFile(source.FileConfig{
			ID: "l", Paths: []string{filepath.Join(dir, "typo.log")}, Mode: source.ModeOnce,
		})
		if err != nil {
			t.Fatal(err)
		}
		h := start(t, src)
		err = h.waitRun()
		if err == nil {
			t.Fatal("a missing file was ignored; a typo in a path must not look like success")
		}
		if !strings.Contains(err.Error(), "typo.log") {
			t.Errorf("the error does not name the file: %v", err)
		}
	})

	t.Run("pattern matching files reads them", func(t *testing.T) {
		src, err := source.NewFile(source.FileConfig{
			ID: "m", Paths: []string{filepath.Join(dir, "*.log")}, Mode: source.ModeOnce,
		})
		if err != nil {
			t.Fatal(err)
		}
		h := start(t, src)
		got := h.waitFor(2)
		if len(got) != 2 {
			t.Errorf("%d records, want 2", len(got))
		}
	})
}

// TestTailModeIsRefusedRatherThanSilentlyDoingSomethingElse. Behaving like
// `once` would look like it worked and quietly stop following the file.
func TestTailModeIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.log")
	if err := os.WriteFile(path, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := source.NewFile(source.FileConfig{
		ID: "t", Paths: []string{path}, Mode: source.ModeTail,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := start(t, src)
	if err := h.waitRun(); err == nil {
		t.Fatal("tail mode silently behaved like once")
	}
}
