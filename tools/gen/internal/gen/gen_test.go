package gen

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestDeterministic is the guarantee the whole corpus rests on: the same seed
// must produce the same bytes. Two runs into two directories must be identical
// file for file, manifest included.
func TestDeterministic(t *testing.T) {
	for _, sample := range []bool{false, true} {
		a, b := t.TempDir(), t.TempDir()
		opts := Options{Seed: 20260928, Sample: sample}
		opts.Out = a
		if err := Run(opts); err != nil {
			t.Fatal(err)
		}
		opts.Out = b
		if err := Run(opts); err != nil {
			t.Fatal(err)
		}
		assertTreesEqual(t, a, b)
	}
}

// TestSeedChangesOutput guards against a generator that ignores its seed,
// which would pass TestDeterministic trivially.
func TestSeedChangesOutput(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if err := Run(Options{Seed: 1, Out: a, Sample: true}); err != nil {
		t.Fatal(err)
	}
	if err := Run(Options{Seed: 2, Out: b, Sample: true}); err != nil {
		t.Fatal(err)
	}
	for _, s := range Sources() {
		x := readFile(t, filepath.Join(a, s.Name))
		y := readFile(t, filepath.Join(b, s.Name))
		if bytes.Equal(x, y) {
			t.Errorf("%s: identical output under different seeds", s.Name)
		}
	}
}

// TestSampleIsPrefixOfFull is not a requirement, but it falls out of seeding
// each source once and emitting records in a single pass. If it ever breaks,
// a source has started consuming its RNG in a count-dependent way, which is
// worth knowing about.
func TestSampleIsPrefixOfFull(t *testing.T) {
	full, sample := t.TempDir(), t.TempDir()
	if err := Run(Options{Seed: 20260928, Out: full}); err != nil {
		t.Fatal(err)
	}
	if err := Run(Options{Seed: 20260928, Out: sample, Sample: true}); err != nil {
		t.Fatal(err)
	}
	for _, s := range Sources() {
		f := readFile(t, filepath.Join(full, s.Name))
		p := readFile(t, filepath.Join(sample, s.Name))
		if !bytes.HasPrefix(f, p) {
			t.Errorf("%s: sample profile is not a prefix of the full profile", s.Name)
		}
	}
}

// TestNoEmptyRecords catches an emitter that silently produced nothing.
func TestNoEmptyRecords(t *testing.T) {
	dir := t.TempDir()
	if err := Run(Options{Seed: 20260928, Out: dir, Sample: true}); err != nil {
		t.Fatal(err)
	}
	for _, s := range Sources() {
		if b := readFile(t, filepath.Join(dir, s.Name)); len(b) == 0 {
			t.Errorf("%s: empty", s.Name)
		}
	}
}

func assertTreesEqual(t *testing.T, a, b string) {
	t.Helper()
	names := listFiles(t, a)
	if got := listFiles(t, b); len(got) != len(names) {
		t.Fatalf("different file counts: %v vs %v", names, got)
	}
	for _, n := range names {
		x := readFile(t, filepath.Join(a, n))
		y := readFile(t, filepath.Join(b, n))
		if !bytes.Equal(x, y) {
			t.Errorf("%s: two runs with the same seed differ (%d vs %d bytes)", n, len(x), len(y))
		}
	}
}

func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
