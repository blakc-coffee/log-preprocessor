package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/blakc-coffee/log-preprocessor/tools/gen/internal/gen"
)

// TestManifestIsSelfConsistent re-derives every number in the manifest from the
// generated files, using its own hashing rather than the generator's. If the
// generator ever records an offset or a hash it did not actually write, this
// fails. It is deliberately independent of the writer's bookkeeping.
func TestManifestIsSelfConsistent(t *testing.T) {
	for _, sample := range []bool{false, true} {
		dir := t.TempDir()
		if err := gen.Run(gen.Options{Seed: 20260928, Out: dir, Sample: sample}); err != nil {
			t.Fatal(err)
		}
		checkCorpus(t, dir)
	}
}

func checkCorpus(t *testing.T, dir string) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m gen.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if !m.Generator.Synthetic {
		t.Error("manifest does not declare the corpus synthetic")
	}

	bodies := map[string][]byte{}
	counted := map[string]int{}

	for name, fi := range m.Files {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		bodies[name] = body
		if len(body) != fi.Bytes {
			t.Errorf("%s: manifest says %d bytes, file is %d", name, fi.Bytes, len(body))
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != fi.SHA256 {
			t.Errorf("%s: manifest sha256 %s, recomputed %s", name, fi.SHA256, got)
		}
	}

	for _, r := range m.Records {
		body, ok := bodies[r.SourceFile]
		if !ok {
			t.Errorf("%s: references unknown file %q", r.RecordID, r.SourceFile)
			continue
		}
		counted[r.SourceFile]++

		if r.ByteStart < 0 || r.ByteEnd < r.ByteStart || r.ByteEnd > len(body) {
			t.Errorf("%s: byte range [%d,%d) outside %s (%d bytes)",
				r.RecordID, r.ByteStart, r.ByteEnd, r.SourceFile, len(body))
			continue
		}
		slice := body[r.ByteStart:r.ByteEnd]
		sum := sha256.Sum256(slice)
		if got := hex.EncodeToString(sum[:]); got != r.ExpectedSHA256 {
			t.Errorf("%s: expected_sha256 does not match bytes[%d:%d]", r.RecordID, r.ByteStart, r.ByteEnd)
		}

		// byte_end excludes the terminator, so the terminator must be the very
		// next thing in the file.
		want := map[string]string{gen.TermLF: "\n", gen.TermCRLF: "\r\n", gen.TermNone: ""}[r.Terminator]
		if want == "" && r.Terminator != gen.TermNone {
			t.Errorf("%s: unknown terminator %q", r.RecordID, r.Terminator)
			continue
		}
		if got := string(body[r.ByteEnd:min(r.ByteEnd+len(want), len(body))]); got != want {
			t.Errorf("%s: terminator %s expected %q at offset %d, found %q",
				r.RecordID, r.Terminator, want, r.ByteEnd, got)
		}

		switch r.Expect {
		case "parse", "raw_only", "unknown_format":
		default:
			t.Errorf("%s: invalid expect %q", r.RecordID, r.Expect)
		}
	}

	for name, fi := range m.Files {
		if counted[name] != fi.Records {
			t.Errorf("%s: manifest says %d records, found %d entries", name, fi.Records, counted[name])
		}
	}
}

// TestRecordsCoverEveryByte proves nothing in a fixture file falls outside a
// manifest record: records must tile the file end to end, in order, separated
// only by their declared terminators. Without this, a generator could emit a
// line it never described and the round-trip test would not notice.
func TestRecordsCoverEveryByte(t *testing.T) {
	dir := t.TempDir()
	if err := gen.Run(gen.Options{Seed: 20260928, Out: dir, Sample: true}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m gen.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	termLen := map[string]int{gen.TermLF: 1, gen.TermCRLF: 2, gen.TermNone: 0}
	next := map[string]int{}
	for _, r := range m.Records {
		if next[r.SourceFile] != r.ByteStart {
			t.Errorf("%s: gap or overlap in %s: expected record to start at %d, starts at %d",
				r.RecordID, r.SourceFile, next[r.SourceFile], r.ByteStart)
		}
		next[r.SourceFile] = r.ByteEnd + termLen[r.Terminator]
	}
	for name, fi := range m.Files {
		if next[name] != fi.Bytes {
			t.Errorf("%s: records account for %d of %d bytes", name, next[name], fi.Bytes)
		}
	}
}
