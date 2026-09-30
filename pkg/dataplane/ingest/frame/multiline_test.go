package frame

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"

	types "github.com/dark-14100/sluice/pkg/types"
)

// isoStart is the pattern gen.MultilineStart exports and that
// testdata/multiline.log is generated against.
const isoStart = `^\d{4}-\d{2}-\d{2}T`

func multiline(t *testing.T, in string, o MultilineOptions) ([]Frame, error) {
	t.Helper()
	return multilineFrom(t, strings.NewReader(in), o)
}

func multilineFrom(t *testing.T, r io.Reader, o MultilineOptions) ([]Frame, error) {
	t.Helper()
	inner, err := New(ModeLF, r, Options{MaxFrameBytes: o.MaxFrameBytes})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMultiline(inner, o)
	if err != nil {
		t.Fatal(err)
	}
	return drain(m)
}

// TestMultilineGroups is the core behaviour: one event, however many lines.
func TestMultilineGroups(t *testing.T) {
	in := "2026-09-28T09:00:00 ERROR one\n\tat a\n\tat b\n" +
		"2026-09-28T09:00:01 ERROR two\n\tat c\n" +
		"2026-09-28T09:00:02 ERROR three\n"

	got, err := multiline(t, in, MultilineOptions{Start: regexp.MustCompile(isoStart)})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"2026-09-28T09:00:00 ERROR one\n\tat a\n\tat b",
		"2026-09-28T09:00:01 ERROR two\n\tat c",
		"2026-09-28T09:00:02 ERROR three",
	}
	if len(got) != len(want) {
		t.Fatalf("%d records, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i].Raw) != want[i] {
			t.Errorf("record %d:\n got %q\nwant %q", i, got[i].Raw, want[i])
		}
	}
}

// TestMultilineIsLossless is the property the round-trip test depends on:
// the records plus their recorded terminators must reconstruct the input byte
// for byte. Internal newlines belong inside the record; only the final one is
// the terminator.
func TestMultilineIsLossless(t *testing.T) {
	inputs := []string{
		"2026-01-01T00:00:00 a\n\tb\n\tc\n2026-01-01T00:00:01 d\n",
		"2026-01-01T00:00:00 a\n\tb\n\tc",                    // unterminated last record
		"\torphan\n2026-01-01T00:00:00 a\n",                  // stream does not start at a boundary
		"2026-01-01T00:00:00 a\n2026-01-01T00:00:01 b\n",     // no continuations at all
		"2026-01-01T00:00:00 a\n\n\n2026-01-01T00:00:01 b\n", // blank continuations
	}

	for _, in := range inputs {
		got, err := multiline(t, in, MultilineOptions{Start: regexp.MustCompile(isoStart)})
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		var rebuilt []byte
		for _, f := range got {
			rebuilt = append(rebuilt, f.Raw...)
			rebuilt = append(rebuilt, termBytes(f.Term)...)
		}
		if string(rebuilt) != in {
			t.Errorf("reconstruction differs\n got %q\nwant %q", rebuilt, in)
		}
	}
}

// TestMultilineChunkingInvariance: grouping must not depend on how the reader
// chops the stream either.
func TestMultilineChunkingInvariance(t *testing.T) {
	in := "2026-09-28T09:00:00 one\n\tat a\n\tat b\n2026-09-28T09:00:01 two\n\tat c\n"
	o := MultilineOptions{Start: regexp.MustCompile(isoStart)}

	want, err := multiline(t, in, o)
	if err != nil {
		t.Fatal(err)
	}

	got, err := multilineFrom(t, iotest.OneByteReader(strings.NewReader(in)), o)
	if err != nil {
		t.Fatal(err)
	}
	if err := framesEqual(want, got); err != nil {
		t.Errorf("one byte at a time: %v", err)
	}

	for _, n := range []int{1, 2, 3, 7, 13, 64} {
		got, err := multilineFrom(t, &chunkReader{b: []byte(in), n: n}, o)
		if err != nil {
			t.Fatalf("chunk %d: %v", n, err)
		}
		if err := framesEqual(want, got); err != nil {
			t.Errorf("chunk %d: %v", n, err)
		}
	}
}

// TestMultilineMaxLines: a source whose lines never match Start must not
// accumulate without bound.
func TestMultilineMaxLines(t *testing.T) {
	in := "2026-01-01T00:00:00 head\n" + strings.Repeat("\tcont\n", 20)

	got, err := multiline(t, in, MultilineOptions{
		Start: regexp.MustCompile(isoStart), MaxLines: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 4 {
		t.Fatalf("%d records; MaxLines did not bound the record", len(got))
	}
	for i, f := range got {
		if n := bytes.Count(f.Raw, []byte("\n")) + 1; n > 5 {
			t.Errorf("record %d holds %d lines, want at most 5", i, n)
		}
	}
}

// TestMultilineFlush covers the timeout path. The decoder cannot notice time
// passing while blocked on a read, so the source drives it - but a record held
// by a continuation that never arrives must still be releasable.
func TestMultilineFlush(t *testing.T) {
	inner, err := New(ModeLF, strings.NewReader("2026-01-01T00:00:00 a\n\tb\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMultiline(inner, MultilineOptions{Start: regexp.MustCompile(isoStart)})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.Flush(); ok {
		t.Error("Flush produced a record before anything was read")
	}

	// Drain to EOF, which flushes the pending record.
	got, err := drain(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Raw) != "2026-01-01T00:00:00 a\n\tb" {
		t.Fatalf("got %q", got)
	}
	if _, ok := m.Flush(); ok {
		t.Error("Flush produced a record after the stream was drained")
	}
}

// TestMultilineFragments: a runaway record must still be bounded in memory.
func TestMultilineFragments(t *testing.T) {
	const max = 64
	in := "2026-01-01T00:00:00 head\n" + strings.Repeat("\t"+strings.Repeat("x", 30)+"\n", 10)

	got, err := multiline(t, in, MultilineOptions{
		Start: regexp.MustCompile(isoStart), MaxFrameBytes: max, MaxLines: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Fatalf("%d records; the over-long record was not fragmented", len(got))
	}
	for i, f := range got {
		if len(f.Raw) > max {
			t.Errorf("fragment %d is %d bytes, over the %d limit", i, len(f.Raw), max)
		}
	}

	var rebuilt []byte
	for _, f := range got {
		rebuilt = append(rebuilt, f.Raw...)
		rebuilt = append(rebuilt, termBytes(f.Term)...)
	}
	if string(rebuilt) != in {
		t.Error("fragmented multiline records did not reconstruct the input")
	}
}

func TestMultilineRequiresAPattern(t *testing.T) {
	inner, _ := New(ModeLF, strings.NewReader(""), Options{})
	if _, err := NewMultiline(inner, MultilineOptions{}); err == nil {
		t.Error("a multiline decoder was built with no Start pattern")
	}
}

// TestMultilineFixtureMatchesTheManifest closes the loop with the corpus the
// way the oversize test does: testdata/multiline.log is 40 events, and the
// manifest describes each as ONE record with its internal newlines inside
// byte_start..byte_end. If the framer split them, the round-trip test at M3.6
// would fail with a confusing mismatch; this says so directly.
func TestMultilineFixtureMatchesTheManifest(t *testing.T) {
	const testdata = "../../../../testdata"

	raw, err := os.ReadFile(filepath.Join(testdata, "manifest.json"))
	if err != nil {
		t.Skipf("no corpus: %v (run `make fixtures`)", err)
	}
	var m struct {
		Records []struct {
			File  string `json:"source_file"`
			Start int    `json:"byte_start"`
			End   int    `json:"byte_end"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(testdata, "multiline.log"))
	if err != nil {
		t.Fatal(err)
	}

	var want [][]byte
	for _, r := range m.Records {
		if r.File == "multiline.log" {
			want = append(want, body[r.Start:r.End])
		}
	}
	if len(want) == 0 {
		t.Fatal("no multiline records in the manifest; the check proved nothing")
	}

	got, err := multilineFrom(t, bytes.NewReader(body), MultilineOptions{
		Start: regexp.MustCompile(isoStart),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("framer produced %d records, the manifest describes %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].Raw, want[i]) {
			t.Errorf("record %d differs from the manifest's byte range:\n got %q\nwant %q",
				i, truncate(got[i].Raw), truncate(want[i]))
		}
	}
	t.Logf("checked %d multiline events against the manifest", len(want))
}

func truncate(b []byte) string {
	if len(b) > 80 {
		return string(b[:80]) + "..."
	}
	return string(b)
}

// TestMultilinePropagatesReadErrors: a broken connection must surface, not
// look like a clean end of stream.
func TestMultilinePropagatesReadErrors(t *testing.T) {
	boom := errors.New("connection reset")
	inner, err := New(ModeLF, iotest.ErrReader(boom), Options{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewMultiline(inner, MultilineOptions{Start: regexp.MustCompile(isoStart)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Next(); !errors.Is(err, boom) {
		t.Errorf("got %v, want the underlying read error", err)
	}
}

var _ = types.TermLF
