package gen

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// corpus generates the full profile once and returns the directory.
func corpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := Run(Options{Seed: 20260928, Out: dir}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestMalformedComposition pins the mix the PRD asks for. These counts are the
// point of the file: a corpus that quietly lost its invalid-UTF-8 records would
// still round-trip, and the byte-exactness claim would go untested.
func TestMalformedComposition(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(corpus(t), "malformed.log"))
	if err != nil {
		t.Fatal(err)
	}
	// Records are LF-framed; the file ends with a terminator, so the trailing
	// empty element is not a record.
	lines := bytes.Split(body, []byte("\n"))
	lines = lines[:len(lines)-1]

	if len(lines) != 100 {
		t.Fatalf("got %d records, want 100", len(lines))
	}

	var empty, invalidUTF8, withNUL, withCR int
	for _, l := range lines {
		switch {
		case len(l) == 0:
			empty++
		}
		if !utf8.Valid(l) {
			invalidUTF8++
		}
		if bytes.IndexByte(l, 0x00) >= 0 {
			withNUL++
		}
		if bytes.IndexByte(l, '\r') >= 0 {
			withCR++
		}
	}

	if empty != badCounts[badEmpty] {
		t.Errorf("empty records: got %d, want %d", empty, badCounts[badEmpty])
	}
	if withNUL != badCounts[badTrailingNUL] {
		t.Errorf("records with NUL: got %d, want %d", withNUL, badCounts[badTrailingNUL])
	}
	if withCR != badCounts[badBareCR] {
		t.Errorf("records with a bare CR: got %d, want %d", withCR, badCounts[badBareCR])
	}
	// The invalid-UTF-8 and binary-noise records both fail UTF-8 validation,
	// and a truncated line can end mid-nothing, so this is a floor, not an
	// equality. It still catches an emitter that stopped producing them.
	if want := badCounts[badInvalidUTF8]; invalidUTF8 < want {
		t.Errorf("records failing UTF-8 validation: got %d, want at least %d", invalidUTF8, want)
	}
}

// TestOversizeFragmentBoundary pins the fragmentation expectations the framer
// will be built against in M3, including the exactly-at-the-limit case.
func TestOversizeFragmentBoundary(t *testing.T) {
	cases := []struct{ size, want int }{
		{70 << 10, 1},
		{MaxFrameBytes - 1, 1},
		{MaxFrameBytes, 1}, // exactly at the limit is one record, not two
		{MaxFrameBytes + 1, 2},
		{MaxFrameBytes + MaxFrameBytes/2, 2},
		{3 * MaxFrameBytes, 3},
	}
	for _, c := range cases {
		if got := expectedFragments(c.size); got != c.want {
			t.Errorf("expectedFragments(%d) = %d, want %d", c.size, got, c.want)
		}
	}

	body, err := os.ReadFile(filepath.Join(corpus(t), "oversize.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(body, []byte("\n"))
	lines = lines[:len(lines)-1]
	if len(lines) != len(oversizeSizes) {
		t.Fatalf("got %d records, want %d", len(lines), len(oversizeSizes))
	}
	for i, l := range lines {
		if len(l) != oversizeSizes[i] {
			t.Errorf("record %d: %d bytes, want %d", i, len(l), oversizeSizes[i])
		}
	}
}

// TestMultilineFramesWholeEvents proves MultilineStart actually frames
// multiline.log the way the manifest describes it: every record starts with a
// matching line and no continuation line matches, so a framer using this
// pattern reproduces the manifest's records exactly.
func TestMultilineFramesWholeEvents(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(corpus(t), "multiline.log"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(MultilineStart)

	starts := 0
	for i, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		if re.MatchString(line) {
			starts++
			continue
		}
		if i == 0 {
			t.Fatal("first line does not match MultilineStart")
		}
	}
	if starts != 40 {
		t.Errorf("got %d events, want 40", starts)
	}
}

// TestPaloAltoColumnCount proves every row has the full positional layout.
// A short row would silently shift every column after it, and since the file
// has no header there is nothing else to catch that.
func TestPaloAltoColumnCount(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(corpus(t), "palo_alto_unknown.log"))
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		// No field in this layout is quoted, so a plain split is the same
		// thing a CSV reader would see.
		if n := strings.Count(line, ",") + 1; n != panColumns {
			t.Errorf("row %d has %d columns, want %d", i, n, panColumns)
		}
		if strings.Contains(line, "=") {
			t.Errorf("row %d contains '=', which would make the format sniffer call it kv, not csv", i)
		}
	}
}

// TestDriftActuallyDrifts proves fortinet_drift.log differs from fortinet.log
// in the ways the sidecar is supposed to detect. If the two files ever
// converge, the drift-detection demo silently becomes a no-op.
func TestDriftActuallyDrifts(t *testing.T) {
	dir := corpus(t)
	base := readFile(t, filepath.Join(dir, "fortinet.log"))
	drift := readFile(t, filepath.Join(dir, "fortinet_drift.log"))

	mustHave := func(name string, body []byte, keys ...string) {
		for _, k := range keys {
			if !bytes.Contains(body, []byte(k)) {
				t.Errorf("%s: expected to contain %q", name, k)
			}
		}
	}
	mustNotHave := func(name string, body []byte, keys ...string) {
		for _, k := range keys {
			if bytes.Contains(body, []byte(k)) {
				t.Errorf("%s: expected NOT to contain %q", name, k)
			}
		}
	}

	// Probes are space-prefixed wherever a key could appear as the tail of
	// another key: without that, " time=" matches inside "eventtime=" and the
	// assertion proves nothing. "date=" is the first key on a pre-drift line,
	// so it has no leading space to match.
	//
	// Pre-drift: separate date/time, srcip/dstip, quoted actions.
	mustHave("fortinet.log", base, "date=", " time=", " srcip=", " dstip=", ` action="deny"`)
	mustNotHave("fortinet.log", base, " eventtime=", " src=", " dst=", " action=blocked")

	// Post-drift: epoch eventtime, renamed keys, unquoted new action values.
	mustHave("fortinet_drift.log", drift, "eventtime=", " src=", " dst=", " sport=", " dport=", " action=blocked", " srcmac=")
	mustNotHave("fortinet_drift.log", drift, "date=", " time=", " srcip=", " dstip=", ` action="deny"`)
}
