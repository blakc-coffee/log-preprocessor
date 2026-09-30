package source_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dark-14100/sluice/pkg/dataplane/ingest/source"
	types "github.com/dark-14100/sluice/pkg/types"
)

// tailFixture is a file being written to while a tail follows it.
type tailFixture struct {
	t    *testing.T
	path string
	f    *os.File
}

func newTailFixture(t *testing.T, dir, name string) *tailFixture {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return &tailFixture{t: t, path: path, f: f}
}

func (tf *tailFixture) write(lines ...string) {
	tf.t.Helper()
	for _, l := range lines {
		if _, err := tf.f.WriteString(l + "\n"); err != nil {
			tf.t.Fatal(err)
		}
	}
	if err := tf.f.Sync(); err != nil {
		tf.t.Fatal(err)
	}
}

// writePartial writes bytes with no terminator, simulating a writer caught
// mid-line.
func (tf *tailFixture) writePartial(s string) {
	tf.t.Helper()
	if _, err := tf.f.WriteString(s); err != nil {
		tf.t.Fatal(err)
	}
	tf.f.Sync()
}

// rotate renames the file away and starts a fresh one, the way logrotate's
// default `create` mode does.
func (tf *tailFixture) rotate() {
	tf.t.Helper()
	tf.f.Close()
	if err := os.Rename(tf.path, tf.path+".1"); err != nil {
		tf.t.Fatal(err)
	}
	f, err := os.OpenFile(tf.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		tf.t.Fatal(err)
	}
	tf.f = f
}

// truncate empties the file in place, the way `copytruncate` does.
func (tf *tailFixture) truncate() {
	tf.t.Helper()
	if err := tf.f.Truncate(0); err != nil {
		tf.t.Fatal(err)
	}
	if _, err := tf.f.Seek(0, 0); err != nil {
		tf.t.Fatal(err)
	}
	tf.f.Sync()
}

func tailSource(t *testing.T, cfg source.FileConfig) *source.File {
	t.Helper()
	cfg.Mode = source.ModeTail
	if cfg.ID == "" {
		cfg.ID = "tail"
	}
	// Poll fast so the tests are quick. Correctness does not depend on it.
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Millisecond
	}
	src, err := source.NewFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// TestTailFollowsAppends is the base case.
func TestTailFollowsAppends(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "app.log")
	tf.write("first", "second")

	h := start(t, tailSource(t, source.FileConfig{Paths: []string{tf.path}}))

	got := h.waitFor(2)
	if strings.Join(raws(got), ",") != "first,second" {
		t.Fatalf("got %q", raws(got))
	}

	// Lines written after the tail started must arrive too.
	tf.write("third", "fourth")
	got = h.waitFor(4)
	if strings.Join(raws(got), ",") != "first,second,third,fourth" {
		t.Errorf("got %q", raws(got))
	}
}

// TestTailHoldsAPartialLine is the property that makes tailing safe.
//
// A writer caught mid-line has written bytes with no terminator yet. A tail
// that treated end-of-file as end-of-record would emit the half-written line
// as a complete record and the rest as a second one, splitting an event in
// two at exactly the moment a writer was mid-write.
func TestTailHoldsAPartialLine(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "partial.log")

	h := start(t, tailSource(t, source.FileConfig{Paths: []string{tf.path}}))

	tf.writePartial("half a li")
	// Give the tail several poll intervals to do the wrong thing.
	time.Sleep(50 * time.Millisecond)
	if n := len(h.collected()); n != 0 {
		t.Fatalf("%d records emitted for an unterminated line", n)
	}

	tf.writePartial("ne\n")
	got := h.waitFor(1)
	if string(got[0].Raw) != "half a line" {
		t.Errorf("got %q, want the whole line", got[0].Raw)
	}
}

// TestTailSurvivesRotation covers logrotate's default: rename the file away
// and create a new one. Records already in the old file must still be read,
// and the new file must be picked up.
func TestTailSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "rot.log")
	tf.write("before-1", "before-2")

	h := start(t, tailSource(t, source.FileConfig{Paths: []string{tf.path}}))
	h.waitFor(2)

	tf.rotate()
	tf.write("after-1", "after-2")

	got := h.waitFor(4)
	if strings.Join(raws(got), ",") != "before-1,before-2,after-1,after-2" {
		t.Errorf("got %q", raws(got))
	}
}

// TestTailReadsDataWrittenJustBeforeRotation: a rotator renames the file the
// instant after a write. Those bytes are in the old inode, and dropping them
// would lose data on every rotation.
func TestTailReadsDataWrittenJustBeforeRotation(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "race.log")

	h := start(t, tailSource(t, source.FileConfig{Paths: []string{tf.path}}))
	time.Sleep(20 * time.Millisecond) // let the tail attach

	tf.write("last-before-rotation")
	tf.rotate()
	tf.write("first-after-rotation")

	got := h.waitFor(2)
	if strings.Join(raws(got), ",") != "last-before-rotation,first-after-rotation" {
		t.Errorf("got %q", raws(got))
	}
}

// TestTailSurvivesTruncation covers copytruncate: the file is emptied in
// place, so its size drops below where we were reading. Continuing at the old
// offset would read whatever lands there as if it followed what came before.
func TestTailSurvivesTruncation(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "trunc.log")
	tf.write("old-1", "old-2", "old-3")

	h := start(t, tailSource(t, source.FileConfig{Paths: []string{tf.path}}))
	h.waitFor(3)

	tf.truncate()
	tf.write("new-1")

	got := h.waitFor(4)
	if last := string(got[3].Raw); last != "new-1" {
		t.Errorf("after truncation got %q, want new-1", last)
	}
}

// TestTailFromEnd: an operator who does not want a year of history replayed
// on startup asks for it explicitly.
func TestTailFromEnd(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "fromend.log")
	tf.write("history-1", "history-2")

	h := start(t, tailSource(t, source.FileConfig{
		Paths: []string{tf.path}, From: source.FromEnd,
	}))
	time.Sleep(50 * time.Millisecond)

	tf.write("live-1")
	got := h.waitFor(1)
	if len(got) != 1 || string(got[0].Raw) != "live-1" {
		t.Errorf("got %q, want only the line written after startup", raws(got))
	}
}

// TestTailWaitsForAFileThatDoesNotExistYet: a file named explicitly may not
// be there yet, or may be between rotations. Failing would make a rotation
// take the source down.
func TestTailWaitsForAFileToAppear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "later.log")

	h := start(t, tailSource(t, source.FileConfig{Paths: []string{path}}))
	time.Sleep(30 * time.Millisecond)

	if err := os.WriteFile(path, []byte("appeared\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := h.waitFor(1)
	if string(got[0].Raw) != "appeared" {
		t.Errorf("got %q", got[0].Raw)
	}
}

// ---------------------------------------------------------- checkpoints

func readCheckpointDir(t *testing.T, dir string) []map[string]any {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("checkpoint %s is not valid JSON: %v", e.Name(), err)
		}
		out = append(out, m)
	}
	return out
}

// TestTailResumesFromCheckpoint is the point of checkpoints: a restart picks
// up where it left off instead of replaying the file.
func TestTailResumesFromCheckpoint(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "checkpoints")
	tf := newTailFixture(t, dir, "resume.log")
	tf.write("one", "two", "three")

	cfg := source.FileConfig{
		Paths: []string{tf.path}, CheckpointDir: ckpt, CheckpointEvery: 1,
	}

	// First run: read everything, then stop.
	h1 := start(t, tailSource(t, cfg))
	h1.waitFor(3)
	h1.stop()

	cps := readCheckpointDir(t, ckpt)
	if len(cps) != 1 {
		t.Fatalf("%d checkpoints written, want 1", len(cps))
	}
	if off, _ := cps[0]["offset"].(float64); int64(off) == 0 {
		t.Fatal("the checkpoint offset is 0 after reading three records")
	}

	// Second run against the same file: only what arrived since.
	tf.write("four")
	h2 := start(t, tailSource(t, cfg))
	got := h2.waitFor(1)
	if len(got) != 1 || string(got[0].Raw) != "four" {
		t.Errorf("after resuming got %q, want only the new line", raws(got))
	}
}

// TestCheckpointFollowsDurability is the ordering that keeps the at-least-once
// promise honest. A checkpoint written before the records were durable could
// skip records a crash then erased; written after, a crash re-reads them
// instead. Duplicates are recoverable, missing data is not.
func TestCheckpointFollowsDurability(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "checkpoints")
	tf := newTailFixture(t, dir, "order.log")
	tf.write("a", "b", "c")

	h := start(t, tailSource(t, source.FileConfig{
		Paths: []string{tf.path}, CheckpointDir: ckpt, CheckpointEvery: 1,
	}))
	h.waitFor(3)

	// Read the vault before stop(), which closes it.
	cps := readCheckpointDir(t, ckpt)
	if len(cps) == 0 {
		t.Fatal("no checkpoint written")
	}
	offset := int64(cps[0]["offset"].(float64))

	// Everything up to the checkpoint offset must already be in the vault.
	var stored int
	if err := h.vault.Scan(bg(), 1, func(types.RawRecord, types.Receipt) error {
		stored++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(tf.path)
	if err != nil {
		t.Fatal(err)
	}
	if offset > fi.Size() {
		t.Errorf("the checkpoint offset %d is past the end of the file (%d)", offset, fi.Size())
	}
	if stored < 3 {
		t.Errorf("the checkpoint was written with only %d of 3 records durable", stored)
	}
}

// TestCheckpointIgnoredForADifferentFile: a device and inode pair is reused
// after a file is deleted and another created, so the fingerprint is what
// actually distinguishes them. Resuming at a stale offset into an unrelated
// file would skip its beginning.
func TestCheckpointIgnoredForADifferentFile(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "checkpoints")
	tf := newTailFixture(t, dir, "reused.log")
	tf.write("original-1", "original-2")

	cfg := source.FileConfig{
		Paths: []string{tf.path}, CheckpointDir: ckpt, CheckpointEvery: 1,
	}
	h1 := start(t, tailSource(t, cfg))
	h1.waitFor(2)
	h1.stop()

	// Replace the file entirely with different content at the same path.
	tf.f.Close()
	if err := os.Remove(tf.path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tf.path, []byte("replacement-1\nreplacement-2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	h2 := start(t, tailSource(t, cfg))
	got := h2.waitFor(2)
	if strings.Join(raws(got), ",") != "replacement-1,replacement-2" {
		t.Errorf("got %q; the stale checkpoint was applied to a different file", raws(got))
	}
}

// TestCorruptCheckpointIsTreatedAsAbsent. A checkpoint is derived state.
// Refusing to start because of one would turn a recoverable annoyance into an
// outage; re-reading duplicates instead, which the de-duplication key handles.
func TestCorruptCheckpointIsTreatedAsAbsent(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "checkpoints")
	tf := newTailFixture(t, dir, "corrupt.log")
	tf.write("x", "y")

	cfg := source.FileConfig{
		Paths: []string{tf.path}, CheckpointDir: ckpt, CheckpointEvery: 1,
	}
	h1 := start(t, tailSource(t, cfg))
	h1.waitFor(2)
	h1.stop()

	entries, err := os.ReadDir(ckpt)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no checkpoint to corrupt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ckpt, entries[0].Name()), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	h2 := start(t, tailSource(t, cfg))
	got := h2.waitFor(2)
	if len(got) != 2 {
		t.Errorf("a corrupt checkpoint did not fall back to reading from the start")
	}
}

// TestCheckpointNamesAreDerivedFromAHash, never from the log path itself. A
// path can contain slashes, spaces and anything else a filesystem allows, and
// building a file name out of it is how directory traversal happens.
func TestCheckpointNamesAreHashed(t *testing.T) {
	dir := t.TempDir()
	ckpt := filepath.Join(dir, "checkpoints")
	tf := newTailFixture(t, dir, "weird name.log")
	tf.write("a")

	h := start(t, tailSource(t, source.FileConfig{
		Paths: []string{tf.path}, CheckpointDir: ckpt, CheckpointEvery: 1,
	}))
	h.waitFor(1)
	h.stop()

	entries, err := os.ReadDir(ckpt)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") && strings.Contains(e.Name(), "weird") {
			t.Errorf("checkpoint file %q is built from the log path", e.Name())
		}
	}
}

// TestTailMultipleFilesConcurrently: one file per goroutine and one stream per
// file, so a stalled file cannot hold up the others.
func TestTailMultipleFiles(t *testing.T) {
	dir := t.TempDir()
	var fixtures []*tailFixture
	for i := 0; i < 3; i++ {
		tf := newTailFixture(t, dir, fmt.Sprintf("f%d.log", i))
		tf.write(fmt.Sprintf("file%d-line0", i))
		fixtures = append(fixtures, tf)
	}

	h := start(t, tailSource(t, source.FileConfig{
		Paths: []string{filepath.Join(dir, "*.log")},
	}))
	h.waitFor(3)

	for i, tf := range fixtures {
		tf.write(fmt.Sprintf("file%d-line1", i))
	}
	got := h.waitFor(6)

	seen := map[string]bool{}
	for _, ev := range got {
		seen[string(ev.Raw)] = true
	}
	for i := 0; i < 3; i++ {
		for j := 0; j < 2; j++ {
			want := fmt.Sprintf("file%d-line%d", i, j)
			if !seen[want] {
				t.Errorf("missing %q", want)
			}
		}
	}
}

// TestTailOriginOffsetsArePositionsInTheFile. Origin.Offset is the
// de-duplication key after an at-least-once replay; if it does not point at
// the record, duplicates cannot be collapsed.
func TestTailOriginOffsets(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "offsets.log")
	tf.write("alpha", "beta", "gamma")

	h := start(t, tailSource(t, source.FileConfig{Paths: []string{tf.path}}))
	got := h.waitFor(3)

	body, err := os.ReadFile(tf.path)
	if err != nil {
		t.Fatal(err)
	}
	for i, ev := range got {
		off := ev.Origin.Offset
		if int(off)+len(ev.Raw) > len(body) {
			t.Fatalf("record %d: offset %d is outside the file", i, off)
		}
		if string(body[off:int(off)+len(ev.Raw)]) != string(ev.Raw) {
			t.Errorf("record %d: offset %d does not point at %q", i, off, ev.Raw)
		}
	}
}

// TestMultilineTimeoutReleasesAHeldRecord is the M4 half of multiline framing.
//
// A multiline record is complete only when the next record's first line
// arrives. If a source goes quiet mid-event, the last event is held
// indefinitely — and that is exactly the event someone is trying to read
// during an incident. The decoder cannot notice, because Next is blocked
// waiting for data that will never come, so the source drives the clock.
func TestMultilineTimeoutReleasesAHeldRecord(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "ml.log")

	h := start(t, tailSource(t, source.FileConfig{
		Paths: []string{tf.path},
		Multiline: &source.MultilineConfig{
			Start:   regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`),
			Timeout: 60 * time.Millisecond,
		},
	}))

	tf.write("2026-09-28T09:00:00 ERROR something failed", "\tat frame one", "\tat frame two")

	// Nothing else arrives. Without the timeout this record is held forever.
	got := h.waitFor(1)
	want := "2026-09-28T09:00:00 ERROR something failed\n\tat frame one\n\tat frame two"
	if string(got[0].Raw) != want {
		t.Errorf("got %q\nwant %q", got[0].Raw, want)
	}

	// And the next event still frames correctly afterwards.
	tf.write("2026-09-28T09:01:00 ERROR another", "\tat frame three")
	got = h.waitFor(2)
	if len(got) < 2 {
		t.Fatal("the second event never arrived")
	}
}

// TestMultilineTimeoutDoesNotCutAnActiveRecord: a record whose continuations
// keep arriving must not be split just because it is taking a while.
func TestMultilineTimeoutDoesNotCutAnActiveRecord(t *testing.T) {
	dir := t.TempDir()
	tf := newTailFixture(t, dir, "active.log")

	h := start(t, tailSource(t, source.FileConfig{
		Paths: []string{tf.path},
		Multiline: &source.MultilineConfig{
			Start:   regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`),
			Timeout: 500 * time.Millisecond,
		},
	}))

	tf.write("2026-09-28T09:00:00 ERROR start")
	for i := 0; i < 4; i++ {
		time.Sleep(30 * time.Millisecond)
		tf.write(fmt.Sprintf("\tat frame %d", i))
	}
	// Close the record by starting the next one.
	tf.write("2026-09-28T09:00:10 ERROR next")

	got := h.waitFor(1)
	first := string(got[0].Raw)
	if !strings.HasPrefix(first, "2026-09-28T09:00:00 ERROR start") {
		t.Fatalf("first record is %q", first)
	}
	if n := strings.Count(first, "\n"); n != 4 {
		t.Errorf("the first record holds %d continuation lines, want 4 — it was cut early:\n%q", n, first)
	}
}
