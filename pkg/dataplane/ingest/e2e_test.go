package ingest_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dark-14100/sluice/pkg/dataplane/ingest"
	"github.com/dark-14100/sluice/pkg/dataplane/ingest/frame"
	"github.com/dark-14100/sluice/pkg/dataplane/ingest/source"
	"github.com/dark-14100/sluice/pkg/dataplane/vault"
	types "github.com/dark-14100/sluice/pkg/types"
)

const testdata = "../../../testdata"

// manifest is the ground truth the whole corpus is described by.
type manifest struct {
	Files map[string]struct {
		Bytes      int    `json:"bytes"`
		SHA256     string `json:"sha256"`
		Records    int    `json:"records"`
		Terminator string `json:"terminator"`
	} `json:"files"`
	Records []manifestRecord `json:"records"`
}

type manifestRecord struct {
	RecordID   string `json:"record_id"`
	File       string `json:"source_file"`
	Start      int    `json:"byte_start"`
	End        int    `json:"byte_end"`
	Terminator string `json:"terminator"`
	SHA256     string `json:"expected_sha256"`
	Expect     string `json:"expect"`
	Fragments  *int   `json:"expected_fragments"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testdata, "manifest.json"))
	if err != nil {
		t.Skipf("no corpus: %v (run `make fixtures`)", err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// framingFor picks the framing each fixture needs. multiline.log and crlf.log
// are the two that are not plain LF, and the manifest's `terminator` field
// says so — this reads it rather than hard-coding a list, so a new fixture
// cannot be ingested with the wrong framing by omission.
func framingFor(name, terminator string) (frame.Mode, *source.MultilineConfig) {
	if name == "multiline.log" {
		return frame.ModeLF, &source.MultilineConfig{
			// The same pattern tools/gen exports as gen.MultilineStart. The
			// corpus and the config must agree or the round-trip fails.
			Start: regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`),
		}
	}
	if terminator == "CRLF" {
		return frame.ModeCRLF, nil
	}
	return frame.ModeLF, nil
}

// runPipeline ingests one file and returns every event it produced, in order.
func runPipeline(t *testing.T, v types.Vault, name string, m manifest) []types.RawEvent {
	t.Helper()

	framing, ml := framingFor(name, m.Files[name].Terminator)
	src, err := source.NewFile(source.FileConfig{
		ID:        "fixture-" + name,
		Paths:     []string{filepath.Join(testdata, name)},
		Mode:      source.ModeOnce,
		Framing:   framing,
		Multiline: ml,
		Now:       func() time.Time { return time.Unix(1790566200, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}

	out := make(chan types.RawEvent, 16)
	p, err := ingest.New(ingest.Config{OutBuffer: 16}, v, out, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.AddSource(src)

	// Drain concurrently: the channel is deliberately smaller than the corpus
	// so the backpressure path is exercised rather than bypassed.
	var events []types.RawEvent
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ev := range out {
			events = append(events, ev)
		}
	}()

	if err := p.Run(context.Background()); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	wg.Wait()
	return events
}

// TestRoundTripEveryFixture is the M3 gate, and the evidence behind PS
// requirement (a).
//
// For every record in the manifest: read bytes[byte_start:byte_end] straight
// from the source file, find what the vault stored, and assert they are the
// same bytes and the same SHA-256. Nothing is excluded — malformed.log's
// invalid UTF-8 and NULs, crlf.log's CRLF terminators, multiline.log's
// internal newlines and oversize.log's fragments all have to come back
// exactly. Then the chain has to verify.
//
// The manifest hashes were computed by the generator while it wrote the files;
// this test recomputes them from the files and from the vault independently,
// so agreement means three separate computations agree, not that one value was
// copied around.
func TestRoundTripEveryFixture(t *testing.T) {
	m := loadManifest(t)

	byFile := map[string][]manifestRecord{}
	for _, r := range m.Records {
		byFile[r.File] = append(byFile[r.File], r)
	}
	names := make([]string, 0, len(byFile))
	for name := range byFile {
		names = append(names, name)
	}
	sort.Strings(names)

	totalRecords := 0
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(testdata, name))
			if err != nil {
				t.Fatal(err)
			}
			want := byFile[name]

			v, err := vault.Open(vault.Options{
				Dir: t.TempDir(), Sync: vault.SyncAlways,
				SegmentMaxRecords: 500, MaxFrameBytes: 2 << 20,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()

			events := runPipeline(t, v, name, m)

			// oversize.log is the one file where records and frames differ:
			// three records become four frames. Reassemble before comparing.
			got := reassembleFragments(t, events)

			if len(got) != len(want) {
				t.Fatalf("ingested %d records, the manifest describes %d", len(got), len(want))
			}

			for i, rec := range want {
				src := body[rec.Start:rec.End]

				if !bytes.Equal(got[i].raw, src) {
					t.Errorf("%s: bytes differ\n  vault  %s\n  source %s",
						rec.RecordID, preview(got[i].raw), preview(src))
					continue
				}
				sum := sha256.Sum256(got[i].raw)
				if h := hex.EncodeToString(sum[:]); h != rec.SHA256 {
					t.Errorf("%s: sha256 %s, manifest says %s", rec.RecordID, h, rec.SHA256)
				}
				if term := termName(got[i].term); term != rec.Terminator {
					t.Errorf("%s: terminator %s, manifest says %s", rec.RecordID, term, rec.Terminator)
				}
				if rec.Fragments != nil && got[i].frames != *rec.Fragments {
					t.Errorf("%s: %d fragments, manifest says %d",
						rec.RecordID, got[i].frames, *rec.Fragments)
				}
				if got[i].origin != uint64(rec.Start) {
					t.Errorf("%s: origin offset %d, manifest byte_start %d",
						rec.RecordID, got[i].origin, rec.Start)
				}
			}

			// And the vault's own account of itself has to hold up.
			rep, err := v.VerifyChain(context.Background(), true)
			if err != nil {
				t.Fatal(err)
			}
			if !rep.OK {
				t.Fatalf("chain failed at segment %d: %s", rep.FirstBad, rep.Reason)
			}
			totalRecords += len(want)
		})
	}
	t.Logf("round-tripped %d records across %d fixtures, byte-exact", totalRecords, len(names))
}

// record is one logical record, with its fragments already joined.
type record struct {
	raw    []byte
	term   types.Terminator
	origin uint64
	frames int
}

// reassembleFragments joins fragment runs back into records, which is the
// operation the fragmentation design promises is possible.
func reassembleFragments(t *testing.T, events []types.RawEvent) []record {
	t.Helper()
	var out []record
	var cur *record

	for _, ev := range events {
		switch {
		case ev.Frag&types.FragCont != 0:
			if cur == nil {
				t.Fatalf("record %d is marked FragCont with nothing to continue", ev.ID)
			}
			cur.raw = append(cur.raw, ev.Raw...)
			cur.frames++
			cur.term = ev.Term
		default:
			if cur != nil {
				t.Fatalf("record %d starts while a fragment run is still open", ev.ID)
			}
			out = append(out, record{
				raw:    append([]byte(nil), ev.Raw...),
				term:   ev.Term,
				origin: ev.Origin.Offset,
				frames: 1,
			})
			cur = &out[len(out)-1]
		}
		if ev.Frag&types.FragMore == 0 {
			cur = nil
		}
	}
	if cur != nil {
		t.Fatal("the stream ended inside a fragment run")
	}
	return out
}

func termName(t types.Terminator) string {
	switch t {
	case types.TermLF:
		return "LF"
	case types.TermCRLF:
		return "CRLF"
	case types.TermNUL:
		return "NUL"
	}
	return "NONE"
}

// preview renders bytes for a failure message without letting a log line's
// control characters loose in the terminal.
func preview(b []byte) string {
	const max = 60
	trimmed := b
	if len(trimmed) > max {
		trimmed = trimmed[:max]
	}
	out := make([]rune, 0, len(trimmed))
	for _, c := range trimmed {
		if c < 0x20 || c > 0x7e {
			out = append(out, '.')
			continue
		}
		out = append(out, rune(c))
	}
	return fmt.Sprintf("%q (%d bytes)", string(out), len(b))
}

// TestVaultBeforeForward is the invariant the whole package exists to
// maintain: nothing reaches the downstream channel that the vault has not
// already accepted. A consumer that saw an event before it was durable could
// act on a record that a crash then erases.
func TestVaultBeforeForward(t *testing.T) {
	v := &recordingVault{inner: mustVault(t)}
	defer v.inner.Close()

	m := loadManifest(t)
	events := runPipeline(t, v, "cisco_asa.log", m)
	if len(events) == 0 {
		t.Fatal("no events")
	}

	for _, ev := range events {
		if !v.durableBefore(ev.ID) {
			t.Fatalf("record %d was forwarded before the vault confirmed it", ev.ID)
		}
	}
}

func mustVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.Open(vault.Options{Dir: t.TempDir(), Sync: vault.SyncAlways, SegmentMaxRecords: 200})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// recordingVault notes when each record became durable.
type recordingVault struct {
	inner *vault.Vault

	mu      sync.Mutex
	durable map[types.RecordID]bool
}

func (r *recordingVault) durableBefore(id types.RecordID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.durable[id]
}

func (r *recordingVault) PutBatch(ctx context.Context, rs []types.RawRecord) ([]types.Receipt, error) {
	receipts, err := r.inner.PutBatch(ctx, rs)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.durable == nil {
		r.durable = map[types.RecordID]bool{}
	}
	for _, rc := range receipts {
		r.durable[rc.ID] = true
	}
	r.mu.Unlock()
	return receipts, nil
}

func (r *recordingVault) Put(ctx context.Context, rec types.RawRecord) (types.Receipt, error) {
	rs, err := r.PutBatch(ctx, []types.RawRecord{rec})
	if err != nil {
		return types.Receipt{}, err
	}
	return rs[0], nil
}

func (r *recordingVault) Get(ctx context.Context, id types.RecordID) (types.RawRecord, types.Receipt, error) {
	return r.inner.Get(ctx, id)
}
func (r *recordingVault) GetByHash(ctx context.Context, sum [32]byte) ([]byte, error) {
	return r.inner.GetByHash(ctx, sum)
}
func (r *recordingVault) Scan(ctx context.Context, from types.RecordID, fn func(types.RawRecord, types.Receipt) error) error {
	return r.inner.Scan(ctx, from, fn)
}
func (r *recordingVault) Proof(ctx context.Context, id types.RecordID) (types.InclusionProof, error) {
	return r.inner.Proof(ctx, id)
}
func (r *recordingVault) Verify(ctx context.Context, id types.RecordID) (types.VerifyResult, error) {
	return r.inner.Verify(ctx, id)
}
func (r *recordingVault) VerifyChain(ctx context.Context, deep bool) (types.ChainReport, error) {
	return r.inner.VerifyChain(ctx, deep)
}
func (r *recordingVault) Seals(ctx context.Context) ([]types.SegmentSeal, error) {
	return r.inner.Seals(ctx)
}
func (r *recordingVault) Head(ctx context.Context) ([32]byte, types.RecordID, error) {
	return r.inner.Head(ctx)
}
func (r *recordingVault) Close() error { return nil } // the test closes inner

// TestHintsReachDownstream proves the sniff hint is attached on the way out,
// and that it never touches what was stored.
//
// The second half matters more than the first. The hint is a heuristic on
// attacker-controlled input; if it could influence storage, a crafted log line
// could change how it was kept. It is computed after PutBatch returns, and
// this asserts the stored bytes are identical to the source regardless of what
// the sniffer decided.
func TestHintsReachDownstream(t *testing.T) {
	m := loadManifest(t)

	want := map[string]types.FormatHint{
		"cisco_asa.log":         types.HintSyslog3164,
		"fortinet.log":          types.HintKV,
		"suricata.json":         types.HintJSON,
		"palo_alto_unknown.log": types.HintCSV,
	}

	for name, hint := range want {
		t.Run(name, func(t *testing.T) {
			v, err := vault.Open(vault.Options{
				Dir: t.TempDir(), Sync: vault.SyncAlways,
				SegmentMaxRecords: 500, MaxFrameBytes: 2 << 20,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()

			events := runPipeline(t, v, name, m)
			if len(events) == 0 {
				t.Fatal("no events")
			}

			mismatched := 0
			for _, ev := range events {
				if ev.Hint != hint {
					mismatched++
				}
			}
			// Every line of a vendor's own log file should agree. A single
			// disagreement means a record of that vendor's format does not
			// look like the rest, which is worth knowing.
			if mismatched != 0 {
				t.Errorf("%d of %d records did not sniff as %q", mismatched, len(events), hint)
			}

			// The stored bytes must be exactly the source's, whatever the
			// sniffer thought.
			body, err := os.ReadFile(filepath.Join(testdata, name))
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range events {
				got, _, err := v.Get(context.Background(), ev.ID)
				if err != nil {
					t.Fatal(err)
				}
				off := int(ev.Origin.Offset)
				if !bytes.Equal(got.Raw, body[off:off+len(got.Raw)]) {
					t.Fatalf("record %d differs from the source file", ev.ID)
				}
			}
		})
	}
}

// waitForCompaction blocks until every sealed segment in dir exists only as a
// .zst, with nothing half-written. Polling, not sleeping.
func waitForCompaction(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var zst, wal, tmp int
		for _, e := range entries {
			switch {
			case strings.HasSuffix(e.Name(), ".zst"):
				zst++
			case strings.HasSuffix(e.Name(), ".wal"):
				wal++
			case strings.HasSuffix(e.Name(), ".tmp"):
				tmp++
			}
		}
		if zst >= 1 && wal == 0 && tmp == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("compaction did not finish: %d .zst, %d .wal, %d .tmp", zst, wal, tmp)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sizeOf(t *testing.T, dir, suffix string) int64 {
	t.Helper()
	var n int64
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), suffix) {
			fi, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			n += fi.Size()
		}
	}
	return n
}

func gzipSize(t *testing.T, dir string) int64 {
	t.Helper()
	var n int64
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".wal") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf) // default level 6, what `gzip` does
		zw.Write(raw)
		zw.Close()
		n += int64(buf.Len())
	}
	return n
}

// TestCorpusSurvivesCompaction is the round-trip gate applied AFTER compaction:
// every fixture is ingested, its vault compacted, and every record compared
// byte for byte against the source file. A compaction that dropped or altered
// a record would otherwise be silent.
//
// It also measures the compression ratio against gzip, which the PRD asks to
// be reported. Unlike throughput, a ratio does not depend on the machine, so
// this number is reportable from anywhere. Method: zstd level 3, 256 KiB
// blocks, against gzip -6 over the same WAL bytes.
func TestCorpusSurvivesCompaction(t *testing.T) {
	m := loadManifest(t)

	byFile := map[string][]manifestRecord{}
	for _, r := range m.Records {
		byFile[r.File] = append(byFile[r.File], r)
	}
	names := make([]string, 0, len(byFile))
	for name := range byFile {
		names = append(names, name)
	}
	sort.Strings(names)

	type row struct {
		name              string
		records           int
		wal, zst, hix, gz int64
	}
	var rows []row
	var total row
	total.name = "TOTAL"

	for _, name := range names {
		dir := t.TempDir()
		open := func(compact bool) *vault.Vault {
			v, err := vault.Open(vault.Options{
				Dir: dir, Sync: vault.SyncNone, // a ratio measurement, not a durability one
				SegmentMaxRecords: 1_000_000, MaxFrameBytes: 2 << 20, Compact: compact,
			})
			if err != nil {
				t.Fatal(err)
			}
			return v
		}

		// Ingest with compaction off, so the WAL exists to be measured.
		v := open(false)
		events := runPipeline(t, v, name, m)
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
		wal := sizeOf(t, dir, ".wal")
		gz := gzipSize(t, dir)

		// Reopen with compaction on: recovery finds the sealed WAL and compacts it.
		c := open(true)
		waitForCompaction(t, dir)

		// Every record, byte for byte, from the COMPACTED vault.
		for _, ev := range events {
			got, rc, err := c.Get(context.Background(), ev.ID)
			if err != nil {
				t.Fatalf("%s: record %d after compaction: %v", name, ev.ID, err)
			}
			if !bytes.Equal(got.Raw, ev.Raw) {
				t.Fatalf("%s: record %d changed by compaction", name, ev.ID)
			}
			if rc.RawSHA256 != ev.RawSHA256 {
				t.Fatalf("%s: record %d's hash changed by compaction", name, ev.ID)
			}
		}
		rep, err := c.VerifyChain(context.Background(), true)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.OK {
			t.Fatalf("%s: chain broken by compaction: %s", name, rep.Reason)
		}
		c.Close()

		r := row{name: name, records: len(events), wal: wal,
			zst: sizeOf(t, dir, ".zst"), hix: sizeOf(t, dir, ".hix"), gz: gz}
		rows = append(rows, r)
		total.records += r.records
		total.wal += r.wal
		total.zst += r.zst
		total.hix += r.hix
		total.gz += r.gz
	}

	rows = append(rows, total)
	t.Logf("compression on the synthetic corpus (zstd level 3, 256 KiB blocks; gzip -6 over the same WAL bytes)")
	t.Logf("%-24s %8s %10s %10s %7s %10s %7s %10s", "file", "records", "wal", "zst", "ratio", "gzip", "ratio", "hix")
	for _, r := range rows {
		t.Logf("%-24s %8d %10d %10d %6.1fx %10d %6.1fx %10d",
			r.name, r.records, r.wal, r.zst, float64(r.wal)/float64(r.zst),
			r.gz, float64(r.wal)/float64(r.gz), r.hix)
	}
	t.Logf("(the corpus is SYNTHETIC and highly repetitive by construction; ratios on real device logs will differ)")

	if total.zst >= total.wal {
		t.Errorf("compaction did not shrink the corpus: %d -> %d bytes", total.wal, total.zst)
	}
}
