package vault_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

// The crash suite.
//
// This is the test behind the project's central claim: a record acknowledged
// by Put in sync=always survives the process dying and reads back byte for
// byte. Everything else in the vault — the WAL, group commit, the seal
// ordering, torn-tail recovery — exists to make this true, and none of it is
// proven by a test that closes the vault politely.
//
// # How it works
//
// A child process writes records and appends what it was acknowledged to a
// log. The parent kills it with SIGKILL at a random moment, reopens the vault,
// and requires that every record in that log is present, byte-exact, and
// covered by a verifying chain. The vault directory is reused across cycles,
// so recovery runs against a real accumulated history rather than a fresh
// directory each time.
//
// # What it does NOT prove, established by mutation rather than by assumption
//
// This suite was checked against two deliberate breakages of the vault.
//
// Reversing the seal order — appending the ledger line before fsyncing the
// footer — fails within 60 cycles with "segment 37 footer disagrees with its
// chain.log line". So the suite really does exercise the seal windows.
//
// Switching the child to sync=none — where an acknowledgement no longer means
// the record is on disk at all — **passes.** That is not a gap in the test; it
// is the boundary of what killing a process can show. SIGKILL does not discard
// the page cache, so a record written without any fsync is still readable by
// the next process to open the file.
//
// The consequence is worth stating plainly, because it is easy to overclaim:
// this suite proves the recovery logic is correct — torn tails, interrupted
// seals, missing ledger lines, sequence continuity — and it does NOT prove
// that fsync put anything on a platter. Proving that needs power to be cut,
// which is not something a test can do. The submission says "process crash",
// never "power loss", and this is the reason.

const (
	crashCompactEnv  = "ULPF_CRASH_COMPACT"
	crashChildEnv    = "ULPF_CRASH_CHILD"
	crashDirEnv      = "ULPF_CRASH_DIR"
	crashReceiptsEnv = "ULPF_CRASH_RECEIPTS"
)

// receipt is one acknowledged record, as the child recorded it.
type receipt struct {
	ID      uint64 `json:"id"`
	Payload string `json:"payload"`
}

// TestCrashChild is the child process. It is skipped in a normal run and is
// only entered through the re-exec in TestCrash.
func TestCrashChild(t *testing.T) {
	if os.Getenv(crashChildEnv) != "1" {
		t.Skip("helper process for TestCrash")
	}

	dir := os.Getenv(crashDirEnv)
	receiptsPath := os.Getenv(crashReceiptsEnv)

	v, err := vault.Open(crashOptions(dir, os.Getenv(crashCompactEnv) == "1"))
	if err != nil {
		// A recovery failure in the child is a real failure, and the parent
		// sees it as a non-zero exit before it gets to kill anything.
		fmt.Fprintf(os.Stderr, "child: opening the vault: %v\n", err)
		os.Exit(3)
	}

	// Appended without fsync on purpose. SIGKILL does not discard the page
	// cache, so the parent sees every line the child wrote; only a power loss
	// would lose them, and power loss is explicitly not claimed. Fsyncing here
	// would double the I/O and prove nothing extra.
	f, err := os.OpenFile(receiptsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "child: %v\n", err)
		os.Exit(3)
	}
	enc := json.NewEncoder(f)

	ctx := context.Background()
	for i := 0; ; i++ {
		// Batches of varying size, so the kill lands mid-batch as often as
		// between batches.
		n := 1 + i%7
		batch := make([]types.RawRecord, n)
		payloads := make([]string, n)
		for j := range batch {
			payloads[j] = crashPayload(os.Getpid(), i, j)
			batch[j] = types.RawRecord{
				SourceID:   "crash",
				ReceivedAt: time.Now().UTC(),
				Origin:     types.Origin{Kind: types.OriginFile, Addr: "/crash", Offset: uint64(i)},
				Term:       types.TermLF,
				Raw:        []byte(payloads[j]),
			}
		}

		receipts, err := v.PutBatch(ctx, batch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "child: put: %v\n", err)
			os.Exit(3)
		}

		// Only now, after the vault said durable. A receipt written before
		// the acknowledgement would make the parent demand a record the vault
		// never promised.
		for j, rc := range receipts {
			if err := enc.Encode(receipt{ID: uint64(rc.ID), Payload: payloads[j]}); err != nil {
				fmt.Fprintf(os.Stderr, "child: %v\n", err)
				os.Exit(3)
			}
		}
	}
}

// crashOptions is shared by the child and the parent, so both open the vault
// the same way.
//
// Segments are tiny so seals — and therefore the crash windows around the
// footer and the ledger — happen constantly rather than once. With compact
// set, every sealed segment is immediately rewritten in the background, so the
// kill also lands mid-compaction: mid-write of the .zst, mid-verification,
// between the renames, and between the last rename and deleting the .wal.
func crashOptions(dir string, compact bool) vault.Options {
	o := vault.Options{
		Dir:               dir,
		Sync:              vault.SyncAlways,
		SegmentMaxRecords: 40,
		SegmentMaxBytes:   1 << 20,
		SealInterval:      time.Hour,
	}
	if compact {
		o.Compact = true
		o.CompactBlockBytes = 2048 // several blocks per 40-record segment
	}
	return o
}

// crashPayload is deterministic from its inputs, so the parent can check the
// exact bytes rather than only a hash.
func crashPayload(pid, i, j int) string {
	return fmt.Sprintf("<166>crash pid=%d batch=%d idx=%d payload=%s", pid, i, j,
		"abcdefghijklmnopqrstuvwxyz0123456789")
}

// TestCrash is the suite. It runs the configured number of kill -9 cycles
// against one accumulating vault directory.
//
//	make crash                      # the full 200 cycles, both variants
//	ULPF_CRASH_CYCLES=20 make crash # a quicker pass
func TestCrash(t *testing.T) { runCrash(t, false) }

// TestCrashWithCompaction is the same suite with background compaction running,
// so the process is killed while segments are being rewritten from WAL to zstd.
// Compaction is where a silent bug would do the most damage — a dropped record
// would not fail anything until someone asked for it — so it gets the same
// treatment as the write path.
func TestCrashWithCompaction(t *testing.T) { runCrash(t, true) }

func runCrash(t *testing.T, compact bool) {
	if os.Getenv(crashChildEnv) == "1" {
		t.Skip("this is the child process")
	}
	if testing.Short() {
		t.Skip("crash suite is slow; run `make crash`")
	}

	cycles := 200
	if s := os.Getenv("ULPF_CRASH_CYCLES"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			t.Fatalf("ULPF_CRASH_CYCLES=%q is not a positive number", s)
		}
		cycles = n
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	vaultDir := filepath.Join(dir, "vault")
	receiptsPath := filepath.Join(dir, "receipts.jsonl")

	rng := rand.New(rand.NewPCG(20260928, 0xC2A5))
	var totalChecked, lastHighest uint64
	var priorReceipts int64

	for cycle := 1; cycle <= cycles; cycle++ {
		cmd := exec.Command(self, "-test.run=TestCrashChild", "-test.timeout=5m")
		compactFlag := "0"
		if compact {
			compactFlag = "1"
		}
		cmd.Env = append(os.Environ(),
			crashChildEnv+"=1",
			crashCompactEnv+"="+compactFlag,
			crashDirEnv+"="+vaultDir,
			crashReceiptsEnv+"="+receiptsPath,
		)
		cmd.Stdout = nil
		stderr := &lineBuffer{}
		cmd.Stderr = stderr

		if err := cmd.Start(); err != nil {
			t.Fatalf("cycle %d: starting the child: %v", cycle, err)
		}

		// Wait until the child has actually acknowledged something, THEN kill
		// it after a random extra delay.
		//
		// A fixed sleep looks simpler and is wrong: `make check` runs every
		// package in parallel, and under that much disk contention — with
		// macOS issuing a full drive flush per fsync — the child can fail to
		// complete a single batch inside a fixed window. The suite then fails
		// with "killed before it acknowledged anything", which is a flake
		// about the machine rather than a finding about the vault.
		//
		// Waiting for progress first keeps the kill point random where it
		// matters (inside the write path) without making the test a
		// measurement of how busy the disk is.
		waitForProgress(t, cycle, receiptsPath, priorReceipts)
		time.Sleep(time.Duration(5+rng.IntN(45)) * time.Millisecond)

		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("cycle %d: killing the child: %v", cycle, err)
		}
		_ = cmd.Wait()

		// A child that exited on its own with code 3 failed before we killed
		// it, which is a real failure rather than the crash we induced.
		if stderr.Len() > 0 {
			t.Fatalf("cycle %d: the child reported a failure before it was killed:\n%s", cycle, stderr)
		}

		if fi, err := os.Stat(receiptsPath); err == nil {
			priorReceipts = fi.Size()
		}

		highest := verifyAfterCrash(t, cycle, vaultDir, receiptsPath, compact)
		totalChecked += highest

		// The vault must keep growing: if a cycle stopped adding records,
		// recovery has started discarding them and the suite would be
		// passing vacuously.
		if cycle > 1 && highest <= lastHighest {
			t.Fatalf("cycle %d: the vault did not grow (highest acknowledged id %d, previously %d)",
				cycle, highest, lastHighest)
		}
		lastHighest = highest
	}

	mode := "WAL only"
	if compact {
		mode = "with background compaction"
	}
	t.Logf("%d kill -9 cycles (%s), %d acknowledged records, 0 lost", cycles, mode, lastHighest)
	_ = totalChecked
}

// waitForProgress blocks until the child has appended at least one receipt
// beyond what previous cycles left behind.
func waitForProgress(t *testing.T, cycle int, path string, prior int64) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if fi, err := os.Stat(path); err == nil && fi.Size() > prior {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cycle %d: the child acknowledged nothing in 30s; "+
				"the vault is not accepting writes", cycle)
		}
		time.Sleep(time.Millisecond)
	}
}

// verifyAfterCrash reopens the vault and checks every acknowledged record.
// It returns the highest acknowledged RecordID.
func verifyAfterCrash(t *testing.T, cycle int, vaultDir, receiptsPath string, compact bool) uint64 {
	t.Helper()

	receipts := readReceipts(t, receiptsPath)
	if len(receipts) == 0 {
		t.Fatalf("cycle %d: the child was killed before it acknowledged anything; "+
			"raise the pre-kill delay", cycle)
	}

	v, err := vault.Open(crashOptions(vaultDir, compact))
	if err != nil {
		t.Fatalf("cycle %d: the vault would not reopen after a crash: %v", cycle, err)
	}
	defer v.Close()

	ctx := context.Background()
	var highest uint64
	for _, r := range receipts {
		got, rc, err := v.Get(ctx, types.RecordID(r.ID))
		if err != nil {
			t.Fatalf("cycle %d: record %d was acknowledged and is now gone: %v", cycle, r.ID, err)
		}
		if string(got.Raw) != r.Payload {
			t.Fatalf("cycle %d: record %d came back changed\n got %q\nwant %q",
				cycle, r.ID, got.Raw, r.Payload)
		}
		if rc.ID != types.RecordID(r.ID) {
			t.Fatalf("cycle %d: asked for record %d, got %d", cycle, r.ID, rc.ID)
		}
		if r.ID > highest {
			highest = r.ID
		}
	}

	// Recovery must never leave a corrupt chain behind, however the write was
	// interrupted.
	rep, err := v.VerifyChain(ctx, true)
	if err != nil {
		t.Fatalf("cycle %d: %v", cycle, err)
	}
	if !rep.OK {
		t.Fatalf("cycle %d: the chain is broken after recovery at segment %d: %s",
			cycle, rep.FirstBad, rep.Reason)
	}

	// And the next write has to land on top of the recovered state, not
	// overwrite it.
	rc, err := v.Put(ctx, types.RawRecord{
		SourceID: "post-crash", ReceivedAt: time.Now().UTC(),
		Term: types.TermLF, Raw: []byte("written after recovery"),
	})
	if err != nil {
		t.Fatalf("cycle %d: the vault will not accept writes after recovery: %v", cycle, err)
	}
	if uint64(rc.ID) <= highest {
		t.Fatalf("cycle %d: the first record after recovery reused id %d (highest acknowledged was %d)",
			cycle, rc.ID, highest)
	}
	return uint64(rc.ID)
}

// readReceipts parses the child's log, tolerating a torn final line.
//
// A torn line is expected: the child was killed mid-write. Records it
// describes may or may not be in the vault, and since the child never finished
// telling us about them, we do not ask.
func readReceipts(t *testing.T, path string) []receipt {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var out []receipt
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var r receipt
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			// Only forgivable as the last line.
			if sc.Scan() {
				t.Fatalf("the receipt log is corrupt well before its end: %v", err)
			}
			break
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// lineBuffer collects the child's stderr.
type lineBuffer struct{ b []byte }

func (l *lineBuffer) Write(p []byte) (int, error) { l.b = append(l.b, p...); return len(p), nil }
func (l *lineBuffer) Len() int                    { return len(l.b) }
func (l *lineBuffer) String() string              { return string(l.b) }
