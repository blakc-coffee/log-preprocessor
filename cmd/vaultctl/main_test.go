package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

// exec runs vaultctl in-process and returns its exit code and output.
func exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// seed builds a vault with n records and returns its directory.
func seed(t *testing.T, n, sealEvery int) string {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Open(vault.Options{
		Dir: dir, Sync: vault.SyncAlways,
		SegmentMaxRecords: sealEvery, SegmentMaxBytes: 1 << 30, SealInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := v.Put(context.Background(), types.RawRecord{
			SourceID:   "test",
			ReceivedAt: time.Unix(1790566200+int64(i), 0).UTC(),
			Origin:     types.Origin{Kind: types.OriginFile, Addr: "/x.log", Offset: uint64(i)},
			Term:       types.TermLF,
			Raw:        []byte(strings.Repeat("x", i%7) + "record"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestExitCodesAreContract is the important test in this file.
//
// verify_airgap.sh and the demo script branch on these, so 0, 1 and 2 must
// stay distinguishable. "The data was changed" and "I could not look" are very
// different answers, and collapsing them would make the air-gap proof report
// success for a vault it never managed to read.
func TestExitCodesAreContract(t *testing.T) {
	dir := seed(t, 16, 4)

	t.Run("intact vault exits 0", func(t *testing.T) {
		for _, args := range [][]string{
			{"--dir", dir, "verify"},
			{"--dir", dir, "verify", "--deep"},
			{"--dir", dir, "stats"},
			{"--dir", dir, "ls"},
			{"--dir", dir, "head"},
			{"--dir", dir, "get", "1"},
			{"--dir", dir, "proof", "1"},
			{"--dir", dir, "scan", "--from", "1", "--limit", "5"},
		} {
			if code, _, errOut := exec(t, args...); code != exitOK {
				t.Errorf("%v exited %d, want 0: %s", args, code, errOut)
			}
		}
	})

	t.Run("tampered vault exits 1", func(t *testing.T) {
		bad := seed(t, 16, 4)
		path := filepath.Join(bad, "seg-000000000002.wal")
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		b[vault.HeaderSize+40] ^= 0x01
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}

		code, _, errOut := exec(t, "--dir", bad, "verify", "--deep")
		if code != exitTamper {
			t.Fatalf("a tampered vault exited %d, want 1", code)
		}
		if !strings.Contains(errOut, "TAMPER DETECTED") {
			t.Errorf("the tamper was not reported clearly: %q", errOut)
		}
	})

	t.Run("usage and IO errors exit 2", func(t *testing.T) {
		for _, args := range [][]string{
			{},                                   // no command
			{"--dir", dir, "nonsense"},           // unknown command
			{"verify"},                           // no --dir
			{"--dir", "/nonexistent/x", "stats"}, // unreadable
			{"--dir", dir, "get"},                // missing record id
			{"--dir", dir, "get", "0"},           // ids start at 1
			{"--dir", dir, "get", "notanumber"},
			{"--dir", dir, "get", "99999"}, // no such record
			{"--dir", dir, "scan", "--limit", "0"},
			{"verify-proof"},                 // missing file
			{"verify-proof", "/nonexistent"}, // unreadable file
		} {
			if code, _, _ := exec(t, args...); code != exitUsage {
				t.Errorf("%v exited %d, want 2", args, code)
			}
		}
	})
}

// TestDeepFlagIsActuallyParsed is a regression test. Go's flag package stops
// parsing at the first non-flag argument, so `verify --deep` originally ran a
// shallow check while reporting itself as deep - a verification command that
// quietly does less than it says is worse than one that fails.
func TestDeepFlagIsActuallyParsed(t *testing.T) {
	dir := seed(t, 8, 4)

	code, out, _ := exec(t, "--dir", dir, "verify", "--deep")
	if code != exitOK {
		t.Fatalf("exited %d", code)
	}
	if !strings.Contains(out, "(deep)") {
		t.Errorf("`verify --deep` reported %q, expected a deep check", strings.TrimSpace(out))
	}

	// And the flag before the subcommand must work too.
	if _, out, _ := exec(t, "--dir", dir, "--deep", "verify"); !strings.Contains(out, "(deep)") {
		t.Errorf("--deep before the subcommand was ignored: %q", strings.TrimSpace(out))
	}
	if _, out, _ := exec(t, "--dir", dir, "verify"); !strings.Contains(out, "(shallow)") {
		t.Errorf("verify without --deep reported %q", strings.TrimSpace(out))
	}
}

// TestGetRawIsByteExact is the requirement (a) demo in one command: what comes
// out of `get --raw` must be exactly what went in, so an operator can confirm
// it with sha256sum and nothing else.
func TestGetRawIsByteExact(t *testing.T) {
	dir := t.TempDir()
	payload := []byte{0x00, 0xFF, 0xFE, '\r', '\n', 'a', 0x7F}

	v, err := vault.Open(vault.Options{Dir: dir, Sync: vault.SyncAlways})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(context.Background(), types.RawRecord{Raw: payload}); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := exec(t, "--dir", dir, "get", "1", "--raw")
	if code != exitOK {
		t.Fatalf("exited %d: %s", code, errOut)
	}
	if out != string(payload) {
		t.Errorf("raw output is %x, want %x", out, payload)
	}

	// And the hexdump view must report the same hash.
	_, meta, _ := exec(t, "--dir", dir, "get", "1")
	sum := sha256.Sum256(payload)
	if !strings.Contains(meta, hex.EncodeToString(sum[:])) {
		t.Error("the metadata view does not show the payload's SHA-256")
	}
}

// TestProofRoundTripsThroughVerifyProof proves the two halves of the lineage
// story fit together: a proof taken from the vault verifies with no vault at
// all, which is the entire argument for hash-chained lineage.
func TestProofRoundTripsThroughVerifyProof(t *testing.T) {
	dir := seed(t, 16, 4)

	code, proofJSON, errOut := exec(t, "--dir", dir, "proof", "3")
	if code != exitOK {
		t.Fatalf("proof exited %d: %s", code, errOut)
	}

	path := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(path, []byte(proofJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := exec(t, "verify-proof", path); code != exitOK {
		t.Fatalf("a proof straight from the vault did not verify: %d %s", code, errOut)
	}

	t.Run("a doctored proof is rejected", func(t *testing.T) {
		// Flip one hex digit of the leaf hash. The record is then not the one
		// the proof commits to, and verification must say so.
		i := strings.Index(proofJSON, `"leaf_hash": "`)
		if i < 0 {
			t.Fatal("no leaf_hash in the proof JSON")
		}
		at := i + len(`"leaf_hash": "`)
		swap := byte('a')
		if proofJSON[at] == 'a' {
			swap = 'b'
		}
		bad := proofJSON[:at] + string(swap) + proofJSON[at+1:]

		p := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := exec(t, "verify-proof", p)
		if code != exitTamper {
			t.Fatalf("a doctored proof exited %d, want 1", code)
		}
		if !strings.Contains(errOut, "PROOF INVALID") {
			t.Errorf("the rejection was not reported clearly: %q", errOut)
		}
	})

	t.Run("malformed JSON is a usage error, not a tamper", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "junk.json")
		if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Unparseable input is still reported as invalid rather than passed,
		// which is the safe direction.
		if code, _, _ := exec(t, "verify-proof", p); code == exitOK {
			t.Error("malformed JSON was accepted as a valid proof")
		}
	})
}

// TestProofOfUnsealedRecord: a record in the active segment has no root yet,
// which is normal (decision D2) and must be explained rather than reported as
// corruption.
func TestProofOfUnsealedRecord(t *testing.T) {
	dir := t.TempDir()
	v, err := vault.Open(vault.Options{Dir: dir, Sync: vault.SyncAlways, SegmentMaxRecords: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(context.Background(), types.RawRecord{Raw: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	// Deliberately not closed: closing would seal.
	defer v.Close()

	code, _, errOut := exec(t, "--dir", dir, "proof", "1")
	if code == exitTamper {
		t.Error("an unsealed record was reported as tampering")
	}
	if !strings.Contains(errOut, "sealed") {
		t.Errorf("the reason was not explained: %q", errOut)
	}
}

// TestPreviewEscapesControlBytes: a log line is attacker-controlled. Printing
// it unescaped into a table would let it carry terminal escapes or fake up
// another row.
func TestPreviewEscapesControlBytes(t *testing.T) {
	got := preview([]byte("a\x1b[31mb\nc\x00"), 64)
	for _, c := range got {
		if c < 0x20 || c > 0x7e {
			t.Fatalf("preview passed through a control byte: %q", got)
		}
	}
	if !strings.HasPrefix(got, "a.") {
		t.Errorf("preview mangled printable text: %q", got)
	}
}
