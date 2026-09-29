//go:build !windows

package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault"
	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

type fixtureManifest struct {
	Records []fixtureRecord `json:"records"`
}
type fixtureRecord struct {
	SourceFile     string `json:"source_file"`
	ByteStart      int    `json:"byte_start"`
	ByteEnd        int    `json:"byte_end"`
	Terminator     string `json:"terminator"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

func TestFixtureCorpusIsByteExactThroughVault(t *testing.T) {
	root := filepath.Join("..", "testdata")
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest fixtureManifest
	if err = json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(t.TempDir(), "vault")
	v, err := vault.Open(vault.Options{Dir: vaultDir, Sync: vault.SyncAlways, SegmentMaxRecords: 1000, MaxFrameBytes: 8 << 20, SealInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	type saved struct {
		id  types.RecordID
		sum [32]byte
		raw []byte
	}
	savedRecords := make([]saved, 0, len(manifest.Records))
	files := map[string][]byte{}
	for _, item := range manifest.Records {
		body := files[item.SourceFile]
		if body == nil {
			body, err = os.ReadFile(filepath.Join(root, item.SourceFile))
			if err != nil {
				t.Fatal(err)
			}
			files[item.SourceFile] = body
		}
		if item.ByteStart < 0 || item.ByteEnd < item.ByteStart || item.ByteEnd > len(body) {
			t.Fatalf("invalid byte range for %s", item.SourceFile)
		}
		original := append([]byte(nil), body[item.ByteStart:item.ByteEnd]...)
		sum := sha256.Sum256(original)
		if hex.EncodeToString(sum[:]) != item.ExpectedSHA256 {
			t.Fatalf("fixture hash mismatch %s[%d:%d]", item.SourceFile, item.ByteStart, item.ByteEnd)
		}
		receipt, err := v.Put(context.Background(), types.RawRecord{SourceID: item.SourceFile, ReceivedAt: time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC), Origin: types.Origin{Kind: types.OriginFile, Addr: item.SourceFile, Offset: uint64(item.ByteStart)}, Term: fixtureTerm(item.Terminator), Raw: original})
		if err != nil {
			t.Fatal(err)
		}
		if receipt.RawSHA256 != sum {
			t.Fatalf("receipt hash mismatch for %d", receipt.ID)
		}
		savedRecords = append(savedRecords, saved{id: receipt.ID, sum: sum, raw: original})
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	v, err = vault.Open(vault.Options{Dir: vaultDir, ReadOnly: true, MaxFrameBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	for _, want := range savedRecords {
		record, receipt, err := v.Get(context.Background(), want.id)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.RawSHA256 != want.sum || !bytes.Equal(record.Raw, want.raw) {
			t.Fatalf("record %d was not byte exact", want.id)
		}
		byHash, err := v.GetByHash(context.Background(), want.sum)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(byHash, want.raw) {
			t.Fatalf("hash lookup for %d was not byte exact", want.id)
		}
	}
	report, err := v.VerifyChain(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK {
		t.Fatalf("deep chain verification failed: %+v", report)
	}
}

func fixtureTerm(v string) types.Terminator {
	switch v {
	case "LF":
		return types.TermLF
	case "CRLF":
		return types.TermCRLF
	case "NUL":
		return types.TermNUL
	default:
		return types.TermNone
	}
}
