//go:build !windows

package tests

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

func TestVerifyChainDetectsTampering(t *testing.T) {
	base := filepath.Join(t.TempDir(), "base")
	v, err := vault.Open(vault.Options{Dir: base, Sync: vault.SyncAlways, SegmentMaxRecords: 2, SealInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err = v.Put(context.Background(), types.RawRecord{SourceID: "tamper", ReceivedAt: time.Date(2026, 9, 29, 0, 0, i, 0, time.UTC), Raw: []byte{byte(i), 'r', 'a', 'w'}}); err != nil {
			t.Fatal(err)
		}
	}
	if err = v.Close(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*testing.T, string){
		"flipped byte": func(t *testing.T, dir string) {
			p := firstSegment(t, dir)
			b := mustRead(t, p)
			b[len(b)/2] ^= 0x01
			mustWrite(t, p, b)
		},
		"deleted record bytes": func(t *testing.T, dir string) {
			p := firstSegment(t, dir)
			b := mustRead(t, p)
			if len(b) < 64 {
				t.Fatal("segment too short")
			}
			mustWrite(t, p, b[:len(b)-32])
		},
		"modified ledger root": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "chain.log")
			b := mustRead(t, p)
			needle := []byte(`"root":"`)
			at := bytes.Index(b, needle)
			if at < 0 {
				t.Fatal("root not found")
			}
			at += len(needle)
			if b[at] == '0' {
				b[at] = '1'
			} else {
				b[at] = '0'
			}
			mustWrite(t, p, b)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "vault")
			copyTree(t, base, dir)
			mutate(t, dir)
			if !tamperDetected(dir) {
				t.Fatal("deep verification accepted tampered vault")
			}
		})
	}
}

func tamperDetected(dir string) bool {
	v, err := vault.Open(vault.Options{Dir: dir, ReadOnly: true})
	if err != nil {
		return true
	}
	defer v.Close()
	report, err := v.VerifyChain(context.Background(), true)
	return err != nil || !report.OK
}
func firstSegment(t *testing.T, dir string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "seg-*.wal"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("segments=%v err=%v", matches, err)
	}
	return matches[0]
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		mustWrite(t, filepath.Join(dst, e.Name()), mustRead(t, filepath.Join(src, e.Name())))
	}
}
