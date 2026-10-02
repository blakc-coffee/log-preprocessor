//go:build !windows

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dark-14100/sluice/pkg/anchor"
	"github.com/dark-14100/sluice/pkg/dataplane/vault"
	"github.com/dark-14100/sluice/pkg/evidence"
	types "github.com/dark-14100/sluice/pkg/types"
)

// defaultDataDir is where `sluice` keeps data when no config is given.
func defaultDataDir() string {
	if v := os.Getenv("SLUICE_DATA"); v != "" {
		return v
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".sluice", "data")
	}
	return "sluice-data"
}

// attachAnchor adds the earliest signed checkpoint that covers the record, with the segment seals
// between the record's segment and that checkpoint, so the verifier can walk the chain offline.
func attachAnchor(b *evidence.Bundle, dataDir, wantHead string) error {
	cps, err := anchor.Read(filepath.Join(dataDir, "anchors.log"))
	if err != nil {
		return err
	}
	var cp *anchor.Checkpoint
	for i := range cps {
		if cps[i].SealedThrough >= b.Record.Seq && cps[i].Segments >= b.Proof.Segment &&
			(wantHead == "" || strings.HasPrefix(cps[i].Head, strings.ToLower(wantHead))) {
			cp = &cps[i]
			break
		}
	}
	if cp == nil && wantHead != "" {
		return fmt.Errorf("no checkpoint with head starting %q covers record %d", wantHead, b.Record.Seq)
	}
	if cp == nil {
		return fmt.Errorf("no signed checkpoint covers record %d yet (checkpoints follow each seal by a few seconds)", b.Record.Seq)
	}
	pub, err := anchor.ReadPublicKey(filepath.Join(dataDir, "keys", "anchor.key"))
	if err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	v, err := vault.Open(vault.Options{Dir: filepath.Join(dataDir, "vault"), ReadOnly: true})
	if err != nil {
		return err
	}
	defer v.Close()
	seals, err := v.Seals(context.Background())
	if err != nil {
		return err
	}
	var links []types.SegmentSeal
	for _, s := range seals {
		if s.Segment > b.Proof.Segment && s.Segment <= cp.Segments {
			links = append(links, s)
		}
	}
	b.Anchor = &evidence.Anchor{Checkpoint: *cp, PublicKey: hex.EncodeToString(pub), Links: links}
	return nil
}

func runAnchor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("anchor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("data-dir", defaultDataDir(), "Sluice data directory")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	pub, err := anchor.ReadPublicKey(filepath.Join(*dir, "keys", "anchor.key"))
	if err != nil {
		fmt.Fprintf(stderr, "sluice anchor: no signing key in %s (run `sluice` once first): %v\n", *dir, err)
		return exitFailure
	}
	logPath := filepath.Join(*dir, "anchors.log")
	n, err := anchor.VerifyLog(logPath, pub)
	if err != nil {
		fmt.Fprintf(stdout, "CHECKPOINT LOG INVALID after %d good checkpoint(s): %v\n", n, err)
		return exitFailure
	}
	cps, _ := anchor.Read(logPath)
	if n == 0 {
		fmt.Fprintln(stdout, "no checkpoints yet: they are signed a few seconds after the vault seals a segment")
		return exitFailure
	}
	last := cps[len(cps)-1]
	line, _ := json.Marshal(last)
	fmt.Fprintf(stdout, "signing key   %s  (public key, hex)\nkey id        %s\ncheckpoints   %d, all signatures valid, each chained to the previous one\n", hex.EncodeToString(pub), anchor.KeyID(pub), n)
	fmt.Fprintf(stdout, "latest        covers %d record(s) in %d segment(s), signed %s\nchain head    %s\n\n", last.SealedThrough, last.Segments, last.SignedAt.Format("2006-01-02 15:04:05 UTC"), last.Head)
	fmt.Fprintf(stdout, "Publish the public key and this line somewhere the operator cannot edit (print it, email it to an auditor, commit it elsewhere):\n%s\n\n", line)
	fmt.Fprintf(stdout, "Anyone holding them can later check evidence:  sluice verify-evidence FILE --pubkey %s\n", hex.EncodeToString(pub))
	fmt.Fprintln(stdout, "Caution: the private key is in "+filepath.Join(*dir, "keys", "anchor.key")+". Anyone who can read it can sign a forged history; move it off this host (anchor_key in the config) for the checkpoints to protect against an administrator.")
	return exitOK
}
