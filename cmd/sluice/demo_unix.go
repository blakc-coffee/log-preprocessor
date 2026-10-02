//go:build !windows

package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dark-14100/sluice/pkg/anchor"
	"github.com/dark-14100/sluice/pkg/dataplane/app"
	"github.com/dark-14100/sluice/pkg/dataplane/normalizer"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/registry"
	"github.com/dark-14100/sluice/pkg/dataplane/vault"
	"github.com/dark-14100/sluice/pkg/evidence"
	types "github.com/dark-14100/sluice/pkg/types"
)

//go:embed demodata/*.sample
var demoData embed.FS

// runDemo plays the whole Sluice story on synthetic data: ingest, parse, quarantine, verify, prove,
// tamper, detect. It uses a temporary directory and no network or ports, and deletes it at the end.
func runDemo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fast := fs.Bool("fast", false, "no pauses between steps")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if err := demo(stdout, *fast); err != nil {
		fmt.Fprintln(stderr, "sluice demo:", err)
		return exitFailure
	}
	return exitOK
}

func demo(out io.Writer, fast bool) error {
	pause := func() {
		if !fast {
			time.Sleep(700 * time.Millisecond)
		}
	}
	say := func(f string, a ...any) { fmt.Fprintf(out, f+"\n", a...); pause() }
	ok := func(f string, a ...any) { fmt.Fprintf(out, "      ✓ "+f+"\n", a...); pause() }
	warn := func(f string, a ...any) { fmt.Fprintf(out, "      ! "+f+"\n", a...); pause() }
	caught := func(f string, a ...any) { fmt.Fprintf(out, "      ✓ CAUGHT: "+f+"\n", a...); pause() }
	ctx := context.Background()

	tmp, err := os.MkdirTemp("", "sluice-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	say("Sluice demo. Everything runs locally and offline, in a temporary folder that is deleted at the end.\n")

	// 1. ingest
	known, _ := demoData.ReadFile("demodata/cisco_asa.sample")
	unknown, _ := demoData.ReadFile("demodata/palo_alto_unknown.sample")
	say("[1/6] Ingest 100 raw log lines: 50 from a Cisco firewall, 50 in a format Sluice has never seen.")
	var recs []types.RawRecord
	base := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	for _, src := range []struct {
		id   string
		data []byte
	}{{"cisco_asa", known}, {"palo_alto_unknown", unknown}} {
		for _, line := range bytes.Split(bytes.TrimRight(src.data, "\n"), []byte("\n")) {
			recs = append(recs, types.RawRecord{SourceID: src.id, ReceivedAt: base.Add(time.Duration(len(recs)) * time.Second),
				Origin: types.Origin{Kind: types.OriginHTTP, Addr: "demo", Offset: uint64(len(recs))}, Term: types.TermLF, Raw: line})
		}
	}
	vdir := filepath.Join(tmp, "vault")
	v, err := vault.Open(vault.Options{Dir: vdir, Sync: vault.SyncAlways, Compact: true})
	if err != nil {
		return err
	}
	receipts, err := v.PutBatch(ctx, recs)
	if err != nil {
		return err
	}
	if err := v.Close(); err != nil { // closing seals the segment, so the records are covered by the chain
		return err
	}
	ok("%d records saved to the vault, byte for byte, before anything else touches them", len(recs))

	// 2. parse
	say("\n[2/6] Parse them into the open OCSF schema.")
	engine := parsers.New()
	reg := registry.New(engine, "")
	if err := app.LoadBuiltins(engine, reg); err != nil {
		return err
	}
	type parsed struct {
		raw    types.RawEvent
		parser *parsers.Parser
		event  types.NormalizedEvent
	}
	var events []parsed
	quarantined := 0
	for i, r := range recs {
		re := types.RawEvent{RawRecord: r, Receipt: receipts[i]}
		var hit *parsed
		for _, p := range reg.Active() {
			res, err := p.Parse(r.Raw, r.ReceivedAt)
			if err == nil && res != nil && res.OCSF != nil {
				hit = &parsed{raw: re, parser: p, event: normalizer.Build(re, p, res)}
				break
			}
		}
		if hit != nil {
			events = append(events, *hit)
		} else {
			quarantined++
		}
	}
	ok("%d became structured events", len(events))
	warn("%d are an unknown format: quarantined with their raw bytes intact, nothing is lost", quarantined)
	say("        (in a real deployment a parser is proposed for them and replayed from the vault once you approve it)")

	// 3. verify the vault
	say("\n[3/6] Prove the vault is intact.")
	rv, err := vault.Open(vault.Options{Dir: vdir, ReadOnly: true})
	if err != nil {
		return err
	}
	rep, err := rv.VerifyChain(ctx, true)
	if err != nil || !rep.OK {
		return fmt.Errorf("the demo vault does not verify: %v %+v", err, rep)
	}
	head, through, _ := rv.Head(ctx)
	seals, _ := rv.Seals(ctx)
	ok("hash chain intact (every record re-read and re-hashed): %d records, head %x…", through, head[:6])

	// 4. evidence for one event, signed and checked offline
	say("\n[4/6] Take ONE parsed event and prove it came from one original, unaltered log line.")
	pick := events[len(events)/2]
	rec, _, err := rv.Get(ctx, pick.raw.ID)
	if err != nil {
		return err
	}
	proof, err := rv.Proof(ctx, pick.raw.ID)
	if err != nil {
		return err
	}
	_ = rv.Close()
	key, err := anchor.LoadOrCreateKey(filepath.Join(tmp, "anchor.key"))
	if err != nil {
		return err
	}
	cp := anchor.Sign(key, head, uint64(through), uint64(len(seals)), time.Now(), nil)
	_, src, err := reg.Get(pick.parser.ID(), pick.parser.Version())
	if err != nil {
		return err
	}
	eventJSON, _ := json.Marshal(pick.event)
	b := evidence.Bundle{
		Format: evidence.Format, CreatedAt: time.Now().UTC(), Engine: parsers.EngineVersion, Sluice: version, Event: eventJSON,
		Record: evidence.Record{Seq: uint64(pick.raw.ID), SourceID: rec.SourceID, ReceivedAt: rec.ReceivedAt, Origin: rec.Origin,
			Terminator: rec.Term, Fragment: rec.Frag, RawBase64: base64.StdEncoding.EncodeToString(rec.Raw)},
		Proof: proof, Chain: evidence.Chain{Head: hex.EncodeToString(head[:]), SealedThrough: uint64(through)},
		Parser: &evidence.Parser{ID: pick.parser.ID(), Version: pick.parser.Version(), YAML: string(src)},
		Anchor: &evidence.Anchor{Checkpoint: cp, PublicKey: hex.EncodeToString(key.Public)},
	}
	fmt.Fprintf(out, "      the original log line:\n        %s\n", strings.TrimSpace(string(rec.Raw)))
	pause()
	r1 := evidence.Verify(b, evidence.Options{PublicKey: hex.EncodeToString(key.Public)})
	writeReport(out, r1)
	if !r1.OK {
		return fmt.Errorf("the genuine evidence did not verify")
	}
	ok("VERIFIED: with only that file, no Sluice and no network, anyone can check this")

	// 5. attacks
	say("\n[5/6] Now attack it.")
	say("      Attack A: someone flips ONE byte in the stored log file on disk.")
	copyDir := filepath.Join(tmp, "vault-tampered")
	if err := copyTree(vdir, copyDir); err != nil {
		return err
	}
	if err := flipByte(copyDir); err != nil {
		return err
	}
	tv, err := vault.Open(vault.Options{Dir: copyDir, ReadOnly: true})
	if err == nil {
		defer tv.Close()
		rep, verr := tv.VerifyChain(ctx, true)
		if verr == nil && rep.OK {
			return fmt.Errorf("tamper was NOT detected: that would be a bug")
		}
		caught("tampering detected: %s", firstNonEmpty(rep.Reason, fmt.Sprint(verr)))
	} else {
		caught("tampering detected: the vault refuses to open: %v", err)
	}
	say("      Attack B: someone edits only the PARSED event (changes the destination port) and leaves the raw log alone.")
	forged := b
	forged.Event = bytes.Replace(b.Event, []byte(`"port":`), []byte(`"port":1`), 1)
	if bytes.Equal(forged.Event, b.Event) {
		return fmt.Errorf("the demo's forgery changed nothing: that would make attack B meaningless")
	}
	r2 := evidence.Verify(forged, evidence.Options{PublicKey: hex.EncodeToString(key.Public)})
	for _, c := range r2.Checks {
		if !c.Skip && !c.OK {
			caught("%s fails: the parsed event does not come from that raw log", c.Name)
		}
	}
	if r2.OK {
		return fmt.Errorf("a forged event passed: that would be a bug")
	}
	say("      Attack C: someone rewrites the chain head in the signed checkpoint.")
	forged = b
	cpBad := b.Anchor.Checkpoint
	cpBad.Head = strings.Repeat("ab", 32)
	forged.Anchor = &evidence.Anchor{Checkpoint: cpBad, PublicKey: b.Anchor.PublicKey}
	if r3 := evidence.Verify(forged, evidence.Options{}); r3.OK {
		return fmt.Errorf("a forged checkpoint passed: that would be a bug")
	}
	caught("the signature does not match: the checkpoint cannot be altered without the signing key")

	// 6. the point
	say("\n[6/6] What this gives you.")
	ok("every raw log is kept exactly, so unknown formats are fixed later with no data loss")
	ok("any parsed event can be handed to an auditor with a proof they can check on their own")
	ok("an attacker changing the log, the parsed event or the checkpoint is caught")
	say("\nLimits, honestly: the checkpoint key lives on the same machine by default, so against an administrator of that")
	say("machine the protection depends on where you keep the key and publish checkpoints (`sluice anchor`).")
	say("Nothing from this demo was left on your machine.")
	return nil
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" && s != "<nil>" {
			return s
		}
	}
	return "the stored data no longer matches its hashes"
}

func copyTree(from, to string) error {
	return filepath.Walk(from, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if fi.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		if fi.Name() == "LOCK" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
}

// flipByte damages one byte inside the first segment file.
func flipByte(dir string) error {
	matches, _ := filepath.Glob(filepath.Join(dir, "seg-*.zst"))
	if len(matches) == 0 {
		matches, _ = filepath.Glob(filepath.Join(dir, "seg-*.wal"))
	}
	if len(matches) == 0 {
		return fmt.Errorf("no segment file to damage in %s", dir)
	}
	b, err := os.ReadFile(matches[0])
	if err != nil || len(b) < 300 {
		return fmt.Errorf("segment too small to damage: %v", err)
	}
	b[200] ^= 0xff
	return os.WriteFile(matches[0], b, 0o600)
}
