package main

// sluice evidence / sluice verify-evidence: export a portable proof that one parsed event came from
// one original record, and check such a proof with no Sluice running (see pkg/evidence).

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dark-14100/sluice/pkg/evidence"
	types "github.com/dark-14100/sluice/pkg/types"
)

// buildEvidence collects everything Verify needs for one event from a running Sluice.
func buildEvidence(c *tuiClient, eventID string) (evidence.Bundle, error) {
	esc := url.PathEscape(eventID)
	var b evidence.Bundle

	eventJSON, err := c.get("/api/events/" + esc)
	if err != nil {
		return b, fmt.Errorf("event %q: %w", eventID, err)
	}
	var ev struct {
		RecordID      uint64 `json:"record_id"`
		SourceID      string `json:"source_id"`
		ParserID      string `json:"parser_id"`
		ParserVersion string `json:"parser_version"`
	}
	if err := json.Unmarshal(eventJSON, &ev); err != nil {
		return b, err
	}

	var raw struct {
		ReceivedAt time.Time        `json:"received_at"`
		Origin     types.Origin     `json:"origin"`
		Terminator types.Terminator `json:"terminator"`
		Fragment   types.Fragment   `json:"fragment"`
		RawBase64  string           `json:"raw_base64"`
	}
	if err := c.do("GET", "/api/events/"+esc+"/raw", nil, &raw); err != nil {
		return b, fmt.Errorf("raw record: %w", err)
	}

	var lin struct {
		Sealed bool                  `json:"sealed"`
		Proof  *types.InclusionProof `json:"proof"`
		Chain  evidence.Chain        `json:"chain"`
	}
	if err := c.do("GET", "/api/lineage/"+esc, nil, &lin); err != nil {
		return b, fmt.Errorf("lineage: %w", err)
	}
	if !lin.Sealed || lin.Proof == nil {
		return b, errors.New("this record is still in the active segment and has no proof yet; try again in a few seconds")
	}

	b = evidence.Bundle{
		Format: evidence.Format, CreatedAt: time.Now().UTC(), Source: c.base, Event: eventJSON,
		Record: evidence.Record{Seq: ev.RecordID, SourceID: ev.SourceID, ReceivedAt: raw.ReceivedAt, Origin: raw.Origin,
			Terminator: raw.Terminator, Fragment: raw.Fragment, RawBase64: raw.RawBase64},
		Proof: *lin.Proof, Chain: lin.Chain,
	}
	if yaml, err := c.get("/api/parsers/" + url.PathEscape(ev.ParserID) + "/versions/" + url.PathEscape(ev.ParserVersion)); err == nil {
		b.Parser = &evidence.Parser{ID: ev.ParserID, Version: ev.ParserVersion, YAML: string(yaml)}
	} // without the parser the bundle still proves the record; it just cannot re-derive the event
	return b, nil
}

func writeReport(w io.Writer, r evidence.Report) {
	for _, c := range r.Checks {
		mark := "PASS"
		switch {
		case c.Skip:
			mark = "skip"
		case !c.OK:
			mark = "FAIL"
		}
		fmt.Fprintf(w, "  %-4s  %s\n        %s\n", mark, c.Name, c.Detail)
	}
}

func runEvidence(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("url", envOr("SLUICE_URL", "http://127.0.0.1:8000"), "control plane URL")
	user := fs.String("user", envOr("SLUICE_USER", ""), "sign-in name, if required")
	pass := fs.String("password", envOr("SLUICE_PASSWORD", ""), "sign-in password")
	insecure := fs.Bool("insecure", false, "accept a self-signed TLS certificate")
	out := fs.String("o", "", "output file (default evidence-<record>.json)")
	// Go's flag package stops at the first positional, so accept the event id before or after the flags.
	var pos []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return exitUsage
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: sluice evidence EVENT_ID [-o FILE]   (EVENT_ID looks like 966.suricata_eve@1.0.0; find one in `sluice tui`)")
		return exitUsage
	}
	c := newTUIClient(*base, "", *user, *pass, *insecure)
	b, err := buildEvidence(c, pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "sluice evidence:", err)
		return exitFailure
	}
	file := *out
	if file == "" {
		file = fmt.Sprintf("evidence-%d.json", b.Record.Seq)
	}
	data, _ := json.MarshalIndent(b, "", "  ")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		fmt.Fprintln(stderr, "sluice evidence:", err)
		return exitFailure
	}
	rep := evidence.Verify(b, evidence.Options{})
	fmt.Fprintf(stdout, "wrote %s (%d bytes)\nself-check:\n", file, len(data))
	writeReport(stdout, rep)
	if !rep.OK {
		return exitFailure
	}
	fmt.Fprintf(stdout, "\nAnyone can check it, offline:  sluice verify-evidence %s [--anchor CHAIN_VALUE]\n", file)
	fmt.Fprintf(stdout, "Segment chain value to pin somewhere the operator cannot edit: %x\n", b.Proof.Chain)
	return exitOK
}

func runVerifyEvidence(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	anchor := fs.String("anchor", "", "a chain value or head you got from somewhere the operator cannot edit")
	var pos []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return exitUsage
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "usage: sluice verify-evidence FILE [--anchor CHAIN_VALUE]")
		return exitUsage
	}
	data, err := os.ReadFile(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "sluice verify-evidence:", err)
		return exitUsage
	}
	var b evidence.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		fmt.Fprintln(stderr, "sluice verify-evidence: not a valid evidence file:", err)
		return exitUsage
	}
	rep := evidence.Verify(b, evidence.Options{Anchor: *anchor})
	fmt.Fprintf(stdout, "evidence for record %d (%s)\n", b.Record.Seq, b.Record.SourceID)
	writeReport(stdout, rep)
	if !rep.OK {
		fmt.Fprintln(stdout, "\nRESULT: FAILED. This evidence does not hold up.")
		return exitFailure
	}
	fmt.Fprintln(stdout, "\nRESULT: VERIFIED.")
	if strings.TrimSpace(*anchor) == "" {
		fmt.Fprintln(stdout, "Note: no --anchor was given, so this shows the bundle is internally consistent. To show it is the chain the operator published, compare the chain value with one you recorded independently.")
	}
	return exitOK
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
