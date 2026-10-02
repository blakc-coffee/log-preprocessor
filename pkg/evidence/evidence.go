// Package evidence builds and checks a portable proof that one parsed event came from one
// original log record, and that the record is exactly what the vault sealed.
//
// A bundle carries the event as served, the full vault record (source, origin, time, terminator
// and raw bytes), the Merkle inclusion proof and chain values, and the parser that produced the
// event. Verify needs nothing else: no vault, no network, no running Sluice.
//
// What a passing bundle shows, and what it does not:
//
//   - The raw bytes hash to the event's raw_sha256, so the event names these bytes.
//   - The encoded record (which covers source, origin, sequence number, terminator and the raw
//     bytes) hashes to the proof's leaf, the leaf is in the segment's Merkle tree, and the
//     segment's chain value follows from the tree root. Edit any byte and a check fails.
//   - Re-running the bundled parser on the raw bytes reproduces the event's OCSF, so the parsed
//     event really derives from the original record.
//   - It does NOT show the segment is the one the operator published, unless you pass an anchor:
//     a chain value or head you obtained somewhere the operator cannot edit. Without one, a
//     party who can rewrite the whole vault consistently could also forge a consistent bundle.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dark-14100/sluice/pkg/anchor"
	"github.com/dark-14100/sluice/pkg/dataplane/normalizer"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/vault/merkle"
	"github.com/dark-14100/sluice/pkg/dataplane/vault/record"
	types "github.com/dark-14100/sluice/pkg/types"
)

// Format names the bundle layout. Verify refuses anything else.
const Format = "sluice-evidence/1"

// Bundle is the portable evidence file.
type Bundle struct {
	Format    string               `json:"format"`
	CreatedAt time.Time            `json:"created_at"`
	Source    string               `json:"source,omitempty"`         // where it was exported from; informational
	Engine    string               `json:"engine_version,omitempty"` // parser engine the exporter re-derived the event with
	Sluice    string               `json:"sluice_version,omitempty"` // informational
	Event     json.RawMessage      `json:"event"`                    // the normalized event exactly as served
	Record    Record               `json:"record"`
	Proof     types.InclusionProof `json:"proof"`
	Chain     Chain                `json:"chain"`
	Parser    *Parser              `json:"parser,omitempty"`
	Anchor    *Anchor              `json:"anchor,omitempty"`
}

// Anchor ties the record's chain to a signed checkpoint: the checkpoint, the key that signed it,
// and the segment seals between the record's segment and the checkpoint.
type Anchor struct {
	Checkpoint anchor.Checkpoint   `json:"checkpoint"`
	PublicKey  string              `json:"public_key"` // hex ed25519
	Links      []types.SegmentSeal `json:"links"`
}

// Record is the vault record, field for field what the vault hashed.
type Record struct {
	Seq        uint64           `json:"seq"`
	SourceID   string           `json:"source_id"`
	ReceivedAt time.Time        `json:"received_at"`
	Origin     types.Origin     `json:"origin"`
	Terminator types.Terminator `json:"terminator"`
	Fragment   types.Fragment   `json:"fragment"`
	RawBase64  string           `json:"raw_base64"`
}

// Chain is the vault's chain state when the bundle was made.
type Chain struct {
	Head          string `json:"head"`
	SealedThrough uint64 `json:"sealed_through"`
}

// Parser is the exact parser version that produced the event.
type Parser struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	YAML    string `json:"yaml"`
}

// Check is one verification step.
type Check struct {
	Name   string
	OK     bool
	Skip   bool // not applicable or not asked for; neither a pass nor a failure
	Detail string
}

// Report is the outcome of Verify.
type Report struct {
	Checks []Check
	OK     bool // every non-skipped check passed
}

// Options tune Verify.
type Options struct {
	// PublicKey is a signing key you trust (hex), obtained independently of the operator. When set,
	// the bundle's checkpoint must be signed by it.
	PublicKey string
	// Anchor is a chain value or head obtained independently of the operator. When set, it must
	// equal the bundle's segment chain value or its recorded head.
	Anchor string
}

type eventView struct {
	EventID         string          `json:"event_id"`
	RecordID        uint64          `json:"record_id"`
	RawSHA256       string          `json:"raw_sha256"`
	SourceID        string          `json:"source_id"`
	ParserID        string          `json:"parser_id"`
	ParserVersion   string          `json:"parser_version"`
	TimeFromReceipt bool            `json:"time_from_receipt"`
	OCSF            json.RawMessage `json:"ocsf"`
}

// Verify checks a bundle and reports every step. It never panics on hostile input.
func Verify(b Bundle, opt Options) (r Report) {
	add := func(name string, ok bool, detail string) {
		r.Checks = append(r.Checks, Check{Name: name, OK: ok, Detail: detail})
	}
	skip := func(name, detail string) { r.Checks = append(r.Checks, Check{Name: name, Skip: true, Detail: detail}) }
	defer func() {
		r.OK = true
		for _, c := range r.Checks {
			if !c.Skip && !c.OK {
				r.OK = false
			}
		}
	}()

	if b.Format != Format {
		add("bundle format", false, fmt.Sprintf("got %q, want %q", b.Format, Format))
		return r
	}
	var ev eventView
	if err := json.Unmarshal(b.Event, &ev); err != nil {
		add("event readable", false, err.Error())
		return r
	}
	raw, err := base64.StdEncoding.DecodeString(b.Record.RawBase64)
	if err != nil {
		add("raw bytes readable", false, err.Error())
		return r
	}

	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	add("raw bytes match the event's SHA-256", got == ev.RawSHA256, fmt.Sprintf("sha256(raw) = %s", short(got)))
	add("event refers to this record", ev.RecordID == b.Record.Seq && ev.SourceID == b.Record.SourceID,
		fmt.Sprintf("event record %d source %q, record %d source %q", ev.RecordID, ev.SourceID, b.Record.Seq, b.Record.SourceID))

	rec := types.RawRecord{SourceID: b.Record.SourceID, ReceivedAt: b.Record.ReceivedAt, Origin: b.Record.Origin,
		Term: b.Record.Terminator, Frag: b.Record.Fragment, Raw: raw}
	body, err := record.Encode(nil, types.RecordID(b.Record.Seq), rec)
	if err != nil {
		add("record re-encodes", false, err.Error())
		return r
	}
	leaf := merkle.LeafHash(body)
	add("record hashes to the vault's leaf", leaf == b.Proof.LeafHash, fmt.Sprintf("leaf = %s", short(hex.EncodeToString(leaf[:]))))
	add("leaf is in the segment's Merkle tree", merkle.VerifyInclusion(b.Proof.LeafHash, b.Proof.LeafIndex, b.Proof.TreeSize, b.Proof.Path, b.Proof.Root),
		fmt.Sprintf("record %d of %d in segment %d", b.Proof.LeafIndex+1, b.Proof.TreeSize, b.Proof.Segment))
	add("segment chain value follows from the tree root", merkle.VerifyChainLink(b.Proof),
		fmt.Sprintf("chain = %s", short(hex.EncodeToString(b.Proof.Chain[:]))))

	switch a := strings.ToLower(strings.TrimSpace(opt.Anchor)); {
	case a == "":
		skip("matches an external anchor", "no --anchor given: this proves the bundle is self-consistent, not that the operator published this chain")
	default:
		chain := hex.EncodeToString(b.Proof.Chain[:])
		add("matches an external anchor", a == chain || a == strings.ToLower(b.Chain.Head), "anchor compared with the segment chain value and the recorded head")
	}

	r.Checks = append(r.Checks, deriveCheck(b, ev, rec))
	r.Checks = append(r.Checks, checkpointChecks(b, opt)...)
	return r
}

// checkpointChecks verifies the signed checkpoint section: the signature, that the chain from this
// record's segment reaches the checkpoint's head, and (if asked) that the key is the trusted one.
func checkpointChecks(b Bundle, opt Options) []Check {
	const covered = "signed checkpoint covers this record's chain"
	const trusted = "checkpoint was signed by the key you trust"
	if b.Anchor == nil {
		return []Check{{Name: covered, Skip: true, Detail: "no signed checkpoint in the bundle (export with --data-dir, or the record is not sealed into a checkpoint yet)"}}
	}
	pub, err := anchor.ParsePublicKey(b.Anchor.PublicKey)
	if err != nil {
		return []Check{{Name: covered, Detail: "bundled public key: " + err.Error()}}
	}
	cp := b.Anchor.Checkpoint
	if err := cp.Verify(pub); err != nil {
		return []Check{{Name: covered, Detail: err.Error()}}
	}
	if b.Record.Seq == 0 || b.Record.Seq > cp.SealedThrough {
		return []Check{{Name: covered, Detail: fmt.Sprintf("record %d is beyond the checkpoint (covers up to %d)", b.Record.Seq, cp.SealedThrough)}}
	}
	running := b.Proof.Chain
	segment := b.Proof.Segment
	for _, l := range b.Anchor.Links {
		if l.Segment != segment+1 || l.Prev != running || merkle.ChainHash(l.Prev, l.Root, l.Segment, l.Count) != l.Chain {
			return []Check{{Name: covered, Detail: fmt.Sprintf("the chain breaks at segment %d", l.Segment)}}
		}
		running, segment = l.Chain, l.Segment
	}
	if hex.EncodeToString(running[:]) != cp.Head || segment != cp.Segments {
		return []Check{{Name: covered, Detail: "walking the chain from this record's segment does not reach the signed head"}}
	}
	out := []Check{{Name: covered, OK: true, Detail: fmt.Sprintf("signed by key %s over %d segment(s), head %s, %s", cp.KeyID, cp.Segments, short(cp.Head), cp.SignedAt.Format("2006-01-02 15:04:05 UTC")+" (the signer's clock)")}}
	switch want := strings.TrimSpace(opt.PublicKey); {
	case want == "":
		out = append(out, Check{Name: trusted, Skip: true, Detail: fmt.Sprintf("no --pubkey given. Compare key %s with one you recorded independently, otherwise the bundle could carry its own key", cp.KeyID)})
	default:
		trust, err := anchor.ParsePublicKey(want)
		switch {
		case err != nil:
			out = append(out, Check{Name: trusted, Detail: "--pubkey: " + err.Error()})
		case anchor.KeyID(trust) != cp.KeyID || !trust.Equal(pub):
			out = append(out, Check{Name: trusted, Detail: fmt.Sprintf("signed by key %s, not the key %s you trust", cp.KeyID, anchor.KeyID(trust))})
		default:
			out = append(out, Check{Name: trusted, OK: true, Detail: "key " + cp.KeyID})
		}
	}
	return out
}

// deriveCheck re-runs the bundled parser on the raw bytes and compares the OCSF it produces.
func deriveCheck(b Bundle, ev eventView, rec types.RawRecord) (c Check) {
	const name = "re-parsing the raw bytes reproduces the event"
	defer func() { // a hostile bundle must produce a failed check, never a crash
		if r := recover(); r != nil {
			c = Check{Name: name, Detail: fmt.Sprintf("parser crashed on this input: %v", r)}
		}
	}()
	if b.Parser == nil || b.Parser.YAML == "" {
		return Check{Name: name, Skip: true, Detail: "no parser in the bundle"}
	}
	if b.Parser.ID != ev.ParserID || b.Parser.Version != ev.ParserVersion {
		return Check{Name: name, Detail: fmt.Sprintf("bundle parser %s@%s is not the event's %s@%s", b.Parser.ID, b.Parser.Version, ev.ParserID, ev.ParserVersion)}
	}
	p, err := parsers.New().Load([]byte(b.Parser.YAML))
	if err != nil {
		return Check{Name: name, Detail: "parser does not load: " + err.Error()}
	}
	res, err := p.Parse(rec.Raw, rec.ReceivedAt)
	if err != nil {
		return Check{Name: name, Detail: "parser failed on the raw bytes: " + err.Error()}
	}
	if res == nil || res.OCSF == nil {
		return Check{Name: name, Detail: "the parser does not match these raw bytes"}
	}
	re := types.RawEvent{RawRecord: rec, Receipt: types.Receipt{ID: types.RecordID(b.Record.Seq), Segment: b.Proof.Segment}}
	derived := normalizer.Build(re, p, res)
	want, err1 := canon(ev.OCSF)
	got, err2 := canonValue(derived.OCSF)
	if err1 != nil || err2 != nil {
		return Check{Name: name, Detail: fmt.Sprintf("cannot compare: %v %v", err1, err2)}
	}
	differs := b.Engine != "" && b.Engine != parsers.EngineVersion
	if !bytes.Equal(want, got) {
		// Fail closed even when the engines differ: letting an unmatched engine version excuse a mismatch
		// would let a forger claim an old engine. The detail says how to tell the two cases apart.
		d := "the parser produces a different OCSF object from the bundled event"
		if differs {
			d += fmt.Sprintf(" (the bundle was verified with parser engine %s and this verifier is engine %s: if the bundle is genuine, check it with a Sluice release that has engine %s)", b.Engine, parsers.EngineVersion, b.Engine)
		}
		return Check{Name: name, Detail: d}
	}
	d := fmt.Sprintf("parser %s@%s, engine %s", b.Parser.ID, b.Parser.Version, parsers.EngineVersion)
	if differs {
		d += fmt.Sprintf(" (the bundle was made with engine %s; same result)", b.Engine)
	}
	return Check{Name: name, OK: true, Detail: d}
}

// canon re-encodes JSON with sorted keys and numbers kept as written, so two encodings of the
// same value compare equal byte for byte.
func canon(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func canonValue(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return canon(b)
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}
