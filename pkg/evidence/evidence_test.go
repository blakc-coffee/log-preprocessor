package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/dark-14100/sluice/pkg/anchor"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dark-14100/sluice/pkg/dataplane/normalizer"
	"github.com/dark-14100/sluice/pkg/dataplane/parsers"
	"github.com/dark-14100/sluice/pkg/dataplane/vault/merkle"
	"github.com/dark-14100/sluice/pkg/dataplane/vault/record"
	types "github.com/dark-14100/sluice/pkg/types"
)

const parserYAML = `id: demo_json
version: 1.0.0
vendor: acme
product: fw
timezone: "+00:00"
match: {signature: '^\{'}
ocsf_defaults: {class_uid: 4001, category_uid: 4}
extractors:
  - id: e
    kind: json
    map:
      - {from: src, to: src_endpoint.ip, type: ip}
      - {const: 6, to: activity_id}
`

// build makes a 3-record segment through the real record encoder, Merkle tree and parser, and
// returns a bundle for record 2.
func build(t *testing.T) Bundle {
	t.Helper()
	at := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	raws := []string{`{"src":"10.0.0.1"}`, `{"src":"10.0.0.2"}`, `{"src":"10.0.0.3"}`}
	var recs []types.RawRecord
	var leaves [][32]byte
	for i, r := range raws {
		rec := types.RawRecord{SourceID: "fw1", ReceivedAt: at.Add(time.Duration(i) * time.Second),
			Origin: types.Origin{Kind: types.OriginHTTP, Addr: "127.0.0.1:1", Offset: uint64(i * 20)}, Term: types.TermLF, Raw: []byte(r)}
		body, err := record.Encode(nil, types.RecordID(i+1), rec)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
		leaves = append(leaves, merkle.LeafHash(body))
	}
	const idx = 1
	root := merkle.Root(leaves)
	proof := types.InclusionProof{Segment: 1, LeafIndex: idx, TreeSize: 3, LeafHash: leaves[idx], Path: merkle.Path(leaves, idx), Root: root}
	proof.Chain = merkle.ChainHash(proof.PrevChain, root, 1, 3)

	p, err := parsers.New().Load([]byte(parserYAML))
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Parse(recs[idx].Raw, recs[idx].ReceivedAt)
	if err != nil {
		t.Fatal(err)
	}
	sum := [32]byte{}
	copy(sum[:], mustSHA(recs[idx].Raw))
	ev := normalizer.Build(types.RawEvent{RawRecord: recs[idx], Receipt: types.Receipt{ID: idx + 1, RawSHA256: sum, Segment: 1}}, p, res)
	evJSON, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{
		Format: Format, Event: evJSON,
		Record: Record{Seq: idx + 1, SourceID: "fw1", ReceivedAt: recs[idx].ReceivedAt, Origin: recs[idx].Origin, Terminator: types.TermLF,
			RawBase64: base64.StdEncoding.EncodeToString(recs[idx].Raw)},
		Proof: proof, Chain: Chain{Head: hex.EncodeToString(proof.Chain[:]), SealedThrough: 3},
		Parser: &Parser{ID: "demo_json", Version: "1.0.0", YAML: parserYAML},
	}
}

func mustSHA(b []byte) []byte {
	h := hexSum(b)
	out, _ := hex.DecodeString(h)
	return out
}

func failed(r Report) []string {
	var out []string
	for _, c := range r.Checks {
		if !c.Skip && !c.OK {
			out = append(out, c.Name)
		}
	}
	return out
}

func TestGoodBundlePassesEveryCheck(t *testing.T) {
	b := build(t)
	r := Verify(b, Options{Anchor: b.Chain.Head})
	if !r.OK {
		t.Fatalf("a correct bundle must pass; failed: %v\n%+v", failed(r), r.Checks)
	}
	// And the anchor-less run passes too, with the anchor check skipped rather than passed.
	r = Verify(b, Options{})
	if !r.OK {
		t.Fatalf("no anchor: %v", failed(r))
	}
}

// Every way of changing the evidence must fail a check. These are the claims the feature makes.
func TestTamperingIsCaught(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b *Bundle)
		want   string // a check that must fail
	}{
		{"raw byte flipped", func(b *Bundle) {
			raw, _ := base64.StdEncoding.DecodeString(b.Record.RawBase64)
			raw[10] ^= 1
			b.Record.RawBase64 = base64.StdEncoding.EncodeToString(raw)
		}, "raw bytes match the event's SHA-256"},
		{"source id changed", func(b *Bundle) { b.Record.SourceID = "fw2" }, "record hashes to the vault's leaf"},
		{"sequence number changed", func(b *Bundle) { b.Record.Seq = 9 }, "record hashes to the vault's leaf"},
		{"received time changed", func(b *Bundle) { b.Record.ReceivedAt = b.Record.ReceivedAt.Add(time.Second) }, "record hashes to the vault's leaf"},
		{"origin changed", func(b *Bundle) { b.Record.Origin.Addr = "6.6.6.6:1" }, "record hashes to the vault's leaf"},
		{"merkle path edited", func(b *Bundle) { b.Proof.Path[0][0] ^= 1 }, "leaf is in the segment's Merkle tree"},
		{"tree root edited", func(b *Bundle) { b.Proof.Root[0] ^= 1 }, "leaf is in the segment's Merkle tree"},
		{"chain value edited", func(b *Bundle) { b.Proof.Chain[0] ^= 1 }, "segment chain value follows from the tree root"},
		{"event ocsf edited", func(b *Bundle) {
			b.Event = []byte(strings.Replace(string(b.Event), `"10.0.0.2"`, `"10.9.9.9"`, 1))
		}, "re-parsing the raw bytes reproduces the event"},
		{"different parser version claimed", func(b *Bundle) { b.Parser.Version = "9.9.9" }, "re-parsing the raw bytes reproduces the event"},
		{"unknown format", func(b *Bundle) { b.Format = "other/9" }, "bundle format"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := build(t)
			c.mutate(&b)
			r := Verify(b, Options{})
			if r.OK {
				t.Fatalf("tampered bundle passed")
			}
			found := false
			for _, f := range failed(r) {
				found = found || f == c.want
			}
			if !found {
				t.Fatalf("expected %q to fail, failed: %v", c.want, failed(r))
			}
		})
	}
}

func TestWrongAnchorFails(t *testing.T) {
	b := build(t)
	if r := Verify(b, Options{Anchor: strings.Repeat("ab", 32)}); r.OK {
		t.Fatal("an anchor that matches neither the chain nor the head must fail")
	}
}

func TestGarbageDoesNotPanic(t *testing.T) {
	for _, b := range []Bundle{{}, {Format: Format}, {Format: Format, Event: []byte("{")}, {Format: Format, Event: []byte("{}"), Record: Record{RawBase64: "!!"}}} {
		if r := Verify(b, Options{}); r.OK {
			t.Fatalf("garbage bundle passed: %+v", b)
		}
	}
}

func hexSum(b []byte) string {
	s := sha256sum(b)
	return hex.EncodeToString(s[:])
}

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }

// withCheckpoint extends the bundle's chain by two more sealed segments and signs the new head, the
// shape a real vault produces: record in segment 1, a checkpoint over segments 1-3.
func withCheckpoint(t *testing.T, b Bundle) (Bundle, anchor.Key) {
	t.Helper()
	k, err := anchor.LoadOrCreateKey(filepath.Join(t.TempDir(), "key"))
	if err != nil {
		t.Fatal(err)
	}
	running := b.Proof.Chain
	var links []types.SegmentSeal
	for seg := uint64(2); seg <= 3; seg++ {
		root := [32]byte{byte(seg), 0xaa}
		seal := types.SegmentSeal{Segment: seg, FirstSeq: seg * 10, LastSeq: seg*10 + 4, Count: 5, Root: root, Prev: running}
		seal.Chain = merkle.ChainHash(running, root, seg, 5)
		links = append(links, seal)
		running = seal.Chain
	}
	cp := anchor.Sign(k, running, 34, 3, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), nil)
	b.Anchor = &Anchor{Checkpoint: cp, PublicKey: hex.EncodeToString(k.Public), Links: links}
	b.Chain = Chain{Head: cp.Head, SealedThrough: 34}
	return b, k
}

func TestSignedCheckpointVerifiesAndPinsTheKey(t *testing.T) {
	b, k := withCheckpoint(t, build(t))
	r := Verify(b, Options{PublicKey: hex.EncodeToString(k.Public)})
	if !r.OK {
		t.Fatalf("a genuine checkpoint must pass: %v", failed(r))
	}
	covered := false
	for _, c := range r.Checks {
		covered = covered || (c.Name == "signed checkpoint covers this record's chain" && c.OK)
	}
	if !covered {
		t.Fatalf("the coverage check did not pass: %+v", r.Checks)
	}
	// Without a trusted key the signature still verifies, but trust is reported as not established.
	if r := Verify(b, Options{}); !r.OK {
		t.Fatalf("no --pubkey: %v", failed(r))
	}
}

func TestCheckpointForgeriesAreCaught(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b *Bundle, other anchor.Key)
		opt    func(k anchor.Key) Options
		want   string
	}{
		{"head edited", func(b *Bundle, _ anchor.Key) { b.Anchor.Checkpoint.Head = strings.Repeat("ab", 32) }, nil, "signed checkpoint covers this record's chain"},
		{"covers fewer records", func(b *Bundle, _ anchor.Key) { b.Anchor.Checkpoint.SealedThrough = 1 }, nil, "signed checkpoint covers this record's chain"},
		{"a link removed", func(b *Bundle, _ anchor.Key) { b.Anchor.Links = b.Anchor.Links[:1] }, nil, "signed checkpoint covers this record's chain"},
		{"a link's root edited", func(b *Bundle, _ anchor.Key) { b.Anchor.Links[0].Root[0] ^= 1 }, nil, "signed checkpoint covers this record's chain"},
		{"record's chain value swapped", func(b *Bundle, _ anchor.Key) { b.Proof.Chain[0] ^= 1 }, nil, "signed checkpoint covers this record's chain"},
		{"signature from another key", func(b *Bundle, other anchor.Key) {
			b.Anchor.Checkpoint = anchor.Sign(other, mustHead(t, b.Anchor.Checkpoint.Head), 34, 3, time.Now(), nil)
		}, nil, "signed checkpoint covers this record's chain"},
		{"attacker signs with own key and bundles it", func(b *Bundle, other anchor.Key) {
			b.Anchor.Checkpoint = anchor.Sign(other, mustHead(t, b.Anchor.Checkpoint.Head), 34, 3, time.Now(), nil)
			b.Anchor.PublicKey = hex.EncodeToString(other.Public)
		}, func(k anchor.Key) Options { return Options{PublicKey: hex.EncodeToString(k.Public)} }, "checkpoint was signed by the key you trust"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, k := withCheckpoint(t, build(t))
			other, _ := anchor.LoadOrCreateKey(filepath.Join(t.TempDir(), "other"))
			c.mutate(&b, other)
			opt := Options{}
			if c.opt != nil {
				opt = c.opt(k)
			}
			r := Verify(b, opt)
			if r.OK {
				t.Fatal("forged checkpoint passed")
			}
			hit := false
			for _, f := range failed(r) {
				hit = hit || f == c.want
			}
			if !hit {
				t.Fatalf("expected %q to fail, failed: %v", c.want, failed(r))
			}
		})
	}
}

func mustHead(t *testing.T, h string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 32 {
		t.Fatal("bad head")
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

func deriveResult(r Report) Check {
	for _, c := range r.Checks {
		if c.Name == "re-parsing the raw bytes reproduces the event" {
			return c
		}
	}
	return Check{}
}

func TestEngineVersionNeverExcusesAForgery(t *testing.T) {
	// A genuine bundle from another engine version still passes when the output is identical.
	b := build(t)
	b.Engine = "0"
	if c := deriveResult(Verify(b, Options{})); !c.OK || !strings.Contains(c.Detail, "engine 0") {
		t.Fatalf("same output under a different engine must pass and say so: %+v", c)
	}
	// A forged event must fail whatever engine the bundle claims, and say how to tell the cases apart.
	for _, claimed := range []string{"", "1", "0", "999"} {
		f := build(t)
		f.Engine = claimed
		f.Event = []byte(strings.Replace(string(f.Event), `"10.0.0.2"`, `"10.9.9.9"`, 1))
		c := deriveResult(Verify(f, Options{}))
		if c.OK || c.Skip {
			t.Fatalf("a forged event passed or was skipped when the bundle claimed engine %q", claimed)
		}
		if claimed != "" && claimed != "1" && !strings.Contains(c.Detail, "engine "+claimed) {
			t.Fatalf("the failure should explain the engine difference: %q", c.Detail)
		}
	}
}
