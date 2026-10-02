package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
