package contracts_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/blakc-coffee/sluice/contracts"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/memvault"
	"github.com/blakc-coffee/sluice/pkg/dataplane/vault/merkle"
	types "github.com/blakc-coffee/sluice/pkg/types"
)

func compile(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(contracts.SchemaJSON))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("uef.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("uef.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func def(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(contracts.SchemaJSON))
	c := jsonschema.NewCompiler()
	_ = c.AddResource("uef.schema.json", doc)
	s, err := c.Compile("uef.schema.json#/$defs/" + name)
	if err != nil {
		t.Fatalf("definition %q: %v", name, err)
	}
	return s
}

func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := contracts.Golden(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decode(t *testing.T, b []byte) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The schema itself must be valid JSON Schema.
func TestSchemaCompiles(t *testing.T) { compile(t) }

// Every golden validates against its definition, and every golden has one.
func TestGoldensValidate(t *testing.T) {
	names := contracts.GoldenNames()
	if len(names) != len(contracts.GoldenSchema) {
		t.Fatalf("%d golden files but %d mappings: %v", len(names), len(contracts.GoldenSchema), names)
	}
	for _, name := range names {
		defName, ok := contracts.GoldenSchema[name]
		if !ok {
			t.Errorf("%s has no schema mapping", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			if err := def(t, defName).Validate(decode(t, golden(t, name))); err != nil {
				t.Fatalf("does not validate against %s:\n%v", defName, err)
			}
		})
	}
}

// The guard must be able to fail: each mutation below is a real contract
// violation and must be rejected. A schema that accepts everything would pass
// TestGoldensValidate too.
func TestSchemaRejects(t *testing.T) {
	cases := []struct{ name, golden, def, from, to string }{
		{"unknown integrity flag", "event_asa_built", "normalized_event", `"integrity_flags": []`, `"integrity_flags": ["made_up"]`},
		{"uppercase hash", "event_asa_built", "normalized_event", `"raw_sha256": "7a`, `"raw_sha256": "7A`},
		{"extra top-level key", "event_asa_built", "normalized_event", `"current": true`, `"current": true, "surprise": 1`},
		{"non-UTC timestamp", "event_asa_built", "normalized_event", `"received_at": "2026-09-28T03:30:07.12Z"`, `"received_at": "2026-09-28T09:00:07.12+05:30"`},
		{"class 4001 missing endpoints", "event_asa_built", "normalized_event", `"dst_endpoint"`, `"dst_endpointX"`},
		{"bad event_id", "event_asa_built", "normalized_event", `"event_id": "1.cisco_asa@1.0.0"`, `"event_id": "abc"`},
		{"sealed lineage without proof", "lineage_sealed", "lineage", `"sealed": true`, `"sealed": false`},
		{"unsealed lineage with proof", "lineage_pending", "lineage", `"sealed": false`, `"sealed": true`},
		{"new proposal with base_version", "proposal_palo_alto", "proposal", `"base_version": ""`, `"base_version": "1.0.0"`},
		{"replay state", "replay_job", "replay_job", `"state": "done"`, `"state": "finished"`},
		{"error code case", "error", "error_response", `"not_found"`, `"NotFound"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := golden(t, c.golden)
			if !bytes.Contains(g, []byte(c.from)) {
				t.Fatalf("test bug: %q not found in %s", c.from, c.golden)
			}
			bad := bytes.Replace(g, []byte(c.from), []byte(c.to), 1)
			if err := def(t, c.def).Validate(decode(t, bad)); err == nil {
				t.Fatal("mutated golden was accepted")
			}
		})
	}
}

// Go and the schema must agree: decode each golden into the Go type with
// unknown fields refused, encode it again, and require the identical document.
func TestGoRoundTrip(t *testing.T) {
	for name, into := range map[string]func() any{
		"event_asa_built": func() any { return new(types.NormalizedEvent) }, "event_asa_deny": func() any { return new(types.NormalizedEvent) },
		"event_fortinet": func() any { return new(types.NormalizedEvent) }, "event_suricata_alert": func() any { return new(types.NormalizedEvent) },
		"event_with_entities": func() any { return new(types.NormalizedEvent) }, "identity_dhcp_bind": func() any { return new(types.NormalizedEvent) },
		"drift_alert": func() any { return new(types.DriftAlert) }, "proposal_palo_alto": func() any { return new(types.Proposal) },
		"dryrun_result": func() any { return new(types.DryRunResult) },
	} {
		t.Run(name, func(t *testing.T) {
			g := golden(t, name)
			v := into()
			d := json.NewDecoder(bytes.NewReader(g))
			d.DisallowUnknownFields()
			if err := d.Decode(v); err != nil {
				t.Fatal(err)
			}
			out, _ := json.Marshal(v)
			var a, b any
			_ = json.Unmarshal(g, &a)
			_ = json.Unmarshal(out, &b)
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("Go type does not reproduce the golden\n golden: %s\n    go: %s", g, out)
			}
		})
	}
}

// The wire forms of the two enums decode back.
func TestEnumWireForms(t *testing.T) {
	var r struct {
		Origin types.Origin     `json:"origin"`
		Term   types.Terminator `json:"terminator"`
	}
	if err := json.Unmarshal(golden(t, "raw_response"), &r); err != nil {
		t.Fatal(err)
	}
	if r.Origin.Kind != types.OriginUDP || r.Term != types.TermLF {
		t.Fatalf("got %v %v", r.Origin.Kind, r.Term)
	}
	if err := json.Unmarshal([]byte(`"bogus"`), &r.Term); err == nil {
		t.Fatal("unknown terminator accepted")
	}
}

// The proof in lineage_sealed is real: it verifies with the production merkle
// code, not just the schema. This is what "golden files come from real Merkle
// output" means.
func TestLineageProofVerifies(t *testing.T) {
	var l struct {
		RecordID uint64          `json:"record_id"`
		SHA      string          `json:"raw_sha256"`
		Proof    vault.ProofJSON `json:"proof"`
		Chain    struct {
			Head string `json:"head"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(golden(t, "lineage_sealed"), &l); err != nil {
		t.Fatal(err)
	}
	p, err := l.Proof.Decode()
	if err != nil {
		t.Fatal(err)
	}
	if !merkle.VerifyInclusion(p.LeafHash, p.LeafIndex, p.TreeSize, p.Path, p.Root) {
		t.Fatal("inclusion proof does not verify")
	}
	if !merkle.VerifyChainLink(p) {
		t.Fatal("chain link does not verify")
	}
	if hex.EncodeToString(p.Chain[:]) != l.Chain.Head {
		t.Fatal("single-segment vault: proof chain must equal chain head")
	}
}

// The same record must look identical in every golden that mentions it.
func TestCrossFileConsistency(t *testing.T) {
	var raw struct {
		RecordID uint64 `json:"record_id"`
		B64      string `json:"raw_base64"`
		SHA      string `json:"raw_sha256"`
		Match    bool   `json:"sha_match"`
	}
	var ev, lin struct {
		RecordID uint64 `json:"record_id"`
		SHA      string `json:"raw_sha256"`
	}
	for f, v := range map[string]any{"raw_response": &raw, "event_asa_built": &ev, "lineage_sealed": &lin} {
		if err := json.Unmarshal(golden(t, f), v); err != nil {
			t.Fatal(err)
		}
	}
	b, err := base64.StdEncoding.DecodeString(raw.B64)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != raw.SHA || !raw.Match {
		t.Fatal("raw_response: sha_match is not true of its own bytes")
	}
	if ev.SHA != raw.SHA || lin.SHA != raw.SHA || ev.RecordID != raw.RecordID || lin.RecordID != raw.RecordID {
		t.Fatalf("record 1 disagrees across files: %+v %+v %+v", raw, ev, lin)
	}
	if !strings.Contains(string(b), "%ASA-6-302013") {
		t.Fatal("record 1 is not the ASA 302013 line")
	}

	// Every evidence RecordID cited by an entity is a real identity record.
	var e7 types.NormalizedEvent
	_ = json.Unmarshal(golden(t, "event_with_entities"), &e7)
	var id5 types.NormalizedEvent
	_ = json.Unmarshal(golden(t, "identity_dhcp_bind"), &id5)
	for _, en := range e7.Entities {
		for _, ev := range en.Evidence {
			if ev.Kind == "dhcp" && id5.Identity.RecordID != ev.RecordID {
				t.Fatalf("entity %s cites dhcp record %d, golden identity record is %d", en.ID, ev.RecordID, id5.Identity.RecordID)
			}
		}
	}
}

// Coverage byte accounting adds up to the raw length for anchored parsers.
func TestCoverageAddsUp(t *testing.T) {
	var e types.NormalizedEvent
	_ = json.Unmarshal(golden(t, "event_asa_built"), &e)
	var r struct {
		B64 string `json:"raw_base64"`
	}
	_ = json.Unmarshal(golden(t, "raw_response"), &r)
	raw, _ := base64.StdEncoding.DecodeString(r.B64)
	c := e.Coverage
	if got := c.MappedBytes + c.UnmappedBytes + c.ConstantBytes + c.UncoveredBytes; got != len(raw) || c.UncoveredBytes != 0 {
		t.Fatalf("coverage sums to %d, raw is %d bytes, uncovered %d", got, len(raw), c.UncoveredBytes)
	}
}

// InclusionProof, SegmentSeal and ChainReport carry [32]byte hashes. Their JSON
// must be hex, must be the shape the vault's ProofJSON already puts on the
// wire, and must satisfy the schema, so the admin API can marshal the Go types
// directly. Produced by a real vault, not built by hand.
func TestHashTypesMarshalToWireForm(t *testing.T) {
	ctx := context.Background()
	mv := memvault.New(memvault.Options{SealEvery: 3, Now: func() time.Time { return time.Unix(1790000000, 0) }})
	var rs []types.RawRecord
	for i := 0; i < 7; i++ {
		rs = append(rs, types.RawRecord{SourceID: "s", ReceivedAt: time.Unix(1790000000, 0), Raw: []byte(fmt.Sprintf("line %d", i))})
	}
	if _, err := mv.PutBatch(ctx, rs); err != nil {
		t.Fatal(err)
	}
	proof, err := mv.Proof(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(proof)
	want, _ := json.Marshal(vault.NewProofJSON(proof))
	if !bytes.Equal(got, want) {
		t.Fatalf("InclusionProof JSON differs from vault.ProofJSON\n got: %s\nwant: %s", got, want)
	}
	if err := def(t, "proof").Validate(decode(t, got)); err != nil {
		t.Fatal(err)
	}
	var back types.InclusionProof
	if err := json.Unmarshal(got, &back); err != nil || !reflect.DeepEqual(back, proof) {
		t.Fatalf("round trip: %v", err)
	}

	seals, _ := mv.Seals(ctx)
	if len(seals) != 2 {
		t.Fatalf("want 2 sealed segments, got %d", len(seals))
	}
	b, _ := json.Marshal(seals)
	var arr []any
	_ = json.Unmarshal(b, &arr)
	for _, s := range arr {
		bs, _ := json.Marshal(s)
		if err := def(t, "segment_seal").Validate(decode(t, bs)); err != nil {
			t.Fatalf("seal: %v\n%s", err, bs)
		}
	}
	var sb []types.SegmentSeal
	if err := json.Unmarshal(b, &sb); err != nil || !reflect.DeepEqual(sb, seals) {
		t.Fatalf("seal round trip: %v", err)
	}

	rep, _ := mv.VerifyChain(ctx, true)
	rb, _ := json.Marshal(rep)
	if err := def(t, "chain_report").Validate(decode(t, rb)); err != nil {
		t.Fatalf("chain report: %v\n%s", err, rb)
	}
	var rback types.ChainReport
	if err := json.Unmarshal(rb, &rback); err != nil || rback != rep {
		t.Fatalf("chain report round trip: %v", err)
	}

	if err := json.Unmarshal([]byte(`{"leaf_hash":"zz"}`), &back); err == nil {
		t.Fatal("malformed hex accepted")
	}
}
