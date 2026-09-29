package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Wire forms for the two enums that cross the admin API. A bare number in
// `"kind": 2` or `"terminator": 1` tells a reader nothing and breaks silently
// if the Go constants are ever reordered, so both travel as strings.
// Fragment stays a number: it is a bit set, not an enum.

var originNames = [...]string{"unknown", "file", "udp", "tcp", "tls", "http"}
var termNames = [...]string{"none", "LF", "CRLF", "NUL"}

func (k OriginKind) String() string {
	if int(k) < len(originNames) {
		return originNames[k]
	}
	return fmt.Sprintf("OriginKind(%d)", k)
}

func (t Terminator) String() string {
	if int(t) < len(termNames) {
		return termNames[t]
	}
	return fmt.Sprintf("Terminator(%d)", t)
}

// MarshalJSON encodes the kind as its name.
func (k OriginKind) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

// UnmarshalJSON decodes a kind name; unknown names are an error.
func (k *OriginKind) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for i, n := range originNames {
		if n == s {
			*k = OriginKind(i)
			return nil
		}
	}
	return fmt.Errorf("types: unknown origin kind %q", s)
}

// MarshalJSON encodes the terminator as "none", "LF", "CRLF" or "NUL".
func (t Terminator) MarshalJSON() ([]byte, error) { return json.Marshal(t.String()) }

// UnmarshalJSON decodes a terminator name; unknown names are an error.
func (t *Terminator) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for i, n := range termNames {
		if n == s {
			*t = Terminator(i)
			return nil
		}
	}
	return fmt.Errorf("types: unknown terminator %q", s)
}

// Hash-carrying types. A [32]byte marshals as an array of 32 numbers, which
// is useless to a browser, a Python client and the schema alike, so the types
// that cross the admin API encode their hashes as lowercase hex. The shapes
// are pinned by contracts/uef.schema.json (proof, segment_seal, chain_report)
// and by a test that compares InclusionProof's encoding with the vault's
// ProofJSON byte for byte.

func hexs(h [32]byte) string { return hex.EncodeToString(h[:]) }

func unhex(s string) (h [32]byte, err error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, fmt.Errorf("types: want 64 hex characters, got %q", s)
	}
	copy(h[:], b)
	return h, nil
}

type proofWire struct {
	Segment   uint64   `json:"segment"`
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	LeafHash  string   `json:"leaf_hash"`
	Path      []string `json:"path"`
	Root      string   `json:"root"`
	PrevChain string   `json:"prev_chain"`
	Chain     string   `json:"chain"`
	Algorithm struct {
		Leaf  string `json:"leaf"`
		Node  string `json:"node"`
		Chain string `json:"chain"`
		Proof string `json:"proof_verification"`
	} `json:"algorithm"`
}

// MarshalJSON encodes the proof with hex hashes and the algorithm block, so a
// verifier holding only this document never has to guess the domain prefixes.
func (p InclusionProof) MarshalJSON() ([]byte, error) {
	w := proofWire{Segment: p.Segment, LeafIndex: p.LeafIndex, TreeSize: p.TreeSize, LeafHash: hexs(p.LeafHash),
		Path: make([]string, 0, len(p.Path)), Root: hexs(p.Root), PrevChain: hexs(p.PrevChain), Chain: hexs(p.Chain)}
	for _, h := range p.Path {
		w.Path = append(w.Path, hexs(h))
	}
	w.Algorithm.Leaf = "SHA-256(0x00 || body)"
	w.Algorithm.Node = "SHA-256(0x01 || left || right)"
	w.Algorithm.Chain = "SHA-256(0x02 || prev || root || segment_be64 || count_be64)"
	w.Algorithm.Proof = "RFC 9162 section 2.1.3.2"
	return json.Marshal(w)
}

// UnmarshalJSON is the inverse; malformed hex is an error, never a zero hash.
func (p *InclusionProof) UnmarshalJSON(b []byte) error {
	var w proofWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	out := InclusionProof{Segment: w.Segment, LeafIndex: w.LeafIndex, TreeSize: w.TreeSize}
	var err error
	if out.LeafHash, err = unhex(w.LeafHash); err != nil {
		return fmt.Errorf("leaf_hash: %w", err)
	}
	if out.Root, err = unhex(w.Root); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	if out.PrevChain, err = unhex(w.PrevChain); err != nil {
		return fmt.Errorf("prev_chain: %w", err)
	}
	if out.Chain, err = unhex(w.Chain); err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	for i, s := range w.Path {
		h, err := unhex(s)
		if err != nil {
			return fmt.Errorf("path[%d]: %w", i, err)
		}
		out.Path = append(out.Path, h)
	}
	*p = out
	return nil
}

type sealWire struct {
	Segment   uint64    `json:"segment"`
	FirstSeq  uint64    `json:"first_seq"`
	LastSeq   uint64    `json:"last_seq"`
	Count     uint64    `json:"count"`
	Root      string    `json:"root"`
	Prev      string    `json:"prev"`
	Chain     string    `json:"chain"`
	SealedAt  time.Time `json:"sealed_at"`
	Recovered bool      `json:"recovered"`
}

// MarshalJSON encodes the seal with hex hashes.
func (s SegmentSeal) MarshalJSON() ([]byte, error) {
	return json.Marshal(sealWire{s.Segment, s.FirstSeq, s.LastSeq, s.Count, hexs(s.Root), hexs(s.Prev), hexs(s.Chain), s.SealedAt.UTC(), s.Recovered})
}

// UnmarshalJSON is the inverse of MarshalJSON.
func (s *SegmentSeal) UnmarshalJSON(b []byte) error {
	var w sealWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	out := SegmentSeal{Segment: w.Segment, FirstSeq: w.FirstSeq, LastSeq: w.LastSeq, Count: w.Count, SealedAt: w.SealedAt, Recovered: w.Recovered}
	var err error
	if out.Root, err = unhex(w.Root); err != nil {
		return fmt.Errorf("root: %w", err)
	}
	if out.Prev, err = unhex(w.Prev); err != nil {
		return fmt.Errorf("prev: %w", err)
	}
	if out.Chain, err = unhex(w.Chain); err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	*s = out
	return nil
}

type chainWire struct {
	OK       bool   `json:"ok"`
	Deep     bool   `json:"deep"`
	Segments int    `json:"segments"`
	Records  uint64 `json:"records"`
	Head     string `json:"head"`
	FirstBad uint64 `json:"first_bad,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// MarshalJSON encodes the report with a hex head.
func (r ChainReport) MarshalJSON() ([]byte, error) {
	return json.Marshal(chainWire{r.OK, r.Deep, r.Segments, r.Records, hexs(r.Head), r.FirstBad, r.Reason})
}

// UnmarshalJSON is the inverse of MarshalJSON.
func (r *ChainReport) UnmarshalJSON(b []byte) error {
	var w chainWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	h, err := unhex(w.Head)
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}
	*r = ChainReport{OK: w.OK, Deep: w.Deep, Segments: w.Segments, Records: w.Records, Head: h, FirstBad: w.FirstBad, Reason: w.Reason}
	return nil
}
