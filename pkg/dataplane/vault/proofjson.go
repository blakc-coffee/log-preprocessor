package vault

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	types "github.com/blakc-coffee/log-preprocessor/pkg/dataplane/ingest/testutil/types"
	"github.com/blakc-coffee/log-preprocessor/pkg/dataplane/vault/merkle"
)

// The JSON shape of an inclusion proof.
//
// types.InclusionProof holds [32]byte arrays, which encoding/json would render
// as arrays of 32 numbers. This is the form that crosses process and language
// boundaries: lowercase hex, snake_case keys, matching the project's JSON
// conventions. The browser verifier and the Python tests parse exactly this.
//
// It is defined here, next to the vault, rather than in vaultctl, because
// three different consumers need to agree on it.

// ProofJSON is an inclusion proof in its wire form.
type ProofJSON struct {
	Segment   uint64   `json:"segment"`
	LeafIndex uint64   `json:"leaf_index"`
	TreeSize  uint64   `json:"tree_size"`
	LeafHash  string   `json:"leaf_hash"`
	Path      []string `json:"path"`
	Root      string   `json:"root"`
	PrevChain string   `json:"prev_chain"`
	Chain     string   `json:"chain"`
	// Algorithm is carried with every proof so a verifier written against one
	// of these files never has to guess at the domain prefixes.
	Algorithm ProofAlgorithm `json:"algorithm"`
}

// ProofAlgorithm spells out the hashes a verifier must implement.
type ProofAlgorithm struct {
	Leaf  string `json:"leaf"`
	Node  string `json:"node"`
	Chain string `json:"chain"`
	Proof string `json:"proof_verification"`
}

func proofAlgorithm() ProofAlgorithm {
	return ProofAlgorithm{
		Leaf:  "SHA-256(0x00 || body)",
		Node:  "SHA-256(0x01 || left || right)",
		Chain: "SHA-256(0x02 || prev || root || segment_be64 || count_be64)",
		Proof: "RFC 9162 section 2.1.3.2",
	}
}

// NewProofJSON converts a proof to its wire form.
func NewProofJSON(p types.InclusionProof) ProofJSON {
	out := ProofJSON{
		Segment:   p.Segment,
		LeafIndex: p.LeafIndex,
		TreeSize:  p.TreeSize,
		LeafHash:  hex.EncodeToString(p.LeafHash[:]),
		Path:      make([]string, 0, len(p.Path)),
		Root:      hex.EncodeToString(p.Root[:]),
		PrevChain: hex.EncodeToString(p.PrevChain[:]),
		Chain:     hex.EncodeToString(p.Chain[:]),
		Algorithm: proofAlgorithm(),
	}
	for _, h := range p.Path {
		out.Path = append(out.Path, hex.EncodeToString(h[:]))
	}
	return out
}

// Decode converts a wire proof back, rejecting anything malformed.
func (j ProofJSON) Decode() (types.InclusionProof, error) {
	var p types.InclusionProof
	var err error

	if p.LeafHash, err = unhex32(j.LeafHash); err != nil {
		return p, fmt.Errorf("leaf_hash: %w", err)
	}
	if p.Root, err = unhex32(j.Root); err != nil {
		return p, fmt.Errorf("root: %w", err)
	}
	if p.PrevChain, err = unhex32(j.PrevChain); err != nil {
		return p, fmt.Errorf("prev_chain: %w", err)
	}
	if p.Chain, err = unhex32(j.Chain); err != nil {
		return p, fmt.Errorf("chain: %w", err)
	}
	for i, h := range j.Path {
		v, err := unhex32(h)
		if err != nil {
			return p, fmt.Errorf("path[%d]: %w", i, err)
		}
		p.Path = append(p.Path, v)
	}
	p.Segment, p.LeafIndex, p.TreeSize = j.Segment, j.LeafIndex, j.TreeSize
	return p, nil
}

// VerifyProofJSON checks a proof on its own, with no vault and no files.
//
// This is what `vaultctl verify-proof` runs, and it is the whole argument for
// hash-chained lineage: anyone handed one of these can confirm the record was
// in the tree, using nothing but the JSON and a SHA-256 implementation.
//
// It confirms the record is in a tree with that root, and that the root is
// linked into the chain at that position. It cannot confirm the root is the
// one the vault really published - for that, compare it against a chain head
// obtained from somewhere other than whoever handed you the proof.
func VerifyProofJSON(raw []byte) (ProofJSON, error) {
	var j ProofJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return j, fmt.Errorf("parsing proof: %w", err)
	}
	p, err := j.Decode()
	if err != nil {
		return j, err
	}
	if !merkle.VerifyInclusion(p.LeafHash, p.LeafIndex, p.TreeSize, p.Path, p.Root) {
		return j, fmt.Errorf("inclusion proof does not verify: record %d of segment %d is not in a tree with root %s",
			p.LeafIndex, p.Segment, j.Root)
	}
	if !merkle.VerifyChainLink(p) {
		return j, fmt.Errorf("chain link does not verify: segment %d's chain hash does not follow from its root and prev", p.Segment)
	}
	return j, nil
}
