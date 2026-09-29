package merkle

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update regenerates testdata/merkle_vectors.json:
//
//	go test ./pkg/dataplane/vault/merkle -run TestWriteVectors -update
//
// Without the flag the test still runs, and fails if the committed file no
// longer matches what this package computes. That is the point: the browser
// verifier and the Python sidecar check themselves against that file, so it
// must never drift from the Go implementation unnoticed.
var update = flag.Bool("update", false, "rewrite testdata/merkle_vectors.json")

// vectorsPath is the repo-root testdata directory, which this workstream owns.
const vectorsPath = "../../../../testdata/merkle_vectors.json"

// Vectors is the cross-implementation answer key for the Merkle and chain
// hashes. Everything in it is derivable from `bodies` alone, so a third-party
// implementation can rebuild the whole file and compare, rather than trusting
// the hashes it is handed.
type Vectors struct {
	Algorithm Algorithm    `json:"algorithm"`
	Trees     []TreeVector `json:"trees"`
	Chain     []ChainStep  `json:"chain"`
}

// Algorithm spells out the three hashes in words, so an implementer never has
// to infer the domain prefixes from the numbers.
type Algorithm struct {
	Leaf      string `json:"leaf"`
	Node      string `json:"node"`
	Chain     string `json:"chain"`
	ChainZero string `json:"chain_zero"`
	Proof     string `json:"proof_verification"`
	Note      string `json:"note"`
}

// TreeVector is one tree: the leaf bodies, their hashes, the head, and an
// inclusion proof for every leaf.
type TreeVector struct {
	Size   int           `json:"size"`
	Bodies []string      `json:"bodies"`
	Leaves []string      `json:"leaves"`
	Root   string        `json:"root"`
	Proofs []ProofVector `json:"proofs"`
}

// ProofVector is one leaf's inclusion path.
type ProofVector struct {
	Index int      `json:"index"`
	Path  []string `json:"path"`
}

// ChainStep is one link of the segment chain.
type ChainStep struct {
	Segment int    `json:"segment"`
	Count   int    `json:"count"`
	Prev    string `json:"prev"`
	Root    string `json:"root"`
	Chain   string `json:"chain"`
}

// vectorSizes are the tree sizes the file covers: every size from 1 to 20,
// which is where the RFC's odd-split cases live, plus 64 as a perfectly
// balanced tree.
func vectorSizes() []int {
	sizes := make([]int, 0, 21)
	for n := 1; n <= 20; n++ {
		sizes = append(sizes, n)
	}
	return append(sizes, 64)
}

func buildVectors() Vectors {
	v := Vectors{Algorithm: Algorithm{
		Leaf:      "SHA-256(0x00 || body)",
		Node:      "SHA-256(0x01 || left || right)",
		Chain:     "SHA-256(0x02 || prev || root || segment_be64 || count_be64)",
		ChainZero: "chain_0 is 32 zero bytes",
		Proof:     "RFC 9162 section 2.1.3.2",
		Note: "Tree structure is RFC 6962: MTH({d0}) = leaf, and MTH(D[n]) splits at the " +
			"largest power of two below n. Every hash here is derivable from `bodies`, so an " +
			"independent implementation should rebuild this file and compare rather than trust it. " +
			"Bodies are ASCII in these vectors; in the real vault a leaf body is the encoded record.",
	}}

	for _, n := range vectorSizes() {
		ls := leaves(n)
		tv := TreeVector{Size: n, Root: hexOf(Root(ls))}
		for i := 0; i < n; i++ {
			tv.Bodies = append(tv.Bodies, string(body(i)))
			tv.Leaves = append(tv.Leaves, hexOf(ls[i]))
			p := Path(ls, uint64(i))
			pv := ProofVector{Index: i, Path: []string{}}
			for _, h := range p {
				pv.Path = append(pv.Path, hexOf(h))
			}
			tv.Proofs = append(tv.Proofs, pv)
		}
		v.Trees = append(v.Trees, tv)
	}

	// A five-segment chain over the first five trees, starting from chain_0.
	var prev [32]byte
	for seg := 1; seg <= 5; seg++ {
		count := seg * 3
		root := Root(leaves(count))
		c := ChainHash(prev, root, uint64(seg), uint64(count))
		v.Chain = append(v.Chain, ChainStep{
			Segment: seg, Count: count,
			Prev: hexOf(prev), Root: hexOf(root), Chain: hexOf(c),
		})
		prev = c
	}
	return v
}

func encodeVectors(t *testing.T, v Vectors) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestWriteVectors keeps testdata/merkle_vectors.json in step with this
// package. With -update it rewrites the file; without it, it fails when the
// committed file has drifted.
func TestWriteVectors(t *testing.T) {
	want := encodeVectors(t, buildVectors())

	if *update {
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes)", vectorsPath, len(want))
		return
	}

	got, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v\nrun: go test ./pkg/dataplane/vault/merkle -run TestWriteVectors -update", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date with the merkle package.\n"+
			"Regenerate it, and tell the Frontend and Contracts workstreams, because the "+
			"browser verifier and the Python tests check themselves against it:\n"+
			"  go test ./pkg/dataplane/vault/merkle -run TestWriteVectors -update", vectorsPath)
	}
}

// TestVectorsAreSelfConsistent re-derives every hash in the committed file
// from its bodies, the way an outside implementation would. If this passes,
// somebody implementing the verifier in JavaScript or Python has a file they
// can actually check themselves against.
func TestVectorsAreSelfConsistent(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Skipf("no vectors file yet: %v", err)
	}
	var v Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Trees) != len(vectorSizes()) {
		t.Fatalf("got %d trees, want %d", len(v.Trees), len(vectorSizes()))
	}

	for _, tv := range v.Trees {
		if len(tv.Bodies) != tv.Size || len(tv.Leaves) != tv.Size || len(tv.Proofs) != tv.Size {
			t.Errorf("size %d: bodies/leaves/proofs are %d/%d/%d",
				tv.Size, len(tv.Bodies), len(tv.Leaves), len(tv.Proofs))
			continue
		}
		ls := make([][32]byte, tv.Size)
		for i, b := range tv.Bodies {
			ls[i] = LeafHash([]byte(b))
			if hexOf(ls[i]) != tv.Leaves[i] {
				t.Errorf("size %d leaf %d: body %q hashes to %s, file says %s",
					tv.Size, i, b, hexOf(ls[i]), tv.Leaves[i])
			}
		}
		root := Root(ls)
		if hexOf(root) != tv.Root {
			t.Errorf("size %d: recomputed root %s, file says %s", tv.Size, hexOf(root), tv.Root)
			continue
		}
		for _, pv := range tv.Proofs {
			path := make([][32]byte, 0, len(pv.Path))
			for _, h := range pv.Path {
				path = append(path, unhex(t, h))
			}
			if !VerifyInclusion(ls[pv.Index], uint64(pv.Index), uint64(tv.Size), path, root) {
				t.Errorf("size %d index %d: the file's own proof does not verify", tv.Size, pv.Index)
			}
		}
	}

	var prev [32]byte
	for i, step := range v.Chain {
		if hexOf(prev) != step.Prev {
			t.Errorf("chain step %d: prev is %s, want %s (the previous step's chain)", i, step.Prev, hexOf(prev))
		}
		got := ChainHash(prev, unhex(t, step.Root), uint64(step.Segment), uint64(step.Count))
		if hexOf(got) != step.Chain {
			t.Errorf("chain step %d: recomputed %s, file says %s", i, hexOf(got), step.Chain)
		}
		prev = got
	}
}

func unhex(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	if len(s) != 64 {
		t.Fatalf("expected a 32-byte hex hash, got %q", s)
	}
	for i := 0; i < 32; i++ {
		out[i] = byte(hexNibble(t, s[2*i])<<4 | hexNibble(t, s[2*i+1]))
	}
	return out
}

func hexNibble(t *testing.T, c byte) int {
	t.Helper()
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	t.Fatalf("not a lowercase hex digit: %q", string(c))
	return 0
}
