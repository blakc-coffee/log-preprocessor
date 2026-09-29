package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	types "github.com/blakc-coffee/log-preprocessor/pkg/types"
)

func leaves(n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = LeafHash(body(i))
	}
	return out
}

// body is the deterministic leaf content the vectors file is built from, so a
// third-party implementation can recompute every leaf hash from scratch.
func body(i int) []byte {
	return []byte("ulpf-merkle-vector-" + itoa(i))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

// TestKnownAnswers pins the three hashes against values computed by hand from
// the RFC 6962 definitions. If someone "optimises" the domain prefixes away,
// every proof this project has ever issued silently changes meaning, and this
// is the test that stops that.
func TestKnownAnswers(t *testing.T) {
	// leaf = SHA-256(0x00 || "")
	wantEmptyLeaf := sha256.Sum256([]byte{0x00})
	if got := LeafHash(nil); got != wantEmptyLeaf {
		t.Errorf("LeafHash(nil) = %x, want %x", got, wantEmptyLeaf)
	}

	// A single-leaf tree's head is the leaf itself, per MTH({d0}).
	l := LeafHash([]byte("a"))
	if got := Root([][32]byte{l}); got != l {
		t.Errorf("Root of one leaf = %x, want the leaf %x", got, l)
	}

	// A two-leaf tree is one interior node.
	a, b := LeafHash([]byte("a")), LeafHash([]byte("b"))
	want := sha256.Sum256(append(append([]byte{0x01}, a[:]...), b[:]...))
	if got := Root([][32]byte{a, b}); got != want {
		t.Errorf("Root of two leaves = %x, want %x", got, want)
	}

	// chain_1 over chain_0 = 32 zero bytes.
	var zero [32]byte
	r := Root([][32]byte{a, b})
	h := sha256.New()
	h.Write([]byte{0x02})
	h.Write(zero[:])
	h.Write(r[:])
	h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 1}) // segment 1
	h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 2}) // count 2
	var wantChain [32]byte
	h.Sum(wantChain[:0])
	if got := ChainHash(zero, r, 1, 2); got != wantChain {
		t.Errorf("ChainHash = %x, want %x", got, wantChain)
	}
}

// TestEveryLeafVerifies is the property that matters: for every tree size the
// vault will ever produce, every leaf's proof must verify against the root.
func TestEveryLeafVerifies(t *testing.T) {
	for n := 1; n <= 300; n++ {
		ls := leaves(n)
		root := Root(ls)
		for i := 0; i < n; i++ {
			p := Path(ls, uint64(i))
			if !VerifyInclusion(ls[i], uint64(i), uint64(n), p, root) {
				t.Fatalf("n=%d index=%d: valid proof rejected (path len %d)", n, i, len(p))
			}
		}
	}
}

// TestTamperedProofsFail is the other half: a proof must fail when anything
// about it is wrong. Tamper-evidence is a claim in the submission, so each of
// these mutations is one way an attacker could try to pass off a record that
// is not in the tree.
func TestTamperedProofsFail(t *testing.T) {
	for _, n := range []int{1, 2, 3, 5, 8, 13, 64, 100} {
		ls := leaves(n)
		root := Root(ls)

		for i := 0; i < n; i++ {
			idx, size := uint64(i), uint64(n)
			p := Path(ls, idx)

			t.Run("flipped leaf", func(t *testing.T) {
				bad := ls[i]
				bad[0] ^= 0x01
				if VerifyInclusion(bad, idx, size, p, root) {
					t.Errorf("n=%d i=%d: accepted a modified leaf", n, i)
				}
			})

			t.Run("wrong index", func(t *testing.T) {
				other := (idx + 1) % size
				if other != idx && VerifyInclusion(ls[i], other, size, p, root) {
					t.Errorf("n=%d i=%d: accepted the leaf at the wrong index", n, i)
				}
			})

			t.Run("proof against a different tree", func(t *testing.T) {
				// The security-relevant version of "wrong size": the proof is
				// checked against the real root of a tree it does not belong
				// to. See TestSizeAloneIsNotBinding for why claiming the wrong
				// size against the *same* root is not the same question.
				if VerifyInclusion(ls[i], idx, size+1, p, Root(leaves(n+1))) {
					t.Errorf("n=%d i=%d: a proof verified against a different tree's root", n, i)
				}
			})

			t.Run("flipped root", func(t *testing.T) {
				bad := root
				bad[31] ^= 0x80
				if VerifyInclusion(ls[i], idx, size, p, bad) {
					t.Errorf("n=%d i=%d: accepted a proof against a modified root", n, i)
				}
			})

			t.Run("flipped path element", func(t *testing.T) {
				for j := range p {
					bad := make([][32]byte, len(p))
					copy(bad, p)
					bad[j][5] ^= 0x20
					if VerifyInclusion(ls[i], idx, size, bad, root) {
						t.Errorf("n=%d i=%d: accepted a proof with path element %d modified", n, i, j)
					}
				}
			})

			t.Run("truncated path", func(t *testing.T) {
				if len(p) > 0 && VerifyInclusion(ls[i], idx, size, p[:len(p)-1], root) {
					t.Errorf("n=%d i=%d: accepted a truncated path", n, i)
				}
			})

			t.Run("extended path", func(t *testing.T) {
				if VerifyInclusion(ls[i], idx, size, append(append([][32]byte{}, p...), root), root) {
					t.Errorf("n=%d i=%d: accepted an over-long path", n, i)
				}
			})
		}
	}
}

// TestSizeAloneIsNotBinding records a property of RFC 6962 proofs that is easy
// to assume the other way round, and that the browser verifier and the Python
// tests will meet too.
//
// Claiming the wrong tree size while presenting the same path against the same
// root often still verifies: for n=100, 96 of the 100 leaves verify against a
// claimed size of 101. That is not a flaw. The root is the commitment; size
// and index only steer which way the path is folded. An attacker who can
// already supply the root has not gained anything, and one who cannot gets
// nothing from lying about the size, because a proof never verifies against
// the real root of a tree it does not belong to - which is the property
// TestTamperedProofsFail/proof_against_a_different_tree asserts.
//
// The practical consequence for anyone verifying lineage: trust the root, and
// get it from somewhere other than the party handing you the proof.
func TestSizeAloneIsNotBinding(t *testing.T) {
	const n = 100
	ls := leaves(n)
	root := Root(ls)

	verified := 0
	for i := 0; i < n; i++ {
		if VerifyInclusion(ls[i], uint64(i), uint64(n+1), Path(ls, uint64(i)), root) {
			verified++
		}
	}
	if verified == 0 {
		t.Skip("no leaf verifies under a mis-stated size; the documented caveat no longer applies")
	}

	// The property that must hold regardless: against the real root of the
	// tree whose size is being claimed, nothing verifies.
	bigRoot := Root(leaves(n + 1))
	for i := 0; i < n; i++ {
		if VerifyInclusion(ls[i], uint64(i), uint64(n+1), Path(ls, uint64(i)), bigRoot) {
			t.Fatalf("index %d: a proof from a tree of %d verified against the root of a tree of %d",
				i, n, n+1)
		}
	}
}

// TestReorderingIsDetected proves a leaf's position is part of what the tree
// commits to. Swapping two records without changing either one must still
// break the root, or "records cannot be reordered" is not a claim we can make.
func TestReorderingIsDetected(t *testing.T) {
	for _, n := range []int{2, 3, 7, 16, 65} {
		ls := leaves(n)
		root := Root(ls)
		swapped := make([][32]byte, n)
		copy(swapped, ls)
		swapped[0], swapped[n-1] = swapped[n-1], swapped[0]
		if Root(swapped) == root {
			t.Errorf("n=%d: swapping the first and last records left the root unchanged", n)
		}
	}
}

// TestDomainSeparation proves a leaf hash can never be passed off as an
// interior node. Without the prefixes, a crafted record body could stand in
// for a subtree, which is the classic second-preimage attack on Merkle trees.
func TestDomainSeparation(t *testing.T) {
	a, b := LeafHash([]byte("a")), LeafHash([]byte("b"))
	node := HashChildren(a, b)
	// The two-leaf tree's root is an interior node. A single leaf whose body
	// happens to be the concatenation of the two children must not collide
	// with it.
	if LeafHash(append(a[:], b[:]...)) == node {
		t.Error("a leaf hash collided with an interior node hash")
	}
}

// TestBoundaries covers the inputs a caller can get wrong.
func TestBoundaries(t *testing.T) {
	ls := leaves(4)
	root := Root(ls)

	if VerifyInclusion(ls[0], 0, 0, nil, root) {
		t.Error("accepted a proof against an empty tree")
	}
	if VerifyInclusion(ls[0], 4, 4, Path(ls, 0), root) {
		t.Error("accepted an index equal to the tree size")
	}
	if VerifyInclusion(ls[0], 99, 4, Path(ls, 0), root) {
		t.Error("accepted an out-of-range index")
	}
	if p := Path(ls, 4); p != nil {
		t.Errorf("Path with an out-of-range index returned %v, want nil", p)
	}
	if got, want := Root(nil), sha256.Sum256(nil); got != want {
		t.Errorf("Root(nil) = %x, want SHA-256 of the empty string %x", got, want)
	}
	if n := len(Path(leaves(1), 0)); n != 0 {
		t.Errorf("a one-leaf tree has a path of length %d, want 0", n)
	}
}

// TestPathLength pins the proof size at ceil(log2(n)), which is what makes
// lineage cheap to serve and cheap to verify in a browser.
func TestPathLength(t *testing.T) {
	for n := 1; n <= 256; n++ {
		want := 0
		for 1<<want < n {
			want++
		}
		if got := len(Path(leaves(n), 0)); got != want {
			t.Errorf("n=%d: path length %d, want %d", n, got, want)
		}
	}
}

// TestVerifyChainLink checks the link a proof carries with it.
func TestVerifyChainLink(t *testing.T) {
	var prev [32]byte
	root := Root(leaves(10))
	p := types.InclusionProof{
		Segment: 7, TreeSize: 10, Root: root, PrevChain: prev,
		Chain: ChainHash(prev, root, 7, 10),
	}
	if !VerifyChainLink(p) {
		t.Fatal("a well-formed chain link was rejected")
	}

	for name, mutate := range map[string]func(*types.InclusionProof){
		"segment renumbered": func(p *types.InclusionProof) { p.Segment++ },
		"count changed":      func(p *types.InclusionProof) { p.TreeSize-- },
		"root replaced":      func(p *types.InclusionProof) { p.Root[0] ^= 1 },
		"prev replaced":      func(p *types.InclusionProof) { p.PrevChain[31] ^= 1 },
		"chain replaced":     func(p *types.InclusionProof) { p.Chain[16] ^= 1 },
	} {
		bad := p
		mutate(&bad)
		if VerifyChainLink(bad) {
			t.Errorf("%s: accepted a broken chain link", name)
		}
	}
}

// TestChainIsOrderDependent proves two segments cannot be swapped in the
// ledger without breaking the chain.
func TestChainIsOrderDependent(t *testing.T) {
	var zero [32]byte
	r1, r2 := Root(leaves(4)), Root(leaves(9))

	forward := ChainHash(ChainHash(zero, r1, 1, 4), r2, 2, 9)
	swapped := ChainHash(ChainHash(zero, r2, 1, 9), r1, 2, 4)
	if forward == swapped {
		t.Error("swapping two segments left the chain head unchanged")
	}
}

func hexOf(h [32]byte) string { return hex.EncodeToString(h[:]) }
