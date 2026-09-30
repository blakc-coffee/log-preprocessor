// Package merkle implements the RFC 6962 Merkle tree the vault seals each
// segment with, and the hash chain that links one sealed segment to the next.
//
// It is deliberately dependency-free apart from the contract types: the whole
// point of an inclusion proof is that anyone can check it without trusting,
// or even having, the thing that produced it. The browser verifier and the
// Python sidecar re-implement these same three hashes and check themselves
// against testdata/merkle_vectors.json, which this package writes.
//
// Three domain-separated hashes, so a value from one position can never be
// replayed in another:
//
//	leaf   SHA-256(0x00 || body)
//	node   SHA-256(0x01 || left || right)
//	chain  SHA-256(0x02 || prev || root || segment_be64 || count_be64)
package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"

	types "github.com/dark-14100/sluice/pkg/types"
)

// Domain separation prefixes, per RFC 6962. The chain prefix is ours.
const (
	prefixLeaf  byte = 0x00
	prefixNode  byte = 0x01
	prefixChain byte = 0x02
)

// LeafHash returns the RFC 6962 leaf hash of body: SHA-256(0x00 || body).
//
// The vault hashes the whole encoded record body, not just the raw payload, so
// that a record's source, origin, sequence number and terminator are all
// covered by the tree. Editing any of them breaks the proof.
func LeafHash(body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{prefixLeaf})
	h.Write(body)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// HashChildren returns the RFC 6962 interior node hash:
// SHA-256(0x01 || left || right).
func HashChildren(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{prefixNode})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// split returns k, the largest power of two strictly less than n. RFC 6962
// splits every subtree here, which is what makes the tree shape a function of
// the leaf count alone.
func split(n int) int {
	if n < 2 {
		panic("merkle: split requires n >= 2")
	}
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// Root returns the RFC 6962 Merkle tree head over the given leaf hashes.
//
// The vault never seals an empty segment, so the empty case should not arise;
// it returns SHA-256 of the empty string, which is what RFC 6962 defines
// MTH({}) to be, rather than a zero value that could be confused with an
// unset root.
func Root(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return HashChildren(Root(leaves[:k]), Root(leaves[k:]))
}

// Path returns the RFC 6962 inclusion path for the leaf at index, ordered from
// the sibling nearest the leaf to the one nearest the root. It returns nil if
// index is out of range.
func Path(leaves [][32]byte, index uint64) [][32]byte {
	if index >= uint64(len(leaves)) {
		return nil
	}
	if len(leaves) == 1 {
		return nil
	}
	k := uint64(split(len(leaves)))
	if index < k {
		return append(Path(leaves[:k], index), Root(leaves[k:]))
	}
	return append(Path(leaves[k:], index-k), Root(leaves[:k]))
}

// VerifyInclusion reports whether leaf really is the record at index in a tree
// of size records whose head is root.
//
// This is the iterative algorithm from RFC 9162 section 2.1.3.2, and it is the
// one function in this package that matters to anyone else: it is what lets a
// browser, a Python test or an auditor confirm a record without the vault.
// It takes no pointers and allocates nothing, so it is safe to hand untrusted
// input.
func VerifyInclusion(leaf [32]byte, index, size uint64, path [][32]byte, root [32]byte) bool {
	if size == 0 || index >= size {
		return false
	}

	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			// More path elements than the tree can account for.
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = HashChildren(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = HashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	// sn != 0 means the path was too short to reach the root.
	return sn == 0 && r == root
}

// ChainHash links a sealed segment to the one before it:
//
//	SHA-256(0x02 || prev || root || segment_be64 || count_be64)
//
// chain_0 is 32 zero bytes. Including the segment id and the record count
// means a segment cannot be moved, duplicated or silently shortened without
// breaking every link after it.
func ChainHash(prev, root [32]byte, segment, count uint64) [32]byte {
	var be [8]byte
	h := sha256.New()
	h.Write([]byte{prefixChain})
	h.Write(prev[:])
	h.Write(root[:])
	binary.BigEndian.PutUint64(be[:], segment)
	h.Write(be[:])
	binary.BigEndian.PutUint64(be[:], count)
	h.Write(be[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// VerifyChainLink reports whether a proof's chain hash really follows from its
// own previous-chain, root, segment id and tree size.
//
// It proves the link is internally consistent. It does not prove the segment
// is the one that belongs at that position in the ledger: that needs
// Vault.VerifyChain, which walks every link from chain_0, or an externally
// anchored head.
func VerifyChainLink(p types.InclusionProof) bool {
	return ChainHash(p.PrevChain, p.Root, p.Segment, p.TreeSize) == p.Chain
}
