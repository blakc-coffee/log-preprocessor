# merkle — RFC 6962 trees and the segment chain

Pure, with no vault dependency, because the point of an inclusion proof is that
anyone can check it without trusting the thing that produced it.

```
leaf   SHA-256(0x00 || body)
node   SHA-256(0x01 || left || right)
chain  SHA-256(0x02 || prev || root || segment_be64 || count_be64)   chain_0 = 32 zero bytes
```

Tree shape is RFC 6962; inclusion verification is the iterative algorithm from
RFC 9162 section 2.1.3.2.

## Run

```sh
go test ./pkg/dataplane/vault/merkle
make merkle-vectors    # regenerate testdata/merkle_vectors.json
```

`testdata/merkle_vectors.json` is the cross-implementation answer key: trees of
every size from 1 to 20 plus 64, a proof for every leaf, and a five-segment
chain. Every hash in it is derivable from the leaf bodies it also carries, so
the browser verifier and the Python sidecar should rebuild it and compare
rather than trust it. The test suite fails if the committed file drifts from
this package, so **tell the Frontend and Contracts workstreams whenever it
changes**.

## One caveat worth knowing

An inclusion proof does not independently bind the tree size. For n=100, 96 of
100 leaves still verify against a claimed size of 101 when the root is held
fixed. That is correct: the root is the commitment, and size and index only
steer how the path is folded. A proof never verifies against the real root of a
tree it does not belong to. Practical consequence: trust the root, and get it
from somewhere other than whoever handed you the proof. See
`TestSizeAloneIsNotBinding`.
