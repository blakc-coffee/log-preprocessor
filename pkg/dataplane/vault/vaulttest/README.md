# vaulttest — the vault conformance suite

Every `types.Vault` implementation passes this, so `memvault` and the on-disk
vault cannot drift apart. Components are built against `memvault` and switched
to the real vault later, and that only works if "behaves the same" is something
a test asserts rather than something a comment claims.

## Use

```go
func TestConformance(t *testing.T) {
    vaulttest.Run(t, vaulttest.Factory{
        New:       func(t *testing.T) types.Vault { return myvault.New(...) },
        SealEvery: 8,
    })
}
```

`SealEvery` tells the suite how many records force a seal, which is how it
knows when a proof can exist. It must be at least 2. Run it twice, once at a
realistic size and once at 2, where nearly every write seals: segment-boundary
bugs hide there.

## What it covers

Contiguous ids from 1 · byte-exact round-trip including invalid UTF-8, NULs,
CR/LF and empty payloads · atomic, contiguous batches · `ErrNotFound` ·
`GetByHash` · `Scan` from every boundary and its error propagation ·
`ErrNotSealed` before sealing · proofs verified with the pure `merkle` package,
the way an auditor would · `Verify` · `VerifyChain` shallow and deep · seal
ledger consistency · head advancing only on seal · `Close` sealing the active
segment · `ErrClosed` afterwards · 16 concurrent batch writers · cancelled
contexts.

The suite uses only the exported contract, so it can run against an
implementation it knows nothing about. It was checked against four deliberate
mutations of `memvault` (ids from 0, chain hash without its domain prefix,
wrong leaf index in proofs, one byte dropped from `Raw`) and caught all four.
