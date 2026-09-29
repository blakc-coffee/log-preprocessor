# memvault — in-memory reference vault

A full `types.Vault` in memory, so nothing has to wait for the on-disk vault.

It is a reference implementation, not a stub: same record codec, same Merkle
and chain hashes, so for the same records in the same order it produces the
same leaf hashes, segment roots and chain head as the real vault. Build against
this and the proofs you see are the proofs you will get in production.

**It persists nothing**, which is the whole of the real vault's difficulty: no
WAL, no group commit, no fsync, no recovery, no compaction. `Put` returns once
the record is in memory, so "durable" here means "the process still has it".
Development and tests only.

## Use

```go
v := memvault.New(memvault.Options{SealEvery: 1000})
defer v.Close()          // seals the active segment
rc, err := v.Put(ctx, rawRecord)
```

`Options`: `SealEvery` (default 1000), `MaxFrameBytes` (default 1 MiB), `Now`
(default `time.Now`; set it in tests for deterministic seal timestamps).

A proof only exists once a record's segment is sealed — `Proof` returns
`ErrNotSealed` until then, which is deliberate (decision D2). Set `SealEvery`
low in tests if you need proofs quickly.

## Test

```sh
go test ./pkg/dataplane/vault/memvault
```

Runs the shared `vaulttest` conformance suite twice, at `SealEvery` 8 and 2.
