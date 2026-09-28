# vault — the durable, hash-chained record store

Requirements (a) and (d) — never lose a record, and be able to prove what it
originally said — are satisfied here or nowhere. Parsers can be wrong and be
fixed later, but only if the raw bytes were kept exactly.

## Use

```go
v, err := vault.Open(vault.Options{Dir: "./data/vault", Sync: vault.SyncAlways})
defer v.Close()                       // seals the active segment
rc, err := v.PutBatch(ctx, records)   // durable on return, contiguous ids
```

Sync modes: `always` (fsync before acknowledging — the only mode where the
acknowledgement means "on disk", and the default), `interval` (acknowledge
now, fsync on a timer; up to one interval of acknowledged records can be lost),
`none` (benchmarks only). **Any benchmark must state which mode it ran in.**

## Layout

```
<dir>/LOCK                    flock, one writer at a time
<dir>/chain.log               append-only JSONL ledger, one line per seal
<dir>/seg-000000000001.wal    header(72) || framed records || footer(100) once sealed
```

"Sealed" is the presence of a valid footer on disk and nothing else. An index
that claims a segment is sealed can disagree with the file; a footer cannot.

## What is guaranteed, and tested

- A record acknowledged in `sync=always` survives process death and reads back
  byte for byte.
- Bytes out equal bytes in — invalid UTF-8, NULs, CR/LF, empty payloads.
  Terminators are recorded, not stripped.
- Any single-record edit, deletion or reordering, and any segment deletion,
  swap or truncation, is caught by `VerifyChain(deep)`. Ten-row tamper matrix,
  zero undetected.
- Reopening after a crash never yields a corrupt segment: a torn tail is
  truncated at the last intact record boundary and the remainder is sealed and
  flagged `recovered`. Tested by cutting the last write at **every** byte
  offset.

## What is NOT claimed

- **Power-loss durability.** The crash tests kill the process; they do not cut
  power and say nothing about the disk's own write cache. We rely on fsync
  being honest and state that plainly.
- **Tamper-proof storage.** This is tamper-*evident*. Someone with write access
  to the whole directory can rewrite it consistently. Only a chain head held
  somewhere else defeats that — see `Head`.

## Failure policy

Any write or fsync error is terminal: the vault enters a failed state, every
later call returns `ErrFailed`, and the process must restart. **A failed fsync
is never retried** — afterwards the kernel may already have dropped the dirty
pages, so a retry that "succeeded" would be a lie about data that is gone.

## Read-only opens are lenient on purpose

A writer refuses to open structurally damaged storage: appending to a broken
history only buries the evidence under valid-looking new chain links. A
read-only open records the damage and continues, because `vaultctl verify` has
to be able to open a tampered vault in order to say what is wrong with it.

## Test

```sh
go test ./pkg/dataplane/vault/          # incl. the conformance suite and tamper matrix
go test -race ./pkg/dataplane/vault/
```

The conformance suite (`../vaulttest`) runs in five configurations, and
`TestAgreesWithMemvault` asserts that this vault and `memvault` produce
identical leaf hashes, roots, chain heads and interchangeable proofs for the
same input — which is what makes it safe to develop against `memvault` and
switch over later.
