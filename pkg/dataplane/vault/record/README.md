# record — the vault's record codec

Encodes and decodes the self-describing record format, with a CRC-32C
(Castagnoli) per record. A separate package rather than a file inside the vault
so `memvault` can produce byte-identical encodings, and therefore identical
leaf hashes and segment roots, without importing the on-disk vault.

```
framed   len u32 | crc u32 | body
body     version u8 | flags u8 | seq u64 | received_at i64
         source_len u16 | source_id | origin_kind u8
         addr_len u16 | addr | origin_off u64
         raw_len u32 | raw
```

All integers big-endian. The Merkle leaf is `SHA-256(0x00 || body)`, so a
record's source, origin, sequence number and terminator are covered by the
tree, not just its payload. `Receipt.RawSHA256` is a separate hash over `Raw`
alone, which is what lineage and `GetByHash` key on.

## Run

```sh
go test ./pkg/dataplane/vault/record
go test -run '^$' -fuzz FuzzRecordDecode -fuzztime 30s ./pkg/dataplane/vault/record
```

## Guarantees

`Decode` never panics on arbitrary input, never accepts a body with a bad CRC,
and never accepts a body that would not re-encode to itself — two spellings of
one record would mean two Merkle leaves for it. Length fields are capped before
any allocation, so a hostile length cannot make the decoder allocate.
`ErrTruncated` means "come back with more bytes"; anything else means the
record is unrecoverable, which during recovery is where a segment gets
truncated.
