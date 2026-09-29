# The ULPF vault: on-disk format and guarantees

Owner: Ingestion & Vault workstream. This is the source material for slide 3
and the two-page architecture document, and the reference for anyone writing a
verifier, a tamper test, or a forensic tool against the vault.

Everything here is implemented and tested. Where something is **not** proven,
it says so — those sections matter more than the rest, because they are what
the submission must not overclaim.

---

## 1. What the vault is for

Perimeter devices emit an event once. If the bytes are not captured exactly,
nothing downstream can recover them: a parser bug can be fixed and the event
re-parsed, but only if the original is still there. The vault is the component
that makes that true, and it is also what lets the system prove, later and to
someone else, that a stored event was not altered.

Two claims, and everything in this document serves one of them:

1. **Byte-exact preservation.** What comes out equals what came in.
2. **Tamper evidence.** Any modification to stored data is detectable.

---

## 2. Directory layout

```
<vault.dir>/
  LOCK                         flock; one writer process at a time
  chain.log                    append-only JSONL ledger, one line per sealed segment
  seg-000000000001.zst         a sealed segment, compacted (header, zstd blocks, footer)
  seg-000000000001.hix         its hash index: sorted (raw_sha256, seq) pairs
  seg-000000000002.wal         a segment not yet compacted: header, records, footer once sealed
  ...
```

A segment is stored as a `.wal` until it is sealed and then compacted; after that
it is a `.zst`. **It is never both for long** — see §6.3 for the brief window and
what recovery does about it.

File names are fixed-width (`seg-%012d`) so a plain lexical sort of the
directory is also a numeric sort. Recovery and `vaultctl ls` both rely on that
and neither has to parse before it can order.

Files are `0600` and the directory `0700`. Raw log data routinely contains
credentials, session tokens and personal data; it is not world-readable.

---

## 3. Segment format

A segment file is:

```
header  (72 bytes, raw)
framed record × n
footer  (100 bytes, raw)        ← present only once the segment is sealed
```

**The presence of a valid footer is what "sealed" means.** Not an index, not a
flag in a database. An index can disagree with the file; a footer cannot, and
recovery finds the segment it must repair by looking for the one without a
valid footer.

All integers are **big-endian**.

### 3.1 Header (72 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | `magic` | `"ULPFSEG1"` |
| 8 | 2 | `version` | 1 |
| 10 | 2 | `reserved` | 0 |
| 12 | 8 | `segment_id` | from 1, consecutive |
| 20 | 8 | `first_seq` | RecordID of the first record |
| 28 | 32 | `prev_chain` | the chain hash this segment follows |
| 60 | 8 | `created_at` | Unix nanoseconds |
| 68 | 4 | `header_crc` | CRC-32C of bytes 0..67 |

`prev_chain` is in the header, written before any record: a segment file on its
own says where it belongs in the chain. Editing it to relocate a segment breaks
the header CRC.

### 3.2 Record

```
len   u32      length of body
crc   u32      CRC-32C (Castagnoli) of body
body:
  version      u8    = 1
  flags        u8    bits 0-1 terminator, bit 2 FragMore, bit 3 FragCont
  seq          u64   RecordID
  received_at  i64   Unix nanoseconds
  source_len   u16 | source_id
  origin_kind  u8
  addr_len     u16 | addr
  origin_off   u64
  raw_len      u32 | raw
```

Maximum body size is `max_frame_bytes + 4 KiB`.

**Terminators are recorded, not stored.** `raw` is the event's bytes and
nothing else; the `flags` byte says what followed it. A CRLF-terminated line
and an LF-terminated line with the same content have identical `raw` and
different flags.

**Timestamps are Unix nanoseconds, which spans 1678-2262.** The zero time
encodes as the Unix epoch and out-of-range times are clamped, because
`time.Time.UnixNano()` is undefined outside that range and an unset timestamp
would otherwise become a confident, wrong, eighteenth-century date. A
consequence worth knowing: "no time" and `1970-01-01T00:00:00Z` are
indistinguishable on disk.

### 3.3 Footer (100 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `magic` = `"ULPFEND1"` |
| 8 | 8 | `count` |
| 16 | 8 | `last_seq` |
| 24 | 32 | `root` — the segment's Merkle root |
| 56 | 32 | `chain` — this segment's chain hash |
| 88 | 8 | `sealed_at` (Unix nanoseconds) |
| 96 | 4 | `footer_crc` — CRC-32C of bytes 0..95 |

The header and footer magics differ, so a truncated segment can never be
mistaken for a sealed one.

### 3.4 Compacted segment (`.zst`)

```
header   (72 bytes, raw, identical to the WAL's)
block × k:  comp_len u32 | uncomp_len u32 | crc u32 | zstd frame
footer   (100 bytes, raw, identical to the WAL's)
```

**A compacted segment is a "logical WAL".** The concatenation of the
decompressed blocks is byte-for-byte the record region of the original `.wal`,
and records keep their original byte offsets. Everything that addresses a record
— the in-memory index, `Get`, `Proof`, recovery, deep verification — does so by
WAL offset and is unaware of compaction; only the layer that turns an offset into
bytes changed. This is why the shared conformance suite passes unmodified against
a vault that is compacting underneath it.

- **The block table lives inside the file**, as the length prefixes, so it can
  never disagree with the data and is rebuilt by walking them. A separate `.meta`
  would be a second copy of information the file already holds.
- Blocks are `compact_block_bytes` (default 256 KiB), **never splitting a
  record**, each an independent zstd frame, so a random read decompresses one
  block and not the segment.
- `crc` is CRC-32C of the *compressed* bytes, checked **before** they reach the
  decompressor, so a flipped bit is reported as a checksum failure rather than as
  whatever the decoder makes of garbage.
- Nothing in a prefix is trusted: lengths are bounded before use, the decoder has
  a hard 64 MiB memory cap, and the decompressed length must equal the prefix's
  claim. A crafted frame that claims to expand to gigabytes fails; it does not
  allocate them.

### 3.5 Hash index (`.hix`)

`(raw_sha256[32] || seq[8])` pairs, sorted by hash then seq, binary-searched over
`ReadAt`. It lets `GetByHash` work on compacted segments without holding every
hash in memory. **It is derived data, not evidence**: at open it is compared byte
for byte with what the just-verified records produce, and a missing or wrong one
is rebuilt (by a writer) or answered from memory (read-only). Editing it cannot
raise a false tamper alarm and cannot make `GetByHash` lie.

A payload stored more than once resolves to the **newest** record everywhere.

**Cost, measured:** 40 bytes per record of incompressible SHA-256. On records
that compress well this can exceed the compressed data it indexes — 304 KB of
`.hix` against 487 KB of compressed segments on the synthetic corpus. It can be
turned off (`hash_index: false`), in which case `GetByHash` returns
`ErrHashIndexDisabled` and no `.hix` is written.

---

## 4. Hashing

Three domain-separated hashes, so a value computed for one position can never
be replayed in another. Without the prefixes, a crafted record body could stand
in for a subtree — the classic second-preimage attack on Merkle trees.

```
leaf   SHA-256(0x00 || body)
node   SHA-256(0x01 || left || right)
chain  SHA-256(0x02 || prev || root || segment_id_be64 || count_be64)
```

`chain_0` is 32 zero bytes.

- **The leaf covers the whole encoded body**, not just the payload. A record's
  source, origin, sequence number and terminator are all inside the tree.
- **`Receipt.RawSHA256` is a separate hash over `raw` alone.** That is the one
  lineage and `GetByHash` use, and the one an operator compares against a
  source file.
- **Tree shape is RFC 6962**: `MTH({d0}) = leaf`, and `MTH(D[n])` splits at the
  largest power of two below `n`.
- **Inclusion verification is RFC 9162 section 2.1.3.2**, the iterative form.

`testdata/merkle_vectors.json` carries trees of every size from 1 to 20 plus 64,
a proof for every leaf, and a five-segment chain. Every hash in it is derivable
from the leaf bodies it also contains, so an independent implementation should
**rebuild it and compare rather than trust it**.

### 4.1 One caveat for anyone writing a verifier

An inclusion proof does **not** independently bind the tree size. For n=100, 96
of the 100 leaves still verify against a claimed size of 101 when the root is
held fixed. That is correct: the root is the commitment, and size and index
only steer how the path is folded. A proof never verifies against the real root
of a tree it does not belong to.

**Practical consequence: trust the root, and get it from somewhere other than
whoever handed you the proof.** `vaultctl head` is what that "somewhere else"
is for.

---

## 5. The ledger

`chain.log` is append-only JSONL, one line per sealed segment:

```json
{"segment":1,"first_seq":1,"last_seq":1000,"count":1000,
 "root":"<hex>","prev":"<hex>","chain":"<hex>",
 "sealed_at":"2026-09-28T09:00:31Z","recovered":false}
```

`recovered: true` means the segment was sealed by crash recovery rather than
cleanly. It is set before the line is written, so the flag survives a restart.

---

## 6. The write path

1. `PutBatch` validates every record and encodes it. A batch that cannot be
   encoded writes nothing — the batch is all-or-nothing, because it becomes one
   write and one fsync.
2. A **single writer goroutine** coalesces concurrent batches into one write
   and one fsync (group commit). Measured group sizes of ~195 records per fsync
   under a light three-source load.
3. Sync, per mode (§7).
4. Publish: offsets, the hash index, leaf hashes.
5. Seal if a trigger fired.

### 6.1 Seal order, and why it is that way

```
compute root → write footer → fsync → append ledger line → fsync
```

The **only** inconsistency a crash can produce with this order is a sealed
segment with no ledger line, which recovery repairs by appending it. The
reverse order would leave a ledger line describing a segment that was never
sealed, which recovery cannot repair because the data to seal it may not exist.

This is not a theoretical preference. Reversing the two fails the 200-cycle
crash suite within 60 cycles with *"segment 37 footer disagrees with its
chain.log line"*.

### 6.2 I/O failure is terminal

Any write or fsync error puts the vault in a **failed** state: every later call
returns `ErrFailed`, `vault_failed` goes to 1, `/healthz` returns 503, and the
process must restart.

**A failed fsync is never retried.** After one, the kernel may already have
dropped the dirty pages, so a retry that "succeeded" would be a lie about data
that is gone.

### 6.3 Compaction

A background goroutine rewrites sealed `.wal` files as `.zst`. It is built around
one rule: **the `.wal` is deleted only after the `.zst` has been read back from
disk, decompressed, and shown to reproduce the segment's Merkle root.** A
compaction that dropped or altered a record would be silent — nothing would fail
until someone asked for that record — so the check is neither optional nor
sampled.

```
1. write seg-N.zst.tmp from the .wal
2. fsync it
3. READ IT BACK FROM DISK: walk blocks, checksum, decompress, parse every record,
   recompute the Merkle root, require it equal to the footer's
4. write seg-N.hix.tmp from the hashes just verified
5. rename .hix, then rename .zst LAST      (.zst present == complete)
6. fsync the directory
7. switch readers over under the vault lock, then delete the .wal
```

A crash leaves either the `.wal` alone (steps 1-5) or both files (between 5 and
7). Recovery removes stale `.tmp` files and orphaned `.hix` files, and when both a
`.wal` and a `.zst` exist it **verifies the `.zst` first** and only then removes
the `.wal`. If the `.zst` is bad the `.wal` is left alone: it may be the only good
copy, and deleting it because "the `.zst` wins" would turn a recoverable situation
into data loss. A read-only open never deletes anything.

**A failed compaction is not a failed vault.** The data is intact in the `.wal`,
so an error is logged and counted (`vault_compaction_failures_total`) and the
segment is skipped until the next open. It never enters `ErrFailed`.

The guard was checked by mutation rather than assumed. With the record-drop bug
injected and verification **disabled**, the reads-equal test still catches it
independently ("index says record 3 is at offset 470, but that record is 4"). With
verification **enabled**, the compaction is refused: the `.wal` is kept, no `.zst`
is left behind, and the segment is not flagged compacted.

---

## 7. Sync modes

| Mode | Behaviour | Does an acknowledgement mean "on disk"? |
|---|---|---|
| `always` | fsync before acknowledging | **Yes.** The default. |
| `interval` | acknowledge, fsync on a timer | No — up to one interval can be lost |
| `none` | never fsync | No. Benchmarks only; needs `ULPF_ALLOW_SYNC_NONE=1` |

**Every benchmark number must state its mode.** The modes differ by orders of
magnitude and only one of them means what "durable" usually means.

---

## 8. Recovery

On `Open`:

1. Take `LOCK` (flock). A second writer fails fast.
2. Read `chain.log`, tolerating **one torn final line** — appending is not
   atomic, so a crash can cut it. A torn line anywhere else means the file was
   edited, which is not something a crash does.
3. Segment ids must be consecutive from 1.
4. For each sealed segment, cross-check the footer against its ledger line.
   A sealed segment with no ledger line is the one repairable case (§6.1).
5. The last segment, if unsealed: scan records validating length, CRC and
   sequence contiguity; **truncate at the first invalid record** and seal the
   remainder, flagged `recovered`.
6. A non-last segment without a footer is fatal corruption.
7. A segment file shorter than a header was created and then interrupted before
   its header was fsynced. That is not corruption — no record was ever
   acknowledged into it — and it is treated as never having existed. (This was
   found by the crash suite at cycle 123, under `-race`: it made a vault
   unopenable, which is strictly worse than losing unacknowledged records.)
8. A `.zst` is verified as thoroughly as a `.wal`: every block checksummed and
   decompressed, every record parsed, the Merkle root recomputed against the
   footer. "It opened" must mean the same thing for both.

### 8.1 A writer refuses damaged storage; a reader does not

A writer that appended to a broken history would bury the evidence under
valid-looking new chain links. But `vaultctl verify` has to be able to **open**
a tampered vault in order to say what is wrong with it — "could not open" is a
far less useful answer than "segment 2 does not match its footer root". A
read-only open therefore records the damage and continues, and `VerifyChain`
reports it ahead of anything the ledger walk finds, because a ledger can look
perfectly consistent precisely because it was the thing that was edited.

---

## 9. What is guaranteed, and how it was tested

| Guarantee | Evidence |
|---|---|
| Bytes out equal bytes in — invalid UTF-8, NULs, CR/LF, empty, 1.5 MiB records | 7598 records across all 13 fixtures round-trip byte-exact against the manifest |
| A record acknowledged in `sync=always` survives process death | 200 kill -9 cycles, 0 lost — 5889 acknowledged records (WAL only) and 4206 (with background compaction, so the kill also lands mid-compaction) |
| Compaction loses and alters nothing | Every record, receipt, seal, proof and the chain head are identical before and after; the whole corpus round-trips byte-exact after compaction |
| A failed write or fsync is terminal and an fsync is never retried | Failure injection at the Nth write / fsync / footer / ledger append; mutation-checked — a vault that retries the fsync fails it, because the retry "succeeds" and callers are told their data is durable |
| A torn tail loses only unacknowledged records | The last write cut at **every** byte offset; exactly the whole records survive |
| Any single-record edit, deletion, reorder, or segment deletion/swap/truncation is detected | 10-row tamper matrix, 0 undetected, each naming the segment |
| Reopening after a crash never yields a corrupt segment | Included in the crash suite: `VerifyChain(deep)` must pass every cycle |

### 9.1 The tamper matrix

All ten are caught by `VerifyChain(deep)` on a read-only open:

flipped byte in a record · deleted record · truncated segment · deleted middle
segment · swapped segments · edited footer root · edited ledger root · ledger
line removed from the middle · emptied `chain.log` · edited segment header

**Compacted storage adds eight more**, all detected: a flipped byte in a
compressed block · a truncated `.zst` · a deleted `.zst` · two `.zst` swapped ·
an edited footer root · an edited header · a block length inflated to demand
gigabytes · and the strongest forgery available — **a block rewritten with a
record's payload changed and every checksum recomputed** (record CRC, block CRC,
length prefix), so that everything the file format can check is valid. Only the
Merkle root catches that one, and it does: *"compacted segment 2 does not match
its footer root"*.

### 9.2 Compression, measured

Synthetic corpus, zstd level 3, 256 KiB blocks, against `gzip -6` over the same
WAL bytes. Ratios do not depend on the machine, so unlike throughput these are
reportable from anywhere.

| file | records | WAL | zst | ratio | gzip | ratio |
|---|---:|---:|---:|---:|---:|---:|
| cisco_asa.log | 2000 | 570,093 | 85,005 | 6.7× | 86,896 | 6.6× |
| fortinet.log | 2000 | 1,265,175 | 146,773 | 8.6× | 144,526 | 8.8× |
| suricata.json | 2000 | 994,941 | 140,974 | 7.1× | 138,530 | 7.2× |
| palo_alto_unknown.log | 500 | 260,311 | 46,476 | 5.6× | 47,584 | 5.5× |
| malformed.log | 100 | 23,860 | 4,750 | 5.0× | 4,774 | 5.0× |
| oversize.log | 4 | 2,693,760 | 1,562 | 1724.6× | 9,142 | 294.7× |

Read this table before quoting a headline number:

- **The corpus total is 12.9×, and that figure is misleading.** It is dominated by
  `oversize.log`, 2.6 MB of one repeated pattern. Excluding it the corpus is
  ~7.4×; typical individual files are **5.0–8.6×**.
- **zstd-3 in 256 KiB blocks does not beat gzip-6 on ratio here** — 6.7× against
  6.6× on ASA, and gzip wins on Fortinet (8.8× vs 8.6×). Whatever the case for
  zstd is, these measurements do not make it on compression ratio. Speed was not
  measured and nothing here claims it.
- **The `.hix` is not free.** It is 303,960 bytes against 487,435 bytes of
  compressed segments — 62% on top. With the index the whole-corpus ratio is far
  lower than the segment ratio above.
- **The corpus is synthetic and repetitive by construction.** Real device logs
  will differ, in either direction.

---

## 10. What is **not** claimed

This section is the important one.

### 10.1 Power-loss durability is not proven

The crash suite kills the process; it does not cut power. This was **measured,
not assumed**: switching the crash child to `sync=none` — where an
acknowledgement means nothing is on disk at all — still **passes** the suite,
because SIGKILL does not discard the page cache.

So the suite proves the **recovery logic** is correct (torn tails, interrupted
seals, missing ledger lines, sequence contiguity). It does **not** prove fsync
put anything on a platter. Proving that needs power to be cut, which no test
can do.

*"0 acknowledged records lost across 200 kill -9 cycles"* is true and measured.
*"Durable"*, unqualified, is not what it shows.

### 10.2 Tamper-evident, not tamper-proof

Someone with write access to the whole directory can rewrite it consistently —
recompute every root, every chain link and every ledger line — and nothing in
the directory will contradict them. The chain detects *inconsistent* edits, not
a coherent rewrite.

The defence is to hold the chain head somewhere the vault's owner cannot reach.
`vaultctl head` prints it. Optional ed25519-signed seals are a documented
future item (VT-11), not implemented.

It also cannot detect deletion of the newest sealed segment together with its
ledger line, for the same reason: nothing left behind refers to it.

### 10.3 Other limits

- **The crash suite under compaction proves the same thing as without it**: the
  recovery logic, not fsync. It also kills the process mid-compaction — mid-write
  of the `.zst`, mid-verification, between the renames, and between the last
  rename and deleting the `.wal`.
- **The in-memory index is O(records).** Every record costs an index entry
  (segment, offset, raw hash — roughly 50 bytes) for the life of the process,
  compacted or not. Compaction moves the hash *lookup* to disk but not the
  per-record locator. A vault holding hundreds of millions of records would need
  that index made per-segment and sparse; that is the documented scale path and it
  is not built. **The PRD's RSS target has not been measured.**
- **UDP is best-effort.** A datagram the kernel dropped never reached the
  process. `ingest_udp_kernel_drops` exposes what Linux can see, and reports
  NaN — not 0 — where the platform cannot tell.
- **File tail is at-least-once.** A crash between a record becoming durable and
  the checkpoint being written replays it. `Origin{path, offset}` is the
  de-duplication key. Checkpointing first would instead let a crash *skip* a
  record, and duplicates are recoverable where missing data is not.
- **Single node.** No replication, no sharding. The scale-out path — an
  independent pipeline per shard — is documented, not built.
- **No encryption at rest, no retention or deletion policy.**

---

## 11. Verifying a vault by hand

```sh
vaultctl --dir ./data/vault verify --deep     # 0 intact, 1 tampered, 2 unreadable
vaultctl --dir ./data/vault head              # copy this somewhere else

# Byte-exactness: three independent hashes must agree.
head -1 testdata/cisco_asa.log | tr -d '\n' | sha256sum
vaultctl --dir ./data/vault get 1 --raw | sha256sum
jq -r '.records[0].expected_sha256' testdata/manifest.json

# An inclusion proof, checked with no vault present at all.
vaultctl --dir ./data/vault proof 1 > proof.json
vaultctl verify-proof proof.json
```

`scripts/send_samples.sh` runs all of this against a live daemon and exits
non-zero if any check fails. Everything above works identically on compacted
segments: `vaultctl` opens a `.zst` exactly as it opens a `.wal`.

---

## 12. Exit codes are contract

`vaultctl`: **0** intact · **1** tamper or corruption detected · **2** usage
error or unreadable.

`verify_airgap.sh` and the demo script branch on these. 1 and 2 must stay
distinguishable: *"someone changed the data"* and *"I could not look"* are very
different answers, and collapsing them would let the air-gap proof report
success for a vault it never managed to read.
