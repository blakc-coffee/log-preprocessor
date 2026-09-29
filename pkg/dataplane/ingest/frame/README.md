# frame — turning a byte stream into records

The first thing that touches hostile input, and deliberately the dumbest
component in the system: it finds record boundaries and does nothing else. No
interpreting, trimming, re-encoding, validating or repairing. Invalid UTF-8,
NULs, control bytes and lone CRs pass through untouched, because the vault's
byte-exactness claim starts here.

## The two rules

1. **The terminator is recorded, never stored.** A record's bytes are the
   event's bytes and nothing else.
2. **Nothing is ever truncated.** A record longer than `MaxFrameBytes` is
   emitted as consecutive fragments; concatenating their `Raw` restores it.

## Modes

| Mode | Splits on | Notes |
|---|---|---|
| `lf` | `\n` | A lone `\r` is **content**. This is what makes `malformed.log`'s bare-CR records meaningful. |
| `crlf` | `\r\n` | A lone `\n` is content. |
| `lines` | `\n`, dropping one preceding `\r` | What HTTP `?framing=lines` means; records which it was. |
| `nul` | `\x00` | |
| `octet` | RFC 6587 `<length> <message>` | The length is the delimiter, so newlines and NULs inside a message are content. |

`Detect(peek)` picks between octet counting and line framing for a syslog
listener, since RFC 6587 allows both on one port: 1-6 ASCII digits then a space
means octet counting. Safe for syslog, which always starts `<PRI>`; **unsafe
for arbitrary text**, so non-syslog TCP sources must set the mode explicitly.

`NewMultiline` groups lines into one record — a line matching `Start` begins a
record, non-matching lines append *including the previous line's terminator*.
The **timeout is the source's job**, not the decoder's: `Next` blocks on the
reader, so a decoder cannot notice time passing while waiting. The source drives
a timer and calls `Flush`.

## The boundary that is already pinned

**A record of exactly `MaxFrameBytes` is ONE record, not two** — one byte of
lookahead. Without it, a record landing exactly on the limit emits a full
fragment plus a trailing zero-length `FragCont`, a boundary case every consumer
would have to know about forever. `testdata/oversize.log` and its manifest's
`expected_fragments` (1 / 1 / 2 for 70 KiB / 1 MiB / 1.5 MiB) commit to this,
and `TestOversizeFixtureMatchesTheManifest` checks the framer against them.

## Chunking invariance

A decoder must give identical output regardless of how the reader chops the
stream. A framer that only works when reads align with record boundaries passes
every hand-written test and then fails against a real TCP socket, where one
record arrives in three pieces and three records arrive in one. Every mode is
tested against `iotest.OneByteReader`, ten fixed chunk sizes, 25 deterministic
random chunkings, and `iotest.DataErrReader` (which returns the final bytes
*with* `io.EOF` — naive decoders drop the last record on it).

## Test

```sh
go test ./pkg/dataplane/ingest/frame/
go test -run '^$' -fuzz FuzzOctet -fuzztime 30s ./pkg/dataplane/ingest/frame
go test -run '^$' -fuzz FuzzDelim -fuzztime 30s ./pkg/dataplane/ingest/frame
```

`FuzzDelim` asserts losslessness against arbitrary input rather than examples:
`Raw` plus the recorded terminators must reconstruct the stream byte for byte.
