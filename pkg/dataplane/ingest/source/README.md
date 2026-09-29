# source — where the bytes come from

Every source does the same three things — read bytes, frame them, submit them —
and differs only in where the bytes come from and how backpressure reaches the
sender.

| Source | Backpressure reaches the sender via | Origin.Offset |
|---|---|---|
| `File` | the read pace | byte offset in the file |
| `TCP` / `TLS` | the TCP receive window | byte offset within the connection |
| `HTTP` | a stalled body read | byte offset within the body |
| `UDP` | **it cannot** — see below | always 0 |

Listeners bind in their constructor, not in `Run`, so a caller can read `Addr()`
before accepting starts. Binding in `Run` would force every test to poll for
readiness, and sleep-based synchronisation is how flaky tests are born.

## What UDP cannot promise

One datagram is one record, and a datagram the kernel dropped never reached this
process. There is no backpressure to apply and nothing to retransmit. This
source makes the receive buffer large (8 MiB default), reads it promptly, and
**warns when the kernel clamps the buffer** — silently getting less than was
asked for is exactly how UDP loss becomes a mystery later. Raise
`net.core.rmem_max` on Linux.

A trailing newline on a datagram is **content**, not a terminator: nothing
framed it, the sender sent 34 bytes, and stripping one would break
byte-exactness for every sender that does it.

## Tail

`mode: tail` follows a file across rotations (rename-and-create) and
truncations (copy-truncate), and resumes from a checkpoint after a restart.

**Polling, not inotify.** The fallback has to exist and be correct anyway —
bind mounts break inotify, so containers run polling regardless — and 500 ms is
far below anything that matters when the vault seals every 5-30 seconds. It
keeps the dependency count at one, which is worth something for an air-gapped
build. See `DECISIONS.log` 09:15.

The tail hands the framer a reader that **never returns EOF**. A framer that
saw EOF would emit a half-written line as a complete record and the rest as a
second one, splitting an event in two at exactly the moment a writer was
mid-write.

### Delivery is at-least-once, by choice

A checkpoint records the offset after the last record the vault confirmed
durable, and is written **after** the flush. A crash in between re-reads those
records and stores them twice. Checkpointing first would instead let a crash
skip a record that was never stored — duplicates are recoverable,
missing data is not. `Origin{path, offset}` is the de-duplication key.

Checkpoints are written atomically (temp file, fsync, rename, fsync the
directory): a half-written one read after a crash would resume at a garbage
offset. A corrupt checkpoint is treated as absent rather than fatal — it is
derived state, and refusing to start over one turns an annoyance into an outage.

A checkpoint stores `fingerprint_len` alongside the fingerprint. That is not
decoration: a log file is append-only so its first N bytes are immutable once
it is N bytes long, but a file *shorter* than the window changes its own
fingerprint every time it grows. Recomputing over the stored length instead of
"however much there is now" is what makes checkpoints work on small files.
Checkpoint file names are a hash of the log path, never the path itself.

## Auto framing

RFC 6587 permits octet counting and newline framing on the same syslog port, so
a listener has to guess: 1-6 ASCII digits then a space means octet counting.
Safe for syslog, which always starts `<PRI>`. **Unsafe for arbitrary text** — a
CSV line beginning `12345 ` would be misread — so non-syslog TCP sources must
set the mode explicitly.

## HTTP

```
POST /ingest/{source_id}?framing=lines|whole|octet|nul   → 202 {"accepted":N,"fragments":M}
GET  /healthz                                            → 200, or 503 if the vault is failed
```

The **202 means durable**. The response is written only after every record in
the body is in the vault, so a client that deletes its copy on seeing one cannot
lose data. Bodies stream, so a chunked upload is framed and vaulted as it
arrives rather than buffered whole.

`source_id` comes off the network and is validated against
`^[A-Za-z0-9._-]{1,64}$`. It is never used to build a filesystem path, and a
rejected value is never echoed back into a response or a log. Unconfigured
source ids are refused unless `DynamicSources` is on — an open endpoint that
mints a source per request is an unbounded metric-label space.

## Defences against a sender that will not behave

- `IdleTimeout` (5 min) on every socket read, and `ReadHeaderTimeout` (10 s) on
  HTTP — the slow-loris defence on both paths.
- `MaxConns` (1024). At the cap a connection is **refused immediately**:
  accepting and then stalling looks to the sender like a working connection that
  silently loses data.
- A framing violation closes the connection and increments a counter, so it
  shows up in metrics rather than only in a log nobody reads.
- `MaxBody` (1 GiB) enforced at the read, not after the body is in memory.

## Test

```sh
go test ./pkg/dataplane/ingest/source/
go test -race -count=4 ./pkg/dataplane/ingest/source/
```

`TestTCPShutdownWithConnectionsArriving` is a regression test for a shutdown
hang: a connection accepted in the window between shutdown closing the live
connections and the accept loop registering it was never closed, so its reader
blocked for the full idle timeout and `Run` never returned. It only reproduced
under `-race`, where the scheduling window is wide enough to hit.
