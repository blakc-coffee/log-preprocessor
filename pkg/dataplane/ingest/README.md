# ingest — devices to durable records

## The rule that never bends

**A record leaves this package only after the vault has said it is durable.**
Everything else here serves that. Parsing can be wrong and be fixed later by
replaying from the vault, but only if the bytes were stored first.

## Backpressure, not dropping

Every queue is bounded. A slow consumer fills the output channel, which blocks
the stream, which blocks the source, which stops reading its socket — and the
sender feels it through the TCP window or a stalled body read. Nothing is
discarded to keep up.

UDP is the exception the design cannot fix: a datagram the kernel drops never
reached us. The counters are exposed and the limit is stated rather than hidden.

## Shape

```go
p, _ := ingest.New(cfg, vault, out, logger)
p.AddSource(src)
err := p.Run(ctx)     // blocks until every source returns, then closes out
```

`Sink` hands out a `Stream` per connection, file or request. **Ordering is
preserved within a stream and not across them**, which is what lets every
connection run concurrently while one file's records keep their sequence.

## Two locks, and why the order matters

A stream holds `writeMu` across a flush and acquires it **before** detaching the
batch. Detaching under the write lock is what makes writes happen in the order
records were appended.

This is not theoretical. Detaching outside it let the batch timer and a
full-batch flush interleave, so two batches from one stream reached the vault
out of order — and an oversize record's fragment run was split across them and
reassembled into garbage. The race detector separately caught the pipeline
closing the output channel while a timer flush was still sending. Both are
covered by `TestFlushesDoNotInterleave`.

It also means `Close` blocks until any in-flight timer flush has finished, so
closing the output channel afterwards cannot race a send.

## Why a timer at all

A stream that goes quiet after one record would otherwise hold it in memory,
undurable, until the next one arrived — which is exactly the record a crash
would lose. A device sending one message a minute must not wait a minute for
durability. It is a `time.AfterFunc` rather than a goroutine per stream:
`max_conns` is 1024, and a thousand goroutines waiting on a ticker is a
thousand goroutines doing nothing.

## Test

```sh
go test ./pkg/dataplane/ingest/...
go test -race -count=3 ./pkg/dataplane/ingest/...
```

`TestRoundTripEveryFixture` is the M3 gate and the evidence behind PS
requirement (a): every record in `testdata/manifest.json` is read straight from
its source file, compared byte for byte against what the vault stored, and
checked against the manifest's SHA-256, terminator, fragment count and byte
offset — then `VerifyChain(deep)` has to pass. Nothing is excluded:
`malformed.log`'s invalid UTF-8 and NULs, `crlf.log`'s terminators,
`multiline.log`'s internal newlines and `oversize.log`'s fragments all have to
come back exactly. **7598 records across 13 fixtures.**
