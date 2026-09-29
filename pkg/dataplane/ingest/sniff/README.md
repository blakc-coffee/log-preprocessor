# sniff — a guess at a record's format

**Advisory and nothing more.** The hint never affects `Raw`, never affects what
is stored, and never decides whether a record is kept. A parser is free to ignore
it and must still be correct when it is wrong — which it sometimes will be, since
this is a heuristic over 256 bytes of attacker-controlled input.

It is computed **after** the vault write, deliberately: computing it first would
mean a crafted log line could influence how that line was kept.

## Rules, in order

1. `<PRI>` header → `syslog5424` if followed by `1 `, else `syslog3164` — unless
   `CEF:` or `LEEF:` appears within 200 bytes, in which case `cef` / `leef`
   (a syslog-framed CEF message is CEF: the transport is incidental)
2. bare `CEF:` / `LEEF:` → `cef` / `leef`
3. first non-space byte `{` or `[` → `json`; `<?xml` or `<` + letter → `xml`
4. at least 3 `word=` pairs → `kv`
5. at least 5 commas and no `=` → `csv`
6. otherwise `unknown`

`unknown` is the honest answer for `multiline.log`, `dhcp.log` and `openvpn.log`,
which have no machine-readable shape at a glance. Inventing a classification
would mislead the parser registry into trying an extractor that cannot work.

## Cost

One pass over at most 256 bytes, hand-rolled rather than `regexp`, no allocation:
about 132 ns/op and ~1 GB/s on the development machine (macOS; a CPU-bound number,
not an fsync one). It runs on every record whether or not anything uses the answer.

## Test

```sh
go test ./pkg/dataplane/ingest/sniff/
go test -run '^$' -bench . -benchmem ./pkg/dataplane/ingest/sniff/
```

Every fixture's first record has an asserted expected hint, and all ~7800 fixture
lines are checked to return a valid hint and never panic.
