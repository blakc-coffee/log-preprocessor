# ingestd — the ingest + vault daemon

```sh
ingestd --config configs/ingest.dev.yaml [--emit none|stdout|jsonl:/path] [--once]
ingestd --healthcheck --config configs/ingest.dev.yaml
```

Receives logs over UDP, TCP and HTTP or reads them from files, and stores them
in the hash-chained vault. In the full data plane the parsing workstream's
binary wires `Pipeline.Out` to the parser instead; `--emit` is how this one is
useful standalone.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean shutdown, or `--once` finished |
| 1 | the vault failed, a source died, or shutdown timed out |
| 2 | bad configuration or usage |

**Shutdown timing out exits 1, not 0.** A shutdown that did not finish may have
left records accepted but not durable, and a supervisor treating that as a
clean stop would hide it.

## `--once`

Exits when every `mode: once` file source has finished. Network listeners never
finish on their own, so the file sources' completion cancels the context and
shutdown runs through the same path a signal would take. `--once` against a
config of only listeners is an error rather than a hang.

## `--emit`

`none` discards, `stdout` prints JSON Lines, `jsonl:<path>` appends to a file.
**The payload is base64-encoded.** A raw log line is attacker-controlled, and
printing it unescaped into a terminal or a log aggregator is log injection.

## Configuration

See `configs/ingest.dev.yaml`. Three rules, all about failing loudly:

- **Unknown keys are an error.** A typo in `segment_max_records` that silently
  left the default in place would surface weeks later as a performance mystery
  rather than immediately as a failure to start. Keys for features that do not
  exist yet are rejected too — accepting and ignoring `compact: true` leaves an
  operator certain compaction is on.
- **Fields from the wrong source type are rejected.** Accepting `paths` on a
  UDP listener and ignoring it is how someone ends up certain a file is being
  read when it is not.
- **`sync: none` needs `ULPF_ALLOW_SYNC_NONE=1`.** In that mode
  acknowledgements stop meaning anything; it exists for benchmarks and must
  never be chosen by accident.

Every error is reported at once, so fixing a config does not take one restart
per mistake.

## Manual smoke test

```sh
make build fixtures
./bin/ingestd --config configs/ingest.dev.yaml --emit stdout &

curl -sS 127.0.0.1:9100/healthz
printf '<134>Sep 28 09:00:01 h app: hello' | nc -u -w1 127.0.0.1 5514      # UDP
printf 'line1\nline2\n'                   | nc -w1 127.0.0.1 5514          # TCP, LF
printf '30 <134>Sep 28 10:14:02 h app: hi'| nc -w1 127.0.0.1 5514          # TCP, octet-counted
curl -sS --data-binary @testdata/sample/cisco_asa.log http://127.0.0.1:8080/ingest/asa-lab

./bin/vaultctl --dir ./data/vault verify --deep; echo "exit=$?"
./bin/vaultctl --dir ./data/vault proof 1 > /tmp/p.json
./bin/vaultctl verify-proof /tmp/p.json
```

## Test

```sh
go test ./cmd/ingestd/
```
