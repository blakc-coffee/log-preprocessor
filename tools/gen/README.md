# tools/gen — synthetic fixture generator

Writes the ULPF test corpus and its ground-truth manifest. **Everything it
produces is synthetic**: faithful approximations of vendor formats, not real
captures. Addresses come from the documentation (RFC 5737) and private (RFC
1918) ranges, and every user name is invented.

## Run

```sh
make fixtures         # full corpus into testdata/
make fixtures-sample  # ~50 records per source into testdata/sample/
make fixtures-check   # prove determinism: regenerate and diff
go run ./tools/gen --list
go run ./tools/gen --seed 20260928 --only cisco_asa.log --out /tmp/x
```

Flags: `--seed` (default 20260928), `--out`, `--profile full|sample`,
`--only a.log,b.log`, `--list`.

## Determinism

The same seed produces byte-identical output on any machine. That rules out
`time.Now`, map iteration order, goroutines and the running toolchain version;
`manifest.generator.go` is therefore a constant, not `runtime.Version()`. Each
source draws from its own PCG stream seeded `(seed, fnv64a(filename))`, so
adding a fixture never shifts the others.

## Output

13 log files plus `manifest.json` (byte ranges, SHA-256s and expected parse
results, all computed while writing) and `identity_truth.json` (the answer key
for identity resolution). `identity_truth.json` is deliberately absent from the
manifest's `files` map, because that map is iterated by the round-trip tests,
which ingest every file in it.

## Test

```sh
go test ./tools/...        # determinism, manifest self-consistency, fixture composition
```
