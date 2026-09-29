# gen — the fixture generator's implementation

Internal to `tools/gen`; see `tools/gen/README.md` for how to run it and what it
produces. This package is the generator itself: one file per fixture source,
plus the identity scenario and the ground-truth writer.

Two properties everything here is built around:

- **Deterministic.** The same seed produces byte-identical output on any machine.
  No `time.Now`, no map iteration order, no goroutines, and no toolchain version
  in the manifest. Each source draws from its own PCG stream seeded
  `(seed, fnv64a(filename))`, so adding a source never shifts the others.
- **Ground truth is computed, never typed.** Byte offsets and SHA-256s are
  recorded by the writer as it writes, and `verify_test.go` re-derives every one
  independently from the files on disk.

The identity scenario (`identity*.go`, `truth.go`) is a pure function of the seed,
so `dhcp.log`, `radius.log`, `openvpn.log`, `identity_firewall.log` and
`identity_truth.json` agree without sharing mutable state.

**Everything generated is synthetic.** Addresses come from the documentation
(RFC 5737) and private (RFC 1918) ranges; every user name is invented.

## Test

```sh
go test ./tools/...
```
