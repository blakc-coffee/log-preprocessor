# vaultctl — vault operator CLI

```sh
vaultctl --dir ./data/vault stats                  segment and record counts
vaultctl --dir ./data/vault ls                     one line per sealed segment
vaultctl --dir ./data/vault head                   chain head, for external anchoring
vaultctl --dir ./data/vault verify [--deep]
vaultctl --dir ./data/vault get SEQ [--raw]        metadata and hexdump, or raw bytes
vaultctl --dir ./data/vault proof SEQ              inclusion proof as JSON
vaultctl --dir ./data/vault scan --from SEQ --limit N
vaultctl verify-proof FILE                         check a proof with no vault at all
```

## Exit codes are part of the contract

| Code | Meaning |
|---|---|
| 0 | the vault is intact, or the command succeeded |
| 1 | tamper or corruption detected |
| 2 | usage error, or the vault could not be read |

`verify_airgap.sh` and the demo script branch on these. **1 and 2 must stay
distinguishable**: "someone changed the data" and "I could not look" are very
different answers, and collapsing them would let the air-gap proof report
success for a vault it never managed to read. `TestExitCodesAreContract` pins
all three.

Every command opens the vault read-only, so vaultctl can inspect a vault
another process is writing to — and can open a *damaged* one in order to say
what is wrong with it.

## Proving a record was never altered

```sh
# byte-exact: these three hashes must agree
head -1 testdata/cisco_asa.log | tr -d '\n' | sha256sum
vaultctl --dir ./data/vault get 1 --raw | sha256sum
jq -r '.records[0].expected_sha256' testdata/manifest.json

# and that the record is in the tree, checked with no vault at all
vaultctl --dir ./data/vault proof 1 > proof.json
vaultctl verify-proof proof.json
```

`verify-proof` confirms the record is in a tree with that root, and that the
root is linked into the chain at that position. It **cannot** confirm the root
is the one the vault really published — for that, compare it against a chain
head (`vaultctl head`) obtained from somewhere other than whoever handed you
the proof. That is what `head` is for.

## Test

```sh
go test ./cmd/vaultctl/
```
