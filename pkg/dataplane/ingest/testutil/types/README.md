# types — TEMPORARY local copy of the frozen contract

The real contract is `pkg/types`, owned by the Contracts workstream. It does
not exist yet, and this workstream may not write it
(`PRD_INGESTION_vault_SCOPED` section 0 and 9.6 step 2) — but it cannot build a
vault without the `Vault` interface either. This copy stands in.

The declarations are copied from `PRD_INGESTION_vault_SCOPED` section 3, which
`PRD_CONTRACTS` section 2.1 tells the Contracts workstream to take verbatim. As
of writing the two agree, so there is **no mismatch to report**.

## When the real `pkg/types` lands

1. Diff it against `types.go` and record any difference in `DECISIONS.log`.
   Where they disagree, **the contract wins** and this workstream adapts.
2. Rewrite the import path in `vault/record`, `vault/merkle`, `vault/memvault`
   and `vault/vaulttest`, then delete this package.

Nothing outside this workstream should import it.
