## What and why


## Checklist

- [ ] Only owned paths changed; contract files untouched (or contract PR approved)
- [ ] `go vet`, `go test -race` (or `pytest`, `npm test`) green
- [ ] No new dependency outside the agent's PRD table (or approval linked)
- [ ] No network access in tests; no `time.Now()` in generators; deterministic
- [ ] Every exported identifier documented; package README updated with run instructions
- [ ] Raw bytes never modified (Ingestion, Parsing): test proving it
- [ ] Bounded queues and length caps for any new input path
- [ ] Metrics added for any new failure mode
- [ ] Definition-of-done items for the milestone met

## Contract changes (delete if none)

A contract PR updates Go types, `uef.schema.json`, `admin.openapi.yaml`, goldens and the PRD text together, passes
`make contract-test`, and needs the user's approval. Agents affected:

-
