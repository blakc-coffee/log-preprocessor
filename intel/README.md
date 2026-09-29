# intel: the intelligence sidecar

Propose-only, off the hot path, opens no listener. **Status: contract conformance only.** Drift detection, semantic
typing and proposal generation start after Gate 0 (`prd/PRD_CONTRACTS_intel_identity.md` section 5).

`ulpf_intel/models.py` mirrors the contract types in pydantic (`extra="forbid"`), and `tests/test_contract.py` validates
every golden in `contracts/golden/` against `contracts/uef.schema.json` and those models.

```sh
cd intel
python3.13 -m venv .venv && . .venv/bin/activate     # 3.11+ required by pyproject
pip install -e '.[test]'
pytest
```

`make contract-test` runs this suite when `intel/.venv` exists and prints `SKIPPED` when it does not.
