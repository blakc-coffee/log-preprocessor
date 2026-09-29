"""Run the language-neutral DSL conformance cases (contracts/conformance/cases.yaml) through the reference evaluator.

The same file is run by the Go harness against Parsing's engine. Passing here means the cases are consistent with
an independent implementation, so a Go failure later points at the engine, not at a mistake in the case.
"""
from datetime import datetime
from pathlib import Path

import pytest
import yaml

from ulpf_intel import dsl_eval

CASES = yaml.safe_load((Path(__file__).resolve().parents[2] / "contracts/conformance/cases.yaml").read_text())["cases"]
RUNNABLE = [c for c in CASES if c["python"]]


def get(flat: dict, path: str):
    return flat.get(path, "<missing>")


@pytest.mark.parametrize("case", RUNNABLE, ids=[c["name"][:70] for c in RUNNABLE])
def test_case(case):
    try:
        doc = dsl_eval.load(case["parser"])
        dsl_eval.validate_parser(doc)
    except ValueError as e:
        assert "load_error" in case, f"unexpected load error: {e}"
        assert case["load_error"] in str(e)
        return
    assert "load_error" not in case, "expected a load error, but the parser loaded"
    ra = datetime.fromisoformat(case["received_at"].replace("Z", "+00:00")) if case.get("received_at") else None
    r = dsl_eval.extract(doc, case["raw"], ra)
    exp = case["expect"]
    assert (r is not None) == exp["matched"]
    if r is None:
        return
    if "extractor" in exp:
        assert r.extractor == exp["extractor"]
    o = dsl_eval.flat(r.ocsf)
    for k, v in exp.get("ocsf", {}).items():
        assert get(o, k) == v, k
    for k in exp.get("ocsf_absent", []):
        assert k not in o, k
    um = dsl_eval.flat({k: v for k, v in r.unmapped.items() if k != "_dupes"})
    for k, v in exp.get("unmapped", {}).items():
        assert (r.unmapped.get(k) if k == "_dupes" else um.get(k, "<missing>")) == v, k
    for k in exp.get("unmapped_absent", []):
        assert k not in um, k
    for f in exp.get("flags", []):
        assert f in r.flags, f
    for f in exp.get("flags_absent", []):
        assert f not in r.flags, f


def test_case_names_are_unique_and_every_case_states_its_spec_section():
    names = [c["name"] for c in CASES]
    assert len(names) == len(set(names)) and all(c["spec"] for c in CASES)
