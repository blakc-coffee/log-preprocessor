"""Conformance: the Go-generated goldens validate here too (PRD A-6).

Two independent checks per golden: the JSON Schema (jsonschema, the same file
Go validates against) and, where a Go type exists, the pydantic mirror with
extra="forbid". A golden that fails is a bug in the contract, not in the consumer.
"""
import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from ulpf_intel.models import MODELS

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
GOLDEN = CONTRACTS / "golden"
SCHEMA = json.loads((CONTRACTS / "uef.schema.json").read_text())


def golden_map() -> dict[str, str]:
    """golden name -> schema definition, read from the Go source so there is one table."""
    src = (CONTRACTS / "contracts.go").read_text()
    block = src.split("var GoldenSchema", 1)[1].split("}", 1)[0]
    return dict(re.findall(r'"([a-z_]+)":\s*"([a-z_]+)"', block))


def validator(defn: str) -> Draft202012Validator:
    return Draft202012Validator(
        {"$schema": SCHEMA["$schema"], "$ref": f"#/$defs/{defn}", "$defs": SCHEMA["$defs"]},
        format_checker=FormatChecker(),
    )


def load(name: str):
    return json.loads((GOLDEN / f"{name}.json").read_text())


MAP = golden_map()


def test_every_golden_is_mapped():
    files = {p.stem for p in GOLDEN.glob("*.json")}
    assert files == set(MAP), files ^ set(MAP)


@pytest.mark.parametrize("name", sorted(MAP))
def test_golden_validates_against_schema(name):
    errs = sorted(validator(MAP[name]).iter_errors(load(name)), key=lambda e: list(e.path))
    assert not errs, "\n".join(f"{list(e.path)}: {e.message}" for e in errs[:5])


@pytest.mark.parametrize("name", sorted(n for n, d in MAP.items() if d in MODELS))
def test_golden_parses_into_pydantic_model(name):
    model = MODELS[MAP[name]]
    obj = model.model_validate(load(name))
    # what the model would emit must itself satisfy the schema
    dumped = json.loads(obj.model_dump_json(exclude_unset=True))
    errs = list(validator(MAP[name]).iter_errors(dumped))
    assert not errs, errs[0].message


def test_pydantic_refuses_unknown_field():
    ev = load("event_asa_built")
    ev["surprise"] = 1
    with pytest.raises(Exception):
        MODELS["normalized_event"].model_validate(ev)


# The guard must be able to fail: each of these is a real contract violation.
@pytest.mark.parametrize(
    "golden,mutate",
    [
        ("event_asa_built", lambda d: d.__setitem__("integrity_flags", ["made_up"])),
        ("event_asa_built", lambda d: d.__setitem__("raw_sha256", d["raw_sha256"].upper())),
        ("event_asa_built", lambda d: d.__setitem__("surprise", 1)),
        ("event_asa_built", lambda d: d.__setitem__("event_id", "abc")),
        ("lineage_sealed", lambda d: d.__setitem__("sealed", False)),
        ("lineage_pending", lambda d: d.__setitem__("sealed", True)),
        ("proposal_palo_alto", lambda d: d.__setitem__("base_version", "1.0.0")),
        ("replay_job", lambda d: d.__setitem__("state", "finished")),
    ],
)
def test_schema_rejects_violation(golden, mutate):
    doc = copy.deepcopy(load(golden))
    mutate(doc)
    assert list(validator(MAP[golden]).iter_errors(doc)), "mutated golden was accepted"
