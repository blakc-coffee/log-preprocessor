"""Proposal generation: PRD_CONTRACTS 5.7. Every value the generated parser yields is checked against the
manifest's ground truth, for every record of the source, not a sample."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from ulpf_intel import dsl_eval
from ulpf_intel.propose import propose_csv, propose_kv_patch
from ulpf_intel.validate import Thresholds, acceptance, local_dry_run, re2_violations

ROOT = Path(__file__).resolve().parents[2]
TESTDATA = ROOT / "testdata"
NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
IST = timezone(timedelta(hours=5, minutes=30))


def lines(name):
    return (TESTDATA / name).read_text().splitlines()


def truth(file):
    return [r for r in json.loads((TESTDATA / "manifest.json").read_text())["records"] if r["source_file"] == file]


def ms(iso):
    return int(datetime.fromisoformat(iso).timestamp() * 1000)


@pytest.fixture(scope="module")
def palo():
    ls = lines("palo_alto_unknown.log")
    return ls, propose_csv("palo_alto", ls, list(range(1, len(ls) + 1)), NOW)


@pytest.fixture(scope="module")
def fortinet():
    base = (ROOT / "contracts/dsl/examples/fortinet.yaml").read_text()
    ls = lines("fortinet_drift.log")
    return base, ls, propose_kv_patch("fortinet", base, "1.0.0", ls, list(range(1, len(ls) + 1)), NOW)


def check_against_manifest(doc, ls, file):
    for raw, t in zip(ls, truth(file)):
        o = dsl_eval.flat(dsl_eval.extract(doc, raw).ocsf)
        want = {"src_endpoint.ip": t["expected_src_ip"], "dst_endpoint.ip": t["expected_dst_ip"],
                "src_endpoint.port": t["expected_src_port"], "dst_endpoint.port": t["expected_dst_port"],
                "connection_info.protocol_name": t["expected_proto"], "time": ms(t["expected_time"])}
        for path, expected in want.items():
            if expected is not None:  # null = the manifest does not know (ICMP has no ports)
                assert o[path] == expected, f"{path}: {o.get(path)} != {expected} in {raw}"


def test_palo_alto_proposal_reproduces_the_manifest_for_all_500_records(palo):
    ls, g = palo
    check_against_manifest(dsl_eval.load(g.proposal.yaml), ls, "palo_alto_unknown.log")


def test_palo_alto_proposal_passes_acceptance_and_is_re2_safe(palo):
    ls, g = palo
    dry = local_dry_run(g.proposal.yaml, list(enumerate(ls, 1)))
    assert acceptance(dry) == [] and dry.match_rate == 1.0
    assert re2_violations(g.proposal.yaml) == []


def test_proposal_shape(palo):
    _, g = palo
    p = g.proposal
    assert (p.kind, p.base_version, p.id, p.status, p.dry_run) == ("new", "", "", "pending", None)
    doc = yaml.safe_load(p.yaml)
    assert doc["id"] == p.parser_id and 1 <= len(doc["extractors"][0]["tests"]) <= 5
    assert len(p.sample_record_ids) <= 20 and all(t.confidence >= 0 for t in p.typed_fields)


def test_vectors_are_real_lines_and_replay_to_themselves(palo):
    ls, g = palo
    doc = dsl_eval.load(g.proposal.yaml)
    for v in doc["extractors"][0]["tests"]:
        assert v["raw"] in ls
        got = dsl_eval.flat(dsl_eval.extract(doc, v["raw"]).ocsf)
        assert all(got[k] == x for k, x in v["expect"].items())


def test_blank_optional_column_is_absent_not_empty(palo):
    ls, g = palo
    doc = dsl_eval.load(g.proposal.yaml)
    blank = next(l for l in ls if l.split(",")[12] == "")
    assert "actor.user.name" not in dsl_eval.flat(dsl_eval.extract(doc, blank).ocsf)


def test_kv_patch_fixes_the_drift_for_all_500_records(fortinet):
    base, ls, g = fortinet
    old = dsl_eval.load(base)
    assert sum(dsl_eval.extract(old, l) is not None for l in ls) == 0        # the drift is real: the old parser fails everywhere
    new = dsl_eval.load(g.proposal.yaml)
    assert sum(dsl_eval.extract(new, l) is not None for l in ls) == len(ls)
    check_against_manifest(new, ls, "fortinet_drift.log")


def test_kv_patch_is_a_patch_that_keeps_unchanged_mappings(fortinet):
    base, _, g = fortinet
    p = g.proposal
    assert (p.kind, p.parser_id, p.base_version) == ("patch", "fortinet", "1.0.0")
    old = {(m.get("to"), yaml.safe_dump(m)) for m in yaml.safe_load(base)["extractors"][0]["map"]}
    new = {(m.get("to"), yaml.safe_dump(m)) for m in yaml.safe_load(p.yaml)["extractors"][0]["map"]}
    kept = {"severity_id", "connection_info.protocol_num", "traffic.bytes_out", "action_id", "disposition_id", "duration", "activity_id"}
    for to in kept:
        assert {y for t, y in old if t == to} == {y for t, y in new if t == to}, f"{to} changed but its key did not"
    assert any("srcip -> src" in w for w in g.warnings) and any("date+time -> eventtime" in w for w in g.warnings)


def test_kv_patch_passes_acceptance_and_is_re2_safe(fortinet):
    _, ls, g = fortinet
    dry = local_dry_run(g.proposal.yaml, list(enumerate(ls, 1)))
    assert acceptance(dry) == [] and re2_violations(g.proposal.yaml) == []


def test_mapping_with_no_successor_is_dropped_and_reported_not_invented():
    base = (ROOT / "contracts/dsl/examples/fortinet.yaml").read_text()
    ls = [l.replace("sentbyte=", "zzz=") for l in lines("fortinet.log")[:100]]
    g = propose_kv_patch("fortinet", base, "1.0.0", ls, [], NOW)
    assert "traffic.bytes_out" not in g.proposal.yaml
    assert any("traffic.bytes_out dropped" in w for w in g.warnings)


def test_deterministic(palo, fortinet):
    ls, g = palo
    assert propose_csv("palo_alto", ls, list(range(1, len(ls) + 1)), NOW).proposal.yaml == g.proposal.yaml
    base, fls, fg = fortinet
    assert propose_kv_patch("fortinet", base, "1.0.0", fls, list(range(1, len(fls) + 1)), NOW).proposal.yaml == fg.proposal.yaml


def test_re2_check_catches_what_python_accepts():
    doc = "id: x\nversion: 1.0.0\nmatch: {signature: '(?<=a)b'}\nextractors:\n- {id: e, kind: regex, pattern: '(a)\\1'}\n"
    v = re2_violations(doc)
    assert any("lookaround" in x for x in v) and any("backreference" in x for x in v)


def test_acceptance_flags_a_bad_proposal_without_dropping_it(palo):
    ls, g = palo
    dry = local_dry_run(g.proposal.yaml, list(enumerate(["garbage"] * 10 + ls[:10], 1)))
    assert dry.failed == 10 and any("match_rate" in w for w in acceptance(dry))
    assert dry.failures[0].error == "no extractor matched"
