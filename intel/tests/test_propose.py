"""Proposal generation: PRD_CONTRACTS 5.7. Every value the generated parser yields is checked against the
manifest's ground truth, for every record of the source, not a sample."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from ulpf_intel import dsl_eval
from ulpf_intel.propose import propose_csv, propose_json, propose_kv_patch, propose_text
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
            if expected is None:
                continue  # null = the manifest does not know (ICMP has no ports)
            got = o[path] // 1000 * 1000 if path == "time" else o[path]  # the manifest keeps whole seconds; Suricata logs milliseconds
            assert got == expected, f"{path}: {o.get(path)} != {expected} in {raw}"


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


@pytest.fixture(scope="module")
def suricata():
    ls = lines("suricata.json")
    return ls, propose_json("suricata", ls, list(range(1, len(ls) + 1)), NOW)


def test_json_proposal_routes_on_event_type_and_matches_every_record(suricata):
    ls, g = suricata
    doc = yaml.safe_load(g.proposal.yaml)
    assert {e["when"]["path"] for e in doc["extractors"]} == {"event_type"}
    assert {e["when"]["equals"] for e in doc["extractors"]} >= {"alert", "flow", "http", "dns"}
    d = doc
    parsed = dsl_eval.load(g.proposal.yaml)
    assert all(dsl_eval.extract(parsed, l) is not None for l in ls)
    check_against_manifest(parsed, ls, "suricata.json")


def test_json_proposal_acceptance_re2_and_layout(suricata):
    ls, g = suricata
    assert acceptance(local_dry_run(g.proposal.yaml, list(enumerate(ls, 1)))) == [] and re2_violations(g.proposal.yaml) == []
    assert "2006-01-02T15:04:05.999999-0700" in g.proposal.yaml   # Go's rfc3339 would refuse a +0530 offset


def test_enum_keys_are_the_observed_values_because_matching_is_exact(suricata):
    _, g = suricata
    doc = yaml.safe_load(g.proposal.yaml)
    proto = next(m for m in doc["extractors"][0]["map"] if m["to"] == "connection_info.protocol_num")
    assert "TCP" in proto["enum"] and "tcp" not in proto["enum"]        # suricata writes TCP


def test_reviewer_is_warned_when_a_severity_scale_is_unverified(suricata):
    _, g = suricata
    assert any("severity_id" in w and "other way" in w for w in g.warnings)


def test_group_too_small_to_propose_is_reported_not_silently_dropped():
    ls = lines("suricata.json")[:200] + ['{"timestamp":"2026-09-28T09:00:00.693000+0530","event_type":"rare","src_ip":"10.0.0.1"}'] * 3
    g = propose_json("suricata", ls, [], NOW)
    assert any("event_type=rare" in w and "quarantine" in w for w in g.warnings)


def test_reference_evaluator_matches_enums_exactly_like_the_spec():
    doc = "id: x\nversion: 1.0.0\nextractors:\n- {id: e, kind: kv, map: [{from: p, to: n, type: enum, enum: {tcp: 6}, default: 0}]}\n"
    d = dsl_eval.load(doc)
    assert dsl_eval.extract(d, "p=tcp a=1 b=2 c=3").ocsf["n"] == 6
    assert dsl_eval.extract(d, "p=TCP a=1 b=2 c=3").ocsf["n"] == 0      # exact, not case-insensitive


@pytest.fixture(scope="module")
def asa():
    ls = lines("cisco_asa.log")
    return ls, propose_text("cisco_asa", ls, list(range(1, len(ls) + 1)), NOW)


def test_text_proposal_matches_every_line_and_gets_time_protocol_and_addresses_right(asa):
    ls, g = asa
    doc = dsl_eval.load(g.proposal.yaml)
    for raw, t in zip(ls, truth("cisco_asa.log")):
        r = dsl_eval.extract(doc, raw)
        assert r is not None, raw
        o = dsl_eval.flat(r.ocsf)
        assert o["time"] == ms(t["expected_time"]) and o["connection_info.protocol_name"] == t["expected_proto"] if t["expected_proto"] else True
        # no address is lost or invented, whichever way round they were assigned
        assert {o["src_endpoint.ip"], o["dst_endpoint.ip"]} == {t["expected_src_ip"], t["expected_dst_ip"]}, raw


# Which address is the source is NOT derivable for every message, and this test says exactly where. The fixture
# manifest orients 302013/302014 with the well-known port on the SOURCE (the real ASA puts it on the destination),
# and 302015/302016 the other way round, so no rule agrees with all of it. The proposal follows the evidence
# (cue words, arrow, port behaviour), flags weak decisions for the reviewer, and agrees with the manifest on every
# other family. A regression in any family fails here; so does silently "fixing" the quirk.
def test_text_direction_agrees_with_the_manifest_except_the_documented_fixture_quirk(asa):
    import re
    from collections import Counter
    ls, g = asa
    doc = dsl_eval.load(g.proposal.yaml)
    agree = Counter()
    for raw, t in zip(ls, truth("cisco_asa.log")):
        o = dsl_eval.flat(dsl_eval.extract(doc, raw).ocsf)
        mid = re.search(r"%ASA-\d-(\d+)", raw)[1]
        same = o["src_endpoint.ip"] == t["expected_src_ip"]
        agree[(mid, same)] += 1
        # ports travel with their address, reversed or not; a null in the manifest means it does not know
        want = {"src_endpoint.port": t["expected_src_port"], "dst_endpoint.port": t["expected_dst_port"]}
        if not same:
            want = {"src_endpoint.port": t["expected_dst_port"], "dst_endpoint.port": t["expected_src_port"]}
        for path, expected in want.items():
            if expected is not None:
                assert o.get(path) == expected, f"{path} in {raw}"
    families = {mid for mid, _ in agree}
    assert families == {"106023", "106100", "302013", "302014", "302015", "302016", "305011"}
    for mid in ("106023", "106100", "302015", "302016", "305011"):
        assert agree[(mid, False)] == 0, f"{mid} disagrees with the manifest"
    for mid in ("302013", "302014"):
        assert agree[(mid, True)] == 0, f"{mid} was the documented quirk; if it now agrees, update this test and DECISIONS.log"


def test_weak_direction_decisions_are_flagged_for_the_reviewer(asa):
    _, g = asa
    assert any("port behaviour" in w and "confirm the direction" in w for w in g.warnings)
    weak = [t for t in g.proposal.typed_fields if t.ocsf_path.endswith("_endpoint.ip") and t.confidence < 0.85]
    assert weak and all(t.alternatives for t in weak)


def test_text_proposal_is_anchored_re2_safe_and_passes_acceptance(asa):
    ls, g = asa
    assert re2_violations(g.proposal.yaml) == []
    dry = local_dry_run(g.proposal.yaml, list(enumerate(ls, 1)))
    assert acceptance(dry) == [] and dry.match_rate == 1.0
    for e in yaml.safe_load(g.proposal.yaml)["extractors"]:
        assert e["pattern"].startswith("^") and e["pattern"].endswith("$")


def test_text_proposal_never_maps_two_slots_to_one_path_and_drops_nat_copies(asa):
    _, g = asa
    for e in yaml.safe_load(g.proposal.yaml)["extractors"]:
        targets = [m["to"] for m in e["map"]]
        assert len(targets) == len(set(targets)), f"{e['id']} sets a path twice: {targets}"
    nat = [t for t in g.proposal.typed_fields if "NAT copy" in t.evidence]
    assert nat == []   # copies are kept unmapped, so they are not in typed_fields with a path


def test_text_proposal_connection_id_is_not_a_port(asa):
    _, g = asa
    doc = yaml.safe_load(g.proposal.yaml)
    for e in doc["extractors"]:
        assert not any("connection" in e["pattern"].split("(?P<v25>")[0][-12:] and m.get("from") == "v25" for m in e["map"])
    built = doc["extractors"][0]
    ports = {m["to"] for m in built["map"] if m["to"].endswith("port")}
    assert ports == {"src_endpoint.port", "dst_endpoint.port"}


def test_text_render_template_reproduces_the_raw_line(asa):
    ls, g = asa
    doc = yaml.safe_load(g.proposal.yaml)
    import re
    e = next(x for x in doc["extractors"] if "render" in x)
    raw = next(l for l in ls if re.match(e["pattern"], l))
    m = re.match(e["pattern"], raw)
    out = re.sub(r"\{(\w+)\}", lambda k: m.group(k.group(1)), e["render"].replace("{{", "\x00").replace("}}", "\x01")).replace("\x00", "{").replace("\x01", "}")
    assert out == raw


def test_text_signature_is_a_real_literal_seen_in_almost_every_line(asa):
    ls, g = asa
    sig = yaml.safe_load(g.proposal.yaml)["match"]["signature"]
    assert len(sig) >= 5 and sum(sig in l for l in ls) >= 0.95 * len(ls)


def test_text_small_templates_are_reported_not_dropped_silently():
    ls = lines("cisco_asa.log")[:300] + ["<166>Sep 28 2026 09:59:59 asa01 : %ASA-6-999999: something else entirely 1 2 3"] * 3
    g = propose_text("cisco_asa", ls, [], NOW)
    assert any("below the 50" in w for w in g.warnings)


def test_text_deterministic(asa):
    ls, g = asa
    assert propose_text("cisco_asa", ls, list(range(1, len(ls) + 1)), NOW).proposal.yaml == g.proposal.yaml


def test_message_codes_that_disagree_on_direction_become_separate_extractors():
    # code 111111: the server (well-known port) is written first; code 222222: last. One template, two meanings.
    import random
    rng = random.Random(7)
    ls = []
    for i in range(120):
        c, s = f"10.1.{i % 200}.{i % 250 + 1}", f"203.0.113.{i % 250 + 1}"
        ls.append(f"Sep 28 2026 09:00:{i % 60:02d} gw : %FW-6-111111: flow for outside:{s}/443 to inside:{c}/{rng.randrange(30000, 60000)}")
        ls.append(f"Sep 28 2026 09:01:{i % 60:02d} gw : %FW-6-222222: flow for inside:{c}/{rng.randrange(30000, 60000)} to outside:{s}/443")
    g = propose_text("gw", ls, [], NOW)
    doc = dsl_eval.load(g.proposal.yaml)
    assert len(doc["extractors"]) == 2
    a = dsl_eval.flat(dsl_eval.extract(doc, ls[0]).ocsf)
    b = dsl_eval.flat(dsl_eval.extract(doc, ls[1]).ocsf)
    assert a["dst_endpoint.port"] == 443 and a["src_endpoint.ip"].startswith("10.1.")      # server first: the client is the source
    assert b["dst_endpoint.port"] == 443 and b["dst_endpoint.ip"].startswith("203.")       # server last: the server is the destination
