"""CEF and LEEF proposals. There are no CEF/LEEF files in the fixture corpus, so these tests use SYNTHETIC samples,
generated deterministically here with their ground truth alongside. Everything below is labelled synthetic."""
import random
from datetime import datetime, timezone

import pytest
import yaml

from ulpf_intel import dsl_eval
from ulpf_intel.loop import Config, Sidecar
from ulpf_intel.propose import propose_cef
from ulpf_intel.validate import acceptance, local_dry_run, re2_violations

NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
ACTS = ["blocked", "allowed", "denied"]


def synthetic(kind: str, n: int = 200, seed: int = 11):
    """(lines, truth) of a made-up 'Acme Perimeter' device. Not a capture of anything."""
    rng = random.Random(seed)
    lines, truth = [], []
    for i in range(n):
        src, dst = f"10.1.{rng.randrange(1, 200)}.{rng.randrange(1, 250)}", f"203.0.113.{rng.randrange(1, 250)}"
        spt, dpt = rng.randrange(30000, 60000), rng.choice([22, 53, 80, 443, 3306])
        act, proto, sev, rt = rng.choice(ACTS), rng.choice(["TCP", "UDP"]), rng.randrange(0, 11), 1790566200000 + i * 1000
        msg = f"policy {rng.randrange(1, 40)} hit by {src}"
        if kind == "cef":
            lines.append(f"<134>Sep 28 09:00:{i % 60:02d} fw01 CEF:0|Acme|Perimeter|2.1|{100 + i % 5}|Traffic event|{sev}|"
                         f"rt={rt} src={src} spt={spt} dst={dst} dpt={dpt} proto={proto} act={act} msg={msg} cs1=corp\\=eu")
        else:
            lines.append(f"LEEF:1.0|Acme|Perimeter|2.1|Traffic|devTime={rt}\tsrc={src}\tsrcPort={spt}\tdst={dst}\tdstPort={dpt}\tproto={proto}\taction={act}\tmsg={msg}")
        truth.append({"src": src, "dst": dst, "spt": spt, "dpt": dpt, "proto": proto.lower(), "time": rt, "act": act, "sev": sev})
    return lines, truth


@pytest.mark.parametrize("kind", ["cef", "leef"])
def test_every_synthetic_record_parses_and_every_value_is_right(kind):
    lines, truth = synthetic(kind)
    g = propose_cef("acme", lines, list(range(1, len(lines) + 1)), NOW)
    doc = dsl_eval.load(g.proposal.yaml)
    assert doc["extractors"][0]["kind"] == kind
    for raw, t in zip(lines, truth):
        r = dsl_eval.extract(doc, raw)
        assert r is not None, raw
        o = dsl_eval.flat(r.ocsf)
        assert (o["src_endpoint.ip"], o["dst_endpoint.ip"], o["src_endpoint.port"], o["dst_endpoint.port"]) == (t["src"], t["dst"], t["spt"], t["dpt"])
        assert o["connection_info.protocol_name"] == t["proto"] and o["time"] == t["time"]
        assert o["action_id"] == (1 if t["act"] == "allowed" else 2)
        if kind == "cef":
            assert o["severity_id"] == {0: 2, 1: 2, 2: 2, 3: 2, 4: 3, 5: 3, 6: 3, 7: 4, 8: 4, 9: 5, 10: 5}[t["sev"]]


@pytest.mark.parametrize("kind", ["cef", "leef"])
def test_cef_proposals_pass_acceptance_are_re2_safe_and_deterministic(kind):
    lines, _ = synthetic(kind)
    g = propose_cef("acme", lines, [], NOW)
    assert acceptance(local_dry_run(g.proposal.yaml, list(enumerate(lines, 1)))) == [] and re2_violations(g.proposal.yaml) == []
    assert propose_cef("acme", lines, [], NOW).proposal.yaml == g.proposal.yaml


def test_detector_is_the_vendor_and_product_from_the_header_not_a_syslog_prefix():
    lines, _ = synthetic("cef")
    sig = yaml.safe_load(propose_cef("acme", lines, [], NOW).proposal.yaml)["match"]["signature"]
    assert sig == r"CEF:\d+\|Acme\|Perimeter\|"
    other_vendor = lines[0].replace("Acme|Perimeter", "Other|Thing")
    assert dsl_eval.extract(dsl_eval.load(propose_cef("acme", lines, [], NOW).proposal.yaml), other_vendor) is None


def test_unmapped_extension_keys_are_kept_including_escaped_values():
    lines, _ = synthetic("cef")
    doc = dsl_eval.load(propose_cef("acme", lines, [], NOW).proposal.yaml)
    r = dsl_eval.extract(doc, lines[0])
    assert r.unmapped["cs1"] == "corp=eu" and r.unmapped["msg"].startswith("policy ")     # a space inside a value, and \= unescaped
    assert r.unmapped["cef.signature_id"] == "100"


def test_a_standard_key_with_the_wrong_kind_of_values_is_left_unmapped_and_reported():
    lines, _ = synthetic("cef")
    bad = [l.replace("src=", "src=host-").replace("host-10.", "host-a.") for l in lines]      # src is now a hostname
    g = propose_cef("acme", bad, [], NOW)
    assert "src_endpoint.ip" not in g.proposal.yaml
    assert any(w.startswith("src is a standard key") for w in g.warnings)


def test_severity_banding_is_stated_to_the_reviewer():
    lines, _ = synthetic("cef")
    assert any("0-3 Low" in w for w in propose_cef("acme", lines, [], NOW).warnings)


def test_non_cef_input_is_refused():
    with pytest.raises(ValueError):
        propose_cef("x", ["a=1 b=2 c=3 d=4"] * 60, [], NOW)


def test_the_loop_routes_cef_and_leef_sources_to_this_generator(tmp_path):
    from fake_admin import FakeAdmin
    from ulpf_intel.client import AdminClient
    from ulpf_intel.state import State
    for kind in ("cef", "leef"):
        admin = FakeAdmin()
        lines, _ = synthetic(kind, 120)
        admin.set("acme", lines, "quarantined")
        sc = Sidecar(AdminClient(transport=admin.transport, sleep=lambda s: None), State(tmp_path / kind), Config(), now=lambda: NOW)
        (o,) = sc.run_once()
        (p,) = admin.proposals
        assert o.action == "proposal" and p["kind"] == "new" and p["dry_run"]["match_rate"] == 1.0
