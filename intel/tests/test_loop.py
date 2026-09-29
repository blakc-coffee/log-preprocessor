"""The sidecar loop against a fake admin API: alerts once, proposes once, proposes only, and stays offline."""
import socket
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from fake_admin import FakeAdmin
from ulpf_intel import egress
from ulpf_intel.__main__ import main
from ulpf_intel.client import AdminClient, AdminError
from ulpf_intel.loop import Config, Sidecar
from ulpf_intel.state import State
from ulpf_intel.validate import Thresholds

ROOT = Path(__file__).resolve().parents[2]
TESTDATA = ROOT / "testdata"
NOW = datetime(2026, 9, 28, 4, 0, tzinfo=timezone.utc)
FORTINET = (ROOT / "contracts/dsl/examples/fortinet.yaml").read_text()


def lines(name):
    return (TESTDATA / name).read_text().splitlines()


def make(tmp_path, **cfg):
    admin = FakeAdmin()
    client = AdminClient("http://127.0.0.1:9000", transport=admin.transport, sleep=lambda s: None)
    return admin, Sidecar(client, State(tmp_path), Config(timezone="+05:30", **cfg), now=lambda: NOW)


def fortinet_world(tmp_path):
    admin, sc = make(tmp_path)
    admin.parsers["fortinet"] = {"active_version": "1.0.0", "yaml": FORTINET}
    admin.set("fortinet", lines("fortinet.log")[:300], "parsed", "fortinet")
    return admin, sc


def test_healthy_source_only_refreshes_its_baseline(tmp_path):
    admin, sc = fortinet_world(tmp_path)
    (o,) = sc.run_once()
    assert (o.action, o.score < 0.1) == ("baseline", True)
    admin.set("fortinet", lines("fortinet.log")[300:600], "parsed", "fortinet")
    (o,) = sc.run_once()
    assert o.action == "baseline" and admin.alerts == [] and admin.proposals == []


def test_drift_raises_one_alert_and_one_validated_patch_proposal(tmp_path):
    admin, sc = fortinet_world(tmp_path)
    sc.run_once()                                                       # learn the baseline
    admin.clear("fortinet")
    admin.set("fortinet", lines("fortinet.log")[:20], "parsed", "fortinet")
    admin.set("fortinet", lines("fortinet_drift.log")[:300], "quarantined")
    (o,) = sc.run_once()
    assert o.action == "proposal" and len(admin.alerts) == 1 and len(admin.proposals) == 1
    a, p = admin.alerts[0], admin.proposals[0]
    assert a["score"] >= 0.35 and any("srcip->src" in s for s in a["signals"]) and a["quarantine_rate"] > 0.9
    assert (p["kind"], p["parser_id"], p["base_version"], p["drift_alert_id"]) == ("patch", "fortinet", "1.0.0", a["id"])
    assert p["dry_run"]["match_rate"] == 1.0 and p["status"] == "pending"
    assert any("srcip -> src" in w for w in p["dry_run"]["warnings"])           # the reviewer sees what was re-pointed
    assert yaml.safe_load(p["yaml"])["extractors"][0]["map"]


def test_second_pass_creates_no_duplicates(tmp_path):
    admin, sc = fortinet_world(tmp_path)
    sc.run_once()
    admin.clear("fortinet")
    admin.set("fortinet", lines("fortinet.log")[:20], "parsed", "fortinet")
    admin.set("fortinet", lines("fortinet_drift.log")[:300], "quarantined")
    sc.run_once()
    for _ in range(3):
        (o,) = sc.run_once()
    assert len(admin.alerts) == 1 and len(admin.proposals) == 1 and o.action == "alert" and "already exists" in o.reason
    # the server would absorb a repeat, so also check the sidecar never SENT one
    sent = [p for m, _, p in admin.requests if m == "POST"]
    assert sent.count("/admin/drift") == 1 and sent.count("/admin/proposals") == 1 and sent.count("/admin/parsers/dryrun") == 1


def test_state_survives_a_restart(tmp_path):
    admin, sc = fortinet_world(tmp_path)
    sc.run_once()
    admin.clear("fortinet")
    admin.set("fortinet", lines("fortinet.log")[:20], "parsed", "fortinet")
    admin.set("fortinet", lines("fortinet_drift.log")[:300], "quarantined")
    client = AdminClient("http://127.0.0.1:9000", transport=admin.transport, sleep=lambda s: None)
    fresh = Sidecar(client, State(tmp_path), Config(timezone="+05:30"), now=lambda: NOW)   # a new process, the same state dir
    (o,) = fresh.run_once()
    assert o.action == "proposal" and o.score >= 0.35


def test_corrupt_state_is_treated_as_empty_not_a_crash(tmp_path):
    admin, sc = fortinet_world(tmp_path)
    (tmp_path / "fortinet.json").write_text("{not json")
    (o,) = sc.run_once()
    assert o.action == "baseline"


def test_brand_new_headerless_csv_source_gets_an_alert_and_a_new_parser_proposal(tmp_path):
    admin, sc = make(tmp_path)
    admin.set("palo_alto", lines("palo_alto_unknown.log")[:300], "quarantined")
    (o,) = sc.run_once()
    a, p = admin.alerts[0], admin.proposals[0]
    assert o.action == "proposal" and any("no baseline" in s for s in a["signals"]) and a["parser_id"] == ""
    assert (p["kind"], p["base_version"]) == ("new", "") and p["dry_run"]["match_rate"] == 1.0
    assert any("assumed +05:30" in w for w in p["dry_run"]["warnings"])           # no zone in the data: said out loud


def test_proposal_that_misses_acceptance_is_still_posted_and_flagged(tmp_path):
    admin, sc = make(tmp_path, thresholds=Thresholds(match_rate=1.01))             # nothing can pass
    admin.set("palo_alto", lines("palo_alto_unknown.log")[:300], "quarantined")
    sc.run_once()
    (p,) = admin.proposals
    assert any(w.startswith("acceptance: match_rate") for w in p["dry_run"]["warnings"])


def test_too_few_samples_or_records_do_nothing_harmful(tmp_path):
    admin, sc = make(tmp_path)
    admin.set("palo_alto", lines("palo_alto_unknown.log")[:10], "quarantined")
    (o,) = sc.run_once()
    assert o.action == "none" and admin.alerts == []
    admin.set("palo_alto", lines("palo_alto_unknown.log")[10:70], "quarantined")   # 70 samples: alert, but < 50 not needed... 
    admin.samples["palo_alto"] = admin.samples["palo_alto"][:49] + [dict(admin.samples["palo_alto"][50], status="parsed", parser_id="x") for _ in range(20)]
    (o,) = sc.run_once()
    assert len(admin.proposals) == 0 and o.action in ("alert", "baseline", "none")


def test_the_sidecar_only_ever_proposes(tmp_path):
    admin, sc = fortinet_world(tmp_path)
    sc.run_once()
    admin.clear("fortinet")
    admin.set("fortinet", lines("fortinet.log")[:20], "parsed", "fortinet")
    admin.set("fortinet", lines("fortinet_drift.log")[:300], "quarantined")
    admin.set("palo_alto", lines("palo_alto_unknown.log")[:300], "quarantined")
    sc.run_once()
    posts = {p for m, _, p in admin.requests if m == "POST"}
    assert posts <= {"/admin/drift", "/admin/proposals", "/admin/parsers/dryrun"}, posts
    assert not any("approve" in p or "reject" in p or "replay" in p or "rollback" in p for _, _, p in admin.requests)


def test_offline_no_socket_and_no_host_other_than_the_admin_url(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("the sidecar opened a real socket")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    admin, sc = fortinet_world(tmp_path)
    sc.run_once()
    admin.set("palo_alto", lines("palo_alto_unknown.log")[:300], "quarantined")
    sc.run_once()
    assert {host for _, host, _ in admin.requests} == {"127.0.0.1:9000"}


# -- client ---------------------------------------------------------------------------------------------
def test_client_retries_transient_failures_with_backoff_then_succeeds():
    admin = FakeAdmin()
    admin.fail_next = [503, 502]
    slept = []
    c = AdminClient(transport=admin.transport, sleep=slept.append, backoff=0.5)
    assert c.healthy() is True and slept == [0.5, 1.0]


def test_client_does_not_retry_a_client_error():
    admin = FakeAdmin()
    c = AdminClient(transport=admin.transport, sleep=lambda s: pytest.fail("retried a 4xx"))
    with pytest.raises(AdminError) as e:
        c.parser_yaml("nope", "1.0.0") if False else c._json("GET", "/admin/nothing")
    assert e.value.status == 404 and e.value.code == "not_found"


def test_client_gives_up_when_the_data_plane_is_unreachable():
    def refuse(req):
        raise httpx.ConnectError("refused")
    slept = []
    c = AdminClient(transport=httpx.MockTransport(refuse), retries=2, sleep=slept.append)
    with pytest.raises(AdminError) as e:
        c.telemetry()
    assert e.value.code == "unreachable" and len(slept) == 2
    assert c.healthy() is False


# -- the flags Packaging depends on -------------------------------------------------------------------
def test_egress_check_passes_only_when_every_attempt_is_blocked():
    def blocked(*a, **k):
        raise OSError("network is unreachable")
    assert egress.run(resolve=blocked, connect=blocked) == 0


def test_egress_check_fails_if_any_attempt_gets_out():
    class Sock:
        def close(self): pass
    def blocked(*a, **k):
        raise OSError("blocked")
    assert egress.run(resolve=blocked, connect=lambda addr, timeout: Sock()) == 1
    assert egress.run(resolve=lambda *a: [("ok",)], connect=blocked) == 1


def test_healthcheck_exit_codes(monkeypatch):
    monkeypatch.setattr(AdminClient, "healthy", lambda self: True)
    assert main(["--healthcheck"]) == 0
    monkeypatch.setattr(AdminClient, "healthy", lambda self: False)
    assert main(["--healthcheck"]) == 1


def test_baseline_is_not_poisoned_while_a_source_is_drifting(tmp_path):
    admin, sc = fortinet_world(tmp_path)
    sc.run_once()
    before = State(tmp_path).load("fortinet").baseline
    admin.clear("fortinet")
    admin.set("fortinet", lines("fortinet.log")[:20], "parsed", "fortinet")
    admin.set("fortinet", lines("fortinet_drift.log")[:300], "quarantined")
    sc.run_once()
    assert State(tmp_path).load("fortinet").baseline == before          # still what healthy looked like
