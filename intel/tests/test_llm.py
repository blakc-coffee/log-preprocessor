"""The optional local-LLM step. Off by default; loopback only; can only name anonymous csv columns; never breaks a proposal."""
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from fake_admin import FakeAdmin
from ulpf_intel import dsl_eval, llm
from ulpf_intel.client import AdminClient
from ulpf_intel.loop import Config, Sidecar
from ulpf_intel.propose import propose_csv
from ulpf_intel.state import State
from ulpf_intel.validate import acceptance, local_dry_run

TESTDATA = Path(__file__).resolve().parents[2] / "testdata"
NOW = datetime(2026, 9, 28, 4, 0, tzinfo=timezone.utc)
LINES = (TESTDATA / "palo_alto_unknown.log").read_text().splitlines()


def fake_llm(answer, calls=None):
    def handler(req: httpx.Request):
        if calls is not None:
            calls.append(json.loads(req.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": answer if isinstance(answer, str) else json.dumps(answer)}}]})
    return httpx.MockTransport(handler)


@pytest.fixture(scope="module")
def base():
    return propose_csv("palo_alto", LINES, list(range(1, len(LINES) + 1)), NOW).proposal.yaml


def refine(base, answer, calls=None):
    cols = llm.anonymous_columns(base, LINES)
    names = llm.suggest_names("http://127.0.0.1:8081", "m", cols, transport=fake_llm(answer, calls))
    return llm.apply_names(base, names)


def test_anonymous_columns_are_the_unmapped_unnamed_ones(base):
    cols = llm.anonymous_columns(base, LINES)
    assert "col_14" in cols and "col_37" in cols                       # app and category: nothing maps them
    assert not {"col_1", "col_7", "col_8", "col_24", "col_25", "col_29", "col_30"} & set(cols)    # mapped: never asked about


def test_names_appear_in_unmapped_and_change_nothing_else(base):
    new, n = refine(base, {"col_14": "application", "col_37": "url_category", "col_11": "rule_name"})
    assert n == 3
    a, b = dsl_eval.load(base), dsl_eval.load(new)
    for raw in LINES[:50]:
        x, y = dsl_eval.extract(a, raw), dsl_eval.extract(b, raw)
        assert x.ocsf == y.ocsf                                        # every mapped value is identical
        assert y.unmapped["application"] == x.unmapped["col_14"] and "col_14" not in y.unmapped
    assert acceptance(local_dry_run(new, list(enumerate(LINES, 1)))) == []
    assert local_dry_run(new, list(enumerate(LINES, 1))).match_rate == 1.0


def test_mapped_columns_cannot_be_renamed_through_this_channel(base):
    new, n = refine(base, {"col_7": "evil", "col_24": "also_evil", "col_14": "application"})
    assert n == 1 and "evil" not in new
    assert yaml.safe_load(new)["extractors"][0]["map"] == yaml.safe_load(base)["extractors"][0]["map"]


@pytest.mark.parametrize("bad", ["Src IP", "col_3", "slot_9", "a: b", "../../etc", "x" * 60, "1abc", "", "drop table", "a\nb: 1", None, 7, ["x"]])
def test_hostile_or_malformed_names_are_dropped(base, bad):
    new, n = refine(base, {"col_14": bad})
    assert n == 0 and new.count("col_14") == base.count("col_14")
    yaml.safe_load(new)                                                # still valid YAML, structure intact


def test_duplicate_suggestions_keep_only_the_first(base):
    new, n = refine(base, {"col_14": "thing", "col_37": "thing"})
    assert n == 1 and yaml.safe_load(new)["extractors"][0]["columns"].count("thing") == 1


def test_a_name_that_collides_with_an_existing_column_is_dropped(base):
    doc = yaml.safe_load(base)
    existing = "col_7"                                                   # a column already named in the extractor
    assert existing in doc["extractors"][0]["columns"]
    new, n = refine(base, {"col_14": existing})                          # also rejected as an anonymous-looking name
    assert (new, n) == (base, 0)
    cols = yaml.safe_load(refine(base, {"col_14": "application", "col_37": "application"})[0])["extractors"][0]["columns"]
    named = [c for c in cols if c != "_"]
    assert len(named) == len(set(named)) and named.count("application") == 1   # no column is ever named twice


def test_prose_around_the_json_is_tolerated_and_garbage_is_not_an_error(base):
    new, n = refine(base, 'Sure! Here you go:\n```json\n{"col_14": "application"}\n```')
    assert n == 1
    _, n = refine(base, "I cannot help with that")
    assert n == 0


def test_a_non_loopback_endpoint_is_refused_before_any_request(base):
    calls = []
    for ep in ("https://api.example.com", "http://10.0.0.5:8080", "http://192.168.1.2", "http://llm.internal:8000"):
        with pytest.raises(ValueError, match="not loopback"):
            llm.suggest_names(ep, "m", {"col_1": ["a"]}, transport=fake_llm({}, calls))
    assert calls == []
    for ok in ("http://127.0.0.1:8080", "http://localhost:11434", "http://[::1]:8080"):
        llm.require_loopback(ok)


def test_the_prompt_carries_a_few_values_per_column_never_a_whole_record(base):
    calls = []
    refine(base, {}, calls)
    prompt = calls[0]["messages"][0]["content"]
    assert all(l not in prompt for l in LINES[:200])
    sent = json.loads(prompt[prompt.index("{"):])
    assert all(len(v) <= llm.SAMPLE for v in sent.values())
    assert calls[0]["temperature"] == 0


def test_deterministic(base):
    assert refine(base, {"col_14": "application"})[0] == refine(base, {"col_14": "application"})[0]


# -- in the loop -------------------------------------------------------------------------------------------
def world(tmp_path, llm_transport=None, endpoint="http://127.0.0.1:8081"):
    admin = FakeAdmin()
    admin.set("palo_alto", LINES[:300], "quarantined")
    cfg = Config(timezone="+05:30", llm_endpoint=endpoint, llm_transport=llm_transport)
    return admin, Sidecar(AdminClient(transport=admin.transport, sleep=lambda s: None), State(tmp_path), cfg, now=lambda: NOW)


def test_the_loop_uses_it_only_when_asked_and_says_so(tmp_path):
    calls = []
    admin, sc = world(tmp_path, fake_llm({"col_14": "application"}, calls))
    sc.run_once()
    (p,) = admin.proposals
    assert "application" in p["yaml"] and p["dry_run"]["match_rate"] == 1.0
    assert any("suggested by a local model" in w and "unverified" in w for w in p["dry_run"]["warnings"])
    assert len(calls) == 1

    calls2 = []
    admin, sc = world(tmp_path / "off", fake_llm({"col_14": "application"}, calls2), endpoint="")
    sc.run_once()
    assert calls2 == [] and "application" not in admin.proposals[0]["yaml"]      # off means no call at all


def test_a_broken_model_never_breaks_the_proposal(tmp_path):
    def down(req):
        raise httpx.ConnectError("refused")
    admin, sc = world(tmp_path, httpx.MockTransport(down))
    (o,) = sc.run_once()
    (p,) = admin.proposals
    assert o.action == "proposal" and p["dry_run"]["match_rate"] == 1.0
    assert any("LLM refinement skipped" in w for w in p["dry_run"]["warnings"])


def test_a_remote_endpoint_configured_by_mistake_is_skipped_not_contacted(tmp_path):
    calls = []
    admin, sc = world(tmp_path, fake_llm({"col_14": "x_y"}, calls), endpoint="https://api.example.com")
    sc.run_once()
    assert calls == [] and any("LLM refinement skipped: ValueError" in w for w in admin.proposals[0]["dry_run"]["warnings"])
