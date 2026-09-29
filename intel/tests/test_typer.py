"""Semantic typing: PRD_CONTRACTS 5.5 acceptance on palo_alto_unknown.log against the manifest's ground truth."""
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ulpf_intel.fingerprint import fields, line_kind
from ulpf_intel.typer import Column, type_columns

TESTDATA = Path(__file__).resolve().parents[2] / "testdata"
IST = timezone(timedelta(hours=5, minutes=30))

# manifest key -> the OCSF path a correct typer assigns
TRUTH = {
    "expected_src_ip": "src_endpoint.ip", "expected_dst_ip": "dst_endpoint.ip",
    "expected_src_port": "src_endpoint.port", "expected_dst_port": "dst_endpoint.port",
    "expected_proto": "connection_info.protocol_name", "expected_action": "action_id", "expected_time": "time",
}


def manifest(file: str) -> list[dict]:
    m = json.loads((TESTDATA / "manifest.json").read_text())
    return [r for r in m["records"] if r["source_file"] == file]


@pytest.fixture(scope="module")
def palo():
    rows = list(csv.reader((TESTDATA / "palo_alto_unknown.log").open()))
    cols = [Column(f"col_{i}", [r[i] for r in rows], named=False, position=i) for i in range(len(rows[0]))]
    return rows, type_columns(cols)


def by_path(typed):
    return {t.ocsf_path: t for t in typed if t.ocsf_path}


def test_every_manifest_field_is_typed_to_the_right_column(palo):
    rows, typed = palo
    truth = manifest("palo_alto_unknown.log")
    got = by_path(typed)
    right = 0
    for key, path in TRUTH.items():
        col = got.get(path)
        assert col, f"{path} was not typed at all"
        i = int(col.field.split("_")[1])
        if key == "expected_time":
            parsed = [datetime.strptime(r[i], "%Y/%m/%d %H:%M:%S").replace(tzinfo=IST).isoformat() for r in rows]
            ok = sum(p == t[key] for p, t in zip(parsed, truth)) / len(rows)
        else:
            ok = sum(str(r[i]).lower() == str(t[key]).lower() for r, t in zip(rows, truth)) / len(rows)
        if ok == 1.0:
            right += 1
        else:
            pytest.fail(f"{path} -> {col.field}: only {ok:.0%} of values match the manifest's {key}")
    assert right / len(TRUTH) >= 0.9


def test_no_wrong_field_has_confidence_above_0_8(palo):
    _, typed = palo
    # every column with an assigned path and confidence > 0.8 must be one the manifest confirms
    confirmed = {"col_1", "col_7", "col_24", "col_29", "col_30"}
    for t in typed:
        if t.ocsf_path and t.confidence > 0.8:
            assert t.field in confirmed, f"{t.field} -> {t.ocsf_path} at {t.confidence}"


def test_ambiguous_columns_are_flagged_not_hidden(palo):
    _, typed = palo
    got = by_path(typed)
    assert "col_9" in got["dst_endpoint.ip"].evidence            # NAT address is also a plausible destination
    assert "col_27" in got["dst_endpoint.port"].evidence         # identical values: NAT copy
    assert got["dst_endpoint.ip"].confidence < got["src_endpoint.ip"].confidence


def test_constants_serials_and_flags_are_not_mistyped(palo):
    _, typed = palo
    t = {x.field: x for x in typed}
    assert t["col_10"].ocsf_path == "" and "constant" in t["col_10"].evidence      # 0.0.0.0 in every row
    assert t["col_2"].type != "timestamp"                                          # serial 001801010001, not an epoch
    assert t["col_23"].type != "protocol"                                          # constant 1 is a flag
    assert t["col_6"].ocsf_path == "" and t["col_35"].ocsf_path == ""              # only the first timestamp is `time`


def test_action_column_beats_the_subtype_column(palo):
    _, typed = palo
    a = by_path(typed)["action_id"]
    assert a.field == "col_30" and a.enum == {"allow": 1, "deny": 2, "drop": 2}    # col_4 has 'end', not in the lexicon


def test_internal_means_rfc1918_not_documentation_ranges(palo):
    _, typed = palo
    assert "external ranges (0% private)" in by_path(typed)["dst_endpoint.ip"].evidence


def test_time_carries_its_go_layout(palo):
    _, typed = palo
    assert by_path(typed)["time"].layout == "2006/01/02 15:04:05"


def test_named_kv_columns_use_name_hints_and_shapes():
    """The drifted Fortinet keys were renamed; the typer must find them again from the values plus the names."""
    lines = (TESTDATA / "fortinet_drift.log").read_text().splitlines()
    cols: dict[str, list[str]] = {}
    for l in lines:
        for k, (v, _) in fields(l, line_kind(l)).items():
            cols.setdefault(k, []).append(v)
    typed = {t.field: t for t in type_columns([Column(k, v, True, i) for i, (k, v) in enumerate(cols.items())])}
    want = {"src": "src_endpoint.ip", "dst": "dst_endpoint.ip", "sport": "src_endpoint.port", "dport": "dst_endpoint.port",
            "proto": "connection_info.protocol_num", "eventtime": "time", "action": "action_id"}
    for key, path in want.items():
        assert typed[key].ocsf_path == path, f"{key}: {typed[key]}"
    assert typed["eventtime"].layout == "epoch_ns"
    assert typed["src"].confidence > 0.8                     # the name agrees with the values


def test_low_confidence_abstains_and_keeps_the_path_as_an_alternative():
    t = type_columns([Column("col_0", ["10.0.0.1", "10.0.0.2"], named=False, position=0)], min_confidence=0.99)[0]
    assert t.ocsf_path == "" and t.alternatives == ["src_endpoint.ip"] and "abstained" in t.evidence


def test_deterministic(palo):
    rows, typed = palo
    cols = [Column(f"col_{i}", [r[i] for r in rows], named=False, position=i) for i in range(len(rows[0]))]
    assert [t.model().model_dump() for t in type_columns(cols)] == [t.model().model_dump() for t in typed]


def test_of_two_action_like_columns_the_one_that_fits_the_lexicon_better_wins():
    weaker = ["allow"] * 23 + ["end"] * 2               # 92% in the lexicon
    stronger = ["deny", "allow", "drop", "allow"] * 6 + ["allow"]
    got = {t.field: t for t in type_columns([Column("col_0", weaker, False, 0), Column("col_1", stronger, False, 1)])}
    assert got["col_1"].ocsf_path == "action_id" and got["col_0"].ocsf_path != "action_id"
