"""Parser proposals from typed columns (PRD_CONTRACTS 5.6). Deterministic: same input, same YAML.

Only generation lives here. Validation is `validate.py`, posting is `client.py`.
"""
from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from datetime import datetime

import yaml

from . import dsl_eval
from .fingerprint import fingerprint
from .models import Proposal, TypedField
from .typer import Column, Typed, type_columns

N_VECTORS = 5


@dataclass
class Generated:
    """A proposal plus the reviewer-facing notes that have no field on the contract type."""
    proposal: Proposal
    warnings: list[str] = field(default_factory=list)


def sanitize(s: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", s.lower()).strip("_") or "source"


def _dump(doc: dict) -> str:
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=None, width=100000, allow_unicode=True)


def _map_entry(t: Typed, source_field: str) -> list[dict]:
    """The DSL map entries for one typed column."""
    p = t.ocsf_path
    if t.type == "timestamp":
        return [{"from": source_field, "to": p, "type": "time", "layout": t.layout}]
    if t.type in ("ipv4", "ipv6"):
        return [{"from": source_field, "to": p, "type": "ip"}]
    if t.type == "port":
        return [{"from": source_field, "to": p, "type": "port"}]
    if t.type == "protocol":
        if p.endswith("protocol_num"):
            return [{"from": source_field, "to": p, "type": "int"}]
        return [{"from": source_field, "to": p, "type": "string", "lower": True},
                {"from": source_field, "to": "connection_info.protocol_num", "type": "enum",
                 "enum": dict(sorted(t.enum.items())), "default": 0}]   # keyed by the values as observed: enum match is exact
    if t.type == "action":
        return [{"from": source_field, "to": p, "type": "enum", "enum": dict(sorted(t.enum.items())), "default": 99}]
    if t.type == "mac":
        return [{"from": source_field, "to": p, "type": "mac"}]
    if t.type == "severity":
        return [{"from": source_field, "to": p, "type": "int"}]
    if t.type == "username":
        return [{"from": source_field, "to": p, "type": "string"}]
    return [{"from": source_field, "to": p, "type": "string"}]


def _vectors(doc: dict, raws: list[str]) -> list[dict]:
    """Test vectors from real samples: expected values are what the generated parser itself yields,
    limited to the mapped scalar paths, so a later edit that changes behaviour fails the vector."""
    out = []
    for raw in raws:
        r = dsl_eval.extract(doc, raw)
        if r is None:
            continue
        exp = {k: v for k, v in sorted(dsl_eval.flat(r.ocsf).items()) if k not in ("class_uid", "category_uid")}
        out.append({"raw": raw, "expect": exp})
        if len(out) == N_VECTORS:
            break
    return out


def _signature_csv(rows: list[list[str]]) -> str:
    """A cheap detector: the field count is not checkable in RE2, so anchor on the first constant word column."""
    for i in range(len(rows[0])):
        vals = {r[i] for r in rows if i < len(r)}
        if len(vals) == 1 and re.fullmatch(r"[A-Za-z][\w-]{2,}", next(iter(vals))):
            return f"^(?:[^,]*,){{{i}}}{re.escape(next(iter(vals)))},"
    return "^(?:[^,]*,)+"


def propose_csv(source_id: str, lines: list[str], record_ids: list[int], now: datetime,
                drift_alert_id: str = "", timezone: str = "+05:30") -> Generated:
    """A new parser for a headerless CSV source."""
    lines = [l for l in lines if l.strip()]
    rows = [next(csv.reader(io.StringIO(l))) for l in lines]
    width = min(len(r) for r in rows)
    cols = [Column(f"col_{i}", [r[i] for r in rows], named=False, position=i) for i in range(width)]
    typed = type_columns(cols)
    mapped = {t.field: t for t in typed if t.ocsf_path}

    last = max((int(f.split("_")[1]) for f in mapped), default=0)
    names = [f"col_{i}" if f"col_{i}" in mapped else "_" for i in range(last + 1)]
    maps: list[dict] = []
    for f in sorted(mapped, key=lambda f: int(f.split("_")[1])):
        maps += _map_entry(mapped[f], f"col_{int(f.split('_')[1])}")
    maps.append({"const": 6, "to": "activity_id"})
    const_sev = {"const": 1, "to": "severity_id"}
    if "severity_id" not in {m["to"] for m in maps}:
        maps.append(const_sev)

    pid = sanitize(source_id) + "_auto"
    marker = next((i for i in range(width) if len({r[i] for r in rows}) == 1 and re.fullmatch(r"[A-Za-z][\w-]{2,}", rows[0][i])), None)
    ext = {"id": "csv_rows", "kind": "csv", "sep": ",", "quote": '"', "min_columns": width}
    if marker is not None:
        ext["when"] = {"column": marker, "equals": rows[0][marker]}
    ext["columns"] = names
    ext["map"] = maps
    doc = {"id": pid, "version": "1.0.0", "vendor": sanitize(source_id), "product": "auto", "timezone": timezone,
           "match": {"signature": _signature_csv(rows)}, "ocsf_defaults": {"class_uid": 4001, "category_uid": 4},
           "extractors": [ext]}
    doc["extractors"][0]["tests"] = _vectors(doc, lines)

    tpl = sorted(fingerprint(lines).templates)
    warnings = [f"{t.field} left unmapped: {t.evidence}" for t in typed if t.type in ("ipv4", "ipv6", "port", "timestamp") and not t.ocsf_path]
    return Generated(Proposal(id="", kind="new", parser_id=pid, base_version="", source_id=source_id, yaml=_dump(doc),
                              cluster_size=len(lines), templates=tpl, sample_record_ids=record_ids[:20],
                              typed_fields=[t.model() for t in typed if t.ocsf_path or t.type in ("ipv4", "ipv6", "port", "timestamp")],
                              dry_run=None, status="pending", created_at=now, drift_alert_id=drift_alert_id), warnings)


def propose_kv_patch(source_id: str, baseline_yaml: str, base_version: str, lines: list[str], record_ids: list[int],
                     now: datetime, drift_alert_id: str = "") -> Generated:
    """A patch (same parser id, full replacement document) for a kv source whose keys drifted.

    Every mapping whose keys still exist is kept byte for byte. A mapping whose key vanished is re-pointed at
    the new key the typer assigns to the same OCSF path (srcip -> src), and its type follows the new values
    (a text date+time becomes an epoch). A mapping with no successor is dropped and reported, never invented.
    """
    from .fingerprint import fields, line_kind

    doc = dsl_eval.load(baseline_yaml)
    ext = next(e for e in doc["extractors"] if e["kind"] == "kv")
    lines = [l for l in lines if l.strip()]
    cols: dict[str, list[str]] = {}
    for l in lines:
        for k, (v, _) in fields(l, "kv").items():
            cols.setdefault(k, []).append(v)
    typed = type_columns([Column(k, v, True, i) for i, (k, v) in enumerate(cols.items())])
    by_path = {t.ocsf_path: t for t in typed if t.ocsf_path}

    warnings: list[str] = []
    new_map: list[dict] = []
    covered: set[str] = set()
    for m in ext["map"]:
        srcs = [] if "const" in m else (m["from"] if isinstance(m["from"], list) else [m["from"]])
        if all(s in cols for s in srcs):
            new_map.append(m)
            covered.add(m["to"])
            continue
        t = by_path.get(m["to"])
        if t is None:
            warnings.append(f"mapping to {m['to']} dropped: key {'+'.join(srcs)} disappeared and no new key was typed to that path")
            continue
        repl = _map_entry(t, t.field)[0]
        if m.get("type") == "enum" and t.type != "action":
            repl = dict(m, **{"from": t.field})
        new_map.append(repl)
        covered.add(m["to"])
        warnings.append(f"{'+'.join(srcs)} -> {t.field} (mapped to {m['to']}, confidence {t.confidence:.2f})")
    for t in typed:  # new keys the typer is sure about and the old parser never read
        if t.ocsf_path and t.ocsf_path not in covered and t.confidence >= 0.8 and t.type in ("ipv4", "ipv6", "port", "mac"):
            new_map.append(_map_entry(t, t.field)[0])
            covered.add(t.ocsf_path)
            warnings.append(f"new key {t.field} mapped to {t.ocsf_path} (confidence {t.confidence:.2f})")

    ext = dict(ext, map=new_map)
    ext.pop("tests", None)
    doc = dict(doc, extractors=[ext if e["id"] == ext["id"] else e for e in doc["extractors"]])
    doc["extractors"][0]["tests"] = _vectors(doc, lines)
    tpl = sorted(fingerprint(lines).templates)
    return Generated(Proposal(id="", kind="patch", parser_id=doc["id"], base_version=base_version, source_id=source_id, yaml=_dump(doc),
                              cluster_size=len(lines), templates=tpl, sample_record_ids=record_ids[:20],
                              typed_fields=[t.model() for t in typed if t.ocsf_path],
                              dry_run=None, status="pending", created_at=now, drift_alert_id=drift_alert_id), warnings)


_ROUTE_KEYS = ("event_type", "type", "kind", "category")


def propose_json(source_id: str, lines: list[str], record_ids: list[int], now: datetime,
                 drift_alert_id: str = "", timezone: str = "+00:00", min_group: int = 50) -> Generated:
    """A new parser for a JSON source: one extractor per value of a low-cardinality routing key
    (`event_type`), each mapping the paths that key's records reliably carry."""
    import json as _json
    from collections import Counter

    from .fingerprint import fields

    lines = [l for l in lines if l.strip()]
    docs = [_json.loads(l) for l in lines]
    route = next((k for k in _ROUTE_KEYS if sum(k in d and isinstance(d[k], str) for d in docs) >= 0.95 * len(docs)
                  and len({d.get(k) for d in docs}) <= 10), None)
    groups: dict[str, list[str]] = {}
    for l, d in zip(lines, docs):
        groups.setdefault(str(d.get(route)) if route else "all", []).append(l)

    warnings: list[str] = []
    exts: list[dict] = []
    all_typed: list[Typed] = []
    for value in sorted(groups):
        g = groups[value]
        if len(g) < min_group:
            warnings.append(f"{route}={value}: {len(g)} records, below the {min_group} needed for an extractor; they will quarantine")
            continue
        cols: dict[str, list[str]] = {}
        for l in g:
            for k, (v, _) in fields(l, "json").items():
                cols.setdefault(k, []).append(v)
        cols = {k: v for k, v in cols.items() if len(v) >= 0.99 * len(g)}      # only paths the group reliably carries
        typed = type_columns([Column(k, v, True, i) for i, (k, v) in enumerate(cols.items())])
        maps: list[dict] = []
        for t in typed:
            if t.ocsf_path:
                maps += _map_entry(t, t.field)
            if t.ocsf_path == "severity_id":
                warnings.append(f"{value}: {t.field} mapped straight to severity_id; its scale may run the other way "
                                "(Suricata 1 is HIGH, OCSF 1 is Informational): confirm before approving")
        maps.append({"const": 6, "to": "activity_id"})
        if "severity_id" not in {m["to"] for m in maps}:
            maps.append({"const": 1, "to": "severity_id"})
        ext: dict = {"id": sanitize(value), "kind": "json"}
        if route:
            ext["when"] = {"path": route, "equals": value}
        ext["map"] = maps
        exts.append(ext)
        all_typed += typed
    if not exts:
        raise ValueError("no group large enough to propose an extractor")

    first = next(iter(_json.loads(lines[0])))
    sig = f'^\\{{"{re.escape(first)}":'
    if not all(re.search(sig, l) for l in lines):
        sig = r"^\{"
    pid = sanitize(source_id) + "_auto"
    doc = {"id": pid, "version": "1.0.0", "vendor": sanitize(source_id), "product": "auto", "timezone": timezone,
           "match": {"signature": sig}, "ocsf_defaults": {"class_uid": 4001, "category_uid": 4}, "extractors": exts}
    for e in exts:
        member = groups[e["when"]["equals"]] if route else lines
        e["tests"] = _vectors({**doc, "extractors": [e]}, member)
    tpl = sorted(fingerprint(lines).templates)
    return Generated(Proposal(id="", kind="new", parser_id=pid, base_version="", source_id=source_id, yaml=_dump(doc),
                              cluster_size=len(lines), templates=tpl, sample_record_ids=record_ids[:20],
                              typed_fields=[t.model() for t in all_typed if t.ocsf_path],
                              dry_run=None, status="pending", created_at=now, drift_alert_id=drift_alert_id), warnings)
