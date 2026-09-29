"""Parser proposals from typed columns (PRD_CONTRACTS 5.6). Deterministic: same input, same YAML.

Only generation lives here. Validation is `validate.py`, posting is `client.py`.
"""
from __future__ import annotations

import csv
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

import yaml

from . import dsl_eval
from .fingerprint import fingerprint
from .models import Proposal, TypedField
from .typer import ACTION_ENUM, PROTO_NUM, WELL_KNOWN, Column, Typed, type_columns

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
        if p.endswith("protocol_num"):     # 6 is tcp: give the reader the name too, as the number alone says little
            out = [{"from": source_field, "to": p, "type": "int"}]
            if t.enum:
                out.append({"from": source_field, "to": "connection_info.protocol_name", "type": "enum", "enum": dict(sorted(t.enum.items())), "default": "other"})
            return out
        return [{"from": source_field, "to": p, "type": "string", "lower": True},
                {"from": source_field, "to": "connection_info.protocol_num", "type": "enum",
                 "enum": dict(sorted(t.enum.items())), "default": 0}]   # keyed by the values as observed: enum match is exact
    if t.type == "action":
        return [{"from": source_field, "to": p, "type": "enum", "enum": dict(sorted(t.enum.items())), "default": 99}]
    if t.type == "mac":
        return [{"from": source_field, "to": p, "type": "mac"}]
    if t.type == "severity":
        if t.enum:   # words (notice, warning): map through the observed values, matching is exact
            return [{"from": source_field, "to": p, "type": "enum", "enum": dict(sorted(t.enum.items())), "default": 99}]
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


# --- free-text syslog: Drain3 templates -> anchored RE2 with typed named groups ----------------------------

_TS_FORMS = [
    (re.compile(r"[A-Z][a-z]{2} +\d+ \d{4} \d\d:\d\d:\d\d"), r"[A-Z][a-z]{2} +\d+ \d{4} [\d:]+"),
    (re.compile(r"[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d"), r"[A-Z][a-z]{2} +\d+ [\d:]+"),
    (re.compile(r"\d{4}/\d\d/\d\d \d\d:\d\d:\d\d"), r"\d{4}/\d\d/\d\d [\d:]+"),
    (re.compile(r"\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?"), r"\d{4}-\d\d-\d\d[ T][\d:.]+(?:Z|[+-]\d\d:?\d\d)?"),
]
_SUB = re.compile(r"\s+|[^\s\w.]|[\w.]+")
_IPRX = r"\d{1,3}(?:\.\d{1,3}){3}"


def _esc(s: str) -> str:
    """Escape RE2 metacharacters only: re.escape also escapes spaces and hyphens, which is legal but unreadable."""
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", s)


def _tokens(line: str) -> list[tuple[str, str]]:
    """(kind, text): ws, d (one delimiter char), w (word/number), ts (a whole timestamp)."""
    def sub(s: str) -> list[tuple[str, str]]:
        return [("ws" if t.isspace() else "w" if re.match(r"[\w.]", t) else "d", t) for t in _SUB.findall(s)]
    for rx, _ in _TS_FORMS:
        m = rx.search(line)
        if m:
            return sub(line[:m.start()]) + [("ts", m.group())] + sub(line[m.end():])
    return sub(line)


def _slot_regex(t: Typed, values: list[str], ts_rx: str) -> str:
    if t.type == "timestamp":
        return ts_rx
    if t.type == "ipv4":
        return _IPRX
    if t.type in ("port", "integer"):
        return r"\d+"
    return r"[\w.]+"


def propose_text(source_id: str, lines: list[str], record_ids: list[int], now: datetime,
                 drift_alert_id: str = "", timezone: str = "+05:30", min_cluster: int = 50) -> Generated:
    """A new parser for free-text syslog: one anchored regex extractor per template of at least `min_cluster` lines.

    Drain3 groups the lines; inside a group the lines are split into words, numbers, delimiters and one timestamp,
    and any position whose value varies becomes a typed named group. Literals stay literal and are escaped.
    """
    from .fingerprint import _miner

    lines = [l for l in lines if l.strip()]
    miner = _miner()
    cid = [miner.add_log_message(l)["cluster_id"] for l in lines]
    toks = [_tokens(l) for l in lines]

    groups: dict[tuple, list[int]] = {}
    for i, (c, tk) in enumerate(zip(cid, toks)):
        skeleton = tuple(k if k in ("ts", "w") else (k, t) if k == "d" else k for k, t in tk)
        groups.setdefault((c, skeleton), []).append(i)

    def split_by_code(g: list[int]) -> list[list[int]]:
        """Message families that share a template but differ in a code (ASA 302014 vs 302016) are different
        parsers: split on a slot holding a handful of same-length integers, each backed by a full extractor's worth of records."""
        for p in range(len(toks[g[0]])):
            if toks[g[0]][p][0] != "w":
                continue
            by: dict[str, list[int]] = {}
            for i in g:
                by.setdefault(toks[i][p][1], []).append(i)
            if 2 <= len(by) <= 12 and all(v.isdigit() and len(v) >= 3 for v in by) and len({len(v) for v in by}) == 1 \
                    and all(len(m) >= min_cluster for m in by.values()):
                return [x for k in sorted(by) for x in split_by_code(by[k])]
        return [g]

    ordered = sorted((x for g in groups.values() for x in split_by_code(g)), key=lambda g: (-len(g), g[0]))

    warnings: list[str] = []
    exts: list[dict] = []
    all_typed: list[Typed] = []
    ts_rx_of = {}
    for n, g in enumerate(ordered, 1):
        if len(g) < min_cluster:
            warnings.append(f"template of {len(g)} records (first: record {record_ids[g[0]] if record_ids else g[0] + 1}) is below the {min_cluster} needed for an extractor; they will quarantine")
            continue
        width = len(toks[g[0]])
        cols = [[toks[i][p][1] for i in g] for p in range(width)]
        kinds = [toks[g[0]][p][0] for p in range(width)]
        slot_pos = [p for p in range(width) if kinds[p] in ("w", "ts") and len(set(cols[p])) > 1]
        if not slot_pos:
            continue
        typed_by_pos = dict(zip(slot_pos, type_columns([Column(f"slot_{p}", cols[p], named=False, position=k) for k, p in enumerate(slot_pos)])))

        copies: set[int] = set()
        # 1. a slot whose values repeat an earlier slot's (NAT translation, "(x/y)" after "x/y") adds nothing
        for k, p in enumerate(slot_pos):
            t = typed_by_pos[p]
            if t.type not in ("ipv4", "port", "integer"):
                continue
            for q in slot_pos[:k]:
                same = sum(a == b for a, b in zip(cols[p], cols[q])) / len(g)
                if same >= 0.95 and typed_by_pos[q].type == t.type:
                    t.ocsf_path, t.confidence = "", 0.5
                    t.evidence = f"same values as slot {q} in {same:.0%} of records (a NAT copy); kept unmapped"
                    copies.add(p)
                    break
        # 2. which address is the source. Evidence in order: a literal cue word right before it (src, dst, from),
        #    an arrow between the two, port behaviour (the address paired with a well-known port is the server),
        #    and last the position. Only the first two are decisive; the rest are guesses the reviewer must confirm.
        ips = [p for p in slot_pos if typed_by_pos[p].type == "ipv4" and p not in copies and len(set(cols[p])) > 1]
        for p in ips[2:]:
            typed_by_pos[p].ocsf_path = ""
        if len(ips) >= 2:
            a_, b_ = ips[0], ips[1]

            def cue(pos: int) -> str:
                lit = 0
                for q in range(pos - 1, max(pos - 8, -1), -1):
                    if kinds[q] == "w" and q not in typed_by_pos:
                        w = cols[q][0].lower()
                        if w in ("src", "source", "from", "orig"):
                            return "src"
                        if w in ("dst", "dest", "destination"):
                            return "dst"
                        lit += 1
                        if lit == 2:
                            break
                return ""

            def server_share(pos: int) -> float | None:
                q = pos + 1
                while q < width and kinds[q] == "d" and q - pos <= 3:
                    q += 1
                t = typed_by_pos.get(q)
                if t is None:  # a port that never varies is a literal: 53 in every DNS message
                    return (1.0 if int(cols[q][0]) in WELL_KNOWN else 0.0) if q < width and kinds[q] == "w" and cols[q][0].isdigit() else None
                if t.type not in ("port", "integer") or q in copies:
                    return None
                return sum(int(v) in WELL_KNOWN for v in cols[q]) / len(g)

            arrow = any(cols[q][0] == ">" and q > 0 and cols[q - 1][0] == "-" for q in range(a_, b_))
            direction = next((cols[q][0].lower() for q in range(width) if kinds[q] == "w" and q not in typed_by_pos
                              and cols[q][0].lower() in ("inbound", "outbound") and q < a_), "")
            ca, cb = cue(a_), cue(b_)
            sa, sb = server_share(a_), server_share(b_)
            if ca == "src" or cb == "dst":
                order, why, conf = (a_, b_), "a literal src/dst/from cue", 0.85
            elif ca == "dst" or cb == "src":
                order, why, conf = (b_, a_), "a literal src/dst/from cue", 0.85
            elif arrow:
                order, why, conf = (a_, b_), "the -> between the addresses", 0.85
            elif direction:
                # ASA-style "for FOREIGN to LOCAL": the foreign address is the source of an inbound connection and the
                # destination of an outbound one. A vendor convention, not a law, so it is flagged for the reviewer.
                order = (a_, b_) if direction == "inbound" else (b_, a_)
                why, conf = f"the word '{direction}' (first address = the foreign host)", 0.75
            elif sa is not None and sb is not None and sa >= 0.8 and sb <= 0.2:
                order, why, conf = (b_, a_), "port behaviour: the other address is paired with a well-known port", 0.75
            elif sa is not None and sb is not None and sb >= 0.8 and sa <= 0.2:
                order, why, conf = (a_, b_), "port behaviour: the other address is paired with a well-known port", 0.75
            else:
                order, why, conf = (a_, b_), "position only (the first address is assumed to be the source)", 0.65
            for role, p, other in (("src", order[0], "dst_endpoint.ip"), ("dst", order[1], "src_endpoint.ip")):
                t = typed_by_pos[p]
                t.ocsf_path, t.confidence = f"{role}_endpoint.ip", conf
                t.evidence += f"; {role} by {why}"
                if conf < 0.85:
                    t.alternatives = [other]
            if conf < 0.85:
                warnings.append(f"tpl_{n}: source and destination were decided by {why}; confirm the direction before approving")
        elif len(ips) == 1:
            typed_by_pos[ips[0]].ocsf_path = "src_endpoint.ip"
        # 3. structural adjacency beats port-behaviour priors: a port belongs to the address right before it, and an
        #    integer with no address in front of it is a counter or an id (a connection number), not a port
        for p in slot_pos:
            t = typed_by_pos[p]
            if t.type not in ("port", "integer") or p in copies:
                continue
            q = p - 1
            while q >= 0 and kinds[q] == "d" and p - q <= 3:
                q -= 1
            ip = typed_by_pos.get(q)
            if ip and ip.ocsf_path.endswith(".ip") and p - q <= 4 and all(0 <= int(v) <= 65535 for v in cols[p]):
                t.type, t.ocsf_path = "port", ip.ocsf_path.replace(".ip", ".port")
                t.confidence = round(ip.confidence * 0.95, 3)
                t.evidence = f"integers 0-65535 directly after the address in slot {q}: its port"
            else:
                t.type, t.ocsf_path, t.confidence = "integer", "", 0.5
                t.evidence = "an integer with no address in front of it: a counter or id, not a port"
        # 4. each OCSF path is set by one slot
        seen: set[str] = set()
        for p in slot_pos:
            t = typed_by_pos[p]
            if t.ocsf_path and t.ocsf_path in seen:
                t.ocsf_path, t.evidence = "", t.evidence + "; another slot already maps this path"
            seen.add(t.ocsf_path)
        used = set()
        names: dict[int, str] = {}
        for p in slot_pos:
            t = typed_by_pos[p]
            base = {"src_endpoint.ip": "src_ip", "dst_endpoint.ip": "dst_ip", "src_endpoint.port": "src_port", "dst_endpoint.port": "dst_port",
                    "time": "ts", "action_id": "action"}.get(t.ocsf_path) or (t.ocsf_path.split(".")[-1] if t.ocsf_path else f"v{p}")
            nm, k = base, 2
            while nm in used:
                nm, k = f"{base}_{k}", k + 1
            used.add(nm)
            names[p] = nm

        ts_pos = next((p for p in range(width) if kinds[p] == "ts"), None)
        ts_rx = next((rx for f, rx in _TS_FORMS if ts_pos is not None and f.fullmatch(cols[ts_pos][0])), r"\S+")
        parts: list[str] = []
        render: list[str] = []
        runs: list[str] = []   # maximal literal text, for the detector
        can_render = True
        for p in range(width):
            if p in typed_by_pos:
                parts.append(f"(?P<{names[p]}>{_slot_regex(typed_by_pos[p], cols[p], ts_rx)})")
                render.append("{" + names[p] + "}")
            elif kinds[p] == "ws":
                same = len(set(cols[p])) == 1
                parts.append(_esc(cols[p][0]) if same else " +")
                runs.append(cols[p][0] if same else "\x00")
                render.append(cols[p][0].replace("{", "{{").replace("}", "}}") if same else "")
                can_render &= same
            else:
                parts.append(_esc(cols[p][0]))
                runs.append(cols[p][0])
                render.append(cols[p][0].replace("{", "{{").replace("}", "}}"))
            if p in typed_by_pos:
                runs.append("\x00")
        pattern = "^" + "".join(parts) + "$"

        maps: list[dict] = []
        for p in slot_pos:
            t = typed_by_pos[p]
            if t.ocsf_path:
                maps += _map_entry(t, names[p])
        have = {m["to"] for m in maps}
        for p in slot_pos:
            t = typed_by_pos[p]
            if t.ocsf_path.endswith("_endpoint.ip"):
                q = p + 1
                while q < width and kinds[q] == "d" and q - p <= 3:
                    q += 1
                port_path = t.ocsf_path.replace(".ip", ".port")
                if q < width and q not in typed_by_pos and kinds[q] == "w" and cols[q][0].isdigit() and port_path not in have:
                    maps.append({"const": int(cols[q][0]), "to": port_path})   # the same port in every record of this template
                    have.add(port_path)
        # constants carried by literal words: a message that only ever says "TCP" or "Teardown"
        for p in range(width):
            if kinds[p] != "w" or p in typed_by_pos:
                continue
            w = cols[p][0].lower()
            if w in PROTO_NUM and "connection_info.protocol_num" not in have:
                maps += [{"const": PROTO_NUM[w], "to": "connection_info.protocol_num"}, {"const": w, "to": "connection_info.protocol_name"}]
                have |= {"connection_info.protocol_num", "connection_info.protocol_name"}
            elif w in ACTION_ENUM and "action_id" not in have:
                maps.append({"const": ACTION_ENUM[w], "to": "action_id"})
                have.add("action_id")
        maps.append({"const": 6, "to": "activity_id"})
        if "severity_id" not in have:
            maps.append({"const": 1, "to": "severity_id"})
        ext: dict = {"id": f"tpl_{n}", "kind": "regex", "pattern": pattern}
        if can_render:
            ext["render"] = "".join(render)
        ext["map"] = maps
        exts.append(ext)
        all_typed += [typed_by_pos[p] for p in slot_pos]
        ext["_members"] = g  # stripped below
        ext["_runs"] = [r for r in "".join(runs).split("\x00") if r]

    if not exts:
        raise ValueError("no template with enough records to propose an extractor")

    # a cheap detector: the longest piece of literal text, from the biggest template, that >= 95% of all lines contain
    cands = sorted({r[i:j] for r in exts[0]["_runs"] for i in range(len(r)) for j in range(i + 5, len(r) + 1)}, key=lambda c: (-len(c), c))
    sig = next((_esc(c) for c in cands if sum(c in l for l in lines) >= 0.95 * len(lines)), r"\S")

    pid = sanitize(source_id) + "_auto"
    members = {e["id"]: e.pop("_members") for e in exts}
    for e in exts:
        e.pop("_runs")
    doc = {"id": pid, "version": "1.0.0", "vendor": sanitize(source_id), "product": "auto", "timezone": timezone,
           "match": {"signature": sig}, "ocsf_defaults": {"class_uid": 4001, "category_uid": 4}, "extractors": exts}
    for e in exts:
        e["tests"] = _vectors({**doc, "extractors": [e]}, [lines[i] for i in members[e["id"]]])
    tpl = sorted(fingerprint(lines).templates)
    return Generated(Proposal(id="", kind="new", parser_id=pid, base_version="", source_id=source_id, yaml=_dump(doc),
                              cluster_size=len(lines), templates=tpl, sample_record_ids=record_ids[:20],
                              typed_fields=[t.model() for t in all_typed if t.ocsf_path],
                              dry_run=None, status="pending", created_at=now, drift_alert_id=drift_alert_id), warnings)


def _kv_prefix(lines: list[str]) -> str:
    """A syslog <pri> in front of the pairs is skipped, not tokenized."""
    return r"^(?:<\d+>)?" if all(re.match(r"<\d+>", l) for l in lines) else ""


def propose_kv(source_id: str, lines: list[str], record_ids: list[int], now: datetime,
               drift_alert_id: str = "", timezone: str = "+05:30") -> Generated:
    """A new parser for a key=value source that has no parser yet (the case propose_kv_patch cannot serve)."""
    from .fingerprint import fields

    lines = [l for l in lines if l.strip()]
    cols: dict[str, list[str]] = {}
    for l in lines:
        for k, (v, _) in fields(l, "kv").items():
            cols.setdefault(k, []).append(v)
    cols = {k: v for k, v in cols.items() if len(v) >= 0.99 * len(lines)}      # only keys every record carries
    typed = type_columns([Column(k, v, True, i) for i, (k, v) in enumerate(cols.items())])
    by = {t.field: t for t in typed}

    warnings: list[str] = []
    maps: list[dict] = []
    date = next((t for t in typed if t.type == "date"), None)
    tod = next((t for t in typed if t.type == "time_of_day"), None)
    if date and tod and "time" not in {t.ocsf_path for t in typed}:
        maps.append({"from": [date.field, tod.field], "to": "time", "type": "time", "layout": f"{date.layout} {tod.layout}"})
        warnings.append(f"{date.field} + {tod.field} joined into one timestamp (layout {date.layout} {tod.layout})")
    for t in typed:
        if t.ocsf_path:
            maps += _map_entry(t, t.field)
            if t.ocsf_path == "severity_id":
                warnings.append(f"{t.field} mapped straight to severity_id; confirm the scale runs the same way as OCSF")
    maps.append({"const": 6, "to": "activity_id"})
    if "severity_id" not in {m["to"] for m in maps if "to" in m}:
        maps.append({"const": 1, "to": "severity_id"})

    # the detector: the first key=value pair that is the same in every record (type=traffic), else the first key
    # The detector must survive tomorrow, so it is built from structure, not from values that happen to be constant in
    # this sample (date=2026-09-28, devname=FG-01): a `type`-like key with one value if there is one, else the first three
    # mapped keys in the order they appear.
    kind_key = next((k for k, v in cols.items() if k in ("type", "logtype", "log_type", "event_type", "category") and len(set(v)) == 1), None)
    order = [f for f in cols if by[f].ocsf_path or by[f].type in ("date", "time_of_day")][:3] or list(cols)[:3]
    if kind_key:
        sig = rf'\b{kind_key}="?{re.escape(cols[kind_key][0])}"?(?: |$)'
    else:
        sig = ".*".join(rf"\b{re.escape(k)}=" for k in order)
    pid = sanitize(source_id) + "_auto"
    ext: dict = {"id": "kv_rows", "kind": "kv"}
    if _kv_prefix(lines):
        ext["skip_prefix"] = _kv_prefix(lines)
    ext.update({"pair_sep": " ", "kv_sep": "=", "quote": '"', "render": "auto", "map": maps})
    doc = {"id": pid, "version": "1.0.0", "vendor": sanitize(source_id), "product": "auto", "timezone": timezone,
           "match": {"signature": sig}, "ocsf_defaults": {"class_uid": 4001, "category_uid": 4}, "extractors": [ext]}
    ext["tests"] = _vectors(doc, lines)
    tpl = sorted(fingerprint(lines).templates)
    return Generated(Proposal(id="", kind="new", parser_id=pid, base_version="", source_id=source_id, yaml=_dump(doc),
                              cluster_size=len(lines), templates=tpl, sample_record_ids=record_ids[:20],
                              typed_fields=[t.model() for t in typed if t.ocsf_path],
                              dry_run=None, status="pending", created_at=now, drift_alert_id=drift_alert_id), warnings)


# --- CEF and LEEF -----------------------------------------------------------------------------------------
# The extension keys are standardized, so unlike free text the mapping starts from a table; the typer only confirms
# that the values in this source really are what the key promises (a `src` full of hostnames is not an address).
_CEF_TABLE: dict[str, tuple[str, str]] = {   # key -> (ocsf path, the typer type its values must have)
    "src": ("src_endpoint.ip", "ipv4"), "dst": ("dst_endpoint.ip", "ipv4"),
    "spt": ("src_endpoint.port", "port"), "dpt": ("dst_endpoint.port", "port"),
    "srcPort": ("src_endpoint.port", "port"), "dstPort": ("dst_endpoint.port", "port"),
    "smac": ("src_endpoint.mac", "mac"), "dmac": ("dst_endpoint.mac", "mac"),
    "proto": ("connection_info.protocol_name", "protocol"), "act": ("action_id", "action"), "action": ("action_id", "action"),
    "rt": ("time", "timestamp"), "devTime": ("time", "timestamp"),
}
_CEF_SEVERITY = {str(i): v for i, v in enumerate([2, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5])}   # CEF: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High


def propose_cef(source_id: str, lines: list[str], record_ids: list[int], now: datetime,
                drift_alert_id: str = "", timezone: str = "+00:00") -> Generated:
    """A new parser for CEF or LEEF (the kind is read from the lines)."""
    from dataclasses import replace

    from .dsl_eval import CEF_HEADER, LEEF_HEADER, parse_cef, parse_leef
    from .fingerprint import fields, line_kind

    lines = [l for l in lines if l.strip()]
    kind = Counter(line_kind(l) for l in lines).most_common(1)[0][0]
    if kind not in ("cef", "leef"):
        raise ValueError(f"not CEF or LEEF (looks like {kind})")
    parse = parse_cef if kind == "cef" else parse_leef
    head = CEF_HEADER if kind == "cef" else LEEF_HEADER
    rows = [r for r in (parse(l) for l in lines) if r]
    ext_keys = [k for k in dict.fromkeys(k for r in rows for k in r[0]) if k not in head]
    cols = {k: [r[0][k] for r in rows if k in r[0]] for k in ext_keys}
    cols = {k: v for k, v in cols.items() if len(v) >= 0.99 * len(rows)}
    typed = {t.field: t for t in type_columns([Column(k, v, True, i) for i, (k, v) in enumerate(cols.items())])}

    warnings: list[str] = []
    maps: list[dict] = []
    used: set[str] = set()
    for key, (path, want) in _CEF_TABLE.items():
        t = typed.get(key)
        if t is None:
            continue
        family = {"ipv4": ("ipv4",), "port": ("port", "integer"), "mac": ("mac",), "protocol": ("protocol",), "action": ("action",), "timestamp": ("timestamp",)}[want]
        if t.type not in family:
            warnings.append(f"{key} is a standard key for {path}, but its values look like {t.type}: left unmapped")
            continue
        if path in used:
            continue     # e.g. both rt and devTime: the first one wins
        used.add(path)
        entry = _map_entry(replace(t, ocsf_path=path), key)
        if kind == "cef" and want == "port":
            entry = [{"from": key, "to": path, "type": "port", "optional": True}]
        maps += entry
    sev_key = "cef.severity" if kind == "cef" else "sev"
    sev_vals = [r[0].get(sev_key) for r in rows if r[0].get(sev_key) not in (None, "")]
    if sev_vals and all(v in _CEF_SEVERITY for v in sev_vals) and kind == "cef":
        seen = sorted(set(sev_vals), key=int)
        maps.append({"from": sev_key, "to": "severity_id", "type": "enum", "enum": {v: _CEF_SEVERITY[v] for v in seen}, "default": 99})
        warnings.append("cef.severity mapped 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High to OCSF 2, 3, 4, 5 (the CEF specification's bands)")
    elif sev_vals:
        warnings.append(f"{sev_key} has values this generator does not band; severity left unmapped")
    maps.append({"from": head[4] if kind == "cef" else head[4], "to": "message", "type": "string"} if kind == "leef" else {"from": "cef.name", "to": "message", "type": "string"})
    maps.append({"const": 6, "to": "activity_id"})
    if "severity_id" not in {m["to"] for m in maps if "to" in m}:
        maps.append({"const": 1, "to": "severity_id"})

    first = rows[0][0]
    vendor, product = first[head[1]], first[head[2]]
    sig = (r"CEF:\d+\|" if kind == "cef" else r"LEEF:\d\.\d\|") + _esc(vendor) + r"\|" + _esc(product) + r"\|"
    pid = sanitize(f"{vendor}_{product}") + "_auto"
    ext = {"id": kind + "_events", "kind": kind, "map": maps}
    doc = {"id": pid, "version": "1.0.0", "vendor": sanitize(vendor), "product": sanitize(product), "timezone": timezone,
           "match": {"signature": sig}, "ocsf_defaults": {"class_uid": 4001, "category_uid": 4}, "extractors": [ext]}
    ext["tests"] = _vectors(doc, lines)
    tpl = sorted(fingerprint(lines).templates)
    return Generated(Proposal(id="", kind="new", parser_id=pid, base_version="", source_id=source_id, yaml=_dump(doc),
                              cluster_size=len(lines), templates=tpl, sample_record_ids=record_ids[:20],
                              typed_fields=[replace(t, ocsf_path=_CEF_TABLE[k][0]).model() for k, t in typed.items() if k in _CEF_TABLE and _CEF_TABLE[k][0] in used],
                              dry_run=None, status="pending", created_at=now, drift_alert_id=drift_alert_id), warnings)
