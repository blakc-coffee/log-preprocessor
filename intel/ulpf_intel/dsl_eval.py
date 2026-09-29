"""A small reference evaluator for the parser DSL (contracts/parser_dsl.md).

NOT the data-plane engine (Parsing owns that). The sidecar needs one for two things:
deriving the `tests:` vectors of a proposal from real samples, and a local pre-check
before it asks the data plane for the authoritative dry-run. It implements the four
extractor kinds the sidecar generates (csv, kv, json, regex) and no render-back.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import yaml

_GO_TO_PY = {
    "2006/01/02 15:04:05": "%Y/%m/%d %H:%M:%S",
    "2006-01-02 15:04:05": "%Y-%m-%d %H:%M:%S",
    "Jan _2 2006 15:04:05": "%b %d %Y %H:%M:%S",
    "Jan _2 15:04:05": "%b %d %H:%M:%S",
    "2006-01-02T15:04:05.999999-0700": "%Y-%m-%dT%H:%M:%S.%f%z",
    "2006-01-02T15:04:05-0700": "%Y-%m-%dT%H:%M:%S%z",
    "02/Jan/2006:15:04:05 -0700": "%d/%b/%Y:%H:%M:%S %z",
}
_EPOCH = {"epoch_s": 1e3, "epoch_ms": 1.0, "epoch_us": 1e-3, "epoch_ns": 1e-6}   # -> milliseconds


@dataclass
class Result:
    extractor: str
    ocsf: dict[str, Any]
    unmapped: dict[str, Any]
    mapped_bytes: int
    unmapped_bytes: int
    raw_len: int
    flags: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        """(mapped + unmapped + constant) / raw, where constant is everything that is not a value: 1 for a fully accounted record."""
        return 1.0 if self.raw_len else 0.0


def load(text: str) -> dict:
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict) or "extractors" not in doc:
        raise ValueError("not a parser document")
    return doc


def _tz(s: str) -> timezone:
    m = re.fullmatch(r"([+-])(\d\d):?(\d\d)", s or "+00:00")
    d = timedelta(hours=int(m[2]), minutes=int(m[3])) if m else timedelta()
    return timezone(-d if m and m[1] == "-" else d)


def _time(v: str, layout: str, tz: timezone, received_at: datetime | None = None) -> int:
    if layout in _EPOCH:
        return int(int(v) * _EPOCH[layout])
    if layout == "rfc3339":
        return int(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp() * 1000)
    py = _GO_TO_PY.get(layout)
    if not py:
        raise ValueError(f"unsupported layout {layout}")
    if "%Y" not in py:
        # a layout with no year takes it from received_at; a month more than one ahead of the receipt month
        # means the previous year (a Dec 31 line received on Jan 2)
        ref = received_at or datetime(2026, 6, 1, tzinfo=timezone.utc)
        d = datetime.strptime(f"2000 {v}", "%Y " + py)          # 2000 is a leap year: "Feb 29" must parse
        year = ref.year - 1 if d.month - ref.month > 1 else ref.year
        d = d.replace(year=year)
    else:
        d = datetime.strptime(v, py)
    if d.tzinfo is None:
        d = d.replace(tzinfo=tz)
    return int(d.timestamp() * 1000)


def _convert(entry: dict, raw: str, tz: timezone, received_at: datetime | None = None) -> Any:
    t = entry.get("type", "string")
    v = raw
    if t == "ip":
        return str(ipaddress.ip_address(v))
    if t in ("int", "uint", "port"):
        n = int(v)
        if t == "port" and not 0 <= n <= 65535:
            raise ValueError("port out of range")
        return n
    if t == "mac":
        return re.sub(r"[-.]", ":", v).lower()
    if t == "float":
        return float(v)
    if t == "time":
        return _time(v, entry["layout"], tz, received_at)
    if t == "enum":
        m = {str(k): x for k, x in entry["enum"].items()}
        return m.get(v, entry.get("default"))  # exact match, as the spec says
    if t == "duration":
        return int(float(v) * (1000 if entry.get("unit", "s") == "s" else 1))
    return v.lower() if entry.get("lower") else v


def _set(d: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = value


def flat(d: dict, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        p = f"{prefix}.{k}" if prefix else k
        out.update(flat(v, p) if isinstance(v, dict) else {p: v})
    return out


_KV = re.compile(r'(?P<k>[A-Za-z_][\w.\-]*)=(?P<v>"[^"]*"|\S*)')


def _values(ext: dict, raw: str) -> tuple[dict[str, str], list[dict]] | None:
    """Named values of one extraction, or None if the extractor does not apply."""
    kind = ext["kind"]
    if kind == "csv":
        try:
            row = next(csv.reader(io.StringIO(raw), delimiter=ext.get("sep", ","), quotechar=ext.get("quote", '"')))
        except (StopIteration, csv.Error):
            return None
        if len(row) < int(ext.get("min_columns", 1)):
            return None
        w = ext.get("when")
        if w and (w["column"] >= len(row) or (row[w["column"]] != str(w["equals"]) if "equals" in w else row[w["column"]] not in map(str, w["in"]))):
            return None
        names = ext.get("columns", [])
        return {(names[i] if i < len(names) and names[i] != "_" else f"col_{i}"): v for i, v in enumerate(row)}, []
    if kind == "kv":
        out: dict[str, str] = {}
        dupes: list[dict] = []
        for m in _KV.finditer(raw):
            v = m["v"]
            v = v[1:-1] if v.startswith('"') and v.endswith('"') and len(v) >= 2 else v
            if m["k"] in out:
                dupes.append({"key": m["k"], "value": v})     # the first occurrence maps, later ones are kept aside
            else:
                out[m["k"]] = v
        return (out, dupes) if out else None
    if kind == "json":
        try:
            doc = json.loads(raw)
        except ValueError:
            return None
        out = {}

        def walk(p: str, v: Any) -> None:
            if isinstance(v, dict):
                for k in v:
                    walk(f"{p}.{k}" if p else k, v[k])
            else:
                out[p] = v if isinstance(v, str) else json.dumps(v)

        walk("", doc)
        w = ext.get("when")
        if w and (out.get(w["path"]) != str(w["equals"]) if "equals" in w else out.get(w["path"]) not in map(str, w["in"])):
            return None
        return out, []
    if kind == "regex":
        m = re.match(ext["pattern"], raw)
        return ({k: v for k, v in m.groupdict().items() if v}, []) if m else None
    raise ValueError(f"kind {kind} not supported by the reference evaluator")


def extract(parser: dict, raw: str, received_at: datetime | None = None) -> Result | None:
    """First extractor to succeed wins. None means the record would be quarantined."""
    sig = (parser.get("match") or {}).get("signature")
    if sig and not re.search(sig, raw[:512]):
        return None
    tz = _tz(parser.get("timezone", "+00:00"))
    for ext in parser["extractors"]:
        got = _values(ext, raw)
        if got is None:
            continue
        vals, dupes = got
        ocsf: dict[str, Any] = {}
        used: set[str] = set()
        flags: list[str] = []
        try:
            for m in ext.get("map", []):
                if "const" in m:
                    _set(ocsf, m["to"], m["const"])
                    continue
                srcs = m["from"] if isinstance(m["from"], list) else [m["from"]]
                if any(s not in vals for s in srcs):
                    raise KeyError(srcs)
                used.update(srcs)
                if any(vals[s] == "" for s in srcs):
                    continue  # empty means absent (parser_dsl.md section 3)
                try:
                    _set(ocsf, m["to"], _convert(m, " ".join(vals[s] for s in srcs), tz, received_at))
                except ValueError:
                    if m.get("type") != "time":
                        raise
                    if "time_unparseable" not in flags:      # the event is kept: time stays unset and is flagged
                        flags.append("time_unparseable")
        except (KeyError, ValueError, TypeError):
            continue
        um: dict[str, Any] = {k: v for k, v in vals.items() if k not in used and v != ""}
        if dupes:
            um["_dupes"] = dupes
            flags.append("duplicate_key")
        return Result(ext["id"], {k: v for k, v in (parser.get("ocsf_defaults") or {}).items()} | ocsf, um,
                      sum(len(vals[k]) for k in used), sum(len(str(v)) for k, v in um.items() if k != "_dupes"), len(raw), flags)
    return None


def validate_parser(doc: dict) -> None:
    """Load-time checks. Every error names the parser, the extractor and the field, in that order (spec section 8)."""
    from .validate import _NOT_RE2

    pid = doc.get("id", "?")
    seen: set[str] = set()
    for e in doc.get("extractors", []):
        eid = e.get("id", "?")
        who = f'parser "{pid}" extractor "{eid}"'
        if eid in seen:
            raise ValueError(f"{who}: duplicate extractor id")
        seen.add(eid)
        names: set[str] = set()
        if e.get("kind") == "regex":
            for rx, what in _NOT_RE2:
                if re.search(rx, e["pattern"]):
                    raise ValueError(f"{who} pattern: RE2 does not support {what}")
            try:
                names = set(re.compile(e["pattern"]).groupindex)
            except re.error as err:
                raise ValueError(f"{who} pattern: {err}")
        if e.get("kind") == "csv":
            names = {c for c in e.get("columns", []) if c != "_"}
        if e.get("kind") in ("regex", "csv"):
            for i, m in enumerate(e.get("map", [])):
                for f in ([] if "const" in m else (m["from"] if isinstance(m["from"], list) else [m["from"]])):
                    if f not in names and not (e["kind"] == "csv" and re.fullmatch(r"col_\d+", f)):
                        raise ValueError(f'{who} map[{i}] (from: {f}): capture "{f}" is not defined by the pattern')
