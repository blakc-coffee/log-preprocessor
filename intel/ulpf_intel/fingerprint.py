"""Structural fingerprints of a source's raw lines and a drift score between two of them.

Independent of any parser: it sees only raw text. Deterministic: sorted iteration,
a fresh Drain3 miner per fingerprint, no clocks, no randomness.
"""
from __future__ import annotations

import csv
import difflib
import io
import json
import re
from collections import Counter
from dataclasses import dataclass, field

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

DELIMS = "=,|:;\"'{}[]\t"

WEIGHTS = {"keyset": 0.30, "delimiters": 0.25, "templates": 0.20, "shapes": 0.15, "quarantine": 0.10}

_KV = re.compile(r'(?P<k>[A-Za-z_][\w.\-]*)=(?P<v>"[^"]*"|\S*)')
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_TS = re.compile(r"^(?:\d{4}[-/]\d\d[-/]\d\d(?:[ T]\S*)?|\d\d:\d\d:\d\d(?:\.\d+)?)$")
_EPOCH = re.compile(r"^(?:\d{10}|\d{13}|\d{16}|\d{19})$")
_INT = re.compile(r"^-?\d+$")
_HEX = re.compile(r"^(?:0x[0-9a-fA-F]+|(?=[0-9a-fA-F]*[a-fA-F])(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{6,})$")
_WORD = re.compile(r"^[A-Za-z][\w\-]*$")


def shape(value: str, quoted: bool = False) -> str:
    """Value-shape class: ip, uuid, timestamp, epoch, int, hex, word, qstr, other."""
    if quoted:
        return "qstr"
    for name, rx in (("ip", _IPV4), ("uuid", _UUID), ("timestamp", _TS), ("epoch", _EPOCH), ("int", _INT), ("hex", _HEX), ("word", _WORD)):
        if rx.match(value):
            return name
    return "other"


def line_kind(line: str) -> str:
    s = line.strip()
    if s.startswith("{"):
        try:
            json.loads(s)
            return "json"
        except ValueError:
            pass
    if re.search(r"CEF:\d+\|", s[:160]):
        return "cef"
    if re.search(r"LEEF:\d\.\d\|", s[:160]):
        return "leef"
    if len(_KV.findall(s)) >= 4:
        return "kv"
    if s.count(",") >= 5:
        return "csv"
    return "text"


def _flatten(prefix: str, v, out: dict[str, tuple[str, bool]]) -> None:
    if isinstance(v, dict):
        for k in sorted(v):
            _flatten(f"{prefix}.{k}" if prefix else k, v[k], out)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            _flatten(f"{prefix}.{i}", x, out)
    else:
        out[prefix] = (json.dumps(v) if not isinstance(v, str) else v, isinstance(v, str))


def fields(line: str, kind: str) -> dict[str, tuple[str, bool]]:
    """key (or json path, or col_N) -> (value, was_quoted)."""
    if kind == "kv":
        out: dict[str, tuple[str, bool]] = {}
        for m in _KV.finditer(line):
            v = m["v"]
            q = len(v) >= 2 and v[0] == '"'
            out.setdefault(m["k"], (v[1:-1] if q else v, q))
        return out
    if kind == "json":
        out = {}
        try:
            _flatten("", json.loads(line), out)
        except ValueError:
            pass
        return out
    if kind in ("cef", "leef"):
        from .dsl_eval import parse_cef, parse_leef
        got = (parse_cef if kind == "cef" else parse_leef)(line)
        return {k: (v, False) for k, v in got[0].items()} if got else {}
    if kind == "csv":
        try:
            row = next(csv.reader(io.StringIO(line)))
        except (StopIteration, csv.Error):
            return {}
        return {f"col_{i}": (v, False) for i, v in enumerate(row)}
    return {}


def _miner() -> TemplateMiner:
    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    cfg.drain_sim_th = 0.5
    cfg.masking_instructions = [
        MaskingInstruction(r'(?<==)(?:"[^"]*"|\S+)', "V"),  # kv values: keep the key structure
        MaskingInstruction(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "IP"),
        MaskingInstruction(r"\b0x[0-9a-fA-F]+\b", "HEX"),
        MaskingInstruction(r"\b\d+\b", "NUM"),
    ]
    return TemplateMiner(None, cfg)


@dataclass
class Fingerprint:
    n: int = 0
    kind: str = "text"
    delims: dict[str, float] = field(default_factory=dict)        # mean count per line
    keys: dict[str, float] = field(default_factory=dict)          # key -> fraction of lines present
    columns: float = 0.0                                          # mean csv column count
    tokens: tuple[float, float, float] = (0.0, 0.0, 0.0)          # mean, p10, p90
    shapes: dict[str, dict[str, float]] = field(default_factory=dict)  # key -> shape -> fraction
    templates: dict[str, float] = field(default_factory=dict)     # Drain3 template -> fraction of lines


def fingerprint(lines: list[str]) -> Fingerprint:
    lines = [l.rstrip("\r\n") for l in lines if l.strip()]
    fp = Fingerprint(n=len(lines))
    if not lines:
        return fp
    kinds = Counter(line_kind(l) for l in lines)
    fp.kind = sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    fp.delims = {d: sum(l.count(d) for l in lines) / len(lines) for d in DELIMS}
    toks = sorted(len(l.split()) for l in lines)
    fp.tokens = (sum(toks) / len(toks), float(toks[len(toks) // 10]), float(toks[min(len(toks) - 1, (len(toks) * 9) // 10)]))

    present: Counter[str] = Counter()
    shp: dict[str, Counter[str]] = {}
    cols = 0
    for l in lines:
        f = fields(l, fp.kind)
        cols += len(f) if fp.kind == "csv" else 0
        for k, (v, q) in f.items():
            present[k] += 1
            shp.setdefault(k, Counter())[shape(v, q)] += 1
    fp.columns = cols / len(lines) if fp.kind == "csv" else 0.0
    fp.keys = {k: c / len(lines) for k, c in sorted(present.items())}
    fp.shapes = {k: {s: c / present[k] for s, c in sorted(cnt.items())} for k, cnt in sorted(shp.items())}

    miner = _miner()
    for l in lines:
        miner.add_log_message(l)
    tpl: Counter[str] = Counter()
    for c in miner.drain.clusters:
        tpl[c.get_template()] += c.size
    fp.templates = {t: c / len(lines) for t, c in sorted(tpl.items())}
    return fp


# --- distances, each in [0, 1] ---------------------------------------------------

def _wjaccard(a: dict[str, float], b: dict[str, float]) -> float:
    keys = set(a) | set(b)
    den = sum(max(a.get(k, 0.0), b.get(k, 0.0)) for k in keys)
    if den == 0:
        return 1.0  # nothing on either side: identical
    return sum(min(a.get(k, 0.0), b.get(k, 0.0)) for k in keys) / den


def keyset_distance(a: Fingerprint, b: Fingerprint) -> float:
    if a.kind != b.kind:
        return 1.0
    if a.kind == "csv":
        m = max(a.columns, b.columns)
        return abs(a.columns - b.columns) / m if m else 0.0
    return 1.0 - _wjaccard(a.keys, b.keys)


def delimiter_distance(a: Fingerprint, b: Fingerprint) -> float:
    num = sum(abs(a.delims.get(d, 0.0) - b.delims.get(d, 0.0)) for d in DELIMS)
    den = sum(a.delims.get(d, 0.0) + b.delims.get(d, 0.0) for d in DELIMS)
    return num / den if den else 0.0


def template_distance(a: Fingerprint, b: Fingerprint) -> float:
    return 1.0 - _wjaccard(a.templates, b.templates)


def shape_distance(a: Fingerprint, b: Fingerprint) -> float:
    ks = sorted(set(a.shapes) | set(b.shapes))
    if not ks:
        return 0.0
    tot = 0.0
    for k in ks:
        if k not in a.shapes or k not in b.shapes:
            tot += 1.0
            continue
        ss = set(a.shapes[k]) | set(b.shapes[k])
        tot += 0.5 * sum(abs(a.shapes[k].get(s, 0.0) - b.shapes[k].get(s, 0.0)) for s in ss)  # total variation
    return tot / len(ks)


def _dominant(fp: Fingerprint, key: str) -> str:
    h = fp.shapes.get(key, {})
    return max(sorted(h), key=lambda s: h[s]) if h else ""


def _gone(base: Fingerprint, cur: Fingerprint, k: str) -> bool:
    """A key the baseline had (in at least half its lines) that has mostly vanished. Not "entirely absent": the
    window the sidecar looks at straddles the change, so old-format lines are still in it."""
    return base.keys.get(k, 0.0) >= 0.5 and cur.keys.get(k, 0.0) < 0.5 * base.keys[k]


def _new(base: Fingerprint, cur: Fingerprint, k: str) -> bool:
    return cur.keys.get(k, 0.0) >= 0.5 and base.keys.get(k, 0.0) < 0.1


def rename_candidates(base: Fingerprint, cur: Fingerprint) -> list[tuple[str, str]]:
    """A removed key paired with an added key of the same dominant value shape, best name match first."""
    removed = [k for k in base.keys if _gone(base, cur, k)]
    added = [k for k in cur.keys if _new(base, cur, k)]
    pairs: list[tuple[str, str]] = []
    free = list(added)
    for r in removed:
        cands = [a for a in free if _dominant(base, r) == _dominant(cur, a) and _dominant(base, r)]
        if not cands:
            continue
        best = max(cands, key=lambda a: (difflib.SequenceMatcher(None, r, a).ratio(), -added.index(a)))
        if difflib.SequenceMatcher(None, r, best).ratio() >= 0.5:
            pairs.append((r, best))
            free.remove(best)
    return pairs


@dataclass
class Drift:
    score: float
    signals: list[str]
    parts: dict[str, float]


def drift_score(base: Fingerprint, cur: Fingerprint, quarantine_rate: float = 0.0, weights: dict[str, float] | None = None) -> Drift:
    w = weights or WEIGHTS
    parts = {
        "keyset": keyset_distance(base, cur),
        "delimiters": delimiter_distance(base, cur),
        "templates": template_distance(base, cur),
        "shapes": shape_distance(base, cur),
        "quarantine": max(0.0, min(1.0, quarantine_rate)),
    }
    score = max(0.0, min(1.0, sum(w[k] * parts[k] for k in parts)))

    sig: list[str] = []
    if base.kind != cur.kind:
        sig.append(f"format kind changed: {base.kind}->{cur.kind}")
    elif base.kind in ("kv", "json"):
        ren = rename_candidates(base, cur)
        if ren:
            sig.append("keys renamed: " + ", ".join(f"{r}->{a}" for r, a in ren))
        gone = sorted(k for k in base.keys if _gone(base, cur, k) and k not in {r for r, _ in ren})
        new = sorted(k for k in cur.keys if _new(base, cur, k) and k not in {a for _, a in ren})
        if gone:
            sig.append("keys removed: " + ", ".join(gone))
        if new:
            sig.append("keys added: " + ", ".join(new))
        unquoted, changed = [], []
        for k in sorted(set(base.keys) & set(cur.keys)):
            b, c = _dominant(base, k), _dominant(cur, k)
            if b == c:
                continue
            (unquoted if b == "qstr" else changed).append((k, b, c))
        if len(unquoted) >= 3:
            sig.append(f"quoting changed: {len(unquoted)} values that were quoted are now bare")
        else:
            changed += unquoted
        for k, b, c in changed:
            sig.append(f"value shape of {k} changed: {b}->{c}")
        if any(_dominant(cur, a) == "epoch" and _dominant(base, r) == "timestamp" for r in base.keys for a in cur.keys if _gone(base, cur, r) and _new(base, cur, a)):
            sig.append("timestamp format changed: text->epoch")
    elif base.kind == "csv" and abs(base.columns - cur.columns) >= 1:
        sig.append(f"column count changed: {base.columns:.0f}->{cur.columns:.0f}")
    if quarantine_rate > 0:
        sig.append(f"quarantine rate {quarantine_rate:.2f}")
    return Drift(round(score, 4), sig, {k: round(v, 4) for k, v in parts.items()})
