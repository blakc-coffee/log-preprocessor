"""Semantic field typing from value shapes (PRD_CONTRACTS 5.5). Rules and statistics, no model.

Input: columns of raw values (a kv key, a JSON path, a headerless CSV position).
Output: a Typed per column with an OCSF path, or an abstention (ocsf_path == "") the
reviewer sees. Deterministic: sorted iteration, no randomness.

Confidence = 0.6 * match_share + 0.25 * name_hint_agreement + 0.15 * positional_prior.
A headerless column has no name to agree or disagree with, so its name term is neutral
(0.5), not zero: otherwise every headerless column would cap at 0.75 for a reason
unrelated to how well its values fit.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime

from .models import TypedField

MIN_CONFIDENCE = 0.6

WELL_KNOWN = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 445, 465, 514, 587, 636, 993, 995,
              1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}
PROTO_NAME = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "132": "sctp"}
PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "sctp": 132}
PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "sctp", "6", "17", "1", "58"}
ACTIONS = {"allow", "allowed", "permit", "permitted", "accept", "accepted", "pass", "passed", "deny", "denied", "drop",
           "dropped", "block", "blocked", "reject", "rejected", "alert", "built", "teardown", "close", "closed",
           "reset", "reset-client", "reset-server", "reset-both", "client-rst", "server-rst", "timeout"}
SEVERITIES = {"low", "medium", "high", "critical", "info", "informational", "notice", "warning", "warn", "error",
              "debug", "emergency", "alert", "fatal"}
ACTION_ENUM = {"allow": 1, "allowed": 1, "permit": 1, "permitted": 1, "accept": 1, "accepted": 1, "pass": 1, "passed": 1,
               "close": 1, "closed": 1, "built": 1, "teardown": 1, "timeout": 1, "deny": 2, "denied": 2, "drop": 2,
               "dropped": 2, "block": 2, "blocked": 2, "reject": 2, "rejected": 2, "reset": 2, "reset-client": 2,
               "reset-server": 2, "reset-both": 2, "client-rst": 2, "server-rst": 2}

SEVERITY_ENUM = {"emergency": 6, "fatal": 6, "alert": 5, "critical": 5, "error": 4, "high": 4, "warning": 3, "warn": 3, "medium": 3,
                 "notice": 2, "low": 2, "information": 1, "informational": 1, "info": 1, "debug": 1}
SRC_HINTS = ("src", "source", "sip", "client", "orig", "sender")
DST_HINTS = ("dst", "dest", "destination", "dip", "server", "resp", "recipient")
TIME_HINTS = ("time", "timestamp", "date", "ts", "eventtime", "datetime")

# (python strptime format, Go layout)
LAYOUTS = [
    ("%Y/%m/%d %H:%M:%S", "2006/01/02 15:04:05"),
    ("%Y-%m-%d %H:%M:%S", "2006-01-02 15:04:05"),
    ("%b %d %H:%M:%S", "Jan _2 15:04:05"),
    ("%d/%b/%Y:%H:%M:%S %z", "02/Jan/2006:15:04:05 -0700"),
    ("%b %d %Y %H:%M:%S", "Jan _2 2006 15:04:05"),
]
_RFC3339 = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?$")
_MAC = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_EMAIL = re.compile(r"^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$")
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://\S+$", re.I)
_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_USER = re.compile(r"^(?:[\w.-]+\\)?[A-Za-z][\w.-]{1,31}$")
_HOST = re.compile(r"^(?=.*[-.])[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)*$")


@dataclass
class Column:
    name: str            # kv key, JSON path, or col_N
    values: list[str]
    named: bool = True   # False for headerless positions: the name says nothing
    position: int = 0    # order of appearance, the positional prior


@dataclass
class Typed:
    field: str
    type: str
    ocsf_path: str
    confidence: float
    evidence: str
    alternatives: list[str] = field(default_factory=list)
    layout: str = ""                      # Go layout or epoch_s|epoch_ms|epoch_us|epoch_ns, for type timestamp
    enum: dict[str, Any] = field(default_factory=dict)  # suggested value map for action columns

    def model(self) -> TypedField:
        return TypedField(field=self.field, ocsf_path=self.ocsf_path, type=self.type, confidence=round(self.confidence, 3),
                          evidence=self.evidence, alternatives=self.alternatives)


@dataclass
class _Cand:
    type: str
    share: float
    detail: str = ""
    layout: str = ""


def _ip_ok(v: str) -> int:
    try:
        return ipaddress.ip_address(v).version
    except ValueError:
        return 0


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def _internal(v: str) -> bool:
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return False
    # Explicit ranges, mirroring pkg/dataplane/identity: ipaddress.is_private also
    # covers the RFC 5737 documentation ranges the fixtures use for "external".
    return any(a in n for n in _INTERNAL if a.version == n.version)


_DATE = re.compile(r"^\d{4}-\d\d-\d\d$")
_TOD = re.compile(r"^\d\d:\d\d:\d\d$")


def _layout(values: list[str]) -> tuple[str, float]:
    best, share = "", 0.0
    if all(_DATE.match(v) for v in values):
        return "2006-01-02", 1.0            # a date on its own: propose.py joins it with a time-of-day key
    if all(_TOD.match(v) for v in values):
        return "15:04:05", 1.0
    if all(_RFC3339.match(v) for v in values):
        if all(re.search(r"(?:Z|[+-]\d\d:\d\d)$", v) for v in values):
            return "rfc3339", 1.0
        # Go's RFC3339 layout wants a colon in the offset; +0530 needs its own layout
        frac = all("." in v for v in values)
        return ("2006-01-02T15:04:05.999999-0700" if frac else "2006-01-02T15:04:05-0700"), 1.0
    for py, go in LAYOUTS:
        ok = 0
        for v in values:
            try:
                # year-less layouts parse under a leap year: Python 3.13 warns that "Feb 29" is ambiguous otherwise
                datetime.strptime(v, py) if "%Y" in py else datetime.strptime("2000 " + v, "%Y " + py)
                ok += 1
            except ValueError:
                pass
        if ok / len(values) > share:
            best, share = go, ok / len(values)
    ints = [int(v) for v in values if v.isdigit() and not v.startswith("0")]  # 0018... is an id, not an epoch
    if len(ints) / len(values) > share:
        for unit, lo, hi in (("epoch_s", 1e9, 4e9), ("epoch_ms", 1e12, 4e12), ("epoch_us", 1e15, 4e15), ("epoch_ns", 1e18, 4e18)):
            s = sum(lo <= i < hi for i in ints) / len(values)
            if s > share:
                best, share = unit, s
    return best, share


def _candidates(values: list[str]) -> list[_Cand]:
    n = len(values)
    low = [v.lower() for v in values]
    out: list[_Cand] = []

    def add(t: str, k: int, detail: str = "", layout: str = ""):
        if k:
            out.append(_Cand(t, k / n, detail, layout))

    v4 = sum(_ip_ok(v) == 4 for v in values)
    v6 = sum(_ip_ok(v) == 6 for v in values)
    if v4 >= v6:
        add("ipv4", v4, f"{100 * v4 / n:.0f}% of values parse as IPv4")
    else:
        add("ipv6", v6, f"{100 * v6 / n:.0f}% of values parse as IPv6")
    add("mac", sum(bool(_MAC.match(v)) for v in values), "MAC address pattern")
    add("uuid", sum(bool(_UUID.match(v)) for v in values), "UUID pattern")
    add("email", sum(bool(_EMAIL.match(v)) for v in values), "email pattern")
    add("url", sum(bool(_URL.match(v)) for v in values), "URL pattern")
    add("hash", sum(bool(_HASH.match(v)) for v in values), "32/40/64 hex digits")
    ints = [int(v) for v in values if re.fullmatch(r"\d{1,20}", v)]
    lay, share = _layout(values)
    if lay and share >= 0.6:
        add({"2006-01-02": "date", "15:04:05": "time_of_day"}.get(lay, "timestamp"), round(share * n), f"layout {lay}", lay)
    if len(ints) == n:
        ports = [i for i in ints if 0 <= i <= 65535]
        wk = sum(i in WELL_KNOWN for i in ints) / n
        eph = sum(1024 <= i <= 65535 for i in ints) / n
        card = len(set(ints)) / n
        if len(ports) == n and (wk >= 0.5 or (eph >= 0.8 and card >= 0.1 and len(set(ints)) >= 3)):
            add("port", n, f"integers in 0-65535; {100 * wk:.0f}% well-known, {100 * eph:.0f}% ephemeral")
        add("integer", n, "non-negative integers")
    add("protocol", sum(v in PROTOCOLS for v in low), "small enum drawn from tcp/udp/icmp or 6/17/1")
    add("action", sum(v in ACTIONS for v in low), "values drawn from the action lexicon")
    add("severity", sum(v in SEVERITIES or (v.isdigit() and 0 <= int(v) <= 10) for v in low), "values drawn from the severity lexicon")
    add("username", sum(bool(_USER.match(v)) and not v.isdigit() for v in values), "word-like, optional DOMAIN\\ prefix")
    add("hostname", sum(bool(_HOST.match(v)) and _ip_ok(v) == 0 for v in values), "dotted or hyphenated labels")
    return sorted(out, key=lambda c: (-c.share, c.type))


def _hint(name: str, words: tuple[str, ...]) -> bool:
    n = name.lower()
    return any(re.search(rf"(?:^|[._\-])({w})(?:[._\-]|$|ip|port|addr|mac|country|intf)", n) or n.startswith(w) for w in words)


def _stats(c: Column) -> dict:
    vals = [v for v in c.values if v != ""]
    return {"vals": vals, "empty": 1 - len(vals) / len(c.values) if c.values else 1.0, "card": len(set(vals)) / len(vals) if vals else 0.0, "distinct": len(set(vals))}


def type_columns(cols: list[Column], min_confidence: float = MIN_CONFIDENCE) -> list[Typed]:
    """Type every column, then assign OCSF roles across columns (which IP is the source)."""
    info: dict[str, dict] = {}
    for c in cols:
        st = _stats(c)
        cands = _candidates(st["vals"]) if st["vals"] else []
        st["cands"] = cands
        st["top"] = {k.type: k for k in cands}
        info[c.name] = st

    def cand(name: str, t: str) -> _Cand | None:
        return info[name]["top"].get(t)

    def conf(share: float, hint: float, prior: float) -> float:
        return 0.6 * share + 0.25 * hint + 0.15 * prior

    results: dict[str, Typed] = {}

    def put(c: Column, t: str, path: str, share: float, hint: float, prior: float, evidence: str, **kw):
        results[c.name] = Typed(c.name, t, path, conf(share, hint, prior), evidence, **kw)

    # -- IPs ---------------------------------------------------------------------
    ipcols = [c for c in cols if (cand(c.name, "ipv4") or cand(c.name, "ipv6")) and info[c.name]["distinct"] > 1
              and (cand(c.name, "ipv4") or cand(c.name, "ipv6")).share >= 0.9]
    def ipc(c: Column) -> _Cand:
        return cand(c.name, "ipv4") or cand(c.name, "ipv6")
    max_card = max((info[c.name]["card"] for c in ipcols), default=1) or 1

    def internal_share(c: Column) -> float:
        v = info[c.name]["vals"]
        return sum(_internal(x) for x in v) / len(v)

    hinted = {c.name: ("src" if _hint(c.name, SRC_HINTS) else "dst" if _hint(c.name, DST_HINTS) else "") for c in ipcols if c.named}
    src_pick = dst_pick = None
    srcs = [c for c in ipcols if hinted.get(c.name) == "src"]
    dsts = [c for c in ipcols if hinted.get(c.name) == "dst"]
    if srcs:
        src_pick = srcs[0]
    else:
        pool = [c for c in ipcols if not hinted.get(c.name)]
        if pool:
            def sscore(c: Column) -> float:
                return 0.5 * internal_share(c) + 0.3 * (c is ipcols[0]) + 0.2 * info[c.name]["card"] / max_card
            src_pick = max(pool, key=lambda c: (round(sscore(c), 6), -c.position))
    if dsts:
        dst_pick = dsts[0]
    else:
        pool = [c for c in ipcols if c is not src_pick and not hinted.get(c.name)]
        if pool:
            dst_pick = pool[0]  # first remaining address column, by position
            rest = [c for c in pool[1:] if internal_share(c) == internal_share(dst_pick)]
    for c, role, path in ((src_pick, "src", "src_endpoint.ip"), (dst_pick, "dst", "dst_endpoint.ip")):
        if c is None:
            continue
        k = ipc(c)
        h = 1.0 if hinted.get(c.name) == role else 0.5
        prior = (0.5 * internal_share(c) + 0.3 * (c is ipcols[0]) + 0.2) if role == "src" else (0.7 if c.position > (src_pick.position if src_pick else -1) else 0.5)
        ev = f"{k.detail}; {'internal' if internal_share(c) > 0.5 else 'external'} ranges ({100 * internal_share(c):.0f}% private); " \
             f"cardinality {info[c.name]['distinct']}; " + ("name says " + role if h == 1.0 else f"{'first' if role == 'src' else 'next'} address column")
        put(c, k.type, path, k.share, h, prior, ev)
        # a second plausible address column for the same role lowers confidence and is shown
        others = [o for o in ipcols if o is not c and o not in (src_pick, dst_pick) and not hinted.get(o.name)]
        if role == "dst" and others:
            results[c.name].confidence = max(0.0, results[c.name].confidence - 0.1)
            results[c.name].alternatives = ["src_endpoint.ip"] if False else []
            results[c.name].evidence += f"; {others[0].name} is also a plausible destination"
    for c in cols:
        if c.name in results or c not in ipcols and not (cand(c.name, "ipv4") or cand(c.name, "ipv6")):
            continue
        if c in ipcols and c.name not in results:
            k = ipc(c)
            results[c.name] = Typed(c.name, k.type, "", 0.5 * k.share, k.detail + "; an address column but not the source or destination (e.g. NAT)")
        elif not info[c.name]["distinct"] > 1 and (cand(c.name, "ipv4") or cand(c.name, "ipv6")):
            k = ipc(c)
            results[c.name] = Typed(c.name, k.type, "", 0.5 * k.share, "single constant address; carries no per-event signal")

    # -- ports: ephemeral first column is the source, well-known first column the destination ------
    portcols = [c for c in cols if cand(c.name, "port") and cand(c.name, "port").share >= 0.99]
    def wk(c: Column) -> float:
        return sum(int(v) in WELL_KNOWN for v in info[c.name]["vals"]) / len(info[c.name]["vals"])
    sp = next((c for c in portcols if c.named and _hint(c.name, SRC_HINTS + ("s",)) and "port" in c.name.lower()), None) or \
        next((c for c in portcols if wk(c) < 0.5), None)
    dp = next((c for c in portcols if c.named and _hint(c.name, DST_HINTS + ("d",)) and "port" in c.name.lower()), None) or \
        next((c for c in portcols if wk(c) >= 0.5), None)
    for c, path, role in ((sp, "src_endpoint.port", "src"), (dp, "dst_endpoint.port", "dst")):
        if c is None:
            continue
        k = cand(c.name, "port")
        h = 1.0 if c.named and "port" in c.name.lower() and (_hint(c.name, SRC_HINTS) or _hint(c.name, DST_HINTS)) else 0.5
        prior = 1.0 if (role == "src") == (wk(c) < 0.5) else 0.4
        ev = k.detail + ("; ephemeral: source port" if role == "src" else "; well-known: destination port")
        twins = [o for o in portcols if o is not c and o is not sp and o is not dp and info[o.name]["vals"] == info[c.name]["vals"]]
        if twins:
            ev += f"; {twins[0].name} has identical values (likely a NAT copy)"
        put(c, "port", path, k.share, h, prior, ev)
        if twins:
            results[c.name].confidence -= 0.1
    for c in portcols:
        if c.name not in results:
            results[c.name] = Typed(c.name, "port", "", 0.5, "port-like values but not the source or destination port")

    # -- timestamps: first column is the event time ---------------------------------------------
    tcols = [c for c in cols if cand(c.name, "timestamp") and cand(c.name, "timestamp").share >= 0.9]
    hinted_t = [c for c in tcols if c.named and _hint(c.name, TIME_HINTS)]
    tpick = (hinted_t or tcols or [None])[0]
    for c in tcols:
        k = cand(c.name, "timestamp")
        if c is tpick:
            put(c, "timestamp", "time", k.share, 1.0 if c in hinted_t else 0.5, 1.0, f"{k.detail}; first timestamp column", layout=k.layout)
        else:
            results[c.name] = Typed(c.name, "timestamp", "", 0.5, f"{k.detail}; a later timestamp column (kept unmapped)", layout=k.layout)

    # -- the rest: protocol, action, severity, mac, username, hostname, ... --------------------
    taken_action = None
    acols = [c for c in cols if cand(c.name, "action") and cand(c.name, "action").share >= 0.9 and info[c.name]["distinct"] <= 12]
    if acols:
        taken_action = max(acols, key=lambda c: (cand(c.name, "action").share, -c.position))
    for c in cols:
        if c.name in results:
            continue
        st = info[c.name]
        if not st["vals"]:
            results[c.name] = Typed(c.name, "empty", "", 0.0, "no values in the sample")
            continue
        p = cand(c.name, "protocol")
        numeric = all(v.isdigit() for v in st["vals"])
        if p and p.share >= 0.9 and st["distinct"] <= 8 and not (numeric and st["distinct"] < 2):  # a constant 1 is a flag, not ICMP
            put(c, "protocol", "connection_info.protocol_num" if numeric else "connection_info.protocol_name", p.share, 0.5, 0.5, p.detail,
                enum=({v: PROTO_NAME[v] for v in sorted(set(st["vals"])) if v in PROTO_NAME} if numeric
                      else {v: PROTO_NUM[v.lower()] for v in sorted(set(st["vals"])) if v.lower() in PROTO_NUM}))
            continue
        if c is taken_action:
            k = cand(c.name, "action")
            vals = sorted(set(v.lower() for v in st["vals"]))
            put(c, "action", "action_id", k.share, 1.0 if c.named and "action" in c.name.lower() else 0.5, 0.5,
                f"{k.detail}: {', '.join(vals)}", enum={v: ACTION_ENUM[v] for v in vals if v in ACTION_ENUM})
            continue
        sev = cand(c.name, "severity")
        if sev and sev.share >= 0.95 and st["distinct"] <= 10 and c.named and re.search(r"sev|level|prio", c.name.lower()):
            words = sorted({v.lower() for v in st["vals"] if not v.isdigit()})
            put(c, "severity", "severity_id", sev.share, 1.0, 0.5, sev.detail, enum={w: SEVERITY_ENUM[w] for w in words if w in SEVERITY_ENUM})
            continue
        for part in ("date", "time_of_day"):
            d = cand(c.name, part)
            if d and d.share >= 0.95:
                results[c.name] = Typed(c.name, part, "", 0.5, f"layout {d.layout}: half of a timestamp; joined with its partner by the proposal", layout=d.layout)
                break
        if c.name in results:
            continue
        m = cand(c.name, "mac")
        if m and m.share >= 0.95:
            put(c, "mac", "src_endpoint.mac" if c.named and _hint(c.name, SRC_HINTS) else "", m.share, 0.5, 0.5, m.detail)
            continue
        u = cand(c.name, "username")
        if u and u.share >= 0.9 and st["distinct"] >= 2 and (c.named and re.search(r"user|usr|account|login", c.name.lower()) or "\\" in "".join(st["vals"])):
            put(c, "username", "actor.user.name", u.share, 1.0 if c.named and re.search(r"user|usr", c.name.lower()) else 0.5, 0.5,
                f"{u.detail}; {st['distinct']} distinct, {100 * st['empty']:.0f}% empty")
            continue
        for t in ("url", "email", "uuid", "hash"):
            k = cand(c.name, t)
            if k and k.share >= 0.95:
                results[c.name] = Typed(c.name, t, "", 0.6 * k.share, k.detail)
                break
        else:
            i = cand(c.name, "integer")
            top = st["cands"][0] if st["cands"] else None
            if i and i.share >= 0.99:
                results[c.name] = Typed(c.name, "integer", "", 0.5, f"{st['distinct']} distinct non-negative integers; no OCSF slot inferred")
            else:
                results[c.name] = Typed(c.name, "string", "", 0.4, f"{st['distinct']} distinct values" + (f"; closest type {top.type} at {100 * top.share:.0f}%" if top else ""))

    out = []
    for c in cols:
        t = results[c.name]
        t.confidence = round(max(0.0, min(1.0, t.confidence)), 3)
        if t.ocsf_path and t.confidence < min_confidence:
            t.evidence += f"; abstained: confidence {t.confidence:.2f} < {min_confidence}"
            t.alternatives = [t.ocsf_path]
            t.ocsf_path = ""
        out.append(t)
    return out
