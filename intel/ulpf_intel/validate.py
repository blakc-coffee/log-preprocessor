"""Acceptance checks on a proposal before it is posted (PRD_CONTRACTS 5.6).

The authoritative dry-run is the data plane's `POST /admin/parsers/dryrun` (client.py).
`local_dry_run` runs the same measurements with the reference evaluator, for tests and
for a pre-check that costs no round trip. It never replaces the data plane's answer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from . import dsl_eval
from .models import DryRunFailure, DryRunResult, FieldStat


@dataclass(frozen=True)
class Thresholds:
    match_rate: float = 0.95
    mean_coverage: float = 0.9
    render_back_ok_rate: float = 0.95


_NOT_RE2 = [(r"\(\?<?[=!]", "lookaround"), (r"\\[1-9]", "backreference"), (r"\(\?<[A-Za-z]", "(?<name>) group: use (?P<name>)")]


def re2_violations(yaml_text: str) -> list[str]:
    """Patterns the Go engine (RE2) would refuse. Python's `re` accepts them, so a proposal that
    passes a Python test can still fail to load: this is the check that closes that gap."""
    doc = dsl_eval.load(yaml_text)
    pats = [("match.signature", (doc.get("match") or {}).get("signature"))]
    for e in doc["extractors"]:
        pats.append((f"extractor {e['id']} pattern", e.get("pattern")))
        pats.append((f"extractor {e['id']} skip_prefix", e.get("skip_prefix")))
    out = []
    for where, p in pats:
        if not p:
            continue
        for rx, what in _NOT_RE2:
            if re.search(rx, p):
                out.append(f"{where}: {what} is not RE2")
        try:
            re.compile(p)
        except re.error as e:
            out.append(f"{where}: {e}")
    return out


def local_dry_run(yaml_text: str, samples: list[tuple[int, str]], max_failures: int = 20) -> DryRunResult:
    doc = dsl_eval.load(yaml_text)
    parsed = 0
    cov = 0.0
    stats: dict[str, list[Any]] = {}
    failures: list[DryRunFailure] = []
    for rid, raw in samples:
        r = dsl_eval.extract(doc, raw)
        if r is None:
            if len(failures) < max_failures:
                failures.append(DryRunFailure(record_id=rid, error="no extractor matched"))
            continue
        parsed += 1
        cov += r.coverage
        for k, v in dsl_eval.flat(r.ocsf).items():
            stats.setdefault(k, []).append(v)
    n = len(samples)
    fs = {k: FieldStat(present=len(v), distinct=len(set(map(str, v))), sample=sorted({str(x) for x in v})[:3]) for k, v in sorted(stats.items())}
    warnings = []
    for k, st in fs.items():
        if parsed and st.present < parsed * 0.5:
            warnings.append(f"{k} present in only {st.present} of {parsed} parsed records")
    return DryRunResult(samples=n, parsed=parsed, failed=n - parsed, match_rate=round(parsed / n, 4) if n else 0.0,
                        mean_coverage=round(cov / parsed, 4) if parsed else 0.0, render_back_ok_rate=None,
                        field_stats=fs, failures=failures, warnings=warnings)


def acceptance(dry: DryRunResult, th: Thresholds = Thresholds()) -> list[str]:
    """Reasons the proposal misses its thresholds; empty means it passes. A miss is posted anyway, flagged."""
    why = []
    if dry.match_rate < th.match_rate:
        why.append(f"match_rate {dry.match_rate:.2f} < {th.match_rate}")
    if dry.mean_coverage < th.mean_coverage:
        why.append(f"mean_coverage {dry.mean_coverage:.2f} < {th.mean_coverage}")
    if dry.render_back_ok_rate is not None and dry.render_back_ok_rate < th.render_back_ok_rate:
        why.append(f"render_back_ok_rate {dry.render_back_ok_rate:.2f} < {th.render_back_ok_rate}")
    return why
