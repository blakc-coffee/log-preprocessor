"""The sidecar loop (PRD_CONTRACTS 5.3): poll, detect drift, propose. Propose only.

Per source, per pass:
  1. fetch recent samples, parsed and quarantined
  2. compare them with the source's stored baseline; score drift
  3. above the threshold (or a high quarantine rate over enough samples): post a DriftAlert, once
  4. enough quarantined records of one shape: generate a proposal, dry-run it, post it, once
Nothing here touches the vault, the parser store or the pipeline.
"""
from __future__ import annotations

import base64
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .client import AdminClient, AdminError
from .fingerprint import Drift, drift_score, fingerprint, line_kind
from .models import DriftAlert, Proposal
from .propose import Generated, propose_csv, propose_json, propose_kv, propose_kv_patch, propose_text
from .state import State
from .validate import Thresholds, acceptance, re2_violations

log = logging.getLogger("ulpf_intel")


@dataclass
class Config:
    poll_interval: float = 5.0
    sample_limit: int = 500
    min_samples: int = 50
    min_cluster: int = 50
    drift_threshold: float = 0.35
    quarantine_rate_threshold: float = 0.2
    dominant_share: float = 0.8
    timezone: str = "+00:00"          # for formats that carry no zone; the data plane's per-source setting wins there
    thresholds: Thresholds = field(default_factory=Thresholds)


@dataclass
class Outcome:
    source_id: str
    action: str = "none"              # none | baseline | alert | proposal | skipped
    reason: str = ""
    score: float = 0.0
    alert_id: str = ""
    proposal_id: str = ""


def _raw(sample: dict) -> str:
    return base64.b64decode(sample["raw_base64"]).decode("utf-8", "replace")


def _dominant_shape(lines: list[str], kind: str) -> float:
    """Share of the quarantined lines that have the modal structure. PRD 5.3 asks for a dominant *template*, but
    Drain3 splits on whitespace and a CSV row has almost none, so for csv and kv the structure is the field count
    or the key set (within 0.9 Jaccard of the most common one)."""
    from .fingerprint import fields
    if kind == "csv":
        counts = Counter(len(fields(l, "csv")) for l in lines)
        return counts.most_common(1)[0][1] / len(lines)
    sets = [frozenset(fields(l, "kv")) for l in lines]
    modal = Counter(sets).most_common(1)[0][0]
    return sum(len(s & modal) / max(1, len(s | modal)) >= 0.9 for s in sets) / len(lines)


class Sidecar:
    def __init__(self, client: AdminClient, state: State, cfg: Config | None = None,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        self.client, self.state, self.cfg, self.now = client, state, cfg or Config(), now

    def sources(self) -> list[str]:
        ids = {s["id"] for s in self.client.telemetry().get("sources", [])}
        ids |= {s["source_id"] for s in self.client.quarantine(limit=1).get("summary", [])}
        return sorted(ids)

    def run_once(self) -> list[Outcome]:
        out = []
        alerts = {a["id"]: a for a in self.client.drift_alerts()}
        proposals = self.client.proposals()
        for src in self.sources():
            try:
                out.append(self._source(src, alerts, proposals))
            except AdminError as e:
                log.warning("source %s: %s", src, e)
                out.append(Outcome(src, "skipped", str(e)))
        return out

    def run_forever(self, sleep: Callable[[float], None], stop: Callable[[], bool] = lambda: False) -> None:
        while not stop():
            try:
                for o in self.run_once():
                    if o.action not in ("none",):
                        log.info("%s: %s %s", o.source_id, o.action, o.reason)
            except AdminError as e:
                log.warning("admin API: %s", e)
            sleep(self.cfg.poll_interval)

    # ------------------------------------------------------------------------------------------------
    def _source(self, src: str, alerts: dict[str, dict], proposals: list[dict]) -> Outcome:
        c = self.cfg
        samples = self.client.samples(src, "any", c.sample_limit)
        if len(samples) < c.min_samples:
            return Outcome(src, "none", f"{len(samples)} samples, need {c.min_samples}")
        parsed = [s for s in samples if s["status"] == "parsed"]
        quar = [s for s in samples if s["status"] == "quarantined"]
        qrate = len(quar) / len(samples)
        st = self.state.load(src)
        parser_id = Counter(s["parser_id"] for s in parsed).most_common(1)[0][0] if parsed else ""

        if st.baseline:
            drift = drift_score(fingerprint(st.baseline_lines()), fingerprint([_raw(s) for s in samples]), qrate)
        else:
            drift = Drift(round(qrate, 4), ["no baseline: this source has never parsed", f"quarantine rate {qrate:.2f}"], {})

        if drift.score < c.drift_threshold and qrate <= c.quarantine_rate_threshold:
            if parsed:   # healthy: this is what "normal" looks like now
                st.set_baseline([_raw(s) for s in parsed])
                st.parser_id, st.alert_id = parser_id or st.parser_id, ""
                self.state.save(src, st)
                return Outcome(src, "baseline", "refreshed", drift.score)
            return Outcome(src, "none", "no parsed samples to baseline", drift.score)

        # ---- drift: one alert -------------------------------------------------------------------
        existing = alerts.get(st.alert_id)
        if existing and existing["status"] in ("open", "proposed"):
            alert_id = existing["id"]
        else:
            posted = self.client.post_drift(DriftAlert(id="", source_id=src, parser_id=parser_id or st.parser_id, score=drift.score,
                                                       signals=drift.signals, quarantine_rate=round(qrate, 4), first_seen=self.now(), status="open"))
            alert_id = st.alert_id = posted.id
            self.state.save(src, st)
            log.info("drift alert %s for %s: score %.2f", alert_id, src, drift.score)

        # ---- proposal: once per alert -----------------------------------------------------------
        if len(quar) < c.min_cluster:
            return Outcome(src, "alert", f"{len(quar)} quarantined, need {c.min_cluster} for a proposal", drift.score, alert_id)
        if any(p["source_id"] == src and p["status"] in ("pending", "approved") and
               (p.get("drift_alert_id") == alert_id or p["parser_id"] == (parser_id or p["parser_id"])) for p in proposals):
            return Outcome(src, "alert", "a pending or approved proposal already exists", drift.score, alert_id)

        gen = self._generate(src, [_raw(s) for s in quar], [s["record_id"] for s in quar], parser_id, alert_id)
        if gen is None:
            return Outcome(src, "alert", "no proposal: unsupported shape or no dominant template", drift.score, alert_id)
        p = gen.proposal
        warnings = list(gen.warnings)
        if c.timezone and "layout" in p.yaml and "epoch" not in p.yaml and "-0700" not in p.yaml and "rfc3339" not in p.yaml:
            warnings.append(f"timestamps carry no zone: assumed {c.timezone}; set the source's timezone in the data-plane config if wrong")
        warnings += [f"not RE2: {v}" for v in re2_violations(p.yaml)]
        dry = self.client.dryrun(p.yaml, src, p.sample_record_ids)
        warnings += [f"acceptance: {r}" for r in acceptance(dry, c.thresholds)]
        dry.warnings = warnings + dry.warnings
        p.dry_run, p.drift_alert_id, p.created_at = dry, alert_id, self.now()
        posted = self.client.post_proposal(p)   # a proposal that misses its thresholds is posted anyway, flagged
        st.proposal_ids.append(posted.id)
        self.state.save(src, st)
        proposals.append(posted.model_dump(mode="json"))
        log.info("proposal %s for %s (match_rate %.2f, %d warnings)", posted.id, src, dry.match_rate, len(dry.warnings))
        return Outcome(src, "proposal", f"match_rate {dry.match_rate:.2f}", drift.score, alert_id, posted.id)

    def _generate(self, src: str, lines: list[str], ids: list[int], parser_id: str, alert_id: str) -> Generated | None:
        c = self.cfg
        kind = Counter(line_kind(l) for l in lines).most_common(1)[0][0]
        now = self.now()
        if kind in ("csv", "kv") and _dominant_shape(lines, kind) < c.dominant_share:
            return None
        if kind == "csv":
            return propose_csv(src, lines, ids, now, alert_id, c.timezone)
        if kind == "json":
            return propose_json(src, lines, ids, now, alert_id, c.timezone, c.min_cluster)
        if kind == "text":
            return propose_text(src, lines, ids, now, alert_id, c.timezone, c.min_cluster)
        if kind == "kv":
            active = next((p["active_version"] for p in self.client.parsers() if p["id"] == parser_id), None) if parser_id else None
            if active:   # a source that used to parse and drifted: patch its parser
                return propose_kv_patch(src, self.client.parser_yaml(parser_id, active), active, lines, ids, now, alert_id)
            return propose_kv(src, lines, ids, now, alert_id, c.timezone)   # never had a parser: a new one
        return None
