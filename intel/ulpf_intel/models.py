"""Pydantic mirrors of the contract types (pkg/types, contracts/uef.schema.json).

extra="forbid" everywhere: a field the Go side adds and this side does not know
about must fail loudly in tests/test_contract.py, not be silently dropped.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceRef(_M):
    record_id: int
    kind: str


class Entity(_M):
    type: str
    id: str
    role: str
    valid_from: Optional[datetime]
    valid_to: Optional[datetime]
    confidence: float
    evidence: list[EvidenceRef]


class IdentityFact(_M):
    kind: str
    action: str
    ip: str
    mac: str = ""
    host: str = ""
    user: str = ""
    at: datetime
    record_id: int
    source_id: str


class Coverage(_M):
    applicable: bool
    render_back_ok: Optional[bool]
    mapped_bytes: int
    unmapped_bytes: int
    constant_bytes: int
    uncovered_bytes: int
    mapped_fields: int
    unmapped_fields: int


class NormalizedEvent(_M):
    event_id: str
    record_id: int
    segment: int
    raw_sha256: str
    source_id: str
    vendor: str
    product: str
    parser_id: str
    parser_version: str
    template_id: str
    schema_version: str
    received_at: datetime
    event_time: Optional[datetime]
    time_from_receipt: bool
    parse_confidence: float
    integrity_flags: list[str]
    ocsf: dict[str, Any]
    unmapped: dict[str, Any]
    entities: list[Entity]
    identity: Optional[IdentityFact] = None
    coverage: Coverage
    current: bool


class QuarantineRecord(_M):
    record_id: int
    source_id: str
    failure_stage: str
    error: str
    received_at: datetime
    status: str
    resolved_by: str = ""


class DriftAlert(_M):
    id: str
    source_id: str
    parser_id: str
    score: float
    signals: list[str]
    quarantine_rate: float
    first_seen: datetime
    status: str


class TypedField(_M):
    field: str
    ocsf_path: str
    type: str
    confidence: float
    evidence: str
    alternatives: list[str] = []


class FieldStat(_M):
    present: int
    distinct: int
    sample: list[str]


class DryRunFailure(_M):
    record_id: int
    error: str


class DryRunResult(_M):
    samples: int
    parsed: int
    failed: int
    match_rate: float
    mean_coverage: float
    render_back_ok_rate: Optional[float]
    field_stats: dict[str, FieldStat]
    failures: list[DryRunFailure]
    warnings: list[str]


class Proposal(_M):
    id: str
    kind: str
    parser_id: str
    base_version: str
    source_id: str
    yaml: str
    drift_alert_id: str = ""
    cluster_size: int
    templates: list[str]
    sample_record_ids: list[int]
    typed_fields: list[TypedField]
    dry_run: Optional[DryRunResult]
    status: str
    created_at: datetime


# golden schema definition name -> model (only shapes that have a Go type)
MODELS: dict[str, type[BaseModel]] = {
    "normalized_event": NormalizedEvent,
    "drift_alert": DriftAlert,
    "proposal": Proposal,
    "dryrun_result": DryRunResult,
}
