"""Per-source baselines, as JSON under state_dir. Derived data: deleting it loses nothing that
cannot be rebuilt from the data plane's samples, it only delays drift detection by one baseline."""
from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

MAX_BASELINE = 500


@dataclass
class SourceState:
    baseline: list[str] = field(default_factory=list)     # raw lines, base64, newest last, bounded
    parser_id: str = ""                                    # the parser that produced the baseline
    alert_id: str = ""                                     # the open drift alert we posted, if any
    proposal_ids: list[str] = field(default_factory=list)

    def baseline_lines(self) -> list[str]:
        return [base64.b64decode(b).decode("utf-8", "replace") for b in self.baseline]

    def set_baseline(self, lines: list[str]) -> None:
        self.baseline = [base64.b64encode(l.encode("utf-8", "replace")).decode() for l in lines[-MAX_BASELINE:]]


class State:
    def __init__(self, directory: str | Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, source_id: str) -> Path:
        return self.dir / (re.sub(r"[^A-Za-z0-9_.-]", "_", source_id) + ".json")

    def load(self, source_id: str) -> SourceState:
        try:
            return SourceState(**json.loads(self._path(source_id).read_text()))
        except (FileNotFoundError, ValueError, TypeError):
            return SourceState()

    def save(self, source_id: str, s: SourceState) -> None:
        p = self._path(source_id)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(s), sort_keys=True))
        os.replace(tmp, p)   # atomic: a crash leaves the old file, never half of a new one
