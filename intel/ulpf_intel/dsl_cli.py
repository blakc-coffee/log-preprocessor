"""python -m ulpf_intel.dsl_cli: the reference evaluator over stdin/stdout, one JSON object per line.

Request : {"yaml": "<parser document>", "raw": "<record>", "received_at": "<RFC 3339, optional>"}
Response: {"load_error": "..."}  or  {"matched": false}  or
          {"matched": true, "extractor": id, "ocsf": {...}, "unmapped": {...}, "flags": [...]}

It exists so the language-neutral conformance cases (contracts/conformance/cases.json) can be run
against an independent implementation before the data plane's engine exists.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime

from . import dsl_eval


def handle(req: dict, cache: dict) -> dict:
    y = req["yaml"]
    if y not in cache:
        try:
            doc = dsl_eval.load(y)
            dsl_eval.validate_parser(doc)
            cache[y] = doc
        except (ValueError, KeyError, TypeError) as e:
            cache[y] = str(e) if isinstance(e, ValueError) else f"invalid parser document: {e!r}"
    doc = cache[y]
    if isinstance(doc, str):
        return {"load_error": doc}
    ra = datetime.fromisoformat(req["received_at"].replace("Z", "+00:00")) if req.get("received_at") else None
    r = dsl_eval.extract(doc, req["raw"], ra)
    if r is None:
        return {"matched": False}
    return {"matched": True, "extractor": r.extractor, "ocsf": r.ocsf, "unmapped": r.unmapped, "flags": r.flags,
            "coverage": {"mapped_bytes": r.mapped_bytes, "unmapped_bytes": r.unmapped_bytes, "raw_len": r.raw_len}}


def main() -> int:
    cache: dict = {}
    for line in sys.stdin:
        if not line.strip():
            continue
        sys.stdout.write(json.dumps(handle(json.loads(line), cache)) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
