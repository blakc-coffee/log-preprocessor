"""An in-memory data-plane admin API for the loop tests, built on httpx.MockTransport (no sockets).

It implements only what the sidecar calls, validates every request body it receives against the contract
schema, and answers dry-runs with the reference evaluator. Every request is recorded so tests can assert
what the sidecar did and, as important, what it did not do.
"""
import base64
import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from jsonschema import Draft202012Validator, FormatChecker

from ulpf_intel.validate import local_dry_run

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "contracts" / "uef.schema.json").read_text())


def _validator(defn):
    return Draft202012Validator({"$schema": SCHEMA["$schema"], "$ref": f"#/$defs/{defn}", "$defs": SCHEMA["$defs"]}, format_checker=FormatChecker())


class FakeAdmin:
    def __init__(self):
        self.samples: dict[str, list[dict]] = {}     # source -> [{record_id, raw, status, parser_id}]
        self.parsers: dict[str, dict] = {}           # id -> {active_version, yaml}
        self.alerts: list[dict] = []
        self.proposals: list[dict] = []
        self.requests: list[tuple[str, str, str]] = []   # (method, host, path)
        self.fail_next: list[int] = []
        self.transport = httpx.MockTransport(self.handle)

    def set(self, source, lines, status, parser_id="", start=1):
        rows = self.samples.setdefault(source, [])
        base = max((r["record_id"] for r in rows), default=start - 1)
        rows.extend({"record_id": base + i + 1, "raw": l, "status": status, "parser_id": parser_id} for i, l in enumerate(lines))

    def clear(self, source):
        self.samples[source] = []

    def _json(self, code, body):
        return httpx.Response(code, json=body)

    def handle(self, req: httpx.Request) -> httpx.Response:
        u = urlparse(str(req.url))
        self.requests.append((req.method, u.netloc, u.path))
        if self.fail_next:
            return httpx.Response(self.fail_next.pop(0), json={"error": {"code": "unavailable", "message": "try later"}})
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        path, m = u.path, req.method
        if path == "/healthz":
            return httpx.Response(200, text="ok")
        if path == "/admin/telemetry":
            return self._json(200, {"sources": [{"id": s, "eps": 1.0, "records": len(r)} for s, r in sorted(self.samples.items())]})
        if path == "/admin/quarantine":
            summ = [{"source_id": s, "open": sum(x["status"] == "quarantined" for x in r), "resolved": 0, "ignored": 0, "by_stage": {}}
                    for s, r in sorted(self.samples.items()) if any(x["status"] == "quarantined" for x in r)]
            return self._json(200, {"records": [], "next_cursor": None, "summary": summ})
        if path == "/admin/samples":
            rows = self.samples.get(q["source_id"], [])
            if q.get("status", "any") != "any":
                rows = [r for r in rows if r["status"] == q["status"]]
            rows = rows[-int(q.get("limit", 100)):]
            return self._json(200, {"samples": [{"record_id": r["record_id"], "source_id": q["source_id"], "raw_base64": base64.b64encode(r["raw"].encode()).decode(),
                                                 "received_at": "2026-09-28T03:30:00Z", "status": r["status"], "parser_id": r["parser_id"]} for r in rows]})
        if path == "/admin/parsers":
            return self._json(200, {"parsers": [{"id": i, "active_version": p["active_version"], "versions": [p["active_version"]], "vendor": "v", "product": "p", "signature": "."}
                                                for i, p in sorted(self.parsers.items())]})
        if mm := re.fullmatch(r"/admin/parsers/(\w+)/versions/([\d.]+)", path):
            return httpx.Response(200, text=self.parsers[mm[1]]["yaml"], headers={"content-type": "text/yaml"})
        if path == "/admin/drift":
            if m == "GET":
                return self._json(200, {"alerts": self.alerts})
            body = json.loads(req.content)
            errs = list(_validator("drift_alert").iter_errors(body))
            assert not errs, f"sidecar posted an invalid DriftAlert: {errs[0].message}"
            hit = next((a for a in self.alerts if a["source_id"] == body["source_id"] and a["parser_id"] == body["parser_id"] and a["status"] in ("open", "proposed")), None)
            if hit:
                return self._json(200, hit)
            body = dict(body, id=f"drift-{len(self.alerts) + 1}", status="open")
            self.alerts.append(body)
            return self._json(201, body)
        if path == "/admin/proposals":
            if m == "GET":
                return self._json(200, {"proposals": [p for p in self.proposals if "status" not in q or p["status"] == q["status"]]})
            body = json.loads(req.content)
            errs = list(_validator("proposal").iter_errors(body))
            assert not errs, f"sidecar posted an invalid Proposal: {errs[0].message} at {list(errs[0].path)}"
            body = dict(body, id=f"prop-{len(self.proposals) + 1}")
            self.proposals.append(body)
            return self._json(201, body)
        if path == "/admin/parsers/dryrun":
            body = json.loads(req.content)
            by_id = {r["record_id"]: r["raw"] for rows in self.samples.values() for r in rows}
            sm = [(i, by_id[i]) for i in body.get("sample_record_ids", []) if i in by_id]
            res = json.loads(local_dry_run(body["yaml"], sm).model_dump_json())
            errs = list(_validator("dryrun_result").iter_errors(res))
            assert not errs, errs[0].message
            return self._json(200, res)
        return self._json(404, {"error": {"code": "not_found", "message": f"{m} {path}"}})
