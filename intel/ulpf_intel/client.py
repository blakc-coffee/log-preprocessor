"""Admin API client (contracts/admin.openapi.yaml). The only thing the sidecar talks to.

Every request goes to one base URL and nowhere else. Retries are bounded and only for
transient failures (connection errors, 502/503/504); a 4xx is the caller's bug and is raised.
"""
from __future__ import annotations

import time
from typing import Any, Callable

import httpx

from .models import DriftAlert, DryRunResult, Proposal


class AdminError(Exception):
    """A non-transient error from the admin API (4xx) or an exhausted retry budget."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"{status} {code}: {message}")
        self.status, self.code, self.message = status, code, message


class AdminClient:
    def __init__(self, base_url: str = "http://127.0.0.1:9000", timeout: float = 5.0, retries: int = 3,
                 backoff: float = 0.5, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.base_url = base_url.rstrip("/")
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)
        self._retries, self._backoff, self._sleep = retries, backoff, sleep

    def close(self) -> None:
        self._http.close()

    def _call(self, method: str, path: str, **kw) -> httpx.Response:
        last: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                r = self._http.request(method, path, **kw)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as e:
                last = e
            else:
                if r.status_code in (502, 503, 504):
                    last = AdminError(r.status_code, "unavailable", r.text[:200])
                elif r.status_code >= 400:
                    try:
                        err = r.json()["error"]
                    except (ValueError, KeyError, TypeError):
                        err = {"code": "http_error", "message": r.text[:200]}
                    raise AdminError(r.status_code, err["code"], err["message"])
                else:
                    return r
            if attempt < self._retries:
                self._sleep(self._backoff * 2 ** attempt)
        raise AdminError(0, "unreachable", f"{method} {path}: {last}")

    def _json(self, method: str, path: str, **kw) -> Any:
        return self._call(method, path, **kw).json()

    # -- reads ----------------------------------------------------------------------------------
    def healthy(self) -> bool:
        try:
            self._call("GET", "/healthz")
            return True
        except AdminError:
            return False

    def telemetry(self) -> dict:
        return self._json("GET", "/admin/telemetry")

    def quarantine(self, source_id: str | None = None, status: str = "open", limit: int = 500) -> dict:
        p: dict[str, Any] = {"status": status, "limit": limit}
        if source_id:
            p["source_id"] = source_id
        return self._json("GET", "/admin/quarantine", params=p)

    def samples(self, source_id: str, status: str = "any", limit: int = 500) -> list[dict]:
        return self._json("GET", "/admin/samples", params={"source_id": source_id, "status": status, "limit": limit})["samples"]

    def parsers(self) -> list[dict]:
        return self._json("GET", "/admin/parsers")["parsers"]

    def parser_yaml(self, parser_id: str, version: str) -> str:
        return self._call("GET", f"/admin/parsers/{parser_id}/versions/{version}").text

    def drift_alerts(self) -> list[dict]:
        return self._json("GET", "/admin/drift")["alerts"]

    def proposals(self, status: str | None = None) -> list[dict]:
        return self._json("GET", "/admin/proposals", params={"status": status} if status else None)["proposals"]

    # -- writes (propose only: nothing here can change what the data plane runs) ------------------------
    def dryrun(self, yaml_text: str, source_id: str, sample_record_ids: list[int]) -> DryRunResult:
        body = {"yaml": yaml_text, "source_id": source_id, "sample_record_ids": sample_record_ids[:1000]}
        return DryRunResult.model_validate(self._json("POST", "/admin/parsers/dryrun", json=body))

    def post_drift(self, alert: DriftAlert) -> DriftAlert:
        return DriftAlert.model_validate(self._json("POST", "/admin/drift", json=alert.model_dump(mode="json")))

    def post_proposal(self, proposal: Proposal) -> Proposal:
        return Proposal.model_validate(self._json("POST", "/admin/proposals", json=proposal.model_dump(mode="json")))
