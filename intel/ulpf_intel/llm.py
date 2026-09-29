"""Optional refinement (PRD A-14, P2): a LOCAL model suggests names for the columns the typer could not map.

Off unless --llm-endpoint is given, and never on the required path. What it may change is deliberately tiny: it names
positions that are currently anonymous (`_` in a csv `columns:` list), so the record's unmapped values show up as
`application` instead of `col_14`. It cannot touch a mapping, a pattern, a type or an OCSF path; whatever it returns
goes through the same dry-run and human approval as everything else.

Air-gap: the endpoint must be loopback (a model server on this machine). Anything else is refused before a byte is sent.
Privacy: the prompt carries at most SAMPLE distinct values per column, never a whole record.
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

import httpx
import yaml

SAMPLE = 5
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,30}$")
_ANON = re.compile(r"^(?:col|slot|v)_?\d+$")


def require_loopback(endpoint: str) -> None:
    host = urlparse(endpoint).hostname or ""
    try:
        ok = ipaddress.ip_address(host).is_loopback
    except ValueError:
        ok = host == "localhost"
    if not ok:
        raise ValueError(f"--llm-endpoint {endpoint!r} is not loopback: the sidecar never talks to another machine")


def suggest_names(endpoint: str, model: str, columns: dict[str, list[str]],
                  transport: httpx.BaseTransport | None = None, timeout: float = 20.0) -> dict[str, str]:
    """{column: proposed name} for the given anonymous columns. Only names that pass validation are returned."""
    require_loopback(endpoint)
    sample = {c: sorted({v for v in vals if v != ""})[:SAMPLE] for c, vals in columns.items()}
    prompt = ("Each key below is an anonymous column of a log format; the list holds a few distinct sample values. "
              "Reply with ONLY a JSON object mapping each key to a short snake_case field name (lowercase letters, digits, "
              "underscores). Use null when you cannot tell.\n" + json.dumps(sample, sort_keys=True))
    body = {"model": model, "temperature": 0, "messages": [{"role": "user", "content": prompt}]}
    with httpx.Client(transport=transport, timeout=timeout) as c:
        r = c.post(endpoint.rstrip("/") + "/v1/chat/completions", json=body)
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
    m = re.search(r"\{.*\}", text, re.S)
    raw = json.loads(m.group(0)) if m else {}
    out: dict[str, str] = {}
    taken: set[str] = set()
    for col in sorted(columns):
        name = raw.get(col)
        if isinstance(name, str) and _NAME.match(name) and not _ANON.match(name) and name not in taken:
            out[col] = name
            taken.add(name)
    return out


def apply_names(yaml_text: str, names: dict[str, str]) -> tuple[str, int]:
    """Give anonymous csv positions their suggested names. Only `_` entries of a `columns:` list are ever replaced, so a
    mapped column, a pattern or a type cannot be altered through here. Returns the new YAML and how many names applied."""
    doc = yaml.safe_load(yaml_text)
    applied = 0
    for ext in doc["extractors"]:
        if ext.get("kind") != "csv":
            continue
        cols = ext["columns"]
        used = {c for c in cols if c != "_"}
        for col, name in sorted(names.items(), key=lambda kv: int(kv[0].split("_")[1])):
            i = int(col.split("_")[1])
            if name in used:
                continue
            if i >= len(cols):
                cols.extend(["_"] * (i + 1 - len(cols)))
            if cols[i] == "_":
                cols[i] = name
                used.add(name)
                applied += 1
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=None, width=100000, allow_unicode=True), applied


def anonymous_columns(yaml_text: str, lines: list[str]) -> dict[str, list[str]]:
    """The csv columns no mapping reads and no name has been given: what there is to ask about."""
    import csv
    import io

    doc = yaml.safe_load(yaml_text)
    ext = next((e for e in doc["extractors"] if e.get("kind") == "csv"), None)
    if ext is None:
        return {}
    mapped = {f for m in ext["map"] for f in ([] if "const" in m else (m["from"] if isinstance(m["from"], list) else [m["from"]]))}
    named = {c for c in ext["columns"] if c != "_"}
    rows = [next(csv.reader(io.StringIO(l))) for l in lines[:200]]
    out: dict[str, list[str]] = {}
    for i in range(min(len(r) for r in rows)):
        name = f"col_{i}"
        if name in mapped or name in named or (i < len(ext["columns"]) and ext["columns"][i] != "_"):
            continue
        vals = [r[i] for r in rows if i < len(r)]
        if any(v != "" for v in vals):
            out[name] = vals
    return out
