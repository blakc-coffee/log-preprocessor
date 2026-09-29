#!/usr/bin/env python3
"""
intel/proposer.py — Standalone Parser Proposal CLI & Offline Miner.
Part of Gate 4 deliverables (owned by Antigravity Pro per AGENTS.md).

Can be executed offline against log files or online against the Data Plane admin API:
  python intel/proposer.py testdata/palo_alto_unknown.log --source-id palo_alto --output parser.yaml
  python intel/proposer.py --admin http://127.0.0.1:9000 --once
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add intel package root to sys.path so ulpf_intel can be imported directly
INTEL_DIR = Path(__file__).resolve().parent
if str(INTEL_DIR) not in sys.path:
    sys.path.insert(0, str(INTEL_DIR))

try:
    from ulpf_intel import dsl_eval, egress
    from ulpf_intel.client import AdminClient
    from ulpf_intel.fingerprint import line_kind
    from ulpf_intel.loop import Config, Sidecar
    from ulpf_intel.propose import (
        propose_cef,
        propose_csv,
        propose_json,
        propose_kv,
        propose_kv_patch,
        propose_text,
    )
    from ulpf_intel.state import State
    from ulpf_intel.validate import re2_violations
except ImportError as err:
    sys.exit(f"Error importing ulpf_intel: {err}\nEnsure dependencies are installed: pip install -e '{INTEL_DIR}[test]'")


def propose_offline(
    source_id: str,
    lines: list[str],
    record_ids: list[int] | None = None,
    timezone_str: str = "+00:00",
    baseline_yaml: str | None = None,
    base_version: str = "",
) -> tuple[str, list[str]]:
    """Generate parser proposal YAML directly from raw log lines without requiring an active data plane."""
    cleaned = [l.rstrip("\r\n") for l in lines if l.strip()]
    if not cleaned:
        raise ValueError("Cannot propose parser for empty log input")

    if record_ids is None:
        record_ids = list(range(1, len(cleaned) + 1))

    now = datetime.now(timezone.utc)
    kind = line_kind(cleaned[0])

    if kind == "csv":
        gen = propose_csv(source_id, cleaned, record_ids, now, timezone=timezone_str)
    elif kind in ("cef", "leef"):
        gen = propose_cef(source_id, cleaned, record_ids, now, timezone=timezone_str)
    elif kind == "json":
        gen = propose_json(source_id, cleaned, record_ids, now, timezone=timezone_str)
    elif kind == "kv":
        if baseline_yaml and base_version:
            gen = propose_kv_patch(source_id, baseline_yaml, base_version, cleaned, record_ids, now)
        else:
            gen = propose_kv(source_id, cleaned, record_ids, now, timezone=timezone_str)
    elif kind == "text":
        gen = propose_text(source_id, cleaned, record_ids, now, timezone=timezone_str)
    else:
        # Fall back to text/Drain3 mining
        gen = propose_text(source_id, cleaned, record_ids, now, timezone=timezone_str)

    p = gen.proposal
    warnings = list(gen.warnings)
    violations = re2_violations(p.yaml)
    if violations:
        warnings.extend([f"not RE2: {v}" for v in violations])

    return p.yaml, warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="proposer.py",
        description="ULPF Standalone Parser Proposer (Offline Miner & Online Sidecar)",
    )
    parser.add_argument("logfile", nargs="?", default="", help="Path to raw log file for offline proposal generation")
    parser.add_argument("--source-id", default="", help="Source identifier (e.g. palo_alto, cisco_asa)")
    parser.add_argument("--output", "-o", default="", help="File path to write the generated YAML proposal")
    parser.add_argument("--admin", default="", help="Data-plane admin API address (e.g. http://127.0.0.1:9000)")
    parser.add_argument("--state-dir", default="intel-state", help="Directory for baseline state storage")
    parser.add_argument("--poll-interval", type=float, default=5.0, help="Seconds between poll passes in loop mode")
    parser.add_argument("--once", action="store_true", help="Run one pass against admin API, then exit")
    parser.add_argument("--timezone", default="+00:00", help="Timezone offset for unzoned timestamps (default: +00:00)")
    parser.add_argument("--healthcheck", action="store_true", help="Check admin API health and exit")
    parser.add_argument("--egress-check", action="store_true", help="Verify zero network egress and exit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.egress_check:
        return egress.run()

    # Online mode via admin API
    if args.admin:
        client = AdminClient(args.admin)
        if args.healthcheck:
            is_healthy = client.healthy()
            print(f"Admin API ({args.admin}): {'HEALTHY' if is_healthy else 'UNHEALTHY'}")
            return 0 if is_healthy else 1

        cfg = Config(poll_interval=args.poll_interval, timezone=args.timezone)
        sidecar = Sidecar(client, State(args.state_dir), cfg)
        if args.once:
            outcomes = sidecar.run_once()
            for o in outcomes:
                print(f"{o.source_id}: {o.action} - {o.reason}")
            return 0

        print(f"Starting ULPF proposal sidecar loop polling {args.admin} every {args.poll_interval}s...")
        try:
            sidecar.run_forever(import_sleep=True)
        except KeyboardInterrupt:
            print("\nStopped proposal loop.")
        return 0

    # Offline mode via log file
    if args.logfile:
        log_path = Path(args.logfile)
        if not log_path.is_file():
            sys.exit(f"Error: file not found: {args.logfile}")

        source_id = args.source_id or log_path.stem
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        print(f"Generating proposal for source '{source_id}' from {len(lines)} lines in {args.logfile}...")
        try:
            yaml_content, warnings = propose_offline(source_id, lines, timezone_str=args.timezone)
        except Exception as e:
            sys.exit(f"Proposal generation failed: {e}")

        if warnings:
            print(f"\n[Warnings ({len(warnings)})]:")
            for w in warnings:
                print(f"  - {w}")

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(yaml_content, encoding="utf-8")
            print(f"\nWrote proposal YAML to: {args.output}")
        else:
            print("\nGenerated Parser Proposal YAML:")
            print("----------------------------------------------------------------")
            print(yaml_content)
            print("----------------------------------------------------------------")
        return 0

    # If neither logfile nor admin is supplied, print usage
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
