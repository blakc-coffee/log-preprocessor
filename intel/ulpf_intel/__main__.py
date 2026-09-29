"""python -m ulpf_intel --admin http://127.0.0.1:9000 [--once]"""
from __future__ import annotations

import argparse
import logging
import sys
import time

from . import egress
from .client import AdminClient
from .loop import Config, Sidecar
from .state import State


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ulpf_intel", description="ULPF intelligence sidecar (propose-only)")
    ap.add_argument("--admin", default="http://127.0.0.1:9000", help="data-plane admin API")
    ap.add_argument("--state-dir", default="intel-state")
    ap.add_argument("--poll-interval", type=float, default=5.0)
    ap.add_argument("--once", action="store_true", help="one pass, then exit (for tests and cron)")
    ap.add_argument("--timezone", default="+00:00", help="zone for timestamps that carry none")
    ap.add_argument("--drift-threshold", type=float, default=0.35)
    ap.add_argument("--min-samples", type=int, default=50)
    ap.add_argument("--min-cluster", type=int, default=50)
    ap.add_argument("--llm-endpoint", default="", help="optional LOCAL model server (loopback only) that names anonymous csv columns")
    ap.add_argument("--llm-model", default="local")
    ap.add_argument("--healthcheck", action="store_true", help="GET <admin>/healthz; exit 0 if healthy, 1 if not")
    ap.add_argument("--egress-check", action="store_true", help="exit non-zero if ANY outbound attempt succeeds")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if a.egress_check:
        return egress.run()
    client = AdminClient(a.admin)
    if a.healthcheck:
        return 0 if client.healthy() else 1

    cfg = Config(poll_interval=a.poll_interval, min_samples=a.min_samples, min_cluster=a.min_cluster,
                 drift_threshold=a.drift_threshold, timezone=a.timezone, llm_endpoint=a.llm_endpoint, llm_model=a.llm_model)
    sidecar = Sidecar(client, State(a.state_dir), cfg)
    if a.once:
        for o in sidecar.run_once():
            print(f"{o.source_id}: {o.action} {o.reason}")
        return 0
    try:
        sidecar.run_forever(time.sleep)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
