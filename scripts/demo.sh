#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose() {
  docker compose -f "$root/docker-compose.yml" "$@"
}

command -v docker >/dev/null 2>&1 || { echo "demo: docker is required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "demo: curl is required" >&2; exit 2; }

echo "[0:00] starting isolated ULPF stack"
compose up -d --wait
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/healthz >/dev/null

echo "[0:10] control plane ready at http://127.0.0.1:8000"
echo "[0:15] send the mixed sample corpus"
echo "        scripts/send_samples.sh"
echo "[0:45] open an event and inspect raw bytes, SHA-256, and Merkle lineage"
echo "[1:00] ingest testdata/fortinet_drift.log and review the proposal"
echo "[1:20] approve and replay, then inspect the identity timeline"
echo "[1:40] show measured results and the saved AIRGAP_VERIFIED log"
echo "[2:00] demo complete"

