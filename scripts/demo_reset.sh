#!/usr/bin/env sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose() {
  docker compose -f "$root/docker-compose.yml" "$@"
}

command -v docker >/dev/null 2>&1 || { echo "demo_reset: docker is required" >&2; exit 2; }

# The named volume is demo-only state. Removing it resets /data/vault and
# /data/quarantine without touching any host path or fixture.
compose down --volumes --remove-orphans
echo "demo state reset: /data/vault and /data/quarantine will be recreated"

