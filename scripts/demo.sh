#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docker compose -f "$root/docker-compose.yml" up -d --wait
echo "ULPF control plane: http://127.0.0.1:8000"

