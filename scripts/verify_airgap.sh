#!/bin/sh
set -eu

image="${ULPF_IMAGE:-ulpf:dev}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

docker run --rm --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -v "$root/testdata:/opt/ulpf/testdata:ro" \
  "$image" selftest --egress

docker compose -f "$root/docker-compose.yml" config >/dev/null
if ! docker compose -f "$root/docker-compose.yml" config | grep -Eq 'internal: true'; then
  echo "airgap: compose network is not internal" >&2
  exit 1
fi

echo AIRGAP_VERIFIED

