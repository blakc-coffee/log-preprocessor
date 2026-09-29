#!/bin/sh
set -eu

image="${ULPF_IMAGE:-ulpf:dev}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compose() {
  docker compose -f "$root/docker-compose.airgap-test.yml" "$@"
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "airgap: $1 is required" >&2
    exit 2
  }
}
need docker

cleanup() {
  compose down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# The binary itself must prove that every public probe fails when the kernel
# gives the container no network namespace interface beyond loopback.
echo "== network-none egress probes"

docker run --rm --network none \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  "$image" selftest --pipeline --egress --ui

config=$(compose config)
if ! printf '%s\n' "$config" | grep -Eq 'internal: true'; then
  echo "airgap: compose network is not internal" >&2
  exit 1
fi
# An internal Docker network must still permit the two local services to work.
echo "== isolated deployment health"
compose up -d --wait
container=$(compose ps -q ulpf)
bindings=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$container")
for port in 8000 9000; do
  expected="\"$port/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"$port\"}]"
  case "$bindings" in
    *"$expected"*) ;;
    *)
      echo "airgap: port $port is not configured loopback-only ($bindings)" >&2
      exit 1
      ;;
  esac
done
compose exec -T ulpf ulpf healthcheck

echo AIRGAP_VERIFIED

