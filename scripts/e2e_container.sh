#!/bin/sh
# e2e_container.sh — prove the shipped image ingests, parses and serves.
#   docker build --target sluice -t sluice:dev . && sh scripts/e2e_container.sh
# Posts the ASA sample over HTTP and one line over TCP, then checks that every
# record became an event, the vault holds them, and the UI answers on the host.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
trap 'docker compose down -v >/dev/null 2>&1 || true' EXIT INT TERM
docker compose up -d --wait >/dev/null
want=$(wc -l < testdata/sample/cisco_asa.log | tr -d ' ')
curl -fsS -X POST --data-binary @testdata/sample/cisco_asa.log 127.0.0.1:8080/ingest/asa >/dev/null
printf '%s\n' '<166>Sep 28 2026 09:00:07 asa01 : %ASA-6-302013: Built inbound TCP connection 1 for outside:192.0.2.179/22 (192.0.2.179/22) to inside:10.1.11.225/56376 (10.1.11.225/56376)' | nc -w1 127.0.0.1 5514
want=$((want + 1))
i=0
while [ $i -lt 30 ]; do
  t=$(curl -fsS 127.0.0.1:8000/api/telemetry)
  events=$(printf '%s' "$t" | sed -n 's/.*"events_total":\([0-9]*\).*/\1/p')
  [ "${events:-0}" -ge "$want" ] && break
  i=$((i + 1)); sleep 1
done
[ "${events:-0}" -eq "$want" ] || { echo "e2e: $events events, want $want" >&2; exit 1; }
curl -fsS -o /dev/null 127.0.0.1:8000/ || { echo "e2e: UI unreachable from the host" >&2; exit 1; }
curl -fsS 127.0.0.1:8000/api/vault/verify | grep -q '"ok":true' || { echo "e2e: vault chain not intact" >&2; exit 1; }
echo "E2E_OK: $events events, UI reachable, vault intact"
