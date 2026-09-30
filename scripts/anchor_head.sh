#!/bin/sh
# anchor_head.sh — print one line that pins the vault's current state:
#   <UTC time> <records> <segments> <chain head sha256>
# Run it from cron and ship the output somewhere the vault's operator cannot
# write (a ticket, a mail, a WORM bucket, paper). The vault is tamper-EVIDENT:
# someone who can rewrite the whole data directory can rewrite it consistently,
# and only a head recorded elsewhere exposes that: compare a later `vaultctl head`
# against these lines (a chain that grew keeps every old head as an ancestor).
#
#   ULPF_URL=https://127.0.0.1:8000 ULPF_USER=alice ULPF_PASS=... sh scripts/anchor_head.sh >> anchors.log
set -eu
url="${ULPF_URL:-http://127.0.0.1:8000}"
auth=""
[ -n "${ULPF_USER:-}" ] && auth="-u ${ULPF_USER}:${ULPF_PASS:-}"
# shellcheck disable=SC2086
body=$(curl -fsSk $auth "$url/api/vault/verify?deep=true")
field() { printf '%s' "$body" | grep -oE "\"$1\":(\"[^\"]*\"|[0-9a-z]+)" | head -1 | sed 's/^[^:]*://; s/"//g'; }
ok=$(field ok)
[ "$ok" = true ] || { echo "anchor: the chain does not verify: $body" >&2; exit 1; }
printf '%s %s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(field records)" "$(field segments)" "$(field head)"
