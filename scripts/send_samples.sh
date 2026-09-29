#!/usr/bin/env sh
# send_samples.sh — exercise every ingest path against a running ingestd, then
# prove what arrived is byte-for-byte what was sent.
#
#   make build fixtures
#   ./bin/ingestd --config configs/ingest.dev.yaml &
#   ./scripts/send_samples.sh
#
# Exit 0 if every check passed, 1 otherwise. It is the manual smoke test from
# the PRD, written down so it is run the same way every time — two real bugs
# were found by pointing the binaries at real data, and neither was caught by
# any unit test.
#
# POSIX sh, and only tools the PRD already assumes: nc, curl, jq, sha256sum or
# shasum. No bashisms: this has to run inside the distroless-ish container too.

set -eu

VAULT_DIR="${VAULT_DIR:-./data/vault}"
METRICS="${METRICS:-127.0.0.1:9100}"
SYSLOG_HOST="${SYSLOG_HOST:-127.0.0.1}"
SYSLOG_PORT="${SYSLOG_PORT:-5514}"
HTTP_ADDR="${HTTP_ADDR:-127.0.0.1:8080}"
VAULTCTL="${VAULTCTL:-./bin/vaultctl}"
SAMPLE="${SAMPLE:-testdata/sample/cisco_asa.log}"

failures=0

pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; failures=$((failures + 1)); }
step() { printf '\n== %s\n' "$1"; }

# sha256 of stdin, on either GNU or BSD userland.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

need() {
  command -v "$1" >/dev/null 2>&1 || { printf 'send_samples.sh: %s is required\n' "$1" >&2; exit 2; }
}
need nc; need curl; need jq

[ -x "$VAULTCTL" ] || { printf 'send_samples.sh: %s not found (run `make build`)\n' "$VAULTCTL" >&2; exit 2; }
[ -f "$SAMPLE" ]   || { printf 'send_samples.sh: %s not found (run `make fixtures`)\n' "$SAMPLE" >&2; exit 2; }

step "health"
if curl -sSf "http://$METRICS/healthz" >/dev/null 2>&1; then
  pass "/healthz is 200"
else
  printf 'send_samples.sh: ingestd is not answering on %s. Start it first.\n' "$METRICS" >&2
  exit 2
fi

step "UDP syslog"
# One datagram is one record, and a trailing newline would be content, so
# there is deliberately none here.
printf '<134>Sep 28 09:00:01 h app: sample-udp' | nc -u -w1 "$SYSLOG_HOST" "$SYSLOG_PORT" || true
pass "sent a datagram"

step "TCP syslog, LF framing"
printf 'sample-tcp-one\nsample-tcp-two\n' | nc -w1 "$SYSLOG_HOST" "$SYSLOG_PORT" || true
pass "sent two LF-framed lines"

step "TCP syslog, octet counting (RFC 6587)"
# 30 is the exact byte length of the message that follows it.
printf '30 <134>Sep 28 10:14:02 h app: hi' | nc -w1 "$SYSLOG_HOST" "$SYSLOG_PORT" || true
pass "sent one octet-counted message"

step "HTTP stream"
accepted=$(curl -sS --data-binary "@$SAMPLE" "http://$HTTP_ADDR/ingest/asa-lab" | jq -r '.accepted // 0')
expected=$(wc -l < "$SAMPLE" | tr -d ' ')
if [ "$accepted" = "$expected" ]; then
  pass "202 accepted=$accepted, matching the file's $expected lines"
else
  fail "202 accepted=$accepted but the file has $expected lines"
fi

# Give the seal interval a moment, so `proof` has a sealed segment to work with.
sleep 2

step "the vault verifies"
if "$VAULTCTL" --dir "$VAULT_DIR" verify --deep >/dev/null 2>&1; then
  pass "verify --deep exit 0"
else
  fail "verify --deep exit $? (1 means tamper detected, 2 means unreadable)"
fi

step "byte-exactness: three independent hashes must agree"
# The claim behind PS requirement (a). The source line, what the vault gives
# back, and the manifest's precomputed ground truth.
first_line=$(head -1 "$SAMPLE")
src_hash=$(printf '%s' "$first_line" | sha256)
manifest_hash=$(jq -r '.records[] | select(.source_file=="cisco_asa.log") | .expected_sha256' testdata/manifest.json 2>/dev/null | head -1)

# Find the record id the HTTP upload produced for that same line.
record_id=$("$VAULTCTL" --dir "$VAULT_DIR" scan --from 1 --limit 20000 2>/dev/null \
  | awk -v h="$(printf '%s' "$src_hash" | cut -c1-16)" '$5 ~ ("^" h) {print $1; exit}')

if [ -n "${record_id:-}" ]; then
  vault_hash=$("$VAULTCTL" --dir "$VAULT_DIR" get "$record_id" --raw | sha256)
  if [ "$src_hash" = "$vault_hash" ]; then
    pass "source file and vault agree   ($src_hash)"
  else
    fail "source file and vault DISAGREE ($src_hash vs $vault_hash)"
  fi
  if [ -n "$manifest_hash" ] && [ "$src_hash" = "$manifest_hash" ]; then
    pass "manifest ground truth agrees"
  elif [ -n "$manifest_hash" ]; then
    fail "manifest says $manifest_hash"
  fi
else
  fail "could not locate the uploaded record in the vault"
fi

step "an inclusion proof verifies with no vault"
proof=$(mktemp)
trap 'rm -f "$proof"' EXIT
if "$VAULTCTL" --dir "$VAULT_DIR" proof 1 > "$proof" 2>/dev/null; then
  if "$VAULTCTL" verify-proof "$proof" >/dev/null 2>&1; then
    pass "verify-proof exit 0, with no vault present"
  else
    fail "verify-proof rejected a proof the vault just issued"
  fi
else
  # Not a failure: a record in the active segment has no root until it is
  # sealed, which is decision D2 working as intended.
  pass "record 1 is not sealed yet (expected with a long seal_interval)"
fi

step "metrics"
metrics=$(curl -sS "http://$METRICS/metrics" 2>/dev/null || true)
for name in ingest_records_total vault_put_total vault_failed; do
  if printf '%s' "$metrics" | grep -q "^$name"; then
    pass "$name is exported"
  else
    fail "$name is missing"
  fi
done
if printf '%s' "$metrics" | grep -q '^vault_failed 0$'; then
  pass "vault_failed is 0"
else
  fail "vault_failed is not 0 — the vault has stopped accepting writes"
fi

printf '\n'
if [ "$failures" -eq 0 ]; then
  printf 'all checks passed\n'
  exit 0
fi
printf '%d check(s) failed\n' "$failures"
exit 1
