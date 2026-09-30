# Operations

What it takes to run ULPF as a service. Everything here was exercised except where it says otherwise.

## Shape

One host, one `ulpf` container (data plane + control plane + UI) and one `ulpf-intel` sidecar that shares its
network namespace. Devices send syslog to 5514 (UDP/TCP) or HTTP to 8080. People use the UI on 8000. The admin API
on 9000 stays on the container's loopback: it can approve parsers and has no sign-in, so only the control plane
(and the sidecar, in the same namespace) can reach it.

```
docker build --target ulpf  -t ulpf:dev .
docker build --target intel -t ulpf-intel:dev .
docker save ulpf:dev ulpf-intel:dev | gzip > ulpf.tar.gz        # carry across the air gap
docker load < ulpf.tar.gz
```

## Turn on sign-in and TLS

`docker-compose.yml` is a demo (`allow_insecure: true`, no sign-in). For a real deployment start from
`configs/production.yaml`: a control plane on `0.0.0.0` **refuses to start without `auth_users_file`**.

```sh
printf '%s' 'a-long-passphrase' | docker run --rm -i ulpf:dev passwd alice approver >> users
printf '%s' 'another-passphrase' | docker run --rm -i ulpf:dev passwd bob viewer    >> users
```

- `approver` can approve, reject and roll back parsers; `viewer` is read-only (403 on any write).
- **An approval is recorded under the login**, not the name typed in the UI.
- Passwords are PBKDF2-SHA256, 600k iterations, 12 characters minimum. There is no lockout or rate limit:
  put a reverse proxy in front if the port is reachable by anyone you do not trust.
- `tls_cert` / `tls_key` serve HTTPS directly. Without them, terminate TLS in front of it: Basic auth over plain
  HTTP is a password in the clear.
- Mount the files read-only under `/etc/ulpf/`. `/healthz` needs no credentials (the container probe has none).

## Monitoring

`GET /metrics` on the control plane (behind sign-in when it is on): Go and process collectors, `vault_*`
(`vault_put_latency_seconds`, `vault_fsync_seconds`, `vault_seal_seconds`, `vault_compaction_ratio`, `vault_failed`)
and `ingest_*` (`ingest_records_total`, `ingest_out_queue_depth`, `ingest_udp_kernel_drops`,
`ingest_frame_errors_total`). Alert on: `vault_failed` becoming 1 (the vault hit an fsync error and is in its terminal
state: restart, do not retry), `ingest_out_queue_depth` staying near its capacity (back-pressure, sources slowing
down), `ingest_udp_kernel_drops` rising (raise `net.core.rmem_max`; UDP loss cannot be fixed in software), and the
container health check failing.

## Storage and sizing

Everything lives in the `/data` volume:

| Path | What | Rebuildable? |
|---|---|---|
| `vault/` | raw records, hash chain, seals | **No. This is the system of record.** |
| `store.db` | parsed events (SQLite, zstd bodies) | yes, from the vault |
| `parsers.d/`, `control/registry.db` | approved parser versions and who approved them | no |
| `lake/`, `exports/` | Parquet, OCSF and ECS output | yes, by replay |

Measured on a MacBook (Apple M2, 16 GB, macOS), `--sync none`, one million Cisco ASA records from one file,
all of ingest, parse, identity enrichment and storage. **These are not throughput or durability numbers**: macOS
`fsync` is not Linux `fsync`, and nothing here was run with `--sync always`.

| | before (in-memory events) | now (SQLite events) |
|---|---|---|
| resident memory after 1M events | 3.2 GiB | **220 MiB** |
| resident memory after restart | 4.7 GiB | **233 MiB** |
| `/admin/events` page (100 rows) | sorted every key per request | 12 ms |
| ingest wall time, 1M records | 25 s | 88 s |
| restart to healthy, 1M records | 16 s | 25-34 s |
| vault on disk (167 MB of raw log lines) | 82 MiB | 82 MiB (about 2x smaller than the raw lines) |
| `store.db` on disk | n/a | 929 MiB (~0.9 KiB per event) |

Memory is flat now; the price is slower ingest and a larger `store.db` than the vault it is derived from. Budget
disk as roughly 1 KiB per event for `store.db` plus about 80 bytes per record for the vault (this corpus; it depends on the logs).
Restart re-reads the whole vault to rebuild identity state and the quarantine list, so it grows linearly
(about 30 s per million records here).

## Backup

- **Back up `/data` while the container is stopped**, or snapshot the volume. `vault/` is append-only and safe to
  copy at any time, but a live copy can end in a torn record that recovery will cut.
- To restore: put the directory back and start. Recovery repairs a torn tail and a missing ledger line by itself.
- `store.db` can be deleted; it is rebuilt on start.

## Anchor the chain head

The vault is tamper-**evident**, not tamper-proof. Someone with write access to the whole directory can rewrite
it consistently; only a head recorded elsewhere exposes that.

```sh
ULPF_URL=https://127.0.0.1:8000 ULPF_USER=alice ULPF_PASS=... sh scripts/anchor_head.sh >> anchors.log
```

Run it from cron and ship `anchors.log` somewhere the vault's operator cannot write. The script refuses to
print a line if the chain does not verify.

## Retention: there is none

The vault has no deletion or expiry (`docs/vault-format.md`): pruning a segment breaks the chain, and no
chain-preserving prune exists yet. What you can do today:

1. Watch disk (roughly 1.1 KiB per event in total).
2. When the volume is nearly full: stop, copy `/data` to cold storage together with the last anchor line, and
   start a new volume. The old vault still verifies on its own; the new one starts a new chain.

Encryption at rest is also not provided: use an encrypted volume.

## Upgrades

Images are immutable; `/data` is the state. Stop, load the new image, start. Parser versions are files and stay
put. `store.db` is derived, so a schema change means delete it and let it rebuild. Keep the previous image until
the new one has verified (`ulpf verify` / `/api/vault/verify?deep=true`).

## Not covered

No high availability (one node, one writer). No power-loss test: the crash suite kills the process, it does not cut
power. No Linux benchmark yet (deferred), so no reportable events-per-second or fsync figure.
