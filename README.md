# Sluice

**Air-gapped log ingestion, tamper-evident vaulting and normalization to OCSF.**
Formerly ULPF (Universal Log Pre-processing Framework).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](go.mod)
[![Air-gap](https://img.shields.io/badge/Air--Gap-Zero--Egress-3fcb7f)](#air-gap-and-zero-egress)
[![Schema](https://img.shields.io/badge/Schema-OCSF%20v1.1.0-9984d8)](contracts/ocsf/)

Sluice takes raw logs from heterogeneous security devices (Cisco ASA, Fortinet, Palo Alto, Suricata, OpenVPN, DHCP,
RADIUS), writes every record **byte-exact** into an append-only Merkle-chained vault *before* acknowledging it, then
parses and normalizes to OCSF v1.1.0. Formats it does not recognise are never dropped: they are quarantined with the
raw bytes intact and replayed from the vault once an analyst approves a mined parser proposal.

Built for the NTRO problem statement SIH26156 (Smart India Hackathon 2026).

- [Install](#install) · [First run](#first-run) · [Send it logs](#send-it-logs) · [Sign-in and TLS](#sign-in-and-tls)
- [Verify the vault](#verify-the-vault) · [Architecture](#architecture) · [Air-gap](#air-gap-and-zero-egress)
- [Develop](#develop-from-source) · [Cutting a release](#cutting-a-release) · [Docs](#docs)

---

## Install

Pick the route that matches the machine. All routes give the same `sluice` binary or image.

| You have | Use | Needs network |
|---|---|---|
| An **air-gapped** host | [Offline bundle](#a-offline-bundle-air-gapped-hosts) | no |
| Docker and a registry | [Container images](#b-container-images) | yes, once |
| A laptop, no Docker | [Release binaries](#c-release-binaries--go-install--homebrew) | yes, once |
| Only the Python sidecar | [`pip install sluice-intel`](#d-the-intelligence-sidecar-alone) | yes, once |

Replace `OWNER` below with the GitHub account that publishes the repo.

### A. Offline bundle (air-gapped hosts)

Download `sluice-offline-<version>.tar` from the Releases page on a connected machine, carry it across, then:

```sh
tar -xf sluice-offline-<version>.tar && cd offline
shasum -a 256 -c SHA256SUMS                      # every line must say OK
zstd -dc sluice-images-*.tar.zst | docker load   # needs docker + zstd on the target
$EDITOR configs/demo.yaml                        # optional; use configs/production.yaml for sign-in + TLS
docker compose up -d --wait
```

Nothing is pulled or built. Requirements on the target: Docker with Compose v2, `zstd`. The images are built for the
architecture listed in `offline/IMAGES.md` (linux/arm64 or linux/amd64), so pick the bundle that matches the host.
Details: [`offline/README.md`](offline/README.md).

### B. Container images

```sh
docker pull ghcr.io/OWNER/sluice:<version>
docker pull ghcr.io/OWNER/sluice-intel:<version>
```

Then use the compose file from the repo, with `ULPF_TAG=<version>` set (the variable keeps its old name for now):

```sh
git clone https://github.com/OWNER/sluice && cd sluice
ULPF_TAG=<version> docker compose up -d --wait
```

Running `docker compose up` builds the images locally instead, which does need network. See
[Develop from source](#develop-from-source).

### C. Release binaries, `go install`, Homebrew

Each release carries `sluice`, `vaultctl` and `ingestd` for linux and darwin on amd64 and arm64, plus `checksums.txt`.

```sh
# a release tarball
curl -LO https://github.com/OWNER/sluice/releases/download/v<version>/sluice_<version>_linux_amd64.tar.gz
shasum -a 256 -c --ignore-missing checksums.txt
tar -xzf sluice_<version>_linux_amd64.tar.gz

# or with Go 1.25+ (the CLIs only)
go install github.com/OWNER/sluice/cmd/vaultctl@v<version>
go install github.com/OWNER/sluice/cmd/sluice@v<version>

# or Homebrew
brew install OWNER/tap/sluice
```

The `sluice` binary embeds the web UI, so it needs nothing else to serve it.

### D. The intelligence sidecar alone

```sh
pip install sluice-intel          # Python 3.11+
python -m ulpf_intel --admin http://127.0.0.1:9000 --state-dir ./intel-state
```

The Python import package is still named `ulpf_intel`. Sidecar details: [`intel/README.md`](intel/README.md).

---

## First run

```sh
docker compose up -d --wait        # or: ./sluice all --config configs/demo.yaml
open http://127.0.0.1:8000         # the analyst UI
```

Ports (all published on the host's `127.0.0.1` only):

| Port | What |
|---|---|
| 8000 | Control plane and UI |
| 5514 udp+tcp | Syslog ingest (TCP framing is auto-detected, including octet-counted) |
| 8080 | HTTP ingest: `POST /ingest/<source-id>` |
| 9000 | Admin API. **Container loopback only**, never published: it can approve parsers and has no sign-in. |

Check it is healthy: `docker compose exec sluice sluice healthcheck`, and `sluice version` prints the tag, commit and
build time.

`configs/demo.yaml` has **no sign-in** (`allow_insecure: true`). It is for trying the product. Do not expose it.

## Send it logs

```sh
# syslog over UDP
printf '<134>Sep 30 10:00:00 fw1 test message\n' | nc -u -w1 127.0.0.1 5514

# syslog over TCP
printf '<134>Sep 30 10:00:00 fw1 test message\n' | nc -w1 127.0.0.1 5514

# a whole file over HTTP (the last path segment is the source id)
curl -fsS -X POST --data-binary @testdata/sample/cisco_asa.log 127.0.0.1:8080/ingest/asa
```

Then open the UI (Lineage Explorer for parsed events, Review Queue for anything the parsers did not recognise).
Sources are configured in `configs/ingest.container.yaml`; file tailing is available in the native `ingestd`
(`configs/ingest.dev.yaml`).

## Sign-in and TLS

The demo config has neither. For a real deployment, start from `configs/production.yaml`. A control plane bound to
`0.0.0.0` **refuses to start without `auth_users_file`**.

```sh
printf '%s' 'a-long-passphrase'  | docker run --rm -i sluice:<version> passwd alice approver >> users
printf '%s' 'another-passphrase' | docker run --rm -i sluice:<version> passwd bob   viewer   >> users
```

Mount `users`, `tls.crt`, `tls.key` read-only under `/etc/sluice/`. `approver` can approve, reject and roll back
parsers, and every approval is recorded under the login. `viewer` is read-only. Passwords are PBKDF2-SHA256 and at
least 12 characters. Put a reverse proxy in front if the port is reachable by anyone you do not trust. Backup,
restore, upgrades, sizing and monitoring: [`docs/operations.md`](docs/operations.md).

## Verify the vault

The vault is the system of record. Everything else can be rebuilt from it.

```sh
vaultctl --dir ./data/vault stats
vaultctl --dir ./data/vault verify --deep; echo "exit=$?"    # 0 intact, 1 tampered, 2 unreadable
vaultctl --dir ./data/vault get 1 --raw | shasum -a 256       # byte-exact original of record 1
vaultctl --dir ./data/vault proof 1 > p.json && vaultctl verify-proof p.json
```

Vaulting is **tamper-evident, not tamper-proof**: someone with write access to the whole directory can rewrite it
consistently. Pin the chain head somewhere else with `scripts/anchor_head.sh` to defeat that.

---

## Architecture

Three strictly separated planes:

```
DATA PLANE (Go, :9000, loopback)
  Ingest (syslog / file / HTTP) -> Write-ahead vault -> Parser engine (RE2) -> OCSF normalizer -> Sinks
                                        ^                    |                                   (Parquet / OCSF JSON / ECS)
                                        |               Quarantine
                                        +--- Replay <--- Human approval

CONTROL PLANE (Go + React, :8000)
  Analyst UI: lineage explorer, review queue, parser registry, identity timeline, vault view.
  In-browser verifier: recomputes SHA-256 and RFC 9162 inclusion proofs itself.

INTELLIGENCE PLANE (Python, off the hot path)
  Drain3 template mining, drift scoring, semantic typing, parser proposals.
  Propose-only: reads quarantine through the admin API and cannot activate anything.
```

- **Zero discard.** A record is durable in the vault before it is acknowledged or forwarded. Overload
  back-pressures; it never drops silently.
- **Linear-time parsing.** Go's RE2 engine with named capture groups is immune to regex denial of service.
- **OCSF v1.1.0.** Unmapped vendor attributes are preserved in `unmapped{}`.
- **Human in the loop.** Parser proposals arrive as `pending`. Only an analyst can activate one.

## Air-gap and zero-egress

1. **The binary has no outbound code.** `sluice selftest --egress` and `scripts/verify_airgap.sh` prove public DNS and
   TCP connections fail under `--network none` and on an internal Docker network.
2. **Loopback binding.** Services bind `127.0.0.1`; Compose publishes only the control plane, ingest ports and HTTP
   ingest, on the host's loopback. The admin API never leaves the container.
3. **No external assets.** Fonts are bundled; no CDN, telemetry or remote calls.

Honest scope: the **runtime** needs no network, and the **install** needs none via the offline bundle. **Building** the
bundle needs a connected machine: it pulls base images by pinned digest and Python wheels, and the UI build runs
`npm ci` (a fully offline build is still on `docs/TODO.md`). `docker-compose.yml` uses an ordinary bridge network
because Docker cannot publish ports from an internal one; `docker-compose.airgap-test.yml` is the internal-network
variant the verifier runs.

## What is and is not claimed

- Byte-exact round trip of all 7598 fixture records, checked against SHA-256 and byte offsets.
- 200 `kill -9` crash cycles, no acknowledged record lost. That proves the recovery logic. It does **not** prove
  power-loss durability, because SIGKILL does not discard the page cache.
- A 10-row tamper matrix with none undetected.
- Throughput and fsync numbers are **Linux-only and not yet recorded**. macOS `fsync` is a full-drive flush, so numbers
  measured there are not reported. Figures in `docs/operations.md` are labelled with their hardware and sync mode.
- No retention or expiry yet, no high availability, no encryption at rest (use an encrypted volume). See
  [`docs/TODO.md`](docs/TODO.md).

---

## Develop from source

Requirements: Go 1.25+, Docker, Node 22 (UI), Python 3.11+ (sidecar tests). On macOS with Homebrew Go, put it on
`PATH`: `export PATH="/opt/homebrew/bin:$PATH"`.

```sh
make check          # the gate: fmt, vet, race tests, determinism, CGO_ENABLED=0 build
make test           # ingest and vault tests
make contract-test  # schemas, OpenAPI and goldens
make ui-test        # frontend tests and lint
make build          # bin/ingestd bin/vaultctl
make ui && CGO_ENABLED=0 go build -o bin/sluice ./cmd/sluice
./bin/sluice all --config configs/demo.yaml
bash scripts/demo.sh                 # scripted demo: ingest, quarantine, approve, replay
bash scripts/verify_airgap.sh        # zero-egress proof (needs Docker)
make help                            # every target
```

Shipped binaries are always `CGO_ENABLED=0`. The race detector needs cgo, so `make race` sets it separately.

## Cutting a release

`make bundle` and `make dist` need a connected machine and Docker.

```sh
make vendor                 # go mod vendor (vendor/ is generated, not committed)
make bundle VERSION=x.y.z   # wheels + both images + offline/ (checksummed)
make dist   VERSION=x.y.z   # dist/: binaries for 4 platforms, checksums.txt, vendor tarball
git tag vX.Y.Z && git push origin vX.Y.Z
gh release create vX.Y.Z dist/* --title vX.Y.Z
```

Also push the images (`docker tag` and `docker push` to `ghcr.io/OWNER/sluice*`) and upload the Python package
(`cd intel && python -m build && twine upload dist/*`). The bundle is architecture-specific: build it on, or with
buildx for, each target architecture.

## Repository layout

```text
cmd/        sluice (operator CLI + unified runtime), dataplane, control, ingestd, vaultctl, bench, integrate
pkg/        types (frozen contract), dataplane/{ingest,vault,parsers,normalizer,store,replay,enrich,admin,app},
            control (server, audit registry, embedded UI), sinks
frontend/   React 18 + TypeScript UI
intel/      Python intelligence sidecar
parsers/    built-in parsers (embedded)
configs/    demo, production, air-gap and ingest configs
contracts/  JSON Schemas, OpenAPI, OCSF, goldens
testdata/   byte-exact fixtures and manifest.json (schema v1, frozen)
scripts/    demo, e2e and zero-egress verifier
offline/    the offline install package (README, compose; generated files are gitignored)
```

## Docs

[`docs/operations.md`](docs/operations.md) run and maintain it ·
[`docs/vault-format.md`](docs/vault-format.md) on-disk format ·
[`docs/integration.md`](docs/integration.md) integration steps ·
[`docs/TODO.md`](docs/TODO.md) what is not built ·
[`DECISIONS.log`](DECISIONS.log) every decision, with reasons.

## License

MIT (add a `LICENSE` file before publishing). Developed for the Smart India Hackathon 2026, NTRO problem statement
SIH26156.
