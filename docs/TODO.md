# Still to build

Kept current by whoever finishes or adds an item. Newest facts about what exists are in `DECISIONS.log`.

## 1. Offline install package (the next thing to build)

The PS says the product runs fully offline. The **running** product does (`scripts/verify_airgap.sh` proves no
egress). What does not exist is the way to **get it onto** an offline machine: PRD_PACKAGING E-11 and E-14 ask for
it, and none of it is built. Today `docker build` pulls Go, Node and Python images and packages from the network, so
an offline machine cannot build, and there is no single file to carry across.

- [ ] `make bundle`: `docker save ulpf:<tag> ulpf-intel:<tag> | zstd -19 > offline/ulpf-images-<tag>.tar.zst`, plus the
      compose file, `configs/`, `offline/SHA256SUMS`, and `offline/README.md` (verify checksums, `zstd -d | docker load`,
      edit config, `docker compose up -d`). Install must be those steps and nothing else.
- [ ] `vendor/` via `go mod vendor`, committed; the Dockerfile builds with `-mod=vendor`.
- [ ] Python wheels for the sidecar in `intel/wheels/`; the `intel` target installs with
      `pip install --no-index --find-links wheels/`.
- [ ] npm offline cache tarball (`offline/npm-cache.tar.zst`, P1) so the UI builds offline.
- [ ] Pin base images by digest; record digests in `offline/IMAGES.md`.
- [ ] `scripts/verify_airgap.sh` step 1 becomes: load the bundle from `offline/` with no network assumptions and check
      `SHA256SUMS` (PRD 4.7). Today it only checks images built locally. Save its log to `benchmarks/results/`.
- [ ] SBOM (P2): `syft` on both images to `offline/sbom-*.spdx.json`.
- [ ] Be honest in the README: **runtime** needs no network; the **build** is offline only from the vendored inputs.
- [ ] Decide the image tag scheme (`ulpf:dev` today) and stamp `version`/`commit`/`builtAt` (the Dockerfile has the args).

## 2. Measurements deferred

- [ ] Linux benchmarks (events/s per sync mode, seal time, RSS at 100k rec/s) into `benchmarks/results/`. macOS numbers
      must not be reported: `File.Sync` is a full-drive flush there. The 1M-event memory figures in
      `docs/operations.md` are macOS, `--sync none`, labelled as such.
- [ ] A browser check of the UI against the real data plane (only the API and unit tests were exercised).
- [ ] Power-loss test (the crash suite kills the process, it does not cut power).

## 3. Known gaps in the deployment

- [ ] Retention/expiry: the vault has none. Pruning a segment breaks the chain; a chain-preserving prune is unbuilt.
      Manual rotate-and-archive is documented in `docs/operations.md`.
- [ ] Login rate limiting / lockout on the control plane.
- [ ] Encryption at rest (use an encrypted volume for now).
- [ ] High availability (one node, one writer).
- [ ] Forwarding sinks in the container: Splunk HEC and CEF-syslog exist in `pkg/sinks` but `cmd/ulpf` only wires
      `parquet`, `ocsfjson`, `ecs`. Forwarding needs one explicitly allowed egress route.
- [ ] Vault-record to event-store consistency on restart: startup replays the whole vault (about 30 s per million records).
- [ ] Integration step 3 (sinks) and step 6 (UI walk-through) have no executable gate in `contracts/integration`.
- [ ] `tests/` has no gate that runs `make integrate` against `cmd/ulpf`; the steps were run by hand against `cmd/dataplane`.
