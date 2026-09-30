# ULPF offline install

Carry this whole directory to the target machine (needs Docker with Compose v2, and `zstd`). No network is used.

```sh
cd offline
shasum -a 256 -c SHA256SUMS                         # every line must say OK
zstd -dc sluice-images-*.tar.zst | docker load
$EDITOR configs/demo.yaml                           # optional; see configs/production.yaml for sign-in + TLS
docker compose up -d
```

UI: http://127.0.0.1:8000. Ingest: UDP/TCP 5514, HTTP 8080 (loopback only). Operations: `docs/operations.md` in the repo.

## What "offline" covers

- **Runtime**: needs no network. The binary has no outbound code; `scripts/verify_airgap.sh` proves it.
- **Install**: needs only this directory.
- **Building the bundle** (`make bundle`, on a connected machine) pulls base images by pinned digest (`IMAGES.md`)
  and Python wheels (`make wheels`). Go is built from the committed `vendor/`. The UI build still runs `npm ci`,
  so it is **not** yet offline (docs/TODO.md: npm cache).
- Each bundle holds images for one architecture (`IMAGES.md` lists it); use the amd64 or arm64 bundle that matches the host.
- Not included: SBOM (`syft` not installed at build time).
