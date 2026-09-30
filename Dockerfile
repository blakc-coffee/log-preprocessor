# syntax=docker/dockerfile:1.7
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS ui-build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM golang:1.25.1-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS build
WORKDIR /src
COPY . .
COPY --from=ui-build /src/frontend/dist ./pkg/control/ui/dist
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
# -mod=vendor: the Go build needs no module proxy. (The ui-build stage still uses npm.)
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -mod=vendor -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" -o /out/sluice ./cmd/sluice \
    && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS sluice
COPY --from=build /out/sluice /usr/local/bin/sluice
COPY --from=build --chown=nonroot:nonroot /out/data /data
VOLUME ["/data"]
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/sluice", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sluice"]
CMD ["all", "--config", "/etc/sluice/config.yaml"]


# The intelligence sidecar. Propose-only: it reads samples and quarantine from
# the admin API and posts drift alerts and parser proposals. It shares the sluice
# container's network namespace (compose: network_mode service:sluice) because
# the admin API listens on that container's loopback and nowhere else.
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS intel
WORKDIR /app
COPY intel/pyproject.toml ./
COPY intel/ulpf_intel ./ulpf_intel
COPY intel/wheels ./wheels
# Offline: every dependency comes from intel/wheels (make wheels), never from PyPI.
RUN pip install --no-cache-dir --no-index --find-links wheels/ . && mkdir /state && chown nobody /state
USER nobody
VOLUME ["/state"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-m", "ulpf_intel", "--healthcheck"]
ENTRYPOINT ["python", "-m", "ulpf_intel"]
CMD ["--admin", "http://127.0.0.1:9000", "--state-dir", "/state"]
