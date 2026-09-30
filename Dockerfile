# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS ui-build
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM golang:1.25.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=ui-build /src/frontend/dist ./pkg/control/ui/dist
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" -o /out/ulpf ./cmd/ulpf \
    && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot AS ulpf
COPY --from=build /out/ulpf /usr/local/bin/ulpf
COPY --from=build --chown=nonroot:nonroot /out/data /data
VOLUME ["/data"]
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/ulpf", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/ulpf"]
CMD ["all", "--config", "/etc/ulpf/config.yaml"]


# The intelligence sidecar. Propose-only: it reads samples and quarantine from
# the admin API and posts drift alerts and parser proposals. It shares the ulpf
# container's network namespace (compose: network_mode service:ulpf) because
# the admin API listens on that container's loopback and nowhere else.
FROM python:3.13-slim AS intel
WORKDIR /app
COPY intel/pyproject.toml ./
COPY intel/ulpf_intel ./ulpf_intel
RUN pip install --no-cache-dir . && mkdir /state && chown nobody /state
USER nobody
VOLUME ["/state"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python", "-m", "ulpf_intel", "--healthcheck"]
ENTRYPOINT ["python", "-m", "ulpf_intel"]
CMD ["--admin", "http://127.0.0.1:9000", "--state-dir", "/state"]
