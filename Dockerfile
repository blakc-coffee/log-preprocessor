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
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" -o /out/ulpf ./cmd/ulpf \
    && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot AS ulpf
COPY --from=build /out/ulpf /usr/local/bin/ulpf
COPY --from=build --chown=nonroot:nonroot /out/data /data
VOLUME ["/data"]
USER nonroot:nonroot
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/ulpf", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/ulpf"]
CMD ["all", "--config", "/etc/ulpf/config.yaml"]

