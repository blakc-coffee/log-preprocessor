# syntax=docker/dockerfile:1.7
FROM golang:1.25.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" -o /out/ulpf ./cmd/ulpf

FROM gcr.io/distroless/static-debian12:nonroot AS ulpf
COPY --from=build /out/ulpf /usr/local/bin/ulpf
COPY testdata /opt/ulpf/testdata
VOLUME ["/data/vault", "/data/quarantine"]
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/ulpf"]
CMD ["all", "--config", "/etc/ulpf/config.yaml"]

