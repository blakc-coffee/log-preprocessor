# ULPF root Makefile.
# The Contracts workstream owns this skeleton; each workstream adds targets in
# its own labelled section. Do not edit another workstream's section.

.DEFAULT_GOAL := help

help:
	@grep -hE '^[a-z][a-zA-Z0-9_-]*:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- contracts (Antigravity Pro) ---
contract-golden: ## Regenerate contracts/golden/*.json (real fixtures, real merkle output, DSL-derived coverage)
	go run ./contracts/gen

contract-test: ## Goldens vs schema, OpenAPI integrity, DSL examples vs fixtures; fails if goldens drifted
	go test -count=1 ./contracts/... ./pkg/types/...
	rm -rf /tmp/sluice-golden && mkdir -p /tmp/sluice-golden
	go run ./contracts/gen --out /tmp/sluice-golden
	diff -r contracts/golden /tmp/sluice-golden
	@if [ -x intel/.venv/bin/pytest ]; then cd intel && .venv/bin/pytest -q tests/test_contract.py; else echo "SKIPPED: python conformance (create intel/.venv: see intel/README.md)"; fi

integrate: ## Run a linking step against a running data plane: make integrate STEP=1 (see docs/integration.md)
	go run ./cmd/integrate --step $(or $(STEP),all) $(ARGS)

intel-test: ## Run the sidecar's pytest suite (needs intel/.venv, see intel/README.md)
	cd intel && .venv/bin/pytest -q

# --- ingest/vault (Codex #1) ---
SEED ?= 20260928
PKGS := ./tools/... ./pkg/dataplane/ingest/... ./pkg/dataplane/vault/... ./cmd/ingestd/... ./cmd/vaultctl/...

fixtures: ## Generate the full synthetic fixture corpus into testdata/
	go run ./tools/gen --seed $(SEED) --out testdata

fixtures-sample: ## Generate the ~50-line-per-source sample corpus into testdata/sample/
	go run ./tools/gen --seed $(SEED) --profile sample --out testdata/sample

fixtures-check: ## Prove the generator is deterministic (regenerate into a temp dir and diff)
	rm -rf /tmp/sluice-fx /tmp/sluice-fx-sample
	go run ./tools/gen --seed $(SEED) --out /tmp/sluice-fx
	go run ./tools/gen --seed $(SEED) --profile sample --out /tmp/sluice-fx-sample
	# testdata/ also holds two artifacts this generator does not write:
	# sample/ (the other profile) and merkle_vectors.json (written by
	# `go test ./pkg/dataplane/vault/merkle -run TestWriteVectors -update`,
	# which has its own drift check).
	diff -r -x sample -x merkle_vectors.json testdata /tmp/sluice-fx
	diff -r testdata/sample /tmp/sluice-fx-sample

merkle-vectors: ## Regenerate testdata/merkle_vectors.json (tell Frontend and Contracts when it changes)
	go test ./pkg/dataplane/vault/merkle -run TestWriteVectors -update

check: ## Everything the chunk rule requires, in one command. Run this first and last.
	@echo "==> gofmt"
	@test -z "$$(gofmt -l pkg cmd tools)" || { echo "unformatted:"; gofmt -l pkg cmd tools; exit 1; }
	@echo "==> go vet"
	@go vet ./...
	@echo "==> go test -race (incl. a 40-cycle crash pass; make crash runs the full 200)"
	@ULPF_CRASH_CYCLES=40 CGO_ENABLED=1 go test -race ./...
	@echo "==> fixture determinism"
	@$(MAKE) --no-print-directory fixtures-check
	@echo "==> CGO_ENABLED=0 build"
	@CGO_ENABLED=0 go build -o /dev/null ./... 2>/dev/null || CGO_ENABLED=0 go build ./...
	@echo "ALL GREEN"

build: ## Build ingestd and vaultctl with CGO disabled
	CGO_ENABLED=0 go build -o bin/ ./cmd/ingestd ./cmd/vaultctl

test: ## Run the ingest/vault test suite
	CGO_ENABLED=1 go test $(PKGS)

race: ## Run the ingest/vault test suite under the race detector (needs cgo)
	CGO_ENABLED=1 go test -race $(PKGS)

crash: ## Run the 200-cycle kill -9 suite, with and without compaction (ULPF_CRASH_CYCLES=20 for a quick pass)
	go test -run 'TestCrash$$|TestCrashWithCompaction' -v -count=1 -timeout 30m ./pkg/dataplane/vault/

fuzz: ## Run the ingest/vault fuzz targets for 30s each
	go test -run '^$$' -fuzz FuzzOctet -fuzztime 30s ./pkg/dataplane/ingest/frame
	go test -run '^$$' -fuzz FuzzDelim -fuzztime 30s ./pkg/dataplane/ingest/frame
	go test -run '^$$' -fuzz FuzzRecordDecode -fuzztime 30s ./pkg/dataplane/vault/record

bench: ## Run the benchmarks. LINUX ONLY for reportable numbers - see docs/vault-format.md
	@echo "Every number must carry its sync mode. durable_ack=1 means the"
	@echo "acknowledgement meant on-disk; 0 means it did not."
	go test -run '^$$' -bench . -benchmem ./pkg/dataplane/vault/ ./pkg/dataplane/ingest/...

.PHONY: help contract-golden contract-test intel-test integrate check fixtures fixtures-sample fixtures-check merkle-vectors build test race crash fuzz bench ui ui-test control-test control-build control-demo

# --- control plane & frontend (Claude Code #2) ---
ui: ## Build the React UI and copy it into pkg/control/ui/dist for go:embed
	cd frontend && npm ci --ignore-scripts && npm run build
	find pkg/control/ui/dist -mindepth 1 ! -name .keep -delete
	cp -R frontend/dist/. pkg/control/ui/dist/

ui-test: ## Frontend unit and component tests, lint and the design-rule check
	cd frontend && npm run typecheck && npm run lint && npm test

control-test: ## Control API, registry and mock admin tests (race detector)
	CGO_ENABLED=1 go test -race ./pkg/control/... ./cmd/control/...

control-build: ## Build cmd/control with CGO disabled (run `make ui` first to embed the UI)
	CGO_ENABLED=0 go build -o bin/ ./cmd/control

control-demo: ui control-build ## Run the control plane on 127.0.0.1:8000 against the built-in mock admin
	./bin/control --mock --registry-db :memory:


# --- offline package (make bundle) ---
# VERSION is the image tag and is stamped into the binary. Override: make bundle VERSION=1.0.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PYIMG   := python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b

.PHONY: vendor wheels bundle dist
vendor: ## Refresh vendor/ from go.mod (commit the result)
	go mod vendor

wheels: ## Download the sidecar's Python wheels (+ build backend) into intel/wheels/{amd64,arm64}/. Needs network; the non-host arch runs under emulation.
	rm -rf intel/wheels && mkdir -p intel/wheels
	@for a in amd64 arm64; do mkdir -p intel/wheels/$$a; \
	  docker run --rm --platform linux/$$a -v "$(CURDIR)/intel:/src:ro" -v "$(CURDIR)/intel/wheels/$$a:/w" $(PYIMG) \
	    sh -c 'cp -r /src /tmp/s && pip wheel -q -w /w /tmp/s setuptools wheel && rm -f /w/sluice_intel-*.whl /w/ulpf_intel-*.whl' || exit 1; done

ARCH ?= $(shell docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')

bundle: vendor wheels ## Build both images for ARCH (default: host; make bundle ARCH=amd64) and write dist/sluice-offline-<ver>-<arch>.tar
	docker build --platform linux/$(ARCH) --target sluice -t sluice:$(VERSION) --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILT_AT=$$(date -u +%Y-%m-%dT%H:%M:%SZ) .
	docker build --platform linux/$(ARCH) --target intel -t sluice-intel:$(VERSION) .
	docker save sluice:$(VERSION) sluice-intel:$(VERSION) | zstd -19 -T0 -f -o offline/sluice-images-$(VERSION)-$(ARCH).tar.zst
	rm -rf offline/configs && cp -r configs offline/configs
	printf 'ULPF_TAG=$(VERSION)\n' > offline/.env
	ARCH=$(ARCH) sh scripts/write_images_md.sh > offline/IMAGES.md
	cd offline && shasum -a 256 sluice-images-$(VERSION)-$(ARCH).tar.zst docker-compose.yml .env IMAGES.md README.md $$(find configs -type f | sort) > SHA256SUMS
	mkdir -p dist && tar -cf dist/sluice-offline-$(VERSION)-$(ARCH).tar offline/README.md offline/docker-compose.yml offline/.env offline/IMAGES.md offline/SHA256SUMS offline/configs offline/sluice-images-$(VERSION)-$(ARCH).tar.zst
	@echo "bundle: dist/sluice-offline-$(VERSION)-$(ARCH).tar"

dist: vendor ui ## Cross-compile sluice, vaultctl, ingestd (linux+darwin, amd64+arm64) into dist/ with checksums
	@test -f pkg/control/ui/dist/index.html || { echo 'dist: the web UI is not built into pkg/control/ui/dist (make ui)'; exit 1; }
	mkdir -p dist && rm -f dist/sluice_* dist/checksums.txt
	@for os in linux darwin; do for arch in amd64 arm64; do \
	  d=dist/sluice_$(VERSION)_$${os}_$${arch}; mkdir -p $$d; \
	  for c in sluice vaultctl ingestd; do \
	    CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -mod=vendor -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.builtAt=$$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o $$d/$$c ./cmd/$$c || exit 1; done; \
	  cp LICENSE README.md $$d/ 2>/dev/null; \
	  tar -C dist -czf $$d.tar.gz $$(basename $$d) && rm -rf $$d; \
	done; done
	tar -C . -cf - vendor | zstd -19 -T0 -f -o dist/sluice_$(VERSION)_vendor.tar.zst
	cd dist && rm -f checksums.txt && shasum -a 256 sluice* > checksums.txt
