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
	rm -rf /tmp/ulpf-golden && mkdir -p /tmp/ulpf-golden
	go run ./contracts/gen --out /tmp/ulpf-golden
	diff -r contracts/golden /tmp/ulpf-golden
	@if [ -x intel/.venv/bin/pytest ]; then cd intel && .venv/bin/pytest -q tests/test_contract.py; else echo "SKIPPED: python conformance (create intel/.venv: see intel/README.md)"; fi

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
	rm -rf /tmp/ulpf-fx /tmp/ulpf-fx-sample
	go run ./tools/gen --seed $(SEED) --out /tmp/ulpf-fx
	go run ./tools/gen --seed $(SEED) --profile sample --out /tmp/ulpf-fx-sample
	# testdata/ also holds two artifacts this generator does not write:
	# sample/ (the other profile) and merkle_vectors.json (written by
	# `go test ./pkg/dataplane/vault/merkle -run TestWriteVectors -update`,
	# which has its own drift check).
	diff -r -x sample -x merkle_vectors.json testdata /tmp/ulpf-fx
	diff -r testdata/sample /tmp/ulpf-fx-sample

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

.PHONY: help contract-golden contract-test intel-test check fixtures fixtures-sample fixtures-check merkle-vectors build test race crash fuzz bench

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

ui-e2e: ui control-build ## Playwright end-to-end checks in local Chrome (dev machine only; report: frontend/playwright-report)
	cd frontend && npx playwright test

control-demo: ui control-build ## Run the control plane on 127.0.0.1:8000 against the built-in mock admin
	./bin/control --mock --registry-db :memory:
