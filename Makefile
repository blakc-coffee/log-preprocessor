# ULPF root Makefile.
# The Contracts workstream owns this skeleton; each workstream adds targets in
# its own labelled section. Do not edit another workstream's section.

.DEFAULT_GOAL := help

help:
	@grep -hE '^[a-z][a-zA-Z0-9_-]*:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

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

crash: ## Run the 200-cycle kill -9 crash suite (ULPF_CRASH_CYCLES=20 for a quick pass)
	go test -run 'TestCrash$$' -v -count=1 -timeout 30m ./pkg/dataplane/vault/

fuzz: ## Run the ingest/vault fuzz targets for 30s each
	go test -run '^$$' -fuzz FuzzOctet -fuzztime 30s ./pkg/dataplane/ingest/frame
	go test -run '^$$' -fuzz FuzzDelim -fuzztime 30s ./pkg/dataplane/ingest/frame
	go test -run '^$$' -fuzz FuzzRecordDecode -fuzztime 30s ./pkg/dataplane/vault/record

bench: ## Run the benchmarks. LINUX ONLY for reportable numbers - see docs/vault-format.md
	@echo "Every number must carry its sync mode. durable_ack=1 means the"
	@echo "acknowledgement meant on-disk; 0 means it did not."
	go test -run '^$$' -bench . -benchmem ./pkg/dataplane/vault/ ./pkg/dataplane/ingest/...

.PHONY: help check fixtures fixtures-sample fixtures-check merkle-vectors build test race crash fuzz bench
