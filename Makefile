DOCKER ?= docker
TEST_IMAGE ?= yaraxwasm-test:latest
CACHE_DIR ?= $(HOME)/.cache/yaraxwasm
REPO_ROOT := $(abspath .)
CONTAINER_WORKDIR := /workspace/$(notdir $(REPO_ROOT))
BENCH_COMPARE_CLONE_DIR ?= $(REPO_ROOT)/.tmp/benchcmp/yara-x
BENCH_COMPARE_PREFIX ?= $(REPO_ROOT)/.tmp/benchcmp/prefix
BENCHCMP_COMPARE_REPO ?= https://github.com/VirusTotal/yara-x.git
BENCHCMP_COMPARE_REF ?= v1.9.0

TEST_LOCAL_GUEST_WASM := $(if $(strip $(YARAX_GUEST_WASM)),$(YARAX_GUEST_WASM),$(abspath guest/release/yarax_guest.wasm))
TEST_PROFILING_GUEST_WASM := $(if $(strip $(YARAX_GUEST_WASM)),$(YARAX_GUEST_WASM),$(abspath guest/release-profiling/yarax_guest.wasm))
DOCKER_YARAX_GUEST_WASM_ENV := $(if $(strip $(YARAX_GUEST_WASM)),-e YARAX_GUEST_WASM=$(YARAX_GUEST_WASM),)

.PHONY: guest-release guest-release-profiling guest-release-memory64 guest-release-memory64-profiling test-local test-profiling-local test-profiling test-userfaultfd-local bench-compare benchcmp-lint ci-local docker-test-image docker-test docker-test-run docker-test-local docker-test-local-run docker-test-userfaultfd docker-test-userfaultfd-run docker-test-userfaultfd-local docker-test-userfaultfd-local-run docker-bench-compare

guest-release:
	cd guest && cargo build-web-release

guest-release-profiling:
	cd guest && cargo build-web-release --profiling

guest-release-memory64:
	cd guest && cargo build-web-release --memory64

guest-release-memory64-profiling:
	cd guest && cargo build-web-release --memory64 --profiling

ifeq ($(strip $(YARAX_GUEST_WASM)),)
test-local: guest-release
else
test-local:
endif
	YARAX_GUEST_WASM='$(TEST_LOCAL_GUEST_WASM)' \
	go test ./... -count=1

ifeq ($(strip $(YARAX_GUEST_WASM)),)
test-profiling-local: guest-release-profiling
else
test-profiling-local:
endif
	YARAX_GUEST_WASM='$(TEST_PROFILING_GUEST_WASM)' \
	YARAX_REQUIRE_PROFILING=1 \
	go test ./... -run 'TestScannerProfilingEnabledWithOverride|TestScannerProfilingAPIs' -count=1

test-profiling: test-profiling-local

ifeq ($(strip $(YARAX_GUEST_WASM)),)
test-userfaultfd-local: guest-release
else
test-userfaultfd-local:
endif
	YARAX_GUEST_WASM='$(TEST_LOCAL_GUEST_WASM)' \
	YARAX_EXPERIMENTAL_UFFD=1 \
	go test ./experimental -count=1

bench-compare:
	mkdir -p $(REPO_ROOT)/.tmp
	COMPARE_BENCH_DATA_DIR='$(REPO_ROOT)/benchcmp/.tmp/datasets' \
	COMPARE_BENCH_LOAD_RULESET_ITERS='$(COMPARE_BENCH_LOAD_RULESET_ITERS)' \
	COMPARE_BENCH_SCAN_CORPUS_ITERS='$(COMPARE_BENCH_SCAN_CORPUS_ITERS)' \
	YARAX_COMPARE_ROOT='$(YARAX_COMPARE_ROOT)' \
	YARAX_COMPARE_REPO='$(YARAX_COMPARE_REPO)' \
	YARAX_COMPARE_REF='$(YARAX_COMPARE_REF)' \
	YARAX_COMPARE_CLONE_DIR='$(BENCH_COMPARE_CLONE_DIR)' \
	YARAX_COMPARE_PREFIX='$(BENCH_COMPARE_PREFIX)' \
	bash $(REPO_ROOT)/scripts/run_compare_benchmarks.sh

benchcmp-lint:
	BENCHCMP_COMPARE_REPO='$(BENCHCMP_COMPARE_REPO)' \
	BENCHCMP_COMPARE_REF='$(BENCHCMP_COMPARE_REF)' \
	BENCH_COMPARE_CLONE_DIR='$(BENCH_COMPARE_CLONE_DIR)' \
	bash $(REPO_ROOT)/scripts/lint_benchcmp.sh

ci-local: docker-test-image
	golangci-lint run ./...
	$(MAKE) benchcmp-lint
	cd guest && cargo clippy --tests --no-deps -- --deny clippy::all
	cd guest && cargo fmt --all --check
	go test ./...
	$(MAKE) test-local
	$(MAKE) test-profiling-local
	$(MAKE) docker-test-run
	$(MAKE) docker-test-local-run
	$(MAKE) docker-test-userfaultfd-run
	$(MAKE) docker-test-userfaultfd-local-run

docker-test-image:
	$(DOCKER) buildx build --load -f Dockerfile.test -t $(TEST_IMAGE) .

docker-test: docker-test-image docker-test-run

docker-test-run:
	mkdir -p $(REPO_ROOT)/.tmp $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target
	$(DOCKER) run --rm \
		-v $(REPO_ROOT):$(CONTAINER_WORKDIR) \
		-v $(CACHE_DIR):/cache \
		-w $(CONTAINER_WORKDIR) \
		-e TMPDIR=$(CONTAINER_WORKDIR)/.tmp \
		-e TMP=$(CONTAINER_WORKDIR)/.tmp \
		-e TEMP=$(CONTAINER_WORKDIR)/.tmp \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		$(TEST_IMAGE) \
		sh -c 'cargo fetch --locked --manifest-path guest/Cargo.toml && go test ./...'

docker-test-local: docker-test-image docker-test-local-run

docker-test-local-run:
	mkdir -p $(REPO_ROOT)/.tmp $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target
	$(DOCKER) run --rm \
		-v $(REPO_ROOT):$(CONTAINER_WORKDIR) \
		-v $(CACHE_DIR):/cache \
		-w $(CONTAINER_WORKDIR) \
		-e TMPDIR=$(CONTAINER_WORKDIR)/.tmp \
		-e TMP=$(CONTAINER_WORKDIR)/.tmp \
		-e TEMP=$(CONTAINER_WORKDIR)/.tmp \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		$(DOCKER_YARAX_GUEST_WASM_ENV) \
		$(TEST_IMAGE) \
		make test-local

docker-test-userfaultfd: docker-test-image docker-test-userfaultfd-run

docker-test-userfaultfd-run:
	mkdir -p $(REPO_ROOT)/.tmp $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target
	$(DOCKER) run --rm --privileged --security-opt seccomp=unconfined \
		-v $(REPO_ROOT):$(CONTAINER_WORKDIR) \
		-v $(CACHE_DIR):/cache \
		-w $(CONTAINER_WORKDIR) \
		-e TMPDIR=$(CONTAINER_WORKDIR)/.tmp \
		-e TMP=$(CONTAINER_WORKDIR)/.tmp \
		-e TEMP=$(CONTAINER_WORKDIR)/.tmp \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		-e YARAX_EXPERIMENTAL_UFFD=1 \
		$(TEST_IMAGE) \
		sh -c 'cargo fetch --locked --manifest-path guest/Cargo.toml && go test ./experimental -count=1'

docker-test-userfaultfd-local: docker-test-image docker-test-userfaultfd-local-run

docker-test-userfaultfd-local-run:
	mkdir -p $(REPO_ROOT)/.tmp $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target
	$(DOCKER) run --rm --privileged --security-opt seccomp=unconfined \
		-v $(REPO_ROOT):$(CONTAINER_WORKDIR) \
		-v $(CACHE_DIR):/cache \
		-w $(CONTAINER_WORKDIR) \
		-e YARAX_EXPERIMENTAL_UFFD=1 \
		-e TMPDIR=$(CONTAINER_WORKDIR)/.tmp \
		-e TMP=$(CONTAINER_WORKDIR)/.tmp \
		-e TEMP=$(CONTAINER_WORKDIR)/.tmp \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		$(DOCKER_YARAX_GUEST_WASM_ENV) \
		$(TEST_IMAGE) \
		make test-userfaultfd-local

docker-bench-compare: docker-test-image
	mkdir -p $(REPO_ROOT)/.tmp $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target $(CACHE_DIR)/benchcmp
	$(DOCKER) run --rm \
		-v $(REPO_ROOT):$(CONTAINER_WORKDIR) \
		-v $(CACHE_DIR):/cache \
		-w $(CONTAINER_WORKDIR) \
		-e TMPDIR=$(CONTAINER_WORKDIR)/.tmp \
		-e TMP=$(CONTAINER_WORKDIR)/.tmp \
		-e TEMP=$(CONTAINER_WORKDIR)/.tmp \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		-e COMPARE_BENCH_COUNT=$(COMPARE_BENCH_COUNT) \
		-e COMPARE_BENCH_SCAN_ITERS=$(COMPARE_BENCH_SCAN_ITERS) \
		-e COMPARE_BENCH_NEW_SCANNER_ITERS=$(COMPARE_BENCH_NEW_SCANNER_ITERS) \
		-e COMPARE_BENCH_RULES_SCAN_ITERS=$(COMPARE_BENCH_RULES_SCAN_ITERS) \
		-e COMPARE_BENCH_READ_FROM_ITERS=$(COMPARE_BENCH_READ_FROM_ITERS) \
		-e COMPARE_BENCH_LOAD_RULESET_ITERS=$(COMPARE_BENCH_LOAD_RULESET_ITERS) \
		-e COMPARE_BENCH_SCAN_CORPUS_ITERS=$(COMPARE_BENCH_SCAN_CORPUS_ITERS) \
		-e COMPARE_BENCH_DATA_DIR=/cache/benchcmp/data \
		-e YARAX_COMPARE_REPO=$(YARAX_COMPARE_REPO) \
		-e YARAX_COMPARE_REF=$(YARAX_COMPARE_REF) \
		-e YARAX_COMPARE_CLONE_DIR=/cache/benchcmp/yara-x \
		-e YARAX_COMPARE_PREFIX=/cache/benchcmp/prefix \
		$(TEST_IMAGE) \
		bash $(CONTAINER_WORKDIR)/scripts/run_compare_benchmarks.sh
