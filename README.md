[![Tests](https://github.com/niallnsec/yaraxwasm/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/niallnsec/yaraxwasm/actions/workflows/tests.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/niallnsec/yaraxwasm.svg)](https://pkg.go.dev/github.com/niallnsec/yaraxwasm)

# yaraxwasm

`yaraxwasm` is a Go package that exposes [YARA-X](https://github.com/VirusTotal/yara-x)
through a WebAssembly guest runtime hosted by [wazero](https://github.com/tetratelabs/wazero).

The project exists to make YARA-X easy to embed in Go programs without asking
callers to manage a separate native shared library. Instead of linking directly
to Rust code, the Go API talks to a bundled or caller-supplied WASM guest that
contains the YARA-X engine.

## Why This Exists

YARA-X is a modern YARA engine implemented in Rust. It is powerful, but wiring a
Rust engine into Go usually means dealing with native build pipelines, ABI
boundaries, or distribution of platform-specific artifacts.

`yaraxwasm` takes a different approach:

- the host side stays in Go
- the scanning engine runs inside a WASM guest
- the default guest can be embedded directly into the Go binary
- callers can still override the guest module when they need to

That gives Go applications a straightforward way to use YARA-X while keeping a
clear runtime boundary between the Go host and the scanning engine.

## Supported Features

- Compile YARA-X rules from Go source strings.
- Scan in-memory byte slices, files, and `io.ReaderAt` sources.
- Load the scanning engine from an embedded guest module, a filesystem path, or
  an `io.Reader`.
- Export and import compiled rules.
- Create and verify signed compiled-rules containers.
- Sign compiled rules with Ed25519 or x509/CMS.
- Verify x509/CMS signatures with optional RFC3161 timestamp, EKU, custom EKU,
  and CRL enforcement.
- Opt into experimental custom guest-memory allocators through
  [`github.com/niallnsec/yaraxwasm/experimental`](https://pkg.go.dev/github.com/niallnsec/yaraxwasm/experimental).

## High-Level Design

At a high level, the library is split into two sides:

1. The Go host API, which exposes familiar types such as `Compiler`, `Rules`,
   and `Scanner`.
2. The YARA-X guest module, which is compiled to WASM and executed by wazero.

The normal workflow looks like this:

1. Go code compiles or loads rules through `yaraxwasm`.
2. The host runtime ensures the guest module is loaded.
3. Rule compilation and scanning work is delegated to the guest.
4. Results are translated back into Go types.

For deployments that need authenticated rule distribution, the library also
supports signed compiled-rules containers. Those containers wrap the compiled
rule bytes in a fixed header plus metadata and signature, so rules can be
transported and verified before loading.

## Quick Start

Compile and scan:

```go
package main

import (
	"fmt"
	"log"

	"github.com/niallnsec/yaraxwasm"
)

func main() {
	rules, err := yaraxwasm.Compile(`
rule demo {
	strings:
		$needle = "hello"
	condition:
		$needle
}`)
	if err != nil {
		log.Fatal(err)
	}
	defer rules.Destroy()

	results, err := rules.Scan([]byte("hello from yaraxwasm"))
	if err != nil {
		log.Fatal(err)
	}

	for _, match := range results.MatchingRules() {
		fmt.Println(match.Identifier())
	}
}
```

## Guest Module Loading

By default, the package uses an embedded guest module. If you want to supply
your own guest build, you can do that explicitly with [`Initialise`] and either
[`GuestWASMPath`] or [`GuestWASMReader`].

If no explicit source is given, initialization falls back in this order:

1. the explicit option passed to `Initialise`
2. `YARAX_GUEST_WASM`
3. the embedded guest module

Example:

```go
err := yaraxwasm.Initialise(
	yaraxwasm.GuestWASMPath("/absolute/path/to/yarax_guest.wasm"),
)
if err != nil {
	// handle error
}
```

You can also provide the module through the environment:

```bash
export YARAX_GUEST_WASM=/absolute/path/to/yarax_guest.wasm
```

## Signed Compiled Rules

The library can wrap compiled rules in a signed container format so that a rule
producer can export them and a consumer can verify them before loading.

Supported signing and verification flows include:

- Ed25519 signatures over the signed container payload
- x509/CMS detached signatures
- optional RFC3161 timestamp verification
- required EKU and custom EKU checks
- optional CRL enforcement

Runnable examples for these flows live under [`examples/`](examples/README.md):

- export and sign with Ed25519
- export and sign with x509/CMS, timestamping, and custom EKU
- verify and load Ed25519-signed compiled rules
- verify and load x509/CMS-signed compiled rules

Initialize the example PKI with:

```bash
./examples/init-pki.sh
```

Then run the example programs with:

```bash
go run ./examples/ed25519_export_sign
go run ./examples/x509_export_sign
go run ./examples/ed25519_verify_load
go run ./examples/x509_verify_load
```

## Experimental Memory Paths

The [`experimental`](https://pkg.go.dev/github.com/niallnsec/yaraxwasm/experimental)
package contains unstable extensions for advanced runtime configuration.

Today that primarily means custom guest-memory allocators that can enable more
efficient file and `io.ReaderAt` scanning paths on supported platforms. These
APIs are intentionally separated from the main package because they may evolve
as the runtime design is refined.

## Development

The repository includes the guest source used to build the WASM engine.

For a reproducible development environment, open the repository in the
included devcontainer. It provides:

- Go 1.26 plus `golangci-lint` and `easyjson`
- Rust 1.94.1 with `clippy`, `rustfmt`, `wasm32-wasip1`, and nightly
  `rust-src` for the experimental memory64 `wasm64-unknown-unknown` path
- native build dependencies such as `clang`, `cmake`, `pkg-config`,
  `libssl-dev`, and `zstd`
- `cargo-c` plus persistent Go, Cargo target, and benchmark caches
- privileged container settings so `make test-userfaultfd-local` works inside
  the devcontainer

Build the guest:

```bash
make guest-release
```

Regenerate the embedded guest artifact:

```bash
go generate ./...
```

Run the Go test suite:

```bash
go test ./...
```

Run the guest-backed test paths:

```bash
make test-local
make test-profiling-local
make test-userfaultfd-local
```

Run the benchmark comparison suite:

```bash
make bench-compare
```

The benchmark helper prepares its own temporary `benchcmp` modfile and
comparison checkout, so `benchcmp` does not need a standalone `go mod download`
during devcontainer startup. By default it compares against
`github.com/VirusTotal/yara-x` on `main`. The extended compare suite also
downloads the pinned YARA Forge full ruleset and refreshes the latest
WordPress source tree under `benchcmp/.tmp/datasets` unless
`COMPARE_BENCH_DATA_DIR` is set.

Run the linters:

```bash
golangci-lint run ./...
(cd guest && cargo clippy --tests --no-deps -- --deny clippy::all)
(cd guest && cargo fmt --all --check)
```

Run the same checks as the GitHub workflows locally:

```bash
make ci-local
```

## Current Benchmark Results

These measurements were taken on March 29, 2026 on Linux `arm64` inside Docker
with `make docker-bench-compare`. The comparison target was
`github.com/VirusTotal/yara-x` `main` at `2f193c33`. Each value below is the
median of 3 runs. The compare harness warms the WASM runtime before
`b.ResetTimer`, and the steady-state scan benchmarks also create scanners and
perform a warmup scan before timing starts, so the reported CPU, `ns/op`,
`B/op`, and `allocs/op` figures exclude one-time WASM startup work.

| Benchmark | CGO ns/op | WASM ns/op | WASM/CGO | CGO MB/s | WASM MB/s | CGO B/op | WASM B/op | CGO allocs/op | WASM allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Scan reuse scanner | 8,159 | 27,615 | 3.38x | 1.59 | 0.47 | 4,514 | 2,276 | 149 | 35 |
| New scanner | 181,891 | 4,802,704 | 26.40x | - | - | 99 | 15,675,610 | 2 | 19,505 |
| Rules.Scan | 192,072 | 4,898,888 | 25.51x | 0.07 | 0.00 | 4,744 | 20,890,227 | 153 | 19,559 |
| ReadFrom | 1,939,326 | 984,739 | 0.51x | - | - | 25,144 | 6,382,788 | 13 | 12,087 |
| LoadRuleset | 5,110,855,145 | 6,413,220,386 | 1.25x | 3.76 | 2.99 | 272 | 2,322,163,920 | 6 | 643,548 |
| ScanWordPressCorpus | 4,699,412,364 | 8,733,536,876 | 1.86x | 16.21 | 8.72 | 80,376 | 8,632,296 | 3,349 | 56,951 |
| ScanWordPressCorpusBuffered | 4,332,508,352 | 9,464,034,019 | 2.18x | 17.58 | 8.05 | 1,407,584 | 2,369,768 | 16,745 | 56,946 |
