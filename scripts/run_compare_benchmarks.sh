#!/usr/bin/env bash
set -euo pipefail

: "${COMPARE_BENCH_COUNT:=3}"
: "${COMPARE_BENCH_SCAN_ITERS:=100000}"
: "${COMPARE_BENCH_NEW_SCANNER_ITERS:=500}"
: "${COMPARE_BENCH_RULES_SCAN_ITERS:=1000}"
: "${COMPARE_BENCH_READ_FROM_ITERS:=500}"
: "${COMPARE_BENCH_LOAD_RULESET_ITERS:=1}"
: "${COMPARE_BENCH_SCAN_CORPUS_ITERS:=1}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
benchcmp_dir="${repo_root}/benchcmp"
default_compare_ref=main

: "${YARAX_COMPARE_REPO:=https://github.com/VirusTotal/yara-x.git}"
: "${YARAX_COMPARE_REF:=${default_compare_ref}}"
: "${YARAX_COMPARE_CLONE_DIR:=${repo_root}/.tmp/benchcmp/yara-x}"
: "${YARAX_COMPARE_PREFIX:=${repo_root}/.tmp/benchcmp/prefix}"

export PATH="${HOME}/.cargo/bin:/usr/local/go/bin:${PATH}"

require_compare_root() {
	local root=$1

	if [[ ! -f "${root}/go/go.mod" ]]; then
		printf 'expected a YARA-X checkout with go bindings at %s/go\n' "${root}" >&2
		exit 1
	fi

	if [[ ! -f "${root}/Cargo.toml" ]]; then
		printf 'expected a YARA-X checkout with Cargo.toml at %s\n' "${root}" >&2
		exit 1
	fi
}

ensure_compare_checkout() {
	local root=$1

	mkdir -p "$(dirname -- "${root}")"

	if [[ -e "${root}" && ! -d "${root}/.git" ]]; then
		printf 'YARAX_COMPARE_CLONE_DIR already exists and is not a git checkout: %s\n' "${root}" >&2
		exit 1
	fi

	if [[ ! -d "${root}/.git" ]]; then
		git clone --no-checkout "${YARAX_COMPARE_REPO}" "${root}"
	else
		git -C "${root}" remote set-url origin "${YARAX_COMPARE_REPO}"
	fi

	git -C "${root}" fetch --depth 1 origin "${YARAX_COMPARE_REF}"
	git -c advice.detachedHead=false -C "${root}" checkout --detach FETCH_HEAD

	require_compare_root "${root}"
	printf '%s\n' "${root}"
}

resolve_compare_root() {
	local candidate

	if [[ -n "${YARAX_COMPARE_ROOT:-}" ]]; then
		require_compare_root "${YARAX_COMPARE_ROOT}"
		printf '%s\n' "${YARAX_COMPARE_ROOT}"
		return
	fi

	for candidate in \
		"${repo_root}/../yara-x" \
		"${repo_root}/../upstream-yara-x-js" \
		"${repo_root}/../third_party/yara-x"
	do
		if [[ -f "${candidate}/go/go.mod" && -f "${candidate}/Cargo.toml" ]]; then
			printf '%s\n' "${candidate}"
			return
		fi
	done

	ensure_compare_checkout "${YARAX_COMPARE_CLONE_DIR}"
}

prepare_bench_modfile() {
	local compare_root=$1
	local mod_dir="${benchcmp_dir}/.tmp"
	local mod_file="${mod_dir}/go.bench.mod"
	local sum_file="${mod_dir}/go.bench.sum"

	mkdir -p "${mod_dir}"
	cp "${benchcmp_dir}/go.mod" "${mod_file}"
	if [[ -f "${benchcmp_dir}/go.sum" ]]; then
		cp "${benchcmp_dir}/go.sum" "${sum_file}"
	else
		: >"${sum_file}"
	fi

	(
		cd "${benchcmp_dir}"
		go mod edit -modfile="${mod_file}" -replace "github.com/niallnsec/yaraxwasm=${repo_root}"
		go mod edit -modfile="${mod_file}" -replace "github.com/VirusTotal/yara-x/go=${compare_root}/go"
		go mod edit -modfile="${mod_file}" -require "github.com/VirusTotal/yara-x/go@v0.0.0"
		go mod tidy -modfile="${mod_file}"
	)
	printf '%s\n' "${mod_file}"
}

if ! cargo cinstall --help >/dev/null 2>&1; then
	cargo install cargo-c --version 0.10.18+cargo-0.92.0 --locked
fi

compare_root=$(resolve_compare_root)
bench_modfile=$(prepare_bench_modfile "${compare_root}")

mkdir -p "${YARAX_COMPARE_PREFIX}/lib" "${YARAX_COMPARE_PREFIX}/include"

printf 'using YARA-X comparison checkout: %s\n' "${compare_root}" >&2
printf 'using benchmark modfile: %s\n' "${bench_modfile}" >&2

cargo_cinstall_args=(
	cinstall
	--manifest-path "${compare_root}/Cargo.toml"
	-p yara-x-capi
	--release
	--prefix "${YARAX_COMPARE_PREFIX}"
	--libdir "${YARAX_COMPARE_PREFIX}/lib"
	--includedir "${YARAX_COMPARE_PREFIX}/include"
)

cargo "${cargo_cinstall_args[@]}"

export PKG_CONFIG_PATH="${YARAX_COMPARE_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
export LD_LIBRARY_PATH="${YARAX_COMPARE_PREFIX}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export DYLD_LIBRARY_PATH="${YARAX_COMPARE_PREFIX}/lib${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}"

cd "${benchcmp_dir}"

go test -modfile="${bench_modfile}" -run "^$" -bench "^(Benchmark(CGO|WASM)ScanReuseScanner)$" -benchmem -benchtime="${COMPARE_BENCH_SCAN_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -modfile="${bench_modfile}" -run "^$" -bench "^(Benchmark(CGO|WASM)NewScanner)$" -benchmem -benchtime="${COMPARE_BENCH_NEW_SCANNER_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -modfile="${bench_modfile}" -run "^$" -bench "^(Benchmark(CGO|WASM)RulesScan)$" -benchmem -benchtime="${COMPARE_BENCH_RULES_SCAN_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -modfile="${bench_modfile}" -run "^$" -bench "^(Benchmark(CGO|WASM)ReadFrom)$" -benchmem -benchtime="${COMPARE_BENCH_READ_FROM_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -modfile="${bench_modfile}" -run "^$" -bench "^(Benchmark(CGO|WASM)LoadRuleset)$" -benchmem -benchtime="${COMPARE_BENCH_LOAD_RULESET_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -modfile="${bench_modfile}" -run "^$" -bench "^(Benchmark(CGO|WASM)ScanWordPressCorpus(Buffered)?)$" -benchmem -benchtime="${COMPARE_BENCH_SCAN_CORPUS_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
