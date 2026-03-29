#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
benchcmp_dir="${repo_root}/benchcmp"

: "${BENCHCMP_COMPARE_REPO:=https://github.com/VirusTotal/yara-x.git}"
: "${BENCHCMP_COMPARE_REF:=v1.9.0}"
: "${BENCH_COMPARE_CLONE_DIR:=${repo_root}/.tmp/benchcmp/yara-x}"
: "${BENCH_COMPARE_PREFIX:=${repo_root}/.tmp/benchcmp/prefix}"

compare_root="${BENCH_COMPARE_CLONE_DIR}"
mod_dir="${benchcmp_dir}/.tmp"
mod_backup="${mod_dir}/go.orig.mod"
sum_backup="${mod_dir}/go.orig.sum"
mod_work="${mod_dir}/go.bench.mod"
sum_work="${mod_dir}/go.bench.sum"

export PATH="${HOME}/.cargo/bin:/usr/local/go/bin:${PATH}"

cleanup() {
	if [[ -f "${mod_backup}" ]]; then
		mv "${mod_backup}" "${benchcmp_dir}/go.mod"
	fi

	if [[ -f "${sum_backup}" ]]; then
		mv "${sum_backup}" "${benchcmp_dir}/go.sum"
	else
		rm -f "${benchcmp_dir}/go.sum"
	fi

	rm -f "${mod_work}" "${sum_work}"
}

trap cleanup EXIT

mkdir -p "${mod_dir}" "$(dirname -- "${compare_root}")"

if [[ -e "${compare_root}" && ! -d "${compare_root}/.git" ]]; then
	printf 'BENCH_COMPARE_CLONE_DIR already exists and is not a git checkout: %s\n' "${compare_root}" >&2
	exit 1
fi

if [[ ! -d "${compare_root}/.git" ]]; then
	git clone --no-checkout "${BENCHCMP_COMPARE_REPO}" "${compare_root}"
else
	git -C "${compare_root}" remote set-url origin "${BENCHCMP_COMPARE_REPO}"
fi

git -C "${compare_root}" fetch --depth 1 origin "${BENCHCMP_COMPARE_REF}"
git -c advice.detachedHead=false -C "${compare_root}" checkout --detach FETCH_HEAD

if [[ ! -f "${compare_root}/go/go.mod" ]]; then
	printf 'expected a YARA-X checkout with go bindings at %s/go\n' "${compare_root}" >&2
	exit 1
fi

if [[ ! -f "${compare_root}/Cargo.toml" ]]; then
	printf 'expected a YARA-X checkout with Cargo.toml at %s\n' "${compare_root}" >&2
	exit 1
fi

if ! cargo cinstall --help >/dev/null 2>&1; then
	cargo install cargo-c --version 0.10.18+cargo-0.92.0 --locked
fi

mkdir -p "${BENCH_COMPARE_PREFIX}/lib" "${BENCH_COMPARE_PREFIX}/include"

cargo cinstall \
	--manifest-path "${compare_root}/Cargo.toml" \
	-p yara-x-capi \
	--release \
	--prefix "${BENCH_COMPARE_PREFIX}" \
	--libdir "${BENCH_COMPARE_PREFIX}/lib" \
	--includedir "${BENCH_COMPARE_PREFIX}/include"

export PKG_CONFIG_PATH="${BENCH_COMPARE_PREFIX}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
export LD_LIBRARY_PATH="${BENCH_COMPARE_PREFIX}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export DYLD_LIBRARY_PATH="${BENCH_COMPARE_PREFIX}/lib${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}"

cp "${benchcmp_dir}/go.mod" "${mod_backup}"
if [[ -f "${benchcmp_dir}/go.sum" ]]; then
	cp "${benchcmp_dir}/go.sum" "${sum_backup}"
fi

(
	cd "${benchcmp_dir}"
	cp "${mod_backup}" "${mod_work}"
	if [[ -f "${sum_backup}" ]]; then
		cp "${sum_backup}" "${sum_work}"
	fi

	go mod edit -modfile=.tmp/go.bench.mod -replace "github.com/niallnsec/yaraxwasm=${repo_root}"
	go mod edit -modfile=.tmp/go.bench.mod -replace "github.com/VirusTotal/yara-x/go=${compare_root}/go"
	go mod tidy -modfile=.tmp/go.bench.mod
	go mod edit -modfile=.tmp/go.bench.mod -require "github.com/VirusTotal/yara-x/go@v0.0.0"

	cp "${mod_work}" go.mod
	if [[ -f .tmp/go.bench.sum ]]; then
		cp "${sum_work}" go.sum
	else
		rm -f go.sum
	fi

	golangci-lint run ./...
)
