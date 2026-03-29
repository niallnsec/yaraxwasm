# syntax=docker/dockerfile:1.7

FROM mcr.microsoft.com/devcontainers/go:2-1.26-trixie

ARG DEBIAN_FRONTEND=noninteractive
ARG RUST_TOOLCHAIN=1.94.1
ARG GOLANGCI_LINT_VERSION=v2.11.3
ARG EASYJSON_VERSION=v0.9.1
ARG CARGO_C_VERSION=0.10.18+cargo-0.92.0

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        cmake \
        libssl-dev \
        make \
        pkg-config \
        zstd && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p \
        /workspace-cache/go-build \
        /workspace-cache/go-mod \
        /workspace-cache/cargo-target \
        /workspace-cache/benchcmp && \
    chown -R vscode:vscode /workspace-cache

USER vscode

ENV PATH=/home/vscode/.cargo/bin:/go/bin:${PATH}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain ${RUST_TOOLCHAIN}

RUN rustup component add clippy rustfmt && \
    rustup target add wasm32-wasip1 && \
    rustup toolchain install nightly --profile minimal --component rust-src && \
    cargo install cargo-c --version ${CARGO_C_VERSION} --locked

RUN GOBIN=/go/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION} && \
    GOBIN=/go/bin go install github.com/mailru/easyjson/...@${EASYJSON_VERSION}

WORKDIR /workspaces/yaraxwasm
