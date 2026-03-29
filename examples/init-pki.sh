#!/usr/bin/env bash
set -euo pipefail

# Resolve the examples directory and repository root no matter where the script
# is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Run the small Go-based PKI generator that creates the root, intermediates,
# signer/TSA certs, and Ed25519 key pair used by the runnable examples.
cd "${REPO_ROOT}"
go run ./examples/internal/pkiinit -out "${SCRIPT_DIR}/pki/generated"
