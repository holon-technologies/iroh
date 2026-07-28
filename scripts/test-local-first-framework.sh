#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

python3 scripts/check-framework-release-gate.py --expect-closed
scripts/check-framework-package-layout.sh
cargo test -p iroh-app --all-features
cargo test -p iroh-docs migration
cargo test -p iroh-local-first-app-tests --test two_node
scripts/tests/check-blobs-v0-interop.sh
scripts/tests/check-gossip-v0-interop.sh
