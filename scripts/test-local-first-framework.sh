#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
toolchain="${KRIKOS_IDENTITY_TOOLCHAIN:-1.91.0}"

python3 scripts/check-framework-release-gate.py --expect-closed
python3 scripts/check-identity-release-gate.py --expect-closed
scripts/check-framework-package-layout.sh
scripts/check-identity-feature-matrix.sh
cargo "+$toolchain" test --locked -p krikos-app --all-features
scripts/check-identity-interop-vectors.sh
scripts/check-identity-wire-inventory.sh
scripts/check-identity-doc-links.py
scripts/check-identity-model.sh
cargo "+$toolchain" run --locked --manifest-path krikos-sim/Cargo.toml --bin cargo-sim -- \
  identity corpus-test krikos-sim/identity-corpus
cargo "+$toolchain" test --locked -p krikos-docs migration
cargo "+$toolchain" test --locked -p krikos-local-first-app-tests --test two_node
scripts/tests/check-blobs-v0-interop.sh
scripts/tests/check-gossip-v0-interop.sh
