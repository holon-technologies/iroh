#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if (($# != 0)); then
  echo "usage: $0" >&2
  exit 2
fi

cd "$repo_root"
cargo test --workspace --all-features --tests -- --test-threads=1
cargo test --manifest-path krikos-sim/Cargo.toml --all-features --tests -- --test-threads=1
