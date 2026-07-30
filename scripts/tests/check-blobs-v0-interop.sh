#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

cargo run \
  --manifest-path "$repo_root/compat/iroh-blobs-v0-103-interop/Cargo.toml" \
  --locked
