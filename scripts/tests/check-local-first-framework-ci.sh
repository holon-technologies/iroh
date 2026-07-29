#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

require_text() {
  local path=$1
  local text=$2
  if ! grep -Fq -- "$text" "$repo_root/$path"; then
    printf '%s is missing local-first framework contract: %s\n' "$path" "$text" >&2
    exit 1
  fi
}

for path in \
  framework/release-gate.toml \
  scripts/check-framework-release-gate.py \
  docs/framework/upstream-sync.md; do
  [[ -f "$repo_root/$path" ]] || {
    printf 'local-first framework contract file is missing: %s\n' "$path" >&2
    exit 1
  }
done

require_text .github/workflows/ci.yml 'local_first_framework:'
require_text .github/workflows/ci.yml 'cargo test -p iroh-local-first-app-tests --test two_node'
require_text .github/workflows/ci.yml 'scripts/tests/check-blobs-v0-interop.sh'
require_text .github/workflows/ci.yml 'scripts/tests/check-gossip-v0-interop.sh'
require_text .github/workflows/ci.yml 'cargo test -p iroh-docs migration'
require_text .github/workflows/ci.yml 'scripts/check-framework-release-gate.py --expect-closed'
require_text .github/workflows/tests.yaml 'iroh-app'
require_text .github/workflows/tests.yaml 'iroh-blobs'
require_text .github/workflows/tests.yaml 'iroh-docs'
require_text .github/workflows/tests.yaml 'iroh-gossip'
require_text .github/workflows/release.yml 'scripts/check-framework-release-gate.py --expect-closed'
require_text scripts/run-format.sh 'fuzz/Cargo.toml'
require_text Makefile.toml '[tasks.local-first-framework]'
require_text Makefile.toml '[tasks.local-first-release-gate]'
require_text docs/release/v2-release-checklist.md 'framework/release-gate.toml'
require_text protocols/iroh-blobs/Cargo.toml 'name = "blobs-transfer"'
require_text protocols/iroh-gossip/Cargo.toml 'name = "gossip-setup"'
require_text protocols/iroh-docs/Cargo.toml 'name = "docs-setup"'

python3 "$repo_root/scripts/check-framework-release-gate.py" --expect-closed
gate_output=$(mktemp)
trap 'rm -f "$gate_output"' EXIT
if python3 "$repo_root/scripts/check-framework-release-gate.py" --require-open \
  >"$gate_output" 2>&1; then
  printf '%s\n' 'framework release gate unexpectedly opened' >&2
  exit 1
fi
grep -Fq 'package naming is not approved' "$gate_output"

printf '%s\n' 'local-first framework CI and release contract passed'
