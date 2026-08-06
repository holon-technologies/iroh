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

require_line() {
  local path=$1
  local pattern=$2
  if ! grep -Eq -- "$pattern" "$repo_root/$path"; then
    printf '%s is missing active local-first framework command: %s\n' "$path" "$pattern" >&2
    exit 1
  fi
}

for path in \
  framework/release-gate.toml \
  scripts/check-identity-feature-matrix.sh \
  scripts/check-framework-release-gate.py \
  docs/framework/upstream-sync.md; do
  [[ -f "$repo_root/$path" ]] || {
    printf 'local-first framework contract file is missing: %s\n' "$path" >&2
    exit 1
  }
done

require_text .github/workflows/ci.yml 'local_first_framework:'
require_line .github/workflows/ci.yml '^[[:space:]]*MSRV:[[:space:]]+"1\.91\.0"[[:space:]]*$'
require_text .github/workflows/ci.yml 'cargo test --locked -p krikos-app --all-features'
require_text .github/workflows/ci.yml 'cargo test --locked -p krikos-local-first-app-tests --test two_node'
require_text .github/workflows/ci.yml 'scripts/tests/check-blobs-v0-interop.sh'
require_text .github/workflows/ci.yml 'scripts/tests/check-gossip-v0-interop.sh'
require_text .github/workflows/ci.yml 'cargo test --locked -p krikos-docs migration'
require_text .github/workflows/ci.yml 'scripts/check-framework-release-gate.py --expect-closed'
require_text .github/workflows/ci.yml 'scripts/check-identity-interop-vectors.sh'
require_text .github/workflows/ci.yml 'scripts/check-identity-wire-inventory.sh'
require_line .github/workflows/ci.yml '^[[:space:]]*run:[[:space:]]+scripts/check-identity-doc-links\.py[[:space:]]*$'
local_first_job=$(sed -n '/^  local_first_framework:/,/^  fuzz_smoke:/p' \
  "$repo_root/.github/workflows/ci.yml")
if ! grep -Fq -- 'sudo apt-get install --yes ripgrep' <<<"$local_first_job"; then
  printf '%s\n' 'local-first framework CI job does not install ripgrep for identity inventory' >&2
  exit 1
fi
require_text .github/workflows/ci.yml 'RUSTDOCFLAGS: "-Dwarnings --cfg krikos_docsrs"'
require_text .github/workflows/ci.yml 'cargo doc --locked --workspace --all-features --no-deps --document-private-items'
require_text .github/workflows/ci.yml 'cargo "+$MSRV" test --locked -p krikos-identity --no-default-features --all-targets'
require_text .github/workflows/ci.yml 'cargo "+$MSRV" test --locked -p krikos-identity --all-features --all-targets'
require_text .github/workflows/ci.yml 'cargo "+$MSRV" check --locked --workspace --all-targets --all-features'
require_text .github/workflows/ci.yml 'cargo "+$MSRV" check --locked --manifest-path krikos-sim/Cargo.toml --all-targets --all-features'
require_text .github/workflows/ci.yml 'cargo "+$MSRV" clippy --locked -p krikos-identity --no-default-features --all-targets -- -D warnings'
require_text .github/workflows/ci.yml 'cargo "+$MSRV" clippy --locked -p krikos-identity --all-features --all-targets -- -D warnings'
require_text .github/workflows/ci.yml "RUSTDOCFLAGS='-Dwarnings' cargo \"+\$MSRV\" doc --locked -p krikos-identity --all-features --no-deps"
require_text .github/workflows/ci.yml 'cargo "+$MSRV" test --locked -p krikos-identity --no-default-features --doc'
require_text .github/workflows/ci.yml 'cargo "+$MSRV" test --locked -p krikos-identity --all-features --doc'
require_text .github/workflows/docs.yaml 'cargo doc --locked --workspace --all-features --no-deps'
require_text .github/workflows/docs.yaml 'RUSTDOCFLAGS: "-Dwarnings --cfg krikos_docsrs"'
require_line .github/workflows/ci.yml '^[[:space:]]*run:[[:space:]]+scripts/check-identity-feature-matrix\.sh[[:space:]]*$'
require_text .github/workflows/ci.yml 'scripts/check-identity-model.sh'
require_text .github/workflows/ci.yml 'identity corpus-test krikos-sim/identity-corpus'
require_text .github/workflows/ci.yml 'cargo run --locked --manifest-path krikos-sim/Cargo.toml --bin cargo-sim -- identity corpus-test krikos-sim/identity-corpus'
require_text .github/workflows/tests.yaml 'krikos-app'
require_text .github/workflows/tests.yaml 'krikos-blobs'
require_text .github/workflows/tests.yaml 'krikos-docs'
require_text .github/workflows/tests.yaml 'krikos-gossip'
require_text .github/workflows/release.yml 'scripts/check-framework-release-gate.py --expect-closed'
require_text scripts/run-format.sh 'fuzz/Cargo.toml'
require_text scripts/test-local-first-framework.sh 'scripts/check-identity-interop-vectors.sh'
require_text scripts/test-local-first-framework.sh 'scripts/check-identity-wire-inventory.sh'
require_line scripts/test-local-first-framework.sh '^[[:space:]]*scripts/check-identity-doc-links\.py[[:space:]]*$'
require_line scripts/test-local-first-framework.sh '^[[:space:]]*scripts/check-identity-feature-matrix\.sh[[:space:]]*$'
require_text scripts/test-local-first-framework.sh 'scripts/check-identity-model.sh'
require_text scripts/test-local-first-framework.sh 'identity corpus-test krikos-sim/identity-corpus'
require_text scripts/test-local-first-framework.sh 'cargo "+$toolchain" test --locked -p krikos-app --all-features'
require_text scripts/test-local-first-framework.sh 'cargo "+$toolchain" run --locked --manifest-path krikos-sim/Cargo.toml'
require_text scripts/test-local-first-framework.sh 'cargo "+$toolchain" test --locked -p krikos-docs migration'
require_text scripts/test-local-first-framework.sh 'cargo "+$toolchain" test --locked -p krikos-local-first-app-tests --test two_node'
require_text scripts/check-framework-package-layout.sh 'cargo "+$toolchain" package'
require_text scripts/check-identity-interop-vectors.sh '--locked'
require_text scripts/check-identity-wire-inventory.sh '--locked'
require_text scripts/check-identity-model.sh '--locked'
require_text .gitattributes 'protocols/krikos-identity/tests/vectors/*.bin binary linguist-generated'
require_text .gitattributes 'fuzz/corpus/identity_*/* binary linguist-generated'
require_text Makefile.toml '[tasks.local-first-framework]'
require_text Makefile.toml '[tasks.local-first-release-gate]'
require_text docs/release/v2-release-checklist.md 'framework/release-gate.toml'
require_text protocols/krikos-blobs/Cargo.toml 'name = "blobs-transfer"'
require_text protocols/krikos-gossip/Cargo.toml 'name = "gossip-setup"'
require_text protocols/krikos-docs/Cargo.toml 'name = "docs-setup"'

"$repo_root/scripts/check-identity-feature-matrix.sh" --static-only

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
