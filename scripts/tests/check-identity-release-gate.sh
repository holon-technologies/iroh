#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

fail() {
  printf 'identity release-gate contract: %s\n' "$1" >&2
  exit 1
}

require_file() {
  local path=$1
  [[ -f "$repo_root/$path" ]] || fail "required file is missing: $path"
}

require_text() {
  local path=$1
  local expected=$2
  grep -Fq -- "$expected" "$repo_root/$path" ||
    fail "$path is missing required contract: $expected"
}

for path in \
  protocols/krikos-identity/release-gate.toml \
  protocols/krikos-identity/docs/release-gate.md \
  scripts/check-identity-release-gate.py; do
  require_file "$path"
done

for approval in \
  third_party_security_audit \
  independently_maintained_interoperability \
  production_provider_diversity \
  protocol_governance \
  public_api_semver_baseline \
  persistent_schema_support; do
  require_text protocols/krikos-identity/release-gate.toml "$approval = false"
done

gate_command='python3 scripts/check-identity-release-gate.py --expect-closed'
require_text .github/workflows/ci.yml "$gate_command"
require_text .github/workflows/release.yml "$gate_command"
require_text scripts/test-local-first-framework.sh "$gate_command"
require_text Makefile.toml '[tasks.identity-release-gate]'
require_text Makefile.toml 'args = ["scripts/check-identity-release-gate.py", "--expect-closed"]'
require_text scripts/tests/check-v2-release-readiness.sh 'protocols/krikos-identity/release-gate.toml'
require_text scripts/tests/check-v2-release-readiness.sh "$gate_command"
require_text docs/release/v2-release-checklist.md 'protocols/krikos-identity/release-gate.toml'
require_text protocols/krikos-identity/README.md 'docs/release-gate.md'
require_text docs/README.md 'Identity stable-release gate'

python3 - "$repo_root" <<'PY'
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
with (root / "framework/release-gate.toml").open("rb") as source:
    policy = tomllib.load(source)

expected = [
    {"order": 1, "name": "krikos-blobs", "path": "protocols/krikos-blobs"},
    {"order": 2, "name": "krikos-gossip", "path": "protocols/krikos-gossip"},
    {"order": 3, "name": "krikos-docs", "path": "protocols/krikos-docs"},
    {"order": 4, "name": "krikos-app", "path": "framework/app"},
]
if policy.get("packages") != expected:
    raise SystemExit("identity gate must not alter the exact four-package framework gate")
PY

python3 "$repo_root/scripts/check-identity-release-gate.py" --expect-closed
open_output=$(mktemp)
fixture_root=$(mktemp -d)
trap 'rm -f "$open_output"; rm -rf "$fixture_root"' EXIT

if python3 "$repo_root/scripts/check-identity-release-gate.py" --require-open \
  >"$open_output" 2>&1; then
  fail 'identity stable-release gate unexpectedly opened'
fi
for blocker in \
  'third-party security audit is not approved' \
  'independently maintained interoperability is not approved' \
  'production provider diversity is not approved' \
  'protocol governance is not approved' \
  'public API and SemVer baseline is not approved' \
  'persistent-schema support is not approved'; do
  grep -Fq -- "$blocker" "$open_output" || fail "missing closed-gate reason: $blocker"
done

seed_fixture() {
  local name=$1
  local fixture="$fixture_root/$name"
  mkdir -p \
    "$fixture/protocols/krikos-identity" \
    "$fixture/scripts"
  cp "$repo_root/Cargo.toml" "$fixture/Cargo.toml"
  cp "$repo_root/Makefile.toml" "$fixture/Makefile.toml"
  cp "$repo_root/scripts/verify-release-packages.sh" "$fixture/scripts/verify-release-packages.sh"
  cp "$repo_root/protocols/krikos-identity/Cargo.toml" \
    "$fixture/protocols/krikos-identity/Cargo.toml"
  cp "$repo_root/protocols/krikos-identity/release-gate.toml" \
    "$fixture/protocols/krikos-identity/release-gate.toml"
  printf '%s\n' "$fixture"
}

expect_fixture_failure() {
  local fixture=$1
  local expected=$2
  local output="$fixture/check-output"
  if python3 "$repo_root/scripts/check-identity-release-gate.py" \
    --repo-root "$fixture" --expect-closed >"$output" 2>&1; then
    fail "tampered fixture unexpectedly passed: $expected"
  fi
  grep -Fq -- "$expected" "$output" ||
    fail "tampered fixture did not report expected failure: $expected"
}

expect_open_fixture_failure() {
  local fixture=$1
  local expected=$2
  local output="$fixture/check-output"
  if python3 "$repo_root/scripts/check-identity-release-gate.py" \
    --repo-root "$fixture" --require-open >"$output" 2>&1; then
    fail "unpublishable open fixture unexpectedly passed: $expected"
  fi
  grep -Fq -- "$expected" "$output" ||
    fail "unpublishable open fixture did not report expected failure: $expected"
}

fixture=$(seed_fixture publish-enabled)
sed -i 's/^publish = false$/publish = true/' \
  "$fixture/protocols/krikos-identity/Cargo.toml"
expect_fixture_failure "$fixture" 'krikos-identity must retain publish = false while the gate is closed'

fixture=$(seed_fixture workspace-removed)
sed -i '\|"protocols/krikos-identity",|d' "$fixture/Cargo.toml"
expect_fixture_failure "$fixture" 'protocols/krikos-identity is not a root workspace member'

fixture=$(seed_fixture release-order-added)
sed -i 's/^packages="/packages="krikos-identity /' \
  "$fixture/scripts/verify-release-packages.sh"
expect_fixture_failure "$fixture" \
  'krikos-identity entered the publishable release order while its gate is closed'

fixture=$(seed_fixture external-types-enabled)
sed -i '\|"protocols/krikos-identity",|d' "$fixture/Makefile.toml"
expect_fixture_failure "$fixture" \
  'protocols/krikos-identity must remain outside the external-types baseline while the gate is closed'

fixture=$(seed_fixture empty-publish-allowlist)
sed -i 's/^status = "blocked"$/status = "open"/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/ = false$/ = true/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/ = \[\]$/ = ["reviewed-evidence"]/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/^publish = false$/publish = []/' \
  "$fixture/protocols/krikos-identity/Cargo.toml"
sed -i '\|"protocols/krikos-identity",|d' "$fixture/Makefile.toml"
sed -i 's/^packages="/packages="krikos-identity /' \
  "$fixture/scripts/verify-release-packages.sh"
expect_open_fixture_failure "$fixture" \
  'krikos-identity publish setting is not open for the stable registry'

fixture=$(seed_fixture wrong-release-order)
sed -i 's/^status = "blocked"$/status = "open"/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/ = false$/ = true/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/ = \[\]$/ = ["reviewed-evidence"]/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/^publish = false$/publish = true/' \
  "$fixture/protocols/krikos-identity/Cargo.toml"
sed -i '\|"protocols/krikos-identity",|d' "$fixture/Makefile.toml"
sed -i 's/^packages="/packages="krikos-identity /' \
  "$fixture/scripts/verify-release-packages.sh"
expect_open_fixture_failure "$fixture" \
  'krikos-identity must follow krikos in the publishable release order'

fixture=$(seed_fixture coordinated-open)
sed -i 's/^status = "blocked"$/status = "open"/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/ = false$/ = true/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/ = \[\]$/ = ["reviewed-evidence"]/' \
  "$fixture/protocols/krikos-identity/release-gate.toml"
sed -i 's/^publish = false$/publish = true/' \
  "$fixture/protocols/krikos-identity/Cargo.toml"
sed -i '\|"protocols/krikos-identity",|d' "$fixture/Makefile.toml"
sed -i 's/ krikos krikos-dns-server/ krikos krikos-identity krikos-dns-server/' \
  "$fixture/scripts/verify-release-packages.sh"
python3 "$repo_root/scripts/check-identity-release-gate.py" \
  --repo-root "$fixture" --require-open

printf '%s\n' 'identity stable-release gate contract passed'
