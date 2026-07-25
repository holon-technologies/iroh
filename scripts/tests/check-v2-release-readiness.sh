#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries are literal workflow and shell contracts.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
failures=0

fail() {
  printf 'v2 release-readiness contract: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_file() {
  local path="$1"
  if [[ ! -f "$repo_root/$path" ]]; then
    fail "required file is missing: $path"
  fi
}

require_text() {
  local path="$1"
  local expected="$2"
  if [[ ! -f "$repo_root/$path" ]]; then
    return
  fi
  if ! grep -Fq -- "$expected" "$repo_root/$path"; then
    fail "$path is missing required contract: $expected"
  fi
}

for path in \
  .github/workflows/ci.yml \
  .github/workflows/tests.yaml \
  .github/workflows/wine.yaml \
  .github/workflows/netsim_runner.yaml \
  .github/workflows/release.yml \
  .github/workflows/docker.yaml \
  .github/workflows/simulation-nightly.yml \
  scripts/run-bounded-fuzz.sh \
  scripts/run-v2-semver-checks.sh \
  scripts/tests/check-release-fork-boundary.sh \
  scripts/verify-release-packages.sh \
  docs/release/v2-migration.md \
  docs/release/v2-release-checklist.md \
  iroh-runtime/CHANGELOG.md \
  iroh-runtime/README.md \
  iroh-runtime/release.toml; do
  require_file "$path"
done

version_manifests=(
  iroh-base/Cargo.toml
  iroh-runtime/Cargo.toml
  iroh-dns/Cargo.toml
  iroh-relay/Cargo.toml
  iroh/Cargo.toml
  iroh-dns-server/Cargo.toml
  iroh/bench/Cargo.toml
  iroh-sim/Cargo.toml
)

for path in "${version_manifests[@]}"; do
  if ! grep -Eq '^version = "2\.0\.0"$' "$repo_root/$path"; then
    fail "$path package version must be exactly 2.0.0"
  fi
  if grep -Fq -- 'version = "1.0.3"' "$repo_root/$path"; then
    fail "$path still contains a stale Iroh 1.0.3 version requirement"
  fi
done

python3 - "$repo_root/Cargo.lock" "$repo_root/iroh-sim/Cargo.lock" <<'PY' ||
import sys
import tomllib

for lock_path in sys.argv[1:]:
    with open(lock_path, "rb") as lock_file:
        lock = tomllib.load(lock_file)
    stale = sorted(
        f"{package['name']} {package['version']}"
        for package in lock["package"]
        if package["name"] in {
            "iroh",
            "iroh-base",
            "iroh-bench",
            "iroh-dns",
            "iroh-dns-server",
            "iroh-relay",
            "iroh-runtime",
            "iroh-sim",
        }
        and package["version"].startswith("1.")
    )
    if stale:
        print(f"{lock_path} contains stale Iroh packages: {', '.join(stale)}", file=sys.stderr)
        raise SystemExit(1)
PY
  fail 'Cargo lockfiles contain stale Iroh 1.x package versions'

portable_workflows=(
  .github/workflows/ci.yml
  .github/workflows/tests.yaml
  .github/workflows/wine.yaml
  .github/workflows/netsim_runner.yaml
  .github/workflows/release.yml
  .github/workflows/docker.yaml
)

for path in "${portable_workflows[@]}"; do
  if grep -Eiq -- 'self-hosted|blacksmith' "$repo_root/$path"; then
    fail "$path still routes portable work to an unavailable runner"
  fi
done

require_text scripts/run-bounded-fuzz.sh 'fuzz_target=$(rustc +nightly -vV'
require_text scripts/run-bounded-fuzz.sh '--target "$fuzz_target"'

nightly="$repo_root/.github/workflows/simulation-nightly.yml"
if grep -Eq '^[[:space:]]+seed: [0-9a-f]{64}[[:space:]]*$' "$nightly"; then
  fail '.github/workflows/simulation-nightly.yml contains an unquoted replay seed'
fi
quoted_seed_count=$(grep -Ec '^[[:space:]]+seed: "[0-9a-f]{64}"[[:space:]]*$' "$nightly" || true)
if ((quoted_seed_count != 5)); then
  fail ".github/workflows/simulation-nightly.yml must contain exactly five quoted replay seeds (found $quoted_seed_count)"
fi

release_workflow="$repo_root/.github/workflows/release.yml"
for forbidden in \
  'push:' \
  'actions/create-release@v1' \
  'actions-upload-release-asset@main' \
  's3://vorc' \
  'n0computer/'; do
  if grep -Fq -- "$forbidden" "$release_workflow"; then
    fail ".github/workflows/release.yml contains legacy release dependency: $forbidden"
  fi
done

for required in \
  'workflow_dispatch:' \
  'publish:' \
  'default: false' \
  'contents: write' \
  'packages: write' \
  'attestations: write' \
  'artifact-metadata: write' \
  'anchore/sbom-action@v0' \
  'actions/attest@v4' \
  'iroh-v2-supply-chain-evidence' \
  'sha256'; do
  if ! grep -Fq -- "$required" "$release_workflow"; then
    fail ".github/workflows/release.yml is missing release safety contract: $required"
  fi
done

docker_workflow="$repo_root/.github/workflows/docker.yaml"
for forbidden in \
  's3://vorc' \
  'n0computer/' \
  'DOCKERHUB_'; do
  if grep -Fq -- "$forbidden" "$docker_workflow"; then
    fail ".github/workflows/docker.yaml contains unavailable publication dependency: $forbidden"
  fi
done

for required in \
  'runs-on: ubuntu-latest' \
  'ghcr.io/holon-technologies/iroh-relay' \
  'ghcr.io/holon-technologies/iroh-dns-server' \
  'provenance: mode=max' \
  'sbom: true'; do
  if ! grep -Fq -- "$required" "$docker_workflow"; then
    fail ".github/workflows/docker.yaml is missing hosted container contract: $required"
  fi
done

require_text .github/workflows/ci.yml 'scripts/tests/check-v2-release-readiness.sh'
require_text .github/workflows/ci.yml 'scripts/tests/check-release-fork-boundary.sh'
require_text .github/workflows/ci.yml 'scripts/run-v2-semver-checks.sh'
if grep -Fq -- 'cargo-semver-checks-action' "$repo_root/.github/workflows/ci.yml"; then
  fail '.github/workflows/ci.yml still uses registry-only semver setup that cannot resolve unpublished owned forks'
fi
require_text .github/workflows/release.yml 'scripts/verify-release-packages.sh'
require_text scripts/verify-release-packages.sh 'iroh-noq iroh-hickory-server iroh-base iroh-runtime iroh-dns iroh-relay iroh iroh-dns-server'
require_text docs/release/v2-migration.md 'PkarrRelayClient::new'
require_text docs/release/v2-migration.md 'dns::Builder::build'
require_text docs/release/v2-migration.md 'quic::QuicClient::new'
require_text docs/release/v2-release-checklist.md 'iroh-runtime'
require_text docs/release/v2-release-checklist.md '2.0.0'
require_text iroh-runtime/CHANGELOG.md '## Unreleased'
require_text iroh-runtime/Cargo.toml 'readme = "README.md"'
require_text iroh-runtime/release.toml 'pre-release-hook'
require_text scripts/run-v2-semver-checks.sh 'baseline_ref=v1.0.3'
require_text scripts/run-v2-semver-checks.sh '--baseline-rustdoc'
require_text scripts/run-v2-semver-checks.sh '--current-rustdoc'
require_text scripts/run-v2-semver-checks.sh '--release-type minor'

if ((failures != 0)); then
  printf 'v2 release-readiness contract failed with %d issue(s)\n' "$failures" >&2
  exit 1
fi

printf '%s\n' 'v2 release-readiness source contract passed'
