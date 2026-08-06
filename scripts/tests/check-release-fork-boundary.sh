#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries are literal Cargo and workflow contracts.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
failures=0

fail() {
  printf 'release fork-boundary contract: %s\n' "$1" >&2
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
  vendor/noq-1.1.0/CHANGELOG.md \
  vendor/noq-1.1.0/KRIKOS-VENDOR.md \
  vendor/noq-1.1.0/LICENSE-APACHE \
  vendor/noq-1.1.0/LICENSE-MIT \
  vendor/noq-1.1.0/README.md \
  vendor/hickory-server-0.26.1/CHANGELOG.md \
  vendor/hickory-server-0.26.1/KRIKOS-VENDOR.md \
  vendor/hickory-server-0.26.1/LICENSE-APACHE \
  vendor/hickory-server-0.26.1/LICENSE-MIT \
  vendor/hickory-server-0.26.1/README.md \
  krikos-sim/Cargo.lock \
  krikos-sim/src/deterministic_crypto.rs; do
  require_file "$path"
done
if [[ -e "$repo_root/krikos/src/simulation/deterministic_crypto.rs" ]]; then
  fail 'patched-Rustls deterministic crypto must live only in the simulator workspace'
fi

root_manifest="$repo_root/Cargo.toml"
for forbidden in hickory-server noq rustls; do
  if grep -Eq -- "^[[:space:]]*${forbidden}[[:space:]]*=[[:space:]]*\\{[[:space:]]*path" "$root_manifest"; then
    fail "Cargo.toml still patches the upstream package directly: $forbidden"
  fi
done
require_text Cargo.toml '"krikos-sim",'
if sed -n '/^members = \[/,/^\]/p' "$root_manifest" | grep -Fq '"krikos-sim",'; then
  fail 'krikos-sim must not remain a root workspace member'
fi
if ! sed -n '/^exclude = \[/,/^\]/p' "$root_manifest" | grep -Fq '"krikos-sim",'; then
  fail 'krikos-sim must be explicitly excluded from the root workspace'
fi
require_text Cargo.toml 'krikos-noq = { path = "vendor/noq-1.1.0" }'
require_text Cargo.toml 'krikos-hickory-server = { path = "vendor/hickory-server-0.26.1" }'

require_text vendor/noq-1.1.0/Cargo.toml 'name = "krikos-noq"'
require_text vendor/noq-1.1.0/Cargo.toml 'version = "1.1.0-holon.1"'
require_text vendor/noq-1.1.0/Cargo.toml 'publish = true'
require_text vendor/noq-1.1.0/Cargo.toml 'repository = "https://github.com/holon-technologies/iroh"'
require_text vendor/noq-1.1.0/Cargo.toml 'documentation = "https://docs.rs/krikos-noq"'
require_text vendor/noq-1.1.0/Cargo.toml 'include = ['
require_text vendor/noq-1.1.0/Cargo.toml 'name = "noq"'
require_text vendor/noq-1.1.0/README.md 'Holon-maintained fork'
require_text vendor/noq-1.1.0/KRIKOS-VENDOR.md 'Upstream base: `noq` 1.1.0'
require_text vendor/noq-1.1.0/CHANGELOG.md '## 1.1.0-holon.1'

require_text vendor/hickory-server-0.26.1/Cargo.toml 'name = "krikos-hickory-server"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'version = "0.26.1-holon.1"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'publish = true'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'repository = "https://github.com/holon-technologies/iroh"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'documentation = "https://docs.rs/krikos-hickory-server"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'include = ['
require_text vendor/hickory-server-0.26.1/Cargo.toml 'name = "hickory_server"'
require_text vendor/hickory-server-0.26.1/README.md 'Holon-maintained fork'
require_text vendor/hickory-server-0.26.1/KRIKOS-VENDOR.md 'Upstream base: `hickory-server` 0.26.1'
require_text vendor/hickory-server-0.26.1/CHANGELOG.md '## 0.26.1-holon.1'

for path in krikos/Cargo.toml krikos-relay/Cargo.toml krikos/bench/Cargo.toml; do
  require_text "$path" 'package = "krikos-noq"'
  require_text "$path" 'version = "=1.1.0-holon.1"'
done
require_text krikos-dns-server/Cargo.toml 'package = "krikos-hickory-server"'
require_text krikos-dns-server/Cargo.toml 'version = "=0.26.1-holon.1"'
for path in \
  krikos/Cargo.toml \
  krikos-base/Cargo.toml \
  krikos-resolver/Cargo.toml \
  krikos-dns/Cargo.toml \
  krikos-dns-server/Cargo.toml \
  krikos-relay/Cargo.toml \
  krikos-runtime/Cargo.toml; do
  require_text "$path" 'repository.workspace = true'
done

sim_manifest=krikos-sim/Cargo.toml
require_text "$sim_manifest" '[workspace]'
require_text "$sim_manifest" 'resolver = "2"'
require_text "$sim_manifest" '[workspace.lints.rust]'
require_text "$sim_manifest" '[workspace.lints.clippy]'
require_text "$sim_manifest" '[patch.crates-io]'
require_text "$sim_manifest" 'krikos-noq = { path = "../vendor/noq-1.1.0" }'
require_text "$sim_manifest" 'rustls = { path = "../vendor/rustls-0.23.41" }'
require_text "$sim_manifest" 'rustls = { version = "0.23.33", default-features = false }'

sim_command_drift=$(
  rg -n --hidden \
    --glob '!check-release-fork-boundary.sh' \
    --glob '!superpowers/plans/**' \
    --glob '!superpowers/specs/**' \
    'cargo[^\n]*(-p|--package)[ =]krikos-sim' \
    "$repo_root/.github" "$repo_root/scripts" "$repo_root/docs/testing" \
    "$repo_root/docs/simulation" "$repo_root/Makefile.toml" || true
)
if [[ -n "$sim_command_drift" ]]; then
  fail "active commands still target krikos-sim as a root package:\n$sim_command_drift"
fi
require_text Makefile.toml 'scripts/run-format.sh'
require_text scripts/krikos-test-env 'scripts/run-all-tests.sh'
require_text scripts/run-all-tests.sh 'cargo test --workspace --all-features --tests'
require_text scripts/run-all-tests.sh 'cargo test --manifest-path krikos-sim/Cargo.toml --all-features --tests'
require_text .github/workflows/ci.yml 'scripts/tests/check-release-fork-boundary.sh'
require_text .github/workflows/ci.yml 'cargo test --locked --manifest-path krikos-sim/Cargo.toml'
require_text .github/workflows/ci.yml 'cargo clippy --locked --manifest-path krikos-sim/Cargo.toml'
require_text .github/workflows/ci.yml 'cargo doc --locked --manifest-path krikos-sim/Cargo.toml'
require_text .github/workflows/release.yml 'krikos-noq'
require_text .github/workflows/release.yml 'krikos-hickory-server'

verifier=scripts/verify-release-packages.sh
require_text "$verifier" 'krikos-noq krikos-hickory-server krikos-base krikos-runtime krikos-resolver krikos-dns krikos-relay krikos krikos-dns-server'
require_text "$verifier" 'target/release-packages'
require_text "$verifier" 'candidate_sources'
require_text "$verifier" 'source paths bootstrap archive creation only'
require_text "$verifier" 'consumes exclusively the normalized, extracted candidate archives'
require_text "$verifier" 'cargo check'

if ((failures != 0)); then
  printf 'release fork-boundary contract failed with %d issue(s)\n' "$failures" >&2
  exit 1
fi

printf '%s\n' 'release fork-boundary source contract passed'
