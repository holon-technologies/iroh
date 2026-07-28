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
  vendor/noq-1.1.0/IROH-VENDOR.md \
  vendor/noq-1.1.0/LICENSE-APACHE \
  vendor/noq-1.1.0/LICENSE-MIT \
  vendor/noq-1.1.0/README.md \
  vendor/hickory-server-0.26.1/CHANGELOG.md \
  vendor/hickory-server-0.26.1/IROH-VENDOR.md \
  vendor/hickory-server-0.26.1/LICENSE-APACHE \
  vendor/hickory-server-0.26.1/LICENSE-MIT \
  vendor/hickory-server-0.26.1/README.md \
  iroh-sim/Cargo.lock \
  iroh-sim/src/deterministic_crypto.rs; do
  require_file "$path"
done
if [[ -e "$repo_root/iroh/src/simulation/deterministic_crypto.rs" ]]; then
  fail 'patched-Rustls deterministic crypto must live only in the simulator workspace'
fi

root_manifest="$repo_root/Cargo.toml"
for forbidden in hickory-server noq rustls; do
  if grep -Eq -- "^[[:space:]]*${forbidden}[[:space:]]*=[[:space:]]*\\{[[:space:]]*path" "$root_manifest"; then
    fail "Cargo.toml still patches the upstream package directly: $forbidden"
  fi
done
require_text Cargo.toml '"iroh-sim",'
if sed -n '/^members = \[/,/^\]/p' "$root_manifest" | grep -Fq '"iroh-sim",'; then
  fail 'iroh-sim must not remain a root workspace member'
fi
if ! sed -n '/^exclude = \[/,/^\]/p' "$root_manifest" | grep -Fq '"iroh-sim",'; then
  fail 'iroh-sim must be explicitly excluded from the root workspace'
fi
require_text Cargo.toml 'iroh-noq = { path = "vendor/noq-1.1.0" }'
require_text Cargo.toml 'iroh-hickory-server = { path = "vendor/hickory-server-0.26.1" }'

require_text vendor/noq-1.1.0/Cargo.toml 'name = "iroh-noq"'
require_text vendor/noq-1.1.0/Cargo.toml 'version = "1.1.0-holon.1"'
require_text vendor/noq-1.1.0/Cargo.toml 'publish = true'
require_text vendor/noq-1.1.0/Cargo.toml 'repository = "https://github.com/holon-technologies/iroh"'
require_text vendor/noq-1.1.0/Cargo.toml 'documentation = "https://docs.rs/iroh-noq"'
require_text vendor/noq-1.1.0/Cargo.toml 'include = ['
require_text vendor/noq-1.1.0/Cargo.toml 'name = "noq"'
require_text vendor/noq-1.1.0/README.md 'Holon-maintained fork'
require_text vendor/noq-1.1.0/IROH-VENDOR.md 'Upstream base: `noq` 1.1.0'
require_text vendor/noq-1.1.0/CHANGELOG.md '## 1.1.0-holon.1'

require_text vendor/hickory-server-0.26.1/Cargo.toml 'name = "iroh-hickory-server"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'version = "0.26.1-holon.1"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'publish = true'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'repository = "https://github.com/holon-technologies/iroh"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'documentation = "https://docs.rs/iroh-hickory-server"'
require_text vendor/hickory-server-0.26.1/Cargo.toml 'include = ['
require_text vendor/hickory-server-0.26.1/Cargo.toml 'name = "hickory_server"'
require_text vendor/hickory-server-0.26.1/README.md 'Holon-maintained fork'
require_text vendor/hickory-server-0.26.1/IROH-VENDOR.md 'Upstream base: `hickory-server` 0.26.1'
require_text vendor/hickory-server-0.26.1/CHANGELOG.md '## 0.26.1-holon.1'

for path in iroh/Cargo.toml iroh-relay/Cargo.toml iroh/bench/Cargo.toml; do
  require_text "$path" 'package = "iroh-noq"'
  require_text "$path" 'version = "=1.1.0-holon.1"'
done
require_text iroh-dns-server/Cargo.toml 'package = "iroh-hickory-server"'
require_text iroh-dns-server/Cargo.toml 'version = "=0.26.1-holon.1"'
for path in \
  iroh/Cargo.toml \
  iroh-base/Cargo.toml \
  iroh-resolver/Cargo.toml \
  iroh-dns/Cargo.toml \
  iroh-dns-server/Cargo.toml \
  iroh-relay/Cargo.toml \
  iroh-runtime/Cargo.toml; do
  require_text "$path" 'repository.workspace = true'
done

sim_manifest=iroh-sim/Cargo.toml
require_text "$sim_manifest" '[workspace]'
require_text "$sim_manifest" 'resolver = "2"'
require_text "$sim_manifest" '[workspace.lints.rust]'
require_text "$sim_manifest" '[workspace.lints.clippy]'
require_text "$sim_manifest" '[patch.crates-io]'
require_text "$sim_manifest" 'iroh-noq = { path = "../vendor/noq-1.1.0" }'
require_text "$sim_manifest" 'rustls = { path = "../vendor/rustls-0.23.41" }'
require_text "$sim_manifest" 'rustls = { version = "0.23.33", default-features = false }'

sim_command_drift=$(
  rg -n --hidden \
    --glob '!check-release-fork-boundary.sh' \
    --glob '!superpowers/plans/**' \
    --glob '!superpowers/specs/**' \
    'cargo[^\n]*(-p|--package)[ =]iroh-sim' \
    "$repo_root/.github" "$repo_root/scripts" "$repo_root/docs/testing" \
    "$repo_root/docs/simulation" "$repo_root/Makefile.toml" || true
)
if [[ -n "$sim_command_drift" ]]; then
  fail "active commands still target iroh-sim as a root package:\n$sim_command_drift"
fi
require_text Makefile.toml 'scripts/run-format.sh'
require_text scripts/iroh-test-env 'scripts/run-all-tests.sh'
require_text scripts/run-all-tests.sh 'cargo test --workspace --all-features --tests'
require_text scripts/run-all-tests.sh 'cargo test --manifest-path iroh-sim/Cargo.toml --all-features --tests'
require_text .github/workflows/ci.yml 'scripts/tests/check-release-fork-boundary.sh'
require_text .github/workflows/ci.yml 'cargo test --manifest-path iroh-sim/Cargo.toml'
require_text .github/workflows/ci.yml 'cargo clippy --manifest-path iroh-sim/Cargo.toml'
require_text .github/workflows/ci.yml 'cargo doc --manifest-path iroh-sim/Cargo.toml'
require_text .github/workflows/release.yml 'iroh-noq'
require_text .github/workflows/release.yml 'iroh-hickory-server'

verifier=scripts/verify-release-packages.sh
require_text "$verifier" 'iroh-noq iroh-hickory-server iroh-base iroh-runtime iroh-resolver iroh-dns iroh-relay iroh iroh-dns-server'
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
