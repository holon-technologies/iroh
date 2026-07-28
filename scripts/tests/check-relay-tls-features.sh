#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
manifest="$repo_root/iroh-relay/Cargo.toml"

python3 - "$manifest" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as source:
    manifest = tomllib.load(source)

features = manifest["features"]
expected = {
    "server-ring": {
        "server",
        "relay-bin",
        "server-acme",
        "tls-ring",
        "tokio-rustls-acme/ring",
    },
    "server-aws-lc-rs": {
        "server",
        "relay-bin",
        "server-acme",
        "tls-aws-lc-rs",
        "tokio-rustls-acme/aws-lc-rs",
    },
}
expected_provider_features = {
    "tls-ring": {"rcgen?/crypto", "rcgen?/ring"},
    "tls-aws-lc-rs": {"rcgen?/crypto", "rcgen?/aws_lc_rs"},
}
failures = []
for provider in ("tls-ring", "tls-aws-lc-rs"):
    if provider in features.get("server", []):
        failures.append(f"provider-neutral server feature includes {provider}")
for name, required in expected.items():
    missing = required - set(features.get(name, []))
    if missing:
        failures.append(f"{name} missing {sorted(missing)}")

dependencies = manifest["dependencies"]
acme = dependencies.get("tokio-rustls-acme", {})
if acme.get("package") != "rustls-acme" or acme.get("default-features") is not False:
    failures.append("tokio-rustls-acme must alias provider-selectable rustls-acme without defaults")
rcgen = dependencies.get("rcgen", {})
if rcgen.get("default-features") is not False:
    failures.append("rcgen defaults must be disabled so server bundles own provider selection")
if "crypto" in rcgen.get("features", []):
    failures.append("rcgen crypto must be selected by the exact TLS provider feature")
for name, required in expected_provider_features.items():
    missing = required - set(features.get(name, []))
    if missing:
        failures.append(f"{name} missing rcgen provider features {sorted(missing)}")

if failures:
    for failure in failures:
        print(f"relay TLS feature contract: {failure}", file=sys.stderr)
    raise SystemExit(1)
PY

cd "$repo_root"
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"

cargo check -p iroh-relay --no-default-features --lib --features server
cargo check -p iroh-relay --no-default-features --lib --features server,test-utils
cargo check -p iroh-relay --no-default-features --features server-ring
cargo check -p iroh-relay --no-default-features --features server-aws-lc-rs
cargo check -p iroh-relay --no-default-features --lib --features tls-ring
cargo check -p iroh-relay --no-default-features --lib --features tls-aws-lc-rs
cargo check -p iroh --no-default-features --lib --features test-utils,tls-ring
cargo check -p iroh --no-default-features --lib --features test-utils,tls-aws-lc-rs

ring_tree=$(cargo tree -p iroh-relay --no-default-features --features server-ring --prefix none)
aws_tree=$(cargo tree -p iroh-relay --no-default-features --features server-aws-lc-rs --prefix none)
iroh_ring_tree=$(cargo tree -p iroh --no-default-features --features test-utils,tls-ring --prefix none)
iroh_aws_tree=$(cargo tree -p iroh --no-default-features --features test-utils,tls-aws-lc-rs --prefix none)
if grep -Eq '^aws-lc-(rs|sys) v' <<<"$ring_tree"; then
  echo "relay TLS feature contract: Ring-only server graph contains AWS-LC" >&2
  exit 1
fi
if grep -Eq '^ring v' <<<"$aws_tree"; then
  echo "relay TLS feature contract: AWS-LC-only server graph contains Ring" >&2
  exit 1
fi
if grep -Eq '^aws-lc-(rs|sys) v' <<<"$iroh_ring_tree"; then
  echo "relay TLS feature contract: Ring-only iroh test-utils graph contains AWS-LC" >&2
  exit 1
fi
if grep -Eq '^ring v' <<<"$iroh_aws_tree"; then
  echo "relay TLS feature contract: AWS-LC-only iroh test-utils graph contains Ring" >&2
  exit 1
fi

failure_log=$(mktemp)
trap 'rm -f "$failure_log"' EXIT
if cargo check -p iroh-relay --no-default-features --bin iroh-relay \
  --features server,relay-bin \
  >"$failure_log" 2>&1; then
  echo "relay TLS feature contract: providerless relay binary unexpectedly compiled" >&2
  exit 1
fi
if ! grep -Fq 'select server-ring or server-aws-lc-rs' "$failure_log"; then
  echo "relay TLS feature contract: providerless binary failure was not actionable" >&2
  cat "$failure_log" >&2
  exit 1
fi

echo "relay TLS feature contract passed"
