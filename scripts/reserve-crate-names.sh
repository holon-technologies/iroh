#!/usr/bin/env bash
# Reserve the Krikos crate names on crates.io.
#
# Publishes a minimal 0.0.0 placeholder for each name so the namespace cannot be
# squatted before the real 1.0.0 release. Placeholders are permanent — crates.io
# allows yanking but never deletion — which is the accepted cost of holding a
# name. See docs/adr/0002-krikos-rebrand.md.
#
# Requires a crates.io token: `cargo login` first. Run with --dry-run to see
# exactly what would be published without contacting the registry.
set -euo pipefail

names=(
  krikos
  krikos-base
  krikos-relay
  krikos-dns
  krikos-dns-server
  krikos-resolver
  krikos-runtime
  krikos-app
  krikos-blobs
  krikos-docs
  krikos-gossip
  krikos-sim
  krikos-noq
  krikos-hickory-server
)

dry_run=0
if (($# > 0)); then
  case "$1" in
    --dry-run) dry_run=1 ;;
    *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
  esac
fi

if (( dry_run == 0 )) && [[ ! -f "${CARGO_HOME:-$HOME/.cargo}/credentials.toml" ]]; then
  echo "FAIL: no crates.io credentials found. Run 'cargo login' first." >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for name in "${names[@]}"; do
  # Ask the registry first so an already-taken name is reported clearly rather
  # than surfacing as an opaque publish error.
  code="$(curl -s -o /dev/null -w '%{http_code}' \
    -H 'User-Agent: krikos-name-reservation' \
    "https://crates.io/api/v1/crates/${name}")"
  if [[ "$code" == "200" ]]; then
    echo "SKIP  ${name} — already exists on crates.io"
    continue
  elif [[ "$code" != "404" ]]; then
    echo "WARN  ${name} — unexpected HTTP ${code} from crates.io; skipping" >&2
    continue
  fi

  crate_dir="${work}/${name}"
  mkdir -p "${crate_dir}/src"
  cat > "${crate_dir}/Cargo.toml" <<EOF
[package]
name = "${name}"
version = "0.0.0"
edition = "2021"
license = "MIT OR Apache-2.0"
description = "Placeholder reserving the ${name} name for the Krikos project. Not yet released."
repository = "https://github.com/holon-technologies/iroh"
EOF
  cat > "${crate_dir}/src/lib.rs" <<EOF
//! Placeholder reserving the \`${name}\` name for the Krikos project.
//!
//! This crate is intentionally empty. See
//! <https://github.com/holon-technologies/iroh> for the real implementation,
//! which will be published as ${name} 1.0.0.
EOF

  if (( dry_run == 1 )); then
    echo "DRY   ${name} — would publish 0.0.0 placeholder"
  else
    echo "PUBLISH ${name}"
    (cd "${crate_dir}" && cargo publish --allow-dirty --no-verify)
    # crates.io rate-limits new crate creation; pace the loop.
    sleep 10
  fi
done

echo "done"
