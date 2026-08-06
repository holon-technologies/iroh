#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
toolchain="${KRIKOS_IDENTITY_TOOLCHAIN:-1.91.0}"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

packages=(
  protocols/krikos-blobs
  protocols/krikos-gossip
  protocols/krikos-docs
  protocols/krikos-identity
  framework/app
)

for package in "${packages[@]}"; do
  listing="$scratch/${package//\//-}.txt"
  cargo "+$toolchain" package \
    --locked \
    --list \
    --allow-dirty \
    --manifest-path "$repo_root/$package/Cargo.toml" \
    >"$listing"
  grep -Fxq 'Cargo.toml' "$listing"
  grep -Fxq 'src/lib.rs' "$listing"
  if grep -Eq '(^|/)(target|\.git|\.github)/' "$listing"; then
    printf 'framework package layout includes repository/build internals: %s\n' "$package" >&2
    exit 1
  fi
done

for package in protocols/krikos-blobs protocols/krikos-gossip protocols/krikos-docs; do
  listing="$scratch/${package//\//-}.txt"
  grep -Fxq 'LICENSE-APACHE' "$listing"
  grep -Fxq 'LICENSE-MIT' "$listing"
  grep -Fxq 'UPSTREAM.md' "$listing"
done

printf '%s\n' 'framework package layout and dependency order passed'
