#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline_ref=v1.0.3
nightly_toolchain=nightly-2026-07-19
evidence_root="$repo_root/target/release-evidence/semver"
baseline_checkout=$(mktemp -d)
allow_dirty=false
packages=(iroh iroh-base iroh-dns iroh-dns-server iroh-relay)

cleanup() {
  if [[ -n "$baseline_checkout" && -d "$baseline_checkout" ]]; then
    rm -rf -- "$baseline_checkout"
  fi
}
trap cleanup EXIT

if (($# > 1)); then
  printf 'usage: %s [--allow-dirty]\n' "$0" >&2
  exit 2
fi
if (($# == 1)); then
  if [[ "$1" != "--allow-dirty" ]]; then
    printf 'usage: %s [--allow-dirty]\n' "$0" >&2
    exit 2
  fi
  allow_dirty=true
fi

if ! command -v cargo-semver-checks >/dev/null 2>&1; then
  printf '%s\n' 'v2 semver verification requires cargo-semver-checks 0.49.0' >&2
  exit 69
fi
if [[ "$(cargo-semver-checks --version)" != "cargo-semver-checks 0.49.0" ]]; then
  printf '%s\n' 'v2 semver verification requires exactly cargo-semver-checks 0.49.0' >&2
  exit 69
fi
if ! rustc "+$nightly_toolchain" --version >/dev/null 2>&1; then
  printf 'v2 semver verification requires Rust %s\n' "$nightly_toolchain" >&2
  exit 69
fi
if ! git -C "$repo_root" rev-parse --verify --quiet "$baseline_ref^{commit}" >/dev/null; then
  printf 'semver baseline ref is missing: %s\n' "$baseline_ref" >&2
  exit 66
fi
if [[ "$allow_dirty" == false && -n "$(git -C "$repo_root" status --porcelain)" ]]; then
  printf '%s\n' 'semver verification requires a clean worktree; pass --allow-dirty for local candidate preparation' >&2
  exit 65
fi

mkdir -p \
  "$evidence_root/current-target" \
  "$evidence_root/baseline-target" \
  "$evidence_root/reports"
git -C "$repo_root" archive "$baseline_ref" | tar -x -C "$baseline_checkout"

for package in "${packages[@]}"; do
  rustdoc_name=${package//-/_}
  current_rustdoc="$evidence_root/current-target/doc/$rustdoc_name.json"
  baseline_rustdoc="$evidence_root/baseline-target/doc/$rustdoc_name.json"

  printf 'Building current public API: %s 2.0.0\n' "$package"
  RUSTDOCFLAGS='' CARGO_TARGET_DIR="$evidence_root/current-target" \
    cargo "+$nightly_toolchain" rustdoc \
      --locked \
      --manifest-path "$repo_root/Cargo.toml" \
      --package "$package" \
      --all-features \
      --lib \
      -- \
      -Z unstable-options \
      --output-format json

  printf 'Building baseline public API: %s 1.0.3\n' "$package"
  RUSTDOCFLAGS='' CARGO_TARGET_DIR="$evidence_root/baseline-target" \
    cargo "+$nightly_toolchain" rustdoc \
      --locked \
      --manifest-path "$baseline_checkout/Cargo.toml" \
      --package "$package" \
      --all-features \
      --lib \
      -- \
      -Z unstable-options \
      --output-format json

  if [[ ! -s "$current_rustdoc" || ! -s "$baseline_rustdoc" ]]; then
    printf 'missing rustdoc JSON for %s\n' "$package" >&2
    exit 66
  fi

  cargo semver-checks \
    --baseline-rustdoc "$baseline_rustdoc" \
    --current-rustdoc "$current_rustdoc" \
    --release-type minor \
    --color never 2>&1 | tee "$evidence_root/reports/$package.txt"
done

printf 'v2 semver verification passed against %s\n' "$baseline_ref"
