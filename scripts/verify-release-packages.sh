#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
release_package_root="$repo_root/target/release-packages"
candidate_sources=$(mktemp -d)
allow_dirty=()

cleanup() {
  rm -rf "$candidate_sources"
}
trap cleanup EXIT

if (($# > 1)); then
  echo "usage: $0 [--allow-dirty]" >&2
  exit 2
fi
if (($# == 1)); then
  if [[ "$1" != "--allow-dirty" ]]; then
    echo "usage: $0 [--allow-dirty]" >&2
    exit 2
  fi
  allow_dirty=(--allow-dirty)
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "release package verification requires jq" >&2
  exit 69
fi

packages="iroh-noq iroh-hickory-server iroh-base iroh-runtime iroh-dns iroh-relay iroh iroh-dns-server"
read -r -a package_order <<< "$packages"
candidate_patches=()
declare -A candidate_manifests=()
source_bootstrap_patches=(
  --config "patch.crates-io.iroh-noq.path=\"$repo_root/vendor/noq-1.1.0\""
  --config "patch.crates-io.iroh-hickory-server.path=\"$repo_root/vendor/hickory-server-0.26.1\""
  --config "patch.crates-io.iroh-base.path=\"$repo_root/iroh-base\""
  --config "patch.crates-io.iroh-runtime.path=\"$repo_root/iroh-runtime\""
  --config "patch.crates-io.iroh-dns.path=\"$repo_root/iroh-dns\""
  --config "patch.crates-io.iroh-relay.path=\"$repo_root/iroh-relay\""
  --config "patch.crates-io.iroh.path=\"$repo_root/iroh\""
  --config "patch.crates-io.iroh-dns-server.path=\"$repo_root/iroh-dns-server\""
)

package_manifest() {
  case "$1" in
    iroh-noq)
      printf '%s\n' "$repo_root/vendor/noq-1.1.0/Cargo.toml"
      ;;
    iroh-hickory-server)
      printf '%s\n' "$repo_root/vendor/hickory-server-0.26.1/Cargo.toml"
      ;;
    *)
      printf '%s\n' "$repo_root/Cargo.toml"
      ;;
  esac
}

package_version() {
  local package=$1
  local manifest=$2
  cargo metadata --format-version 1 --no-deps --manifest-path "$manifest" |
    jq -er --arg package "$package" \
      '.packages[] | select(.name == $package) | .version'
}

extract_candidate() {
  local package=$1
  local version=$2
  local archive="$release_package_root/package/$package-$version.crate"
  local extracted="$candidate_sources/$package-$version"

  if [[ ! -f "$archive" ]]; then
    printf 'packaged crate archive is missing: %s\n' "$archive" >&2
    exit 66
  fi
  tar -xzf "$archive" -C "$candidate_sources"
  if [[ ! -f "$extracted/Cargo.toml" ]]; then
    printf 'packaged crate did not extract a Cargo.toml: %s\n' "$extracted" >&2
    exit 65
  fi

  candidate_manifests["$package"]="$extracted/Cargo.toml"
  candidate_patches+=(
    --config "patch.crates-io.$package.path=\"$extracted\""
  )
}

verify_dependency_identity() {
  local manifest=$1
  local package=$2
  local expected_source=$3
  local count

  count=$(
    cargo metadata --locked --format-version 1 --manifest-path "$manifest" |
      jq -er --arg package "$package" --arg expected_source "$expected_source" '
        [.packages[]
          | select(.name == $package)
          | select(
              if $expected_source == "registry" then
                (.source // "") | startswith("registry+")
              else
                .source == null
              end
            )]
        | length
      '
  )
  if [[ "$count" != "1" ]]; then
    printf '%s must resolve exactly once from %s (found %s)\n' \
      "$package" "$expected_source" "$count" >&2
    exit 65
  fi
}

rm -rf "$release_package_root"
mkdir -p "$release_package_root"

cd "$repo_root"
for package in "${package_order[@]}"; do
  manifest=$(package_manifest "$package")
  version=$(package_version "$package" "$manifest")

  printf 'Creating locked crate archive: %s %s\n' "$package" "$version"
  if [[ "$manifest" == "$repo_root/Cargo.toml" ]]; then
    # Cargo requires unpublished versioned dependencies to resolve before it will create an
    # archive. These source paths bootstrap archive creation only. The verification pass below
    # consumes exclusively the normalized, extracted candidate archives.
    cargo package \
      --locked \
      --no-verify \
      --target-dir "$release_package_root" \
      --manifest-path "$manifest" \
      --package "$package" \
      "${allow_dirty[@]}" \
      "${source_bootstrap_patches[@]}"
  else
    cargo package \
      --locked \
      --no-verify \
      --target-dir "$release_package_root" \
      --manifest-path "$manifest" \
      --package "$package" \
      "${allow_dirty[@]}"
  fi
  extract_candidate "$package" "$version"
done

for package in "${package_order[@]}"; do
  printf 'Verifying candidate-local package graph: %s\n' "$package"
  CARGO_TARGET_DIR="$release_package_root/verify-target" \
    cargo check \
      --manifest-path "${candidate_manifests[$package]}" \
      "${candidate_patches[@]}"
done

verify_dependency_identity "$repo_root/Cargo.toml" rustls registry
verify_dependency_identity "$repo_root/Cargo.toml" iroh-noq path
verify_dependency_identity "$repo_root/Cargo.toml" iroh-hickory-server path
verify_dependency_identity "$repo_root/iroh-sim/Cargo.toml" rustls path
verify_dependency_identity "$repo_root/iroh-sim/Cargo.toml" iroh-noq path

printf '%s\n' 'Release package verification passed'
