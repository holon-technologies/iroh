#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
nightly_toolchain=nightly-2026-07-19
metadata="$repo_root/scripts/v2-api-baseline.toml"
inventory="$repo_root/scripts/v2-api-breaks.txt"
evidence_root="$repo_root/target/release-evidence/semver"
baseline_checkout=$(mktemp -d)
allow_dirty=false

cleanup() {
  if [[ -n "$baseline_checkout" && -d "$baseline_checkout" ]]; then
    rm -r -- "$baseline_checkout"
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
if [[ ! -f "$metadata" ]]; then
  printf 'v2 API baseline metadata is missing: %s\n' "$metadata" >&2
  exit 66
fi

readarray -t baseline_values < <(python3 - "$metadata" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as source:
    metadata = tomllib.load(source)
if metadata.get("schema_version") != 1:
    raise SystemExit("unsupported v2 API baseline metadata schema")
print(metadata.get("legacy_inventory_ref", ""))
print(metadata.get("post_cut_ref", ""))
PY
)
legacy_ref=${baseline_values[0]:-}
post_cut_ref=${baseline_values[1]:-}
if [[ -n "$post_cut_ref" ]]; then
  mode=post-cut
  baseline_ref=$post_cut_ref
  packages=(krikos krikos-base krikos-runtime krikos-resolver krikos-dns krikos-dns-server krikos-relay)
  if [[ ! "$baseline_ref" =~ ^[0-9a-f]{40}$ ]]; then
    printf '%s\n' 'post-cut API baseline must be a full lowercase 40-character commit SHA' >&2
    exit 65
  fi
else
  mode=legacy-inventory
  baseline_ref=$legacy_ref
  packages=(krikos krikos-base krikos-dns krikos-dns-server krikos-relay)
  if [[ "$baseline_ref" != "v1.0.3" ]]; then
    printf 'legacy API inventory baseline must remain v1.0.3, got %s\n' "$baseline_ref" >&2
    exit 65
  fi
fi

# Every current package name above is looked up against
# scripts/rename-map.toml to find the name it had BEFORE the Krikos rebrand
# (Task 5), because both baseline refs here (the pre-rename v2
# architecture-cut commit, and the upstream v1.0.3 tag) predate the rename
# entirely and still carry the pre-rebrand package names. Building the
# baseline rustdoc JSON with the current (krikos-*) package name against
# that old checkout fails outright ("cannot specify features for packages
# outside of workspace") because no such package exists there -- this is
# not a cosmetic mismatch, the baseline build cannot start at all without
# it. A package with no [[packages]] entry in the map (there is none among
# the packages compared here) falls back to its own name unchanged.
readarray -t baseline_package_pairs < <(python3 - "$repo_root/scripts/rename-map.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as source:
    rename_map = tomllib.load(source)
for entry in rename_map.get("packages", []):
    print(f"{entry['new_package']}\t{entry['old_package']}")
PY
)
declare -A baseline_name_for_current=()
for pair in "${baseline_package_pairs[@]}"; do
  new_name=${pair%%$'\t'*}
  old_name=${pair#*$'\t'}
  baseline_name_for_current[$new_name]=$old_name
done

if ! git -C "$repo_root" rev-parse --verify --quiet "$baseline_ref^{commit}" >/dev/null; then
  printf 'semver baseline ref is missing: %s\n' "$baseline_ref" >&2
  exit 66
fi
if [[ "$mode" == legacy-inventory ]] &&
  [[ "$(git -C "$repo_root" rev-parse "$baseline_ref^{commit}")" != f2eb930dda3779c6d852b72f3712aacd6e573ab1 ]]; then
  printf '%s\n' 'legacy v1.0.3 API inventory resolved to an unexpected commit' >&2
  exit 65
fi
if [[ "$allow_dirty" == false && -n "$(git -C "$repo_root" status --porcelain)" ]]; then
  printf '%s\n' 'semver verification requires a clean worktree; pass --allow-dirty for local candidate preparation' >&2
  exit 65
fi

mkdir -p \
  "$evidence_root/current-target" \
  "$evidence_root/baseline-target" \
  "$evidence_root/reports"
actual_inventory="$evidence_root/actual-v1-breaks.txt"
: >"$actual_inventory"
git -C "$repo_root" archive "$baseline_ref" | tar -x -C "$baseline_checkout"

for package in "${packages[@]}"; do
  baseline_package=${baseline_name_for_current[$package]:-$package}
  current_rustdoc_name=${package//-/_}
  baseline_rustdoc_name=${baseline_package//-/_}
  current_rustdoc="$evidence_root/current-target/doc/$current_rustdoc_name.json"
  baseline_rustdoc="$evidence_root/baseline-target/doc/$baseline_rustdoc_name.json"
  report="$evidence_root/reports/$package.txt"

  printf 'Building current public API: %s\n' "$package"
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

  printf 'Building baseline public API: %s as %s (%s)\n' "$package" "$baseline_package" "$baseline_ref"
  RUSTDOCFLAGS='' CARGO_TARGET_DIR="$evidence_root/baseline-target" \
    cargo "+$nightly_toolchain" rustdoc \
      --locked \
      --manifest-path "$baseline_checkout/Cargo.toml" \
      --package "$baseline_package" \
      --all-features \
      --lib \
      -- \
      -Z unstable-options \
      --output-format json

  if [[ ! -s "$current_rustdoc" || ! -s "$baseline_rustdoc" ]]; then
    printf 'missing rustdoc JSON for %s\n' "$package" >&2
    exit 66
  fi

  if [[ "$baseline_package" != "$package" ]]; then
    # The baseline crate's own root name (and every path rustdoc recorded
    # under it) is still the pre-rebrand name -- cargo-semver-checks compares items by
    # their full path INCLUDING the crate root, so without this it would
    # report the entire public API as removed-and-re-added under a new
    # name (every item's path starts with the wrong crate name) instead of
    # actually comparing the API surface. Only the local crate's own index
    # root entry and its own paths entries (crate_id 0, i.e. NOT an
    # external dependency such as iroh-metrics, which must keep its real
    # name) are touched.
    python3 - "$baseline_rustdoc" "$baseline_package" "$package" <<'PY'
import json
import sys

path, old_name, new_name = sys.argv[1], sys.argv[2].replace("-", "_"), sys.argv[3].replace("-", "_")
with open(path) as fh:
    data = json.load(fh)

root_id = str(data["root"])
root_entry = data["index"][root_id]
if root_entry.get("name") != old_name:
    raise SystemExit(
        f"expected baseline crate root name {old_name!r}, found {root_entry.get('name')!r}"
    )
root_entry["name"] = new_name

renamed = 0
for entry in data["paths"].values():
    if entry.get("crate_id") == 0 and entry.get("path") and entry["path"][0] == old_name:
        entry["path"][0] = new_name
        renamed += 1

with open(path, "w") as fh:
    json.dump(data, fh)
print(f"normalized baseline crate root {old_name!r} -> {new_name!r} ({renamed} local path(s))", file=sys.stderr)
PY
  fi

  set +e
  cargo semver-checks \
    --baseline-rustdoc "$baseline_rustdoc" \
    --current-rustdoc "$current_rustdoc" \
    --release-type minor \
    --color never 2>&1 | tee "$report"
  semver_status=${PIPESTATUS[0]}
  set -e
  "$repo_root/scripts/check-v2-semver-result.sh" "$mode" "$package" "$semver_status"

  if [[ "$mode" == legacy-inventory ]]; then
    awk -v package="$package" '
      /^--- failure / {
        lint = $3
        sub(/:$/, "", lint)
        next
      }
      /^Failed in:$/ { capturing = 1; next }
      capturing && /^  / {
        item = $0
        sub(/^  /, "", item)
        print package "\t" lint "\t" item
        next
      }
      capturing { capturing = 0 }
    ' "$report" >>"$actual_inventory"
  fi
done

if [[ "$mode" == legacy-inventory ]]; then
  "$repo_root/scripts/check-v2-api-inventory.sh" "$inventory" "$actual_inventory"
  printf 'v2 migration API inventory passed against %s; post-cut baseline is pending\n' \
    "$baseline_ref"
else
  printf 'v2 post-cut API stability passed against %s\n' "$baseline_ref"
fi
