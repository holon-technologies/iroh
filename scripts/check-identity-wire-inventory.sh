#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${KRIKOS_IDENTITY_TOOLCHAIN:-1.91.0}"
doc_target="${KRIKOS_IDENTITY_DOC_TARGET:-$repo_root/target/identity-wire-inventory}"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

CARGO_TARGET_DIR="$doc_target" cargo "+$toolchain" doc \
  --quiet \
  --locked \
  --manifest-path "$repo_root/Cargo.toml" \
  -p krikos-identity \
  --all-features \
  --no-deps \
  --document-private-items

implementors="$doc_target/doc/krikos_identity/codec/sealed/trait.CanonicalCodec.html"
[[ -f "$implementors" ]] || {
  printf 'missing rustdoc CanonicalCodec implementor inventory: %s\n' "$implementors" >&2
  exit 1
}

grep -o 'id="impl-CanonicalCodec-for-[^"]*"' "$implementors" \
  | sed 's/id="impl-CanonicalCodec-for-//; s/"$//' \
  | sort -u > "$scratch/implemented"

{
  rg --no-filename -o 'round_trip::<[A-Za-z0-9_]+' \
    "$repo_root"/fuzz/fuzz_targets/identity_*.rs \
    | sed 's/round_trip::<//'
  rg --no-filename -o '[A-Za-z0-9_]+::from_canonical_bytes' \
    "$repo_root"/fuzz/fuzz_targets/identity_*.rs \
    | sed 's/::from_canonical_bytes//'
} | grep -v '^T$' | sort -u > "$scratch/covered"

comm -23 "$scratch/implemented" "$scratch/covered" > "$scratch/missing"
comm -13 "$scratch/implemented" "$scratch/covered" > "$scratch/stale"

if [[ -s "$scratch/missing" || -s "$scratch/stale" ]]; then
  if [[ -s "$scratch/missing" ]]; then
    printf '%s\n' 'public canonical decoders missing from identity target inventories:' >&2
    sed 's/^/  /' "$scratch/missing" >&2
  fi
  if [[ -s "$scratch/stale" ]]; then
    printf '%s\n' 'stale identity target decoder names without a canonical implementation:' >&2
    sed 's/^/  /' "$scratch/stale" >&2
  fi
  exit 1
fi

implemented_count="$(wc -l < "$scratch/implemented")"
covered_count="$(wc -l < "$scratch/covered")"
[[ "$implemented_count" -eq "$covered_count" ]] || {
  printf 'canonical decoder count mismatch: implemented=%s covered=%s\n' \
    "$implemented_count" "$covered_count" >&2
  exit 1
}

printf 'identity canonical decoder inventory is complete: %s types\n' "$implemented_count"
