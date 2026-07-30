#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
selector="$repo_root/scripts/select-simulation-gate.sh"
sim_bin="$repo_root/krikos-sim/target/debug/cargo-sim"

if [[ ! -x "$selector" ]]; then
  echo "simulation gate selector is missing or not executable" >&2
  exit 1
fi
bash -n "$selector"
cargo build --quiet --manifest-path "$repo_root/krikos-sim/Cargo.toml" --bin cargo-sim

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
git -C "$fixture_root" init --quiet
git -C "$fixture_root" config user.email simulation@example.invalid
git -C "$fixture_root" config user.name "Simulation Contract"
mkdir -p "$fixture_root/krikos/src/discovery" "$fixture_root/krikos-relay/src"
printf '%s\n' old >"$fixture_root/krikos/src/discovery/old.rs"
printf '%s\n' relay >"$fixture_root/krikos-relay/src/lib.rs"
git -C "$fixture_root" add .
git -C "$fixture_root" commit --quiet -m base
base=$(git -C "$fixture_root" rev-parse HEAD)

mkdir -p "$fixture_root/docs"
git -C "$fixture_root" mv krikos/src/discovery/old.rs docs/renamed.md
git -C "$fixture_root" rm --quiet krikos-relay/src/lib.rs
git -C "$fixture_root" commit --quiet -m rename-delete
candidate=$(git -C "$fixture_root" rev-parse HEAD)

selection="$fixture_root/selection.json"
(
  cd "$fixture_root"
  "$selector" \
    --base-revision "$base" \
    --candidate-revision "$candidate" \
    --tier pull-request \
    --impact-policy "$repo_root/krikos-sim/change-impact-policy.json" \
    --coverage-policy "$repo_root/krikos-sim/coverage-policy.json" \
    --sim-bin "$sim_bin" \
    --output "$selection"
)
jq -e '
  .schema_version == 1
  and .mode == "mapped"
  and .base_revision == $base
  and .candidate_revision == $candidate
  and .impacted_domains == ["discovery", "relay"]
  and (.universal | length) == 12
  and (.targeted | length) == 4
  and ([.changed_paths[] | select(. == "krikos/src/discovery/old.rs")] | length) == 1
  and ([.changed_paths[] | select(. == "docs/renamed.md")] | length) == 1
  and ([.changed_paths[] | select(. == "krikos-relay/src/lib.rs")] | length) == 1
' --arg base "$base" --arg candidate "$candidate" "$selection" >/dev/null

repeat="$fixture_root/repeat.json"
(
  cd "$fixture_root"
  "$selector" \
    --base-revision "$base" \
    --candidate-revision "$candidate" \
    --tier pull-request \
    --impact-policy "$repo_root/krikos-sim/change-impact-policy.json" \
    --coverage-policy "$repo_root/krikos-sim/coverage-policy.json" \
    --sim-bin "$sim_bin" \
    --output "$repeat"
)
cmp "$selection" "$repeat"

missing_base="$fixture_root/missing-base.json"
(
  cd "$fixture_root"
  "$selector" \
    --base-revision ffffffffffffffffffffffffffffffffffffffff \
    --candidate-revision "$candidate" \
    --tier pull-request \
    --impact-policy "$repo_root/krikos-sim/change-impact-policy.json" \
    --coverage-policy "$repo_root/krikos-sim/coverage-policy.json" \
    --sim-bin "$sim_bin" \
    --output "$missing_base"
)
jq -e '
  .mode == "global_fallback"
  and (.impacted_domains | length) == 6
  and (.universal | length) == 12
  and (.targeted | length) == 12
' "$missing_base" >/dev/null

mkdir -p "$fixture_root/unknown-crate/src"
printf '%s\n' unknown >"$fixture_root/unknown-crate/src/lib.rs"
git -C "$fixture_root" add .
git -C "$fixture_root" commit --quiet -m unknown
unknown_candidate=$(git -C "$fixture_root" rev-parse HEAD)
unknown_output="$fixture_root/unknown.json"
(
  cd "$fixture_root"
  "$selector" \
    --base-revision "$candidate" \
    --candidate-revision "$unknown_candidate" \
    --tier pull-request \
    --impact-policy "$repo_root/krikos-sim/change-impact-policy.json" \
    --coverage-policy "$repo_root/krikos-sim/coverage-policy.json" \
    --sim-bin "$sim_bin" \
    --output "$unknown_output"
)
jq -e '.mode == "global_fallback" and (.targeted | length) == 12' \
  "$unknown_output" >/dev/null

if [[ -e "$fixture_root/paths_jsonl" ]]; then
  echo "simulation gate selector must not leak scratch files into its working directory" >&2
  exit 1
fi

echo "simulation gate selector contract passed"
