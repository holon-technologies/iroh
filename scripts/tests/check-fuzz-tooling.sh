#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries are literal shell-source contracts.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="$repo_root/scripts/run-bounded-fuzz.sh"
ci_workflow="$repo_root/.github/workflows/ci.yml"
scheduled_workflow="$repo_root/.github/workflows/fuzz.yml"
readonly -a targets=(
  doh_extract
  pkarr_body
  relay_segmentation
  config_deserialize
  gossip_message
)

[[ -x "$runner" ]] || {
  printf '%s\n' 'bounded fuzz runner is missing or not executable' >&2
  exit 1
}

[[ -f "$repo_root/fuzz/Cargo.lock" ]] || {
  printf '%s\n' 'fuzz workspace lockfile is missing' >&2
  exit 1
}

for generated_dir in fuzz/target fuzz/artifacts; do
  git -C "$repo_root" check-ignore -q "$generated_dir" || {
    printf 'generated fuzz directory is not ignored: %s\n' "$generated_dir" >&2
    exit 1
  }
done

for fork in \
  '../vendor/hickory-server-0.26.1' \
  '../vendor/noq-1.1.0'; do
  grep -Fq -- "$fork" "$repo_root/fuzz/Cargo.toml" || {
    printf 'fuzz workspace does not use production fork: %s\n' "$fork" >&2
    exit 1
  }
done

for target in "${targets[@]}"; do
  [[ -f "$repo_root/fuzz/fuzz_targets/$target.rs" ]] || {
    printf 'missing fuzz target: %s\n' "$target" >&2
    exit 1
  }
  [[ -d "$repo_root/fuzz/corpus/$target" ]] || {
    printf 'missing reviewed corpus: %s\n' "$target" >&2
    exit 1
  }
  find "$repo_root/fuzz/corpus/$target" -type f -print -quit | grep -q . || {
    printf 'empty reviewed corpus: %s\n' "$target" >&2
    exit 1
  }
  grep -Fq -- "- $target" "$ci_workflow" || {
    printf 'pull-request fuzz matrix is missing target: %s\n' "$target" >&2
    exit 1
  }
  grep -Fq -- "- $target" "$scheduled_workflow" || {
    printf 'scheduled fuzz matrix is missing target: %s\n' "$target" >&2
    exit 1
  }
done

if "$runner" --seconds 0 >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted an unbounded zero-second campaign' >&2
  exit 1
fi

if "$runner" --target not-a-target >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted an unknown fuzz target' >&2
  exit 1
fi

grep -Fq -- '-rss_limit_mb=2048' "$runner"
grep -Fq -- 'artifact_file_limit=64' "$runner"
grep -Fq -- 'artifact_byte_limit=67108864' "$runner"
grep -Fq -- 'fuzz_toolchain="${IROH_FUZZ_TOOLCHAIN:-nightly-2026-07-19}"' "$runner"
grep -Fq -- 'fuzz_target=$(rustc "+$fuzz_toolchain" -vV' "$runner"
grep -Fq -- 'cargo "+$fuzz_toolchain" fuzz run' "$runner"

for workflow in "$ci_workflow" "$scheduled_workflow"; do
  grep -Fq -- 'IROH_FUZZ_TOOLCHAIN: "nightly-2026-07-19"' "$workflow" || {
    printf 'fuzz workflow does not select the reviewed nightly: %s\n' "$workflow" >&2
    exit 1
  }
  grep -Fq -- 'toolchain: nightly-2026-07-19' "$workflow" || {
    printf 'fuzz workflow does not install the reviewed nightly: %s\n' "$workflow" >&2
    exit 1
  }
done

workflow_contracts=(
  "$ci_workflow|fuzz_smoke:"
  "$ci_workflow|--seconds 1"
  "$ci_workflow|actions/upload-artifact@v7"
  "$ci_workflow|retention-days: 7"
  "$scheduled_workflow|schedule:"
  "$scheduled_workflow|workflow_dispatch:"
  "$scheduled_workflow|--seconds 300"
  "$scheduled_workflow|actions/upload-artifact@v7"
  "$scheduled_workflow|retention-days: 30"
)

for contract in "${workflow_contracts[@]}"; do
  file="${contract%%|*}"
  text="${contract#*|}"
  grep -Fq -- "$text" "$file" || {
    printf 'fuzz workflow is missing required contract: %s\n' "$text" >&2
    exit 1
  }
done

if grep -Eq '^[[:space:]]+pull_request:' "$scheduled_workflow"; then
  printf '%s\n' 'scheduled fuzz campaign must not duplicate the pull-request trigger' >&2
  exit 1
fi

printf '%s\n' 'bounded fuzz tooling contract passed'
