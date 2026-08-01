#!/usr/bin/env bash
# The daily flaky sweep must run exactly the tests ignored FOR FLAKINESS.
#
# flaky.yaml runs tests.yaml with `--run-ignored all`, which runs every
# #[ignore]d test. nextest cannot read the ignore reason, so without a filter
# the sweep also runs tests ignored because they are manual, unimplemented, or
# known-broken. Those fail on every run, which is how the sweep came to be
# permanently red (2026-07-29, -30, -31) -- and a red-by-construction sweep
# cannot report a NEW flake, which is the only thing it exists to do.
#
# tests.yaml therefore excludes the non-flaky ignores by name. That list has to
# stay in step with the tree, in BOTH directions:
#
#   - a new #[ignore = "todo"]-style test that nobody excludes puts the sweep
#     back to permanently red;
#   - a test ignored "flaky" that ends up excluded silently stops being
#     watched, which is worse than the sweep being red, because it looks fine.
#
# This asserts both. Classification is by ignore reason: a reason beginning
# "flaky" means sweep it, anything else means exclude it.
set -euo pipefail

cd "$(dirname "$0")/../.."

workflow=".github/workflows/tests.yaml"
nextest_config=".config/nextest.toml"

# The filterset is emitted by a GitHub expression on the nextest command line
# (not a shell variable -- this step runs under pwsh on Windows, where bash
# parameter expansion silently yields nothing). Grab that line.
filter_line=$(grep -E "cargo nextest run .*-E ''not " "$workflow" || true)
if [[ -z "$filter_line" ]]; then
  echo "FAIL: no flaky-sweep -E filterset found on the nextest command in $workflow" >&2
  echo "  Without it the sweep runs every ignored test and is red forever." >&2
  echo "  Expected a \${{ inputs.flaky && '-E ''not ...''' || '' }} fragment." >&2
  exit 1
fi

# A shell-expansion form would parse here but silently do nothing on Windows.
# Comment lines are stripped first: the comment above that step documents this
# exact hazard, and matching the documentation would be a false positive.
if grep -vE '^[[:space:]]*#' "$workflow" | grep -qE '\$\{[A-Z_]+:[+-]'; then
  echo "FAIL: $workflow uses bash parameter expansion (\${VAR:+...})." >&2
  echo "  This step runs under pwsh on the windows matrix entries, which does" >&2
  echo "  not expand it -- the value silently vanishes there. Emit the argument" >&2
  echo "  from a \${{ }} GitHub expression instead." >&2
  exit 1
fi

failed=0

# Collect `#[ignore = "reason"]` plus the fn it applies to. Attributes may sit
# between the ignore and the fn (#[traced_test], #[cfg(...)]), so scan forward.
# vendor/ is excluded: those are third-party trees this sweep does not own.
scan=$(git ls-files '*.rs' | grep -v '^vendor/' | while read -r file; do
  awk -v F="$file" '
    match($0, /#\[ignore[[:space:]]*=[[:space:]]*"/) {
      line = $0
      sub(/.*#\[ignore[[:space:]]*=[[:space:]]*"/, "", line)
      sub(/".*/, "", line)
      reason = line
      for (i = 1; i <= 8; i++) {
        if ((getline nxt) <= 0) break
        if (match(nxt, /fn [a-zA-Z0-9_]+/)) {
          name = substr(nxt, RSTART + 3, RLENGTH - 3)
          print F "\t" name "\t" reason
          break
        }
      }
    }
  ' "$file"
done)

if [[ -z "$scan" ]]; then
  echo "FAIL: found no #[ignore = \"...\"] tests at all -- the scan is broken, not the tree." >&2
  exit 1
fi

while IFS=$'\t' read -r file name reason; do
  [[ -z "$name" ]] && continue

  # patchbay tests are excluded wholesale by default-filter in nextest.toml.
  if [[ "$file" == *patchbay* ]]; then
    if ! grep -q "not binary(patchbay)" "$nextest_config"; then
      echo "FAIL: $name ($file) relies on 'not binary(patchbay)' in $nextest_config, which is gone" >&2
      failed=1
    fi
    continue
  fi

  if [[ "$reason" == flaky* ]]; then
    # Must NOT be excluded -- the sweep exists to watch these.
    if grep -qF "$name" <<<"$filter_line"; then
      echo "FAIL: $name is ignored \"$reason\" but is excluded from the flaky sweep" >&2
      echo "    $file" >&2
      echo "  A flaky test that the sweep does not run is unwatched, and looks fine." >&2
      failed=1
    fi
  else
    # Must be excluded, by test name or by its binary.
    binary=$(basename "$file" .rs)
    if ! grep -qF "$name" <<<"$filter_line" && ! grep -qF "binary($binary)" <<<"$filter_line"; then
      echo "FAIL: $name is ignored \"$reason\" -- not flakiness -- but the sweep runs it" >&2
      echo "    $file" >&2
      echo "  It will fail every night and keep the sweep red, hiding real flakes." >&2
      echo "  Add 'not test($name)' (or 'not binary($binary)') to FLAKY_EXCLUDE in $workflow." >&2
      failed=1
    fi
  fi
done <<<"$scan"

[[ $failed -ne 0 ]] && exit 1

swept=$(awk -F'\t' '$3 ~ /^flaky/ && $1 !~ /patchbay/' <<<"$scan" | wc -l)
excluded=$(awk -F'\t' '$3 !~ /^flaky/ && $1 !~ /patchbay/' <<<"$scan" | wc -l)
echo "ok: flaky sweep watches $swept flaky test(s); $excluded non-flaky ignore(s) excluded"
