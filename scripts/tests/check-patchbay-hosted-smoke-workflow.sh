#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries are literal workflow expressions.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
workflow="$repo_root/.github/workflows/patchbay-hosted-smoke.yml"

if [[ ! -f "$workflow" ]]; then
  echo "GitHub-hosted Patchbay smoke workflow is missing" >&2
  exit 1
fi

# Third-party actions are pinned to a commit SHA with a trailing `# <ref>`
# comment (e.g. `actions/upload-artifact@<40-hex>  # v7`). Normalize that
# back to `actions/upload-artifact@v7` before matching contract literals and
# doing the line-order check below, so this check asserts on the
# human-readable ref rather than a SHA that Dependabot will rotate on every
# bump. sed does not add or remove lines, so line numbers used by the
# order check further down stay accurate.
normalized_workflow=$(mktemp)
trap 'rm -f "$normalized_workflow"' EXIT
sed -E 's/@[0-9a-f]{40}[[:space:]]+#[[:space:]]*([^[:space:]]+)/@\1/' "$workflow" > "$normalized_workflow"
workflow="$normalized_workflow"

required=(
  'name: GitHub-hosted Patchbay Public Parity Smoke'
  'schedule:'
  'cron: "47 4 * * *"'
  'workflow_dispatch:'
  'permissions:'
  'contents: read'
  'group: iroh-patchbay-hosted-public-smoke'
  'cancel-in-progress: false'
  'runs-on: ubuntu-latest'
  'timeout-minutes: 15'
  'mkdir -p "$RUNNER_TEMP/patchbay-hosted"'
  'kernel.apparmor_restrict_unprivileged_userns=0'
  'unshare --user --map-root-user'
  'cargo nextest run -p iroh --features qlog --test patchbay'
  '--profile patchbay nat::nat_none_x_none --no-capture'
  'IROH_PATCHBAY_PARITY_RECEIPT: ${{ runner.temp }}/patchbay-hosted/public-receipt.json'
  'test -s "$IROH_PATCHBAY_PARITY_RECEIPT"'
  'parity import-patchbay'
  'parity export public'
  'parity compare'
  '--source-revision "${{ github.sha }}"'
  'if: always()'
  'actions/upload-artifact@v7'
  'if-no-files-found: error'
  'retention-days: 7'
)

for expected in "${required[@]}"; do
  if ! grep -Fq -- "$expected" "$workflow"; then
    echo "hosted Patchbay smoke is missing required contract: $expected" >&2
    exit 1
  fi
done

for forbidden in \
  'self-hosted' \
  'continue-on-error:' \
  'cargo make patchbay'; do
  if grep -Fq -- "$forbidden" "$workflow"; then
    echo "hosted Patchbay smoke contains forbidden contract: $forbidden" >&2
    exit 1
  fi
done

if grep -Eq '^[[:space:]]+(pull_request|push|merge_group):' "$workflow"; then
  echo "hosted Patchbay smoke must remain scheduled/manual until retained evidence exists" >&2
  exit 1
fi

preflight_line=$(grep -n -m1 'unshare --user --map-root-user' "$workflow" | cut -d: -f1)
test_line=$(grep -n -m1 'cargo nextest run -p iroh' "$workflow" | cut -d: -f1)
compare_line=$(grep -n -m1 'parity compare' "$workflow" | cut -d: -f1)
upload_line=$(grep -n -m1 'actions/upload-artifact@v7' "$workflow" | cut -d: -f1)
if ((preflight_line >= test_line || compare_line >= upload_line)); then
  echo "hosted Patchbay smoke has unsafe execution or reporting order" >&2
  exit 1
fi

echo "GitHub-hosted Patchbay public-parity smoke workflow contract passed"
