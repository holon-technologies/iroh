#!/usr/bin/env bash
# Asserts every non-local `uses:` step across .github/ is pinned to a full
# 40-character commit SHA with a trailing `# <ref>` comment recording the
# human-readable ref it resolves to (e.g. `actions/checkout@<40-hex>  # v7`).
#
# Unpinned or tag-pinned third-party actions are a supply-chain risk: the
# upstream maintainer (or anyone who compromises their account) can silently
# swap out what a mutable ref points to. The `# <ref>` comment is load-bearing
# for a handful of other guards (check-fuzz-tooling.sh,
# check-daily-simulation-workflow.sh, check-patchbay-hosted-smoke-workflow.sh,
# check-simulation-issue-closure-workflow.sh, check-v2-release-readiness.sh),
# which normalize `@<sha>  # <ref>` back to `@<ref>` before matching contract
# literals -- so it must stay accurate, not just present.
#
# Local `uses:` references (reusable workflows in this same repo, e.g.
# `uses: ./.github/workflows/tests.yaml`) are exempt: they're version-locked
# together with the rest of the branch, not a third-party supply-chain risk.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

status=0
files=()
while IFS= read -r -d '' f; do
  files+=("$f")
done < <(find .github -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)

for f in "${files[@]}"; do
  while IFS=: read -r lineno content; do
    # Extract the value after `uses:`.
    ref=$(sed -E 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*//' <<<"$content")
    ref=${ref%\"}
    ref=${ref#\"}
    ref=${ref%\'}
    ref=${ref#\'}

    # Local reusable workflows/actions are not a third-party supply-chain
    # risk; they're version-locked with the rest of this branch.
    [[ "$ref" == ./* || "$ref" == .\\* ]] && continue

    if ! [[ "$ref" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*[^[:space:]]+ ]]; then
      echo "FAIL: $f:$lineno: unpinned or malformed action reference: $content" >&2
      status=1
    fi
  done < <(grep -nE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*' "$f")
done

if ((status != 0)); then
  echo "FAIL: one or more actions are not pinned to a 40-character commit SHA with a trailing '# <ref>' comment" >&2
  exit 1
fi

echo "ok: every non-local action reference under .github/ is pinned to a commit SHA with a '# <ref>' comment"
