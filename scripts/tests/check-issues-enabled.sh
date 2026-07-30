#!/usr/bin/env bash
# The simulation triage lifecycle writes GitHub Issues. If Issues are disabled,
# every failure is detected and then silently discarded, and the workflow still
# reports success. Fail loudly instead.
set -euo pipefail

repo="${GITHUB_REPOSITORY:-holon-technologies/iroh}"

has_issues=$(gh api "repos/$repo" --jq '.has_issues')
if [[ "$has_issues" != "true" ]]; then
  echo "FAIL: Issues are disabled on $repo, so simulation triage cannot record failures." >&2
  echo "Enable Issues, or replace the triage mechanism. Do not leave it as a no-op." >&2
  exit 1
fi
echo "ok: Issues are enabled on $repo"
