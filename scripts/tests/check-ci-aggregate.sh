#!/usr/bin/env bash
# Asserts every job in ci.yml appears in ci-ok's `needs` list. Without this,
# a new job silently escapes the required status check.
#
# Uses python3's yaml module rather than yq: python3 is preinstalled
# everywhere this needs to run, and PyYAML avoids adding a yq install step.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

workflow=".github/workflows/ci.yml"

jobs=$(python3 -c '
import sys
import yaml

with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)

jobs = sorted(k for k in data["jobs"].keys() if k != "ci-ok")
print("\n".join(jobs))
' "$workflow")

needs=$(python3 -c '
import sys
import yaml

with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)

needs = sorted(data["jobs"].get("ci-ok", {}).get("needs", []) or [])
print("\n".join(needs))
' "$workflow")

if ! diff <(echo "$jobs") <(echo "$needs") >/dev/null; then
  echo "FAIL: ci-ok needs does not match the job list" >&2
  echo "  '<' = job defined but not required; '>' = listed in needs but not defined" >&2
  diff <(echo "$jobs") <(echo "$needs") >&2
  exit 1
fi
echo "ok: ci-ok covers all $(echo "$jobs" | wc -l) jobs"
