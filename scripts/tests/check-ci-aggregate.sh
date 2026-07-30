#!/usr/bin/env bash
# Asserts two invariants that `ci-ok` (the sole required status check for
# `main`) depends on:
#
#   1. Every job in ci.yml appears in ci-ok's `needs` list. Without this, a
#      new job silently escapes the required status check.
#
#   2. No job other than ci-ok declares its own `needs:`. ci-ok treats a
#      `skipped` dependency result as acceptable (several jobs legitimately
#      skip via a `flaky-test` label guard). But in GitHub Actions, a job
#      whose `needs:` dependency FAILED also reports `skipped` to anything
#      that depends on it. If any job in this file ever gains a `needs:` on
#      a sibling, a genuine failure downstream of it could report as
#      `skipped` and ci-ok would silently accept it as green. Until ci-ok's
#      result logic is revisited to tell "legitimately skipped" apart from
#      "skipped because a dependency failed", no inter-job `needs:` may
#      exist besides ci-ok's own.
#
# Uses python3's PyYAML rather than yq: python3 is preinstalled everywhere
# this needs to run. PyYAML is NOT preinstalled on stock GitHub-hosted
# ubuntu-latest runners (actions/runner-images' Ubuntu 24.04 manifest ships
# libyaml-dev and yamllint, but not python3-yaml/PyYAML) -- any CI job that
# runs this script must first run one of:
#   pip install pyyaml
#   apt-get install -y python3-yaml
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

workflow=".github/workflows/ci.yml"

if ! output=$(python3 -c '
import sys

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is not available to this python3 interpreter (import yaml failed).", file=sys.stderr)
    print("  Install it with: pip install pyyaml   (or: apt-get install -y python3-yaml)", file=sys.stderr)
    sys.exit(1)

path = sys.argv[1]
try:
    with open(path) as f:
        data = yaml.safe_load(f)
except yaml.YAMLError as e:
    print(f"FAIL: could not parse {path} as YAML: {e}", file=sys.stderr)
    sys.exit(1)
except OSError as e:
    print(f"FAIL: could not read {path}: {e}", file=sys.stderr)
    sys.exit(1)

jobs_dict = data.get("jobs") or {}
jobs = sorted(k for k in jobs_dict.keys() if k != "ci-ok")
needs = sorted((jobs_dict.get("ci-ok") or {}).get("needs", []) or [])
needy = sorted(
    k for k, v in jobs_dict.items()
    if k != "ci-ok" and isinstance(v, dict) and "needs" in v
)

print("JOBS")
print("\n".join(jobs))
print("NEEDS")
print("\n".join(needs))
print("NEEDY")
print("\n".join(needy))
' "$workflow"); then
  exit 1
fi

jobs=$(printf '%s\n' "$output" | awk '/^JOBS$/{f=1;next} /^NEEDS$/{f=0} f')
needs=$(printf '%s\n' "$output" | awk '/^NEEDS$/{f=1;next} /^NEEDY$/{f=0} f')
needy=$(printf '%s\n' "$output" | awk '/^NEEDY$/{f=1;next} f')

status=0

# An empty job list (e.g. `jobs:` missing or empty in ci.yml) makes `jobs`
# and `needs` both empty strings, which the diff check below would treat as
# trivially matching -- a silent vacuous pass, not a real invariant check.
# `echo "$jobs" | wc -l` reports 1 for an empty string (one empty line), not
# 0, so that miscount would also print a misleading "ok: ... 1 jobs".
if [ -z "$jobs" ]; then
  echo "FAIL: ci.yml has no jobs (or 'jobs:' is missing/empty) -- nothing to aggregate" >&2
  exit 1
fi

if ! diff <(echo "$jobs") <(echo "$needs") >/dev/null; then
  echo "FAIL: ci-ok needs does not match the job list" >&2
  echo "  '<' = job defined but not required; '>' = listed in needs but not defined" >&2
  diff <(echo "$jobs") <(echo "$needs") >&2
  status=1
fi

if [ -n "$needy" ]; then
  echo "FAIL: job(s) other than ci-ok declare their own needs: $(echo "$needy" | tr '\n' ' ')" >&2
  echo "  ci-ok accepts a 'skipped' result as a legitimate flaky-test-label skip." >&2
  echo "  But a job whose own needs: dependency failed also reports 'skipped' --" >&2
  echo "  ci-ok cannot currently tell those apart, so it would silently accept a" >&2
  echo "  real failure laundered through as 'skipped'. Revisit ci-ok's result" >&2
  echo "  logic (distinguish a genuine skip from a needs-failure) before adding" >&2
  echo "  any inter-job needs: to a job other than ci-ok." >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "ok: ci-ok covers all $(echo "$jobs" | wc -l) jobs; no job other than ci-ok declares needs:"
