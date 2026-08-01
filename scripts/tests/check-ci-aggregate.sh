#!/usr/bin/env bash
# Asserts two invariants that `ci-ok` (the sole required status check for
# `main`) depends on:
#
#   1. Every job in ci.yml appears in ci-ok's `needs` list. Without this, a
#      new job silently escapes the required status check.
#
#   2. No job other than ci-ok declares its own `needs:`. This is now
#      defence in depth rather than the sole protection -- see invariant 3 --
#      but inter-job `needs:` still makes results harder to reason about,
#      because GitHub reports `skipped` for a job whose dependency failed.
#
#   3. ci-ok's verdict step does not accept a `skipped` dependency result.
#      It used to: the step read "succeeded or was skipped". That was a hole,
#      because the only thing that skips a job in ci.yml is the `flaky-test`
#      label, and that label suppresses SEVEN jobs including the entire
#      `tests` suite. One label therefore turned the sole required check
#      green while almost nothing ran, and a PR was nearly merged that way.
#      The same acceptance also laundered a failed-dependency `skipped` into
#      a pass. ci-ok now requires `success` from every dependency; this
#      invariant stops that reverting quietly.
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
  echo "  A job whose own needs: dependency failed reports 'skipped', which makes" >&2
  echo "  results hard to reason about. ci-ok now requires 'success' from every" >&2
  echo "  dependency, so such a job would correctly fail the aggregate -- but keep" >&2
  echo "  the job graph flat so the reported reason stays truthful." >&2
  status=1
fi

# Invariant 3: ci-ok must not accept a 'skipped' dependency as a pass.
# Matching on the jq predicate rather than prose: the wording of the step name
# can change without changing behaviour, but this comparison IS the behaviour.
verdict=$(awk '/^  ci-ok:/{f=1} f' "$workflow")
if [ -z "$verdict" ]; then
  echo "FAIL: could not locate the ci-ok job in $workflow to inspect its verdict logic" >&2
  status=1
elif printf '%s' "$verdict" | grep -qE '\.value\.result[[:space:]]*!=[[:space:]]*"skipped"'; then
  echo "FAIL: ci-ok treats a 'skipped' dependency result as acceptable." >&2
  echo "  The only thing that skips a job in ci.yml is the 'flaky-test' label," >&2
  echo "  which suppresses seven jobs including the entire tests suite. Accepting" >&2
  echo "  'skipped' lets one label turn the sole required check green with almost" >&2
  echo "  nothing run. Require 'success' from every dependency instead." >&2
  status=1
elif ! printf '%s' "$verdict" | grep -qE '\.value\.result[[:space:]]*!=[[:space:]]*"success"'; then
  echo "FAIL: ci-ok's verdict step does not test dependencies against 'success'." >&2
  echo "  Expected a jq select on .value.result != \"success\"; found neither that" >&2
  echo "  nor the old 'skipped' acceptance. Check the step has not been rewritten" >&2
  echo "  into something that cannot fail." >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit 1
fi

echo "ok: ci-ok covers all $(echo "$jobs" | wc -l) jobs; no job other than ci-ok declares needs:"
