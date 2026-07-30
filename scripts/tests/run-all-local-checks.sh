#!/usr/bin/env bash
# Discovers and runs every check script that is locally runnable, by parsing
# `run:` steps out of every workflow and composite action under .github/ --
# rather than hardcoding a list. A hardcoded list of "the scripts you're
# supposed to verify locally" silently drifts from what CI actually invokes
# as the workflows grow; that drift is exactly what let two CI-only failures
# through local verification before this script existed (see the
# 2026-07-29 repo-showcase-readiness CI-fix report for the incident).
#
# A discovered invocation is treated as locally runnable only when its exact
# command line -- the same flags CI passes, joined across `\` continuations
# -- contains no GitHub Actions expression (`${{ ... }}`) and no shell
# variable expansion (`$...`). Those always reference something only a live
# run has (a matrix value, $RUNNER_TEMP, a revision SHA, an event payload,
# $GITHUB_TOKEN, ...) that this script cannot fabricate faithfully. Running
# such a script with made-up inputs would either crash on a usage error or,
# worse, "pass" against inputs that don't resemble what CI actually feeds
# it -- a misleading result is worse than an honest skip. Every skip is
# reported with its reason so the summary can't be mistaken for a pass.
#
# Uses python3's PyYAML to parse workflow YAML, matching the precedent set
# by check-ci-aggregate.sh. PyYAML is not preinstalled everywhere; install
# it with `pip install pyyaml` or `apt-get install -y python3-yaml` if the
# discovery step reports it missing.

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

discovery=$(python3 <<'PYEOF'
import glob
import re
import sys

try:
    import yaml
except ImportError:
    print("FAIL: PyYAML is not available to this python3 interpreter.", file=sys.stderr)
    print("  Install it with: pip install pyyaml   (or: apt-get install -y python3-yaml)", file=sys.stderr)
    sys.exit(1)

SCRIPT_RE = re.compile(r'(?:python3\s+)?scripts/[\w./-]+\.(?:sh|py)')
EXPR_RE = re.compile(r'\$\{\{|\$')

def run_steps(node):
    """Yield every `run:` string under jobs[*].steps[] or runs.steps[]."""
    if not isinstance(node, dict):
        return
    jobs = node.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                if isinstance(step, dict) and isinstance(step.get("run"), str):
                    yield step["run"]
    runs = node.get("runs")
    if isinstance(runs, dict):
        for step in runs.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                yield step["run"]

def logical_commands(run_text):
    """Join `\`-continued lines into logical commands; split on newlines
    otherwise. Good enough for the plain, script-invoking steps this repo
    writes -- it does not need to understand full shell grammar."""
    lines = run_text.splitlines()
    buf = []
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continues = line.endswith("\\")
        piece = line[:-1] if continues else line
        buf.append(piece.strip())
        if not continues:
            yield " ".join(buf)
            buf = []
    if buf:
        yield " ".join(buf)

runnable = {}   # invocation -> None (dict keeps first-seen order, dedups)
skipped = {}    # invocation -> reason

paths = sorted(glob.glob(".github/workflows/*.yml") + glob.glob(".github/workflows/*.yaml") +
                glob.glob(".github/actions/*/action.yml") + glob.glob(".github/actions/*/action.yaml"))
for path in paths:
    with open(path) as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"FAIL: could not parse {path} as YAML: {e}", file=sys.stderr)
            sys.exit(1)
    for run_text in run_steps(doc):
        if "scripts/" not in run_text:
            continue
        for cmd in logical_commands(run_text):
            if not SCRIPT_RE.search(cmd):
                continue
            if EXPR_RE.search(cmd):
                skipped.setdefault(cmd, "references a GitHub Actions expression or shell variable "
                                         "(matrix value, $RUNNER_TEMP, a revision SHA, an event "
                                         "payload, ...) only a live CI run supplies")
            else:
                runnable.setdefault(cmd, None)

# A command skipped in one job might be discovered runnable verbatim in
# another; runnable wins since we did observe a literal, safe invocation.
for cmd in list(skipped):
    if cmd in runnable:
        del skipped[cmd]

for cmd in runnable:
    print("RUNNABLE\t" + cmd)
for cmd, reason in skipped.items():
    print("SKIPPED\t" + cmd + "\t" + reason)
PYEOF
)

if [[ -z "$discovery" ]]; then
  echo "no scripts/ invocations discovered in .github/ -- discovery is broken" >&2
  exit 1
fi

runnable_cmds=()
while IFS=$'\t' read -r kind cmd _reason; do
  [[ "$kind" == "RUNNABLE" ]] || continue
  runnable_cmds+=("$cmd")
done <<<"$discovery"

echo "discovered $(grep -c '^RUNNABLE' <<<"$discovery") locally-runnable invocation(s) and $(grep -c '^SKIPPED' <<<"$discovery") requiring live CI context:"
while IFS=$'\t' read -r kind cmd reason; do
  [[ "$kind" == "SKIPPED" ]] || continue
  printf '  SKIP  %s\n        (%s)\n' "$cmd" "$reason"
done <<<"$discovery"
echo

results=()
failures=0
for cmd in "${runnable_cmds[@]}"; do
  printf '=== %s ===\n' "$cmd"
  if bash -c "$cmd"; then
    results+=("PASS	$cmd")
  else
    code=$?
    results+=("FAIL($code)	$cmd")
    failures=$((failures + 1))
  fi
  echo
done

echo "==================== summary ===================="
printf '%s\n' "${results[@]}" | column -t -s $'\t'
echo "==================================================="
echo "$((${#runnable_cmds[@]} - failures))/${#runnable_cmds[@]} passed"

if ((failures > 0)); then
  exit 1
fi
