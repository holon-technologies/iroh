#!/usr/bin/env bash
# Discovers and runs every check that is locally runnable, by parsing `run:`
# steps out of every workflow and composite action under .github/ -- rather
# than hardcoding a list. A hardcoded list of "the checks you're supposed to
# verify locally" silently drifts from what CI actually invokes as the
# workflows grow; that drift is exactly what let two CI-only failures
# through local verification before this script existed (see the
# 2026-07-29 repo-showcase-readiness CI-fix report for the incident), and a
# THIRD time after this script existed: it originally discovered only
# `scripts/*.sh|py` invocations inside `run:` blocks that happened to
# mention "scripts/" anywhere, so hygiene's inline
# `cargo metadata --locked ...` / `cargo check --locked ...` steps -- which
# never call a script -- were invisible to it. A stale sub-workspace
# lockfile then passed this runner locally and in a from-scratch clean
# checkout, and failed in CI, because the one command that would have caught
# it was never run. Every `run:` step is now decomposed, not just the ones
# that happen to mention `scripts/`.
#
# A discovered invocation is treated as locally runnable when its exact
# command line -- the same flags CI passes, joined across `\` continuations
# -- contains no GitHub Actions expression (`${{ ... }}`) and no shell
# variable expansion (`$...`), AND is either a `scripts/*.sh|py` invocation
# or a plain `cargo metadata`/`cargo check` invocation (the fast,
# side-effect-free, deterministic family that this class of defect lives
# in). Everything else discovered inside a `run:` block -- shell control-flow
# fragments (`for`, `if`, `fi`, `done`, bare variable assignments, `{`/`}`,
# heredocs), commands that install or mutate toolchain/system/repository
# state (`sudo`, `apt-get`, `pip install`, `rustup`, `cargo install`,
# `docker`, `adb`, `git push`, ...), and `cargo` subcommands other than
# metadata/check (`build`, `test`, `clippy`, `run`, `ndk`, ...) -- is
# reported as an explicit, reasoned skip rather than either executed
# blindly or silently dropped. `cargo build`/`test`/`clippy` are excluded
# deliberately, not by oversight: CI already dedicates whole separate jobs
# and matrices to them (tests.yaml, wasm/android/cross builds, MSRV,
# clippy_check); duplicating every one of those inline here would turn a
# fast local-check runner into a second, slower copy of full CI rather than
# closing a visibility gap. Any command that isn't recognized by either
# runnable pattern still gets an explicit reason -- there is no silent
# default-runnable bucket -- so an unclassified fragment is never executed
# on a guess.
#
# GitHub Actions expressions/shell variables always reference something
# only a live run has (a matrix value, $RUNNER_TEMP, a revision SHA, an
# event payload, $GITHUB_TOKEN, ...) that this script cannot fabricate
# faithfully. Running such a command with made-up inputs would either crash
# on a usage error or, worse, "pass" against inputs that don't resemble what
# CI actually feeds it -- a misleading result is worse than an honest skip.
# Every skip is reported with its reason so the summary can't be mistaken
# for a pass.
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
# The fast, side-effect-free, deterministic cargo subcommand family this
# runner also executes inline (see the module docstring for why the scope
# stops here rather than covering every cargo subcommand).
CARGO_CHECK_RE = re.compile(r'^!?\s*cargo\s+(metadata|check)\b')
# Toolchain/system/repository-mutating commands: never executed, always
# skipped with this specific reason rather than the generic fallback.
TOOLING_RE = re.compile(
    r'^!?\s*(sudo\b|apt-get\b|pip\d?\s+install\b|rustup\b|cargo\s+install\b|'
    r'cargo\s+ndk\b|npm\s+install\b|docker\b|adb\b|cross\b|gh\b|'
    r'git\s+(config|push|commit)\b)'
)
# Any other cargo subcommand: technically runnable, deliberately out of
# scope (see the module docstring).
CARGO_OTHER_RE = re.compile(r'^!?\s*cargo(-\w+)?\s+\S')

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
    """Join `\`-continued lines, and lines ending in a bare pipe `|` (a
    `cmd |\n  next` pipeline split across lines, which bash's own grammar
    treats as one logical command with no `\` needed), into logical
    commands; split on newlines otherwise. Good enough for the plain,
    script-invoking and cargo-metadata-piped-to-jq steps this repo writes --
    it does not attempt full shell grammar, so a pipeline whose OWN
    continuation line doesn't end in `\` or `|` (e.g. a multi-line quoted
    jq filter body) still splits early. That under-joins rather than
    over-joins: the leftover fragments don't match either runnable pattern
    (scripts/*.sh|py, cargo metadata|check) so they fall through to an
    explicit, reasoned skip instead of being executed as a broken
    fragment."""
    lines = run_text.splitlines()
    buf = []
    for raw in lines:
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line.endswith("\\"):
            continues = True
            piece = line[:-1]
        elif line.endswith("|") and not line.endswith("||"):
            continues = True
            piece = line
        else:
            continues = False
            piece = line
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
        for cmd in logical_commands(run_text):
            is_script = bool(SCRIPT_RE.search(cmd))
            is_cargo_check = bool(CARGO_CHECK_RE.match(cmd))
            if not (is_script or is_cargo_check):
                # Not one of the two runnable families. Still give every
                # discovered fragment a specific, reasoned skip rather than
                # silently dropping it -- that silent drop is exactly the
                # defect class this script exists to close.
                if EXPR_RE.search(cmd):
                    skipped.setdefault(
                        cmd,
                        "references a GitHub Actions expression or shell variable "
                        "(matrix value, $RUNNER_TEMP, a revision SHA, an event "
                        "payload, ...) only a live CI run supplies",
                    )
                elif TOOLING_RE.match(cmd):
                    skipped.setdefault(
                        cmd,
                        "installs or mutates toolchain/system/repository state, not a "
                        "read-only check",
                    )
                elif CARGO_OTHER_RE.match(cmd):
                    skipped.setdefault(
                        cmd,
                        "cargo subcommand other than metadata/check duplicates a "
                        "dedicated CI job (tests/wasm/android/cross/msrv/clippy/...) "
                        "and is out of scope for this fast local-check runner",
                    )
                else:
                    skipped.setdefault(
                        cmd,
                        "not a scripts/*.sh|py invocation or a cargo metadata/check "
                        "invocation; not decomposed further by this runner (may be a "
                        "shell control-flow fragment, a heredoc, a builtin, or a "
                        "step-local variable/assignment) -- requires live CI or "
                        "manual review",
                    )
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
