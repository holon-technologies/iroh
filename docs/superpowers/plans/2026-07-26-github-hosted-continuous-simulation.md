# GitHub-Hosted Continuous Simulation Plan

## Goal and Boundary

Turn the existing daily deterministic soak into a GitHub-hosted, CFO-like recurring service without
self-hosted or paid larger runners. Run four windows per day, build the simulator once per window,
fan out all 12 domain/crypto lanes, preserve bounded fresh-process epochs and failure artifacts, and
fail closed through a final aggregate report.

Success means each window has a source-bound simulator binary, exactly 12 independently observable
lane jobs, disjoint seed windows, a combined ceiling of 999,936 runs, compact retained summaries,
and an aggregate job that rejects missing, duplicate, failed, or malformed lane evidence. Existing
PR, nightly, weekly, corpus, replay, and fuzz workflows remain unchanged.

The implementation uses only standard `ubuntu-latest` runners. Scheduled runs may be delayed by
GitHub and are therefore recurring burst coverage, not a claim of guaranteed continuous service.
Overlapping windows queue instead of being cancelled.

### Task 1: Make one lane independently executable

**Resources:** `iroh-sim/src/cli.rs`, `iroh-sim/tests/cli.rs`,
`scripts/run-daily-simulation-soak.sh`, `scripts/tests/check-daily-simulation-soak.sh`

**Depends on:** Existing strict daily soak plan.

**Interfaces and state:** Add optional `--lane ID` to the Rust soak CLI and shell runner. Validate
the unchanged canonical twelve-lane plan first, select exactly one declared lane at the typed CLI
boundary, preserve its canonical index for seed derivation, and include the lane identity and
configured run ceiling in `daily-soak-summary.json`. Preserve no-argument compatibility.

**Failure and operations:** Unknown or duplicate lanes fail before simulator execution. Epochs stay
sequential and each remains a fresh simulator process.

**Validation:** Extend the shell contract fixture to inspect the selected plan and report, then test
unknown-lane rejection.

### Task 2: Aggregate lane evidence fail-closed

**Resources:** `scripts/aggregate-daily-simulation-soak.sh`,
`scripts/tests/check-daily-simulation-aggregate.sh`

**Depends on:** Task 1 summary schema.

**Interfaces and state:** Scan downloaded lane artifacts, require the exact 12 lane IDs once each,
require distinct seed windows and complete counter-reconciled evidence for the production
8 × 10,416 configuration, sum run/resource counters, deduplicate failure signatures, and write one
atomic `daily-soak-aggregate.json`.

**Failure and operations:** Missing, duplicate, malformed, infrastructure-failed, or
simulation-failed lane reports produce an aggregate artifact and a nonzero exit. The script never
depends on artifact directory names.

**Validation:** Fixture tests cover the successful 12-lane aggregate, duplicate failure
deduplication, and missing-lane rejection.

### Task 3: Fan out the GitHub-hosted workflow

**Resources:** `.github/workflows/simulation-daily-soak.yml`,
`scripts/tests/check-daily-simulation-workflow.sh`

**Depends on:** Tasks 1-2.

**Interfaces and state:** Schedule at minute 23 every six hours. A build job uploads a SHA-named
release binary plus checksum. A 12-entry matrix downloads and verifies it, derives
`seed_window = run_number * 16 + lane_index`, and runs eight epochs capped at 10,416 runs each. An
always-running aggregate job downloads lane artifacts and publishes the combined report.

**Failure and operations:** Use `fail-fast: false`, `max-parallel: 12`, standard hosted runners,
one-day build-artifact retention, 14-day evidence retention, and status propagation only after
artifact upload. Download failure must not prevent aggregate missing-evidence reporting.

**Validation:** Update the workflow source contract and verify YAML parsing through the repository's
existing workflow checks.

### Task 4: Integrate and verify

**Resources:** `.github/workflows/ci.yml`, release-readiness checks, documentation if affected.

**Depends on:** Tasks 1-3.

**Interfaces and state:** Add the aggregate contract test to PR CI and preserve existing release
source checks.

**Failure and operations:** No workflow may introduce `self-hosted`, paid larger runners, overlap
cancellation, or unbounded artifact retention.

**Validation:** Run all daily workflow/runner/aggregate contracts, release readiness, shell syntax,
formatting, `git diff --check`, and the relevant simulator test suite.
