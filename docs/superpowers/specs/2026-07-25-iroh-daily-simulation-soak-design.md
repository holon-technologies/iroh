# Daily Deterministic Simulation Soak Design

## Outcome

Run one free GitHub-hosted simulation service every day for four hours, with at most one workflow
run active at a time. Exercise every checked swarm domain under deterministic-test and production
cryptography, retain a consolidated machine-readable report, and preserve exact replay identity
for every failure.

The service supplements pull-request, nightly, and weekly run-count campaigns. It does not replace
Patchbay, real-network parity, production resource evidence, or the permanent regression corpus.

## Chosen Approach

Follow TigerBeetle's bounded-epoch pattern at GitHub-hosted scale:

- one `ubuntu-latest` job and one workflow concurrency group;
- one optimized `cargo-sim` build;
- eight sequential 30-minute epochs;
- a fresh `cargo sim soak` process for every epoch;
- four deterministic workers inside the single hosted runner;
- fixed-size batches that rotate through direct, NAT, discovery, mobility, relay, and ready-order
  swarm templates under both crypto lanes;
- atomic summary publication after every batch; and
- a final report aggregating all completed epochs.

The workflow runs daily and is manually dispatchable. `cancel-in-progress: false` ensures a manual
run cannot replace an active scheduled run. The simulation budget is four hours; the GitHub job
timeout is five hours, leaving bounded time for checkout, compilation, final reporting, and upload
below GitHub's six-hour hosted-job ceiling.

## Determinism and Identity

Wall time controls only service orchestration. Each scenario still receives an explicit seed,
virtual clock, scheduler stream, bounded scenario budgets, source revision, and crypto lane.

Work items are assigned canonically from:

```text
(workflow epoch, epoch ordinal, lane ordinal, lane-local seed ordinal)
```

The workflow run number supplies a checked seed-window offset so daily runs explore new seeds.
Every summary records the exact completed seed ranges. A failed scenario retains its signature,
first seed, lane, and replay inputs.

## Bounds

- daily simulation wall budget: 240 minutes;
- epoch wall budget: 30 minutes;
- workflow timeout: 300 minutes;
- active workflow runs: one;
- hosted runners: one;
- workers per epoch: four;
- runs per batch: 64;
- hard run count: 1,000,000 per daily service;
- retained failure artifacts: at most 16 first failure occurrences;
- retained artifact bytes: at most 256 MiB;
- artifact retention: 14 days; and
- soak lanes: exactly twelve canonical domain/crypto pairs.

The runner checks the wall deadline between batches. Scenario event, packet, virtual-time, task,
action, trace, and payload limits remain authoritative inside each run. The GitHub timeout is the
last-resort bound for a process that stops making progress outside those contracts.

Successful run traces are not retained. They contribute bounded counters to the summary. Failure
bundles are retained until the count or byte ceiling is reached; later failures remain represented
by signature, seed, and lane in the report.

## Reports and Failure Behavior

Each epoch writes `soak-summary.json` atomically after every batch. It contains:

- source and plan identity;
- epoch and seed-window identity;
- elapsed time and stop reason;
- completed, successful, failed, errored, and panicked counts;
- per-lane counts and next seed;
- deduplicated failure signatures and occurrence counts; and
- retained/omitted failure-artifact counts and bytes.

The orchestrator keeps completed epoch summaries even when an epoch exits nonzero. It starts the
next clean epoch unless the outer job deadline is near. The final `daily-soak-report.json` and
GitHub step summary aggregate every completed or missing epoch.

Simulation failures make the final job fail only after report generation and unconditional
artifact upload. A missing epoch summary, build failure, runner timeout, disk exhaustion, or
artifact-service failure is classified as infrastructure failure rather than a passing soak.

## Rollout and Validation

Add the command and report model test-first, then the bounded epoch orchestrator, workflow contract,
operations-policy update, and runbook changes. Validate pure scheduling/accounting with injected
elapsed time, execute a seconds-long multi-epoch smoke locally, and run the complete simulator
tests, strict Clippy, formatting, determinism inventories, shell syntax, and workflow contracts.

The first GitHub run is execution evidence only after its uploaded report is inspected. The
workflow definition itself is never reported as a completed soak.
