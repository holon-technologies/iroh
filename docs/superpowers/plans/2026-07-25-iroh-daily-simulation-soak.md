# Daily Deterministic Simulation Soak Implementation Plan

**Goal:** add one daily four-hour GitHub-hosted deterministic simulation soak with concurrency one,
bounded failure retention, atomic progress, and a consolidated report.

**Success criteria:** eight fresh 30-minute epochs rotate all twelve domain/crypto lanes, every
completed scenario is accounted exactly, failures retain replay identity, reports survive ordinary
epoch failure, and the final workflow uploads before returning failure.

**Scope:** `iroh-sim` soak scheduling/reporting, its operations policy and CLI, one bounded
orchestration script, one workflow, executable contracts, and simulation operations documentation.

**Non-goals:** real networking, Patchbay execution, production capacity qualification, indefinite
workers, retaining successful traces, or replacing existing CI/nightly/weekly campaigns.

**Approach:** execute the approved design directly with `executing-plans`,
`test-driven-development`, `tigerstyle-rust`, and `verification-before-completion`.

### Task 1: Bounded soak model and accounting

**Resources:** `iroh-sim/src/soak.rs`, `iroh-sim/src/lib.rs`, focused unit tests.

**Depends on:** existing `CampaignRunner`, `Scenario`, and `FailureSignature` contracts.

**Interfaces and state:** validated soak configuration; canonical lane state; checked aggregate and
per-lane counters; deduplicated failure signatures; explicit wall/run stop reasons; injected
elapsed-time and checkpoint callbacks.

**Implementation:** write failing tests for round-robin lane scheduling, wall/run bounds, exact
accounting, failure deduplication, overflow, and checkpoint failure. Implement fixed-size batches
by reusing `CampaignRunner`, then refactor only while tests remain green.

**Failure and operations:** invalid zero/excessive bounds return typed errors. Counter or seed
overflow fails closed. One batch is the maximum deadline overshoot unit.

**Validation:** focused `soak` unit tests and `cargo test -p iroh-sim --lib`.

### Task 2: Strict daily plan and CLI epoch execution

**Resources:** `iroh-sim/src/cli.rs`, `iroh-sim/src/soak.rs`,
`iroh-sim/soaks/daily.json`, `iroh-sim/tests/cli.rs`.

**Depends on:** Task 1.

**Interfaces and state:** strict canonical plan schema with twelve unique lanes, workspace-relative
swarm paths, template digests, crypto lanes, epoch/seed-window inputs, artifact root, and wall/run
bounds. `cargo sim soak` emits atomic `soak-summary.json`.

**Implementation:** add a failing CLI test, validate the plan before execution, reuse production
scenario/swarm construction, retain no successful traces, retain bounded failure bundles, and
return nonzero after summary finalization when any run failed.

**Failure and operations:** path traversal, digest drift, duplicate lanes, unsupported crypto,
artifact exhaustion, missing summary, and scenario errors fail closed with bounded diagnostics.

**Validation:** focused CLI smoke with second-scale wall budget, plan canonicalization tests, and
full `iroh-sim` CLI tests.

### Task 3: Daily epoch orchestration and consolidated report

**Resources:** `scripts/run-daily-simulation-soak.sh`,
`scripts/tests/check-daily-simulation-soak.sh`, report fixtures or seconds-long smoke.

**Depends on:** Task 2.

**Interfaces and state:** eight sequential epochs, fresh process per epoch, checked run-number seed
window, per-epoch directories, atomic aggregate JSON, GitHub step summary, and final exit status.

**Implementation:** write the contract test first, add bounded argument parsing and explicit
directories, continue after an epoch-level simulation failure, classify missing summaries as
infrastructure errors, aggregate with checked `jq` expressions, and fail only after reporting.

**Failure and operations:** no background processes; traps propagate termination; all paths remain
under the caller-selected artifact root; partial summaries remain uploadable.

**Validation:** shell syntax, contract test, and a two-epoch seconds-long local smoke.

### Task 4: Daily GitHub-hosted workflow and policy

**Resources:** `.github/workflows/simulation-daily-soak.yml`,
`iroh-sim/operations-policy.json`, `iroh-sim/src/operations.rs`,
`iroh-sim/tests/operations.rs`, workflow contract.

**Depends on:** Tasks 2-3.

**Interfaces and state:** daily/manual trigger, `ubuntu-latest`, one concurrency group,
`cancel-in-progress: false`, 300-minute job timeout, release build, 240-minute/8-epoch invocation,
unconditional 14-day artifact upload, and post-upload failure propagation.

**Implementation:** add RED policy/workflow tests; add a strict long-soak policy with the approved
bounds; implement the workflow; keep the simulator exit status until after report upload.

**Failure and operations:** one scheduled/manual run at a time. Larger paid runners and
self-hosted labels are forbidden by the workflow contract.

**Validation:** operations tests, workflow contract, configuration inspection, and local command
surface checks.

### Task 5: Documentation and integrated verification

**Resources:** `docs/simulation/operations.md`, `docs/testing/simulation.md`,
`docs/testing/determinism-audit.md`, determinism baselines, final diff.

**Depends on:** Tasks 1-4.

**Interfaces and state:** current runbook documents daily soak scope, report interpretation,
replay/triage, retention, and the distinction between a checked definition and executed evidence.

**Implementation:** update current-state documents and classify any orchestration boundary drift.

**Failure and operations:** explicitly report that the four-hour hosted service is not locally
executed during verification; validate its seconds-long equivalent and workflow contract instead.

**Validation:** focused/full simulator tests, strict Clippy, formatting, docs consistency,
determinism inventories, shell syntax, workflow contracts, and `git diff --check`.
