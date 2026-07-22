# Iroh Deterministic Simulation Stage 6 Implementation Plan

> Status: approved as part of the deterministic simulation platform specification.

**Goal:** Put simulator-supported production endpoint paths under seed-controlled kernel scheduling, make task ownership and remaining executor escapes observable, and provide replayable rare-schedule campaigns with bounded liveness diagnostics.

**Architecture:** The production-local backend supplies the kernel executor through `RuntimeContext`. The kernel selects among simultaneously ready tasks through a domain-separated decision stream, with a deterministic fairness bound. Kernel snapshots expose live task parentage and scheduler accounting. Any dependency-owned Tokio task set that cannot yet migrate is explicitly registered in the run manifest and boundary audit so it cannot silently qualify as fully deterministic.

**Tech stack:** Rust, Tokio compatibility primitives, `iroh-runtime` capability traits, `iroh-sim` kernel/campaign/artifact tooling.

---

### Task 1: Move production endpoint roots to the kernel

- [x] Construct the production-local endpoint runtime with `Kernel::runtime_context`.
- [x] Prove direct QUIC still works through production endpoint/socket actors.
- [x] Prove relay QUIC still works through production relay actors.
- [x] Add a regression assertion that the production root tasks appear in the kernel ownership graph.

### Task 2: Seeded, fairness-bounded ready-task scheduling

- [x] Open a `kernel/ready-task` decision stream from the run root seed.
- [x] Select every legal ready task through that stream when more than one task is runnable.
- [x] Enforce and report a deterministic maximum-ready-wait fairness bound.
- [x] Test same-seed identity, seed sensitivity, duplicate-wake handling, and bounded fairness.

### Task 3: Ownership and liveness diagnostics

- [x] Expose stable task metadata snapshots including parent/child relationships.
- [x] Distinguish clean completion, blocked quiescence, and budget-bounded runnable livelock evidence.
- [x] Include scheduler/task diagnostics in artifacts and explain output.
- [x] Test cancellation, panic, stalled, and runnable-budget terminal states.

### Task 4: Eliminate or declare executor/time escapes

- [x] Inventory child `JoinSet`/`tokio::spawn` and direct Tokio-time use reached by supported paths.
- [x] Migrate feasible child task sets to `TaskGroup` ownership.
- [x] Register unavoidable dependency compatibility sets explicitly in manifests.
- [x] Update the boundary checker so a new unclassified escape fails CI.

### Task 5: Replayable rare-schedule campaigns

- [x] Add scheduler seeds to campaign sharding and artifact identity.
- [x] Add a focused rare-order corpus/campaign fixture.
- [x] Verify failing schedules replay and minimize without changing scheduler decisions unexpectedly.
- [x] Add bounded Stage 6 smoke and nightly matrices.

### Task 6: Documentation and Stage 6 gates

- [x] Update architecture, simulation guide, determinism audit, and performance evidence.
- [x] Refresh the reviewed boundary baseline with every remaining exception classified.
- [x] Run formatting, lint, native tests, wasm/minimal-feature checks, benchmark build, corpus replay, and deterministic replay gates.
- [x] Record measured overhead and close every Stage 6 checklist item before Stage 7.
