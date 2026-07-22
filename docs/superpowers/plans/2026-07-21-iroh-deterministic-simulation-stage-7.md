# Iroh Deterministic Simulation Stage 7 Implementation Plan

> Status: approved as part of the deterministic simulation platform specification.

**Goal:** Turn the deterministic simulator into an owned engineering service with machine-readable cross-backend reports, explicit operating policy, recurring soak/parity workflows, and a complete triage/schema/corpus runbook.

**Architecture:** Backend-specific jobs emit strict `ParityFixture` envelopes and the simulator compares only their common declared semantic capabilities. A checked operational policy is the source of truth for tier budgets, retention, replay compatibility, and service objectives. CI remains bounded; weekly workflows perform larger campaigns and publish immutable artifacts without weakening exact-source replay.

**Tech stack:** Rust, `cargo-sim`, strict JSON schemas, GitHub Actions, Criterion, Patchbay fixture adapters.

---

### Task 1: Cross-backend parity operations

- [x] Add fail-closed fixture-to-fixture comparison with explicit skip semantics.
- [x] Add `cargo sim parity export` for canonical deterministic outcomes.
- [x] Add `cargo sim parity compare` for Patchbay/local/platform fixture jobs.
- [x] Test mismatched cases, capability intersection, semantic differences, canonical output, and immutable writes.

### Task 2: Engineering-service policy

- [x] Define a strict versioned operations policy for PR/main/nightly/weekly budgets and retention.
- [x] Encode replay/source/schema compatibility and corpus-review requirements.
- [x] Add policy validation tests that reject non-monotonic tiers and unsafe zero limits.

### Task 3: Recurring operational workflows

- [x] Add weekly direct/relay schedule soak shards and canonical parity export.
- [x] Publish campaign, parity, benchmark, and failure artifacts with policy-aligned retention.
- [x] Keep realistic Patchbay failures distinct from deterministic semantic comparison failures.

### Task 4: Operator documentation

- [x] Publish fresh-checkout run, replay, minimize, promote, compare, and triage commands.
- [x] Document artifact SLOs, ownership, escalation, schema migration, and compatibility windows.
- [x] Record real-router/interoperability limitations and performance-correlation methodology.

### Task 5: Stage 7 exit gates

- [x] Run parity and policy self-tests, full simulator tests, formatting, lint, boundary audit, and workflow syntax checks.
- [x] Execute one deterministic export/compare report and one bounded soak shard locally.
- [x] Update architecture evidence and close all 17 deliverables with remaining boundaries stated explicitly.
