# Deterministic Tooling Closure Implementation Plan

**Goal:** implement the approved deterministic-tooling closure design and turn every discovered gap
into a bounded executable regression gate.

**Success criteria:** exact reusable load conservation, production-horizon virtual-time coverage,
structured canary failures, scheduled dedicated-host evidence, syntax-aware stable effect
inventory, four bounded fuzz targets, and consistent current-state documentation all validate on
the final tree.

**Scope:** `iroh/bench`, determinism-check tooling, an excluded fuzz package, CI workflows, and
testing/audit documentation. Production limits, public protocol behavior, and production entropy
are unchanged.

**Approach:** land independent test-first slices, preserve the lexical checker as a backstop, use
the existing canary and simulation artifact patterns, and keep realistic host checks outside PR
CI.

**Global constraints:** Rust 2024, workspace lints, no new unsafe code, checked arithmetic, bounded
inputs/tasks/channels/artifacts, supervised shutdown, deterministic failure identity, and no
secrets or peer payloads in retained artifacts.

### Task 1: Reusable workload conservation and lifecycle contracts

**Resources:** `iroh/bench/src/canary.rs`, `iroh/bench/src/canary/workloads.rs`, focused tests.

**Depends on:** none.

**Interfaces and state:** introduce validated bounded workload counts and a final conservation
result. Relay driver ownership transitions from filling to active to shutdown; no completed fill
future may remain undrained across a schedule tick.

**Implementation:** first add failing tests for overflow, missing outcomes, transport failures,
driver progress, and production-horizon keepalive. Implement the smallest pure accounting API and
supervised lifecycle changes needed for them to pass.

**Failure and operations:** invalid external counts return `CanaryError`; internal ownership
violations assert with the violated invariant. All joins retain existing deadlines.

**Validation:** focused canary library/workload tests and all `iroh-bench` resource-canary tests.

### Task 2: Structured lane failure snapshots

**Resources:** `iroh/bench/src/bin/resource_canary.rs`, workload progress types, JSON tests and
artifact schema documentation.

**Depends on:** Task 1.

**Interfaces and state:** every workload publishes bounded progress through a watch channel.
Failure reports contain lane, phase, error class/message, deadline/elapsed state, last resource
sample, and latest progress.

**Implementation:** add a failing serialization/error-path test, implement the shared diagnostic
schema, then route DNS, relay, endpoint, sampler, and timeout failures through it.

**Failure and operations:** failure reporting is best-effort only after the primary artifact path
itself fails; diagnostic serialization may not hide the original error.

**Validation:** focused error injection tests plus reduced smoke runs for all lanes.

### Task 3: Scheduled dedicated-host canary

**Resources:** new `.github/workflows/resource-canary.yml`, canary operator docs.

**Depends on:** Task 2.

**Interfaces and state:** weekly/manual workflow on the `iroh-resource-canary` self-hosted runner
label; optimized release build; exact evidence arguments; bounded timeout and artifact retention.

**Implementation:** add static workflow contract tests before the workflow, then add preflight,
execution, digest verification, and unconditional artifact upload.

**Failure and operations:** preflight failure stops load generation. Workflow artifacts remain
available for 30 days and never contain secrets.

**Validation:** workflow contract test and local preflight/smoke command where host constraints
permit.

### Task 4: Syntax-aware stable determinism inventory

**Resources:** new unpublished checker crate or tool, `scripts/check-determinism-boundaries.sh`,
`scripts/tests/check-determinism-boundaries.sh`, semantic baseline.

**Depends on:** none.

**Interfaces and state:** output stable category/path/owner/API/ordinal identities. Resolve
file-local aliases, reject malformed Rust, and ignore comments/string literals.

**Implementation:** add failing fixture cases for alias detection, comment/string exclusion, and
line-movement stability. Implement the syntax visitor, add update/check modes, and invoke both
lexical and syntax-aware checks from CI.

**Failure and operations:** parse failures, unknown baseline format, or inventory drift fail
closed with actionable added/removed identities.

**Validation:** checker contract, current baseline check, formatting, and strict Clippy.

### Task 5: Bounded fuzz targets and automation

**Resources:** excluded `fuzz/` package, four adapters/targets/corpora, `.github/workflows/ci.yml`,
`.github/workflows/simulation-nightly.yml`, fuzz runbook.

**Depends on:** stable target adapters from existing production modules.

**Interfaces and state:** each adapter accepts at most its named maximum bytes and returns typed
success/rejection. Targets never open sockets, files, databases, or ambient configuration.

**Implementation:** add deterministic regression tests for each adapter, expose the narrow
adapters, create cargo-fuzz targets and synthetic seeds, then add fixed-budget smoke/nightly jobs.

**Failure and operations:** CI caps target duration, RSS, corpus/artifact size, and retention.
Crashes retain reproducible target/input identity.

**Validation:** deterministic adapters, target compilation, one fixed-budget local smoke per
target when `cargo fuzz` is available, and workflow contracts.

### Task 6: Current-state documentation reconciliation

**Resources:** `docs/testing/determinism-audit.md`, `docs/testing/simulation.md`,
`docs/testing/production-resource-canary.md`, exit audit, operations/runbooks.

**Depends on:** Tasks 1-5.

**Interfaces and state:** one active gap table; historical discovery labelled as historical;
current simulation boundary statements agree.

**Implementation:** update evidence and commands, remove contradictory current claims, and add a
script test that rejects duplicate active status for the same boundary.

**Failure and operations:** documentation must distinguish checked evidence from scheduled but not
yet executed service evidence.

**Validation:** consistency script, docs tests, links, and requirement-by-requirement inspection.

### Task 7: Integrated verification

**Resources:** all affected files and final diff.

**Depends on:** Tasks 1-6.

**Interfaces and state:** no generated/baseline drift and no untracked failure artifacts.

**Implementation:** run focused tests first, then formatting, affected strict Clippy/tests, boundary
checks, fuzz target compilation, workflow contracts, and final diff review.

**Failure and operations:** report any unavailable platform/runner validation explicitly; never
substitute a shared-host run for dedicated production evidence.

**Validation:** all commands above on the final state, with exact failures retained if blocked.
