# Iroh Deterministic Simulation Stage 0/1 Implementation Plan

## Goal and success criteria

Establish the production-quality foundation for Iroh's long-term deterministic simulation platform without implementing synthetic networking prematurely.

This slice is complete when:

- the revision-pinned nondeterminism inventory is enforced by an executable source-policy check;
- existing endpoint/runtime behavior has characterization coverage before refactoring;
- a lockstep-published `iroh-runtime` crate defines and tests shared clock, wall-clock, executor/task-group, decision-stream, and trace contracts;
- the production Tokio implementation preserves shutdown and cancellation behavior;
- Iroh's Noq runtime uses the shared context for time, timers, tasks, and behavioral seed derivation;
- every test run can create a versioned run identity, normalized trace, artifact manifest, and replay command skeleton;
- existing native and wasm checks remain green, and benchmark baselines are captured for later comparison.

## Chosen approach and tradeoffs

Use the approved capability-injection architecture. Add a lockstep-published `iroh-runtime` workspace crate first, then a private `iroh-sim` workspace crate for run artifacts and future kernel/network work. Production constructors install Tokio, system wall time, OS-backed behavioral seed creation, and a no-op trace sink. Simulation constructors will supply deterministic implementations explicitly in later stages.

The shared contracts live in Iroh before possible upstreaming to `n0-future` or Noq. This keeps the first migration atomic and lets real usage harden the API. Runtime-path trait dispatch is acceptable; packet-hot production paths do not gain a new per-packet allocation or dynamic dispatch in this slice.

## Constraints and non-goals

- Preserve the existing public `Endpoint::builder(...).bind()` behavior and production cryptographic entropy.
- Do not simulate QUIC, relay protocol behavior, NAT, DNS, or IP networking in this slice.
- Do not use ambient globals, thread-local simulator modes, or behavior-selection feature flags.
- Do not claim full determinism while any core task/time/socket escape remains; record the determinism grade honestly.
- Follow RED-GREEN-REFACTOR for new behavior and characterization-first refactoring for preserved behavior.
- Preserve wasm-browser support; Tokio-only adapters must remain target-gated.
- Do not weaken or remove existing tests to accommodate the refactor.

## Affected technologies

Rust 2024, Tokio, Tokio-util task tracking/cancellation, Noq runtime and endpoint configuration, Blake3 domain separation, Rand/ChaCha behavioral streams, Serde/JSON artifact schemas, GitHub Actions, cargo metadata, and the existing Iroh endpoint/socket lifecycle.

## Resolved decisions

- Architecture Option B is approved.
- `iroh-runtime` is a lockstep-published internal workspace dependency.
- `iroh-sim` is initially `publish = false` and owns simulator-only artifacts and CLI foundations.
- Exact-source replay is the safe default; schema migration is explicit and never silent.
- CI budgets remain configurable until operational budgets are supplied.
- Internal dependency changes, including Noq, are permitted when proven necessary.

## Blocking open decisions

None for Stage 0/1.

### Task 1: Enforce the nondeterminism occurrence baseline

**Resources:** `docs/testing/determinism-audit.md`; new `scripts/check-determinism-boundaries.sh`; new `scripts/determinism-boundaries.txt`; `.github/workflows/ci.yml`

**Depends on:** approved architecture and the current revision-pinned audit.

**Interfaces and state:** The baseline is a normalized, sorted list of `category<TAB>path:line<TAB>matched-source-fragment`. Categories cover spawn/task, clock/timer, entropy/randomness, sockets/DNS/interfaces/port mapping, external state, and unordered collections. The checker has `--check` and `--update` modes. `--check` is read-only and fails with added/removed entries plus the audit-update instruction.

**Implementation:**

- [x] Write a shell-level contract test that demonstrates `--check` fails when a fixture contains an unclassified direct runtime call and succeeds after updating its isolated baseline.
- [x] Implement deterministic `rg` collection and normalization without depending on absolute paths or locale ordering.
- [x] Generate the repository baseline and reference its SHA-256 from the audit.
- [x] Add a focused CI step after formatting/lint setup; do not make the check platform-dependent.

**Failure behavior:** Missing `rg`, malformed baseline rows, collection errors, and drift fail closed with actionable messages. Updating is explicit and never performed by CI.

**Validation:** Run the contract test, `scripts/check-determinism-boundaries.sh --check`, `shellcheck` when available, and verify an intentional temporary occurrence produces a useful failure before reverting that temporary edit.

### Task 2: Characterize current Iroh/Noq runtime lifecycle

**Resources:** `iroh/src/runtime.rs`; `iroh/src/socket.rs`; existing endpoint shutdown tests in `iroh/src/endpoint.rs`; new focused runtime tests in `iroh/src/runtime.rs`

**Depends on:** Task 1 baseline.

**Interfaces and state:** Preserve current behavior: Noq tasks spawn while open, runtime abort cancels them, graceful shutdown waits for tracked tasks, post-close spawns are dropped, timers use Tokio time on native and browser timers on wasm, and endpoint close remains idempotent.

**Implementation:**

- [x] Add characterization tests for spawn completion, abort cancellation, shutdown waiting, post-close spawn rejection, and timer firing/reset.
- [x] Run each new test before structural changes and retain green baseline output.
- [x] Add endpoint-level coverage only where runtime-unit behavior cannot prove externally visible shutdown semantics.

**Failure behavior:** Tests use bounded wall-clock watchdogs only to prevent a hung harness; protocol assertions use controlled Tokio time where possible.

**Validation:** `cargo test -p iroh runtime --all-features` plus the exact endpoint shutdown tests identified during implementation.

### Task 3: Introduce stable runtime identity and observation types

**Resources:** new `iroh-runtime/Cargo.toml`; new `iroh-runtime/src/lib.rs`; new `iroh-runtime/src/id.rs`; new `iroh-runtime/src/trace.rs`; root `Cargo.toml`; affected external-type allowlists

**Depends on:** Task 2 characterization baseline.

**Interfaces and state:** Define nonzero/stable `TaskId`, `TimerId`, `DecisionId`, and `TraceSequence`; `TaskKind` and `TaskMetadata` with parent ID and child ordinal; `TraceContext` with typed optional entity identifiers; versioned `TraceEvent` and `TraceEventKind`; and `TraceSink` with a zero-cost no-op implementation.

**Implementation:**

- [x] Write failing serialization and stable-order tests for identity/event types.
- [x] Add the lockstep crate metadata and workspace membership.
- [x] Implement types with explicit numeric/string encoding and no pointer/debug-address identity.
- [x] Keep payloads structured and redactable; do not store application secrets.

**Failure behavior:** ID exhaustion is an explicit error, unknown serialized enum variants fail schema validation, and trace-sink failures are surfaced to simulator callers while the production no-op cannot fail.

**Validation:** `cargo test -p iroh-runtime`; `cargo check -p iroh-runtime --all-targets`; JSON golden-schema test; `cargo metadata --no-deps` confirms workspace/package topology.

### Task 4: Add monotonic and wall-clock contracts with production adapters

**Resources:** new `iroh-runtime/src/time.rs`; `iroh-runtime/src/lib.rs`; `iroh/src/runtime.rs`; `iroh/src/endpoint/quic.rs`

**Depends on:** Task 3 IDs and trace contracts.

**Interfaces and state:** `Clock::now/new_timer`, resettable `Timer`, and `WallClock::now_system` are object-safe. `TokioClock` delegates to Tokio without changing clock domains. `SystemWallClock` delegates to `SystemTime::now`. Noq TLS `TimeSource` is adapted from the same wall-clock capability.

**Implementation:**

- [x] Write failing timer order/reset/cancel tests and a wall-clock delegation test.
- [x] Implement production adapters and trace timer create/reset/fire/drop events.
- [x] Add a Noq timer adapter without duplicating timer state.
- [x] Wire the endpoint TLS time source through the runtime context while preserving the default result.

**Failure behavior:** Deadlines in the past become immediately ready; dropping a timer emits a cancellation/drop observation; wall-clock conversion errors are explicit rather than saturating silently.

**Validation:** `cargo test -p iroh-runtime time`; `cargo test -p iroh runtime`; relevant TLS configuration tests; native and wasm `cargo check` commands used by CI.

### Task 5: Add executor and structured task-group contracts

**Resources:** new `iroh-runtime/src/task.rs`; `iroh-runtime/src/context.rs`; `iroh/src/runtime.rs`

**Depends on:** Tasks 3 and 4.

**Interfaces and state:** `Executor` accepts owned boxed tasks plus `TaskMetadata`; `TaskGroup` owns children, supports close/cancel/join, rejects post-close spawn, and exposes a stable snapshot. `TokioExecutor` and `TokioTaskGroup` use `TaskTracker` and `CancellationToken`. Parent/child task IDs derive from stable creation ordinals.

**Implementation:**

- [x] Write failing tests for parent-child IDs, concurrent child completion, cancellation, close/join, rejection after close, and empty final snapshots.
- [x] Implement the production task group using existing runtime semantics.
- [x] Adapt `iroh::runtime::Runtime` to delegate Noq task spawning and shutdown to the group.
- [x] Keep the existing tracing span fields while adding structured task observations.

**Failure behavior:** Spawn rejection drops the future without polling and emits a rejected event. Panics/JoinErrors are classified and observable. Cancellation is idempotent. Joining has no implicit wall-clock timeout.

**Validation:** Observe RED for each contract test, then `cargo test -p iroh-runtime task`, `cargo test -p iroh runtime`, and endpoint shutdown suites.

### Task 6: Add domain-separated behavioral decision streams

**Resources:** new `iroh-runtime/src/decision.rs`; `iroh-runtime/Cargo.toml`; `iroh/src/socket.rs`

**Depends on:** Task 3 trace IDs.

**Interfaces and state:** `RootSeed([u8; 32])`, validated `DecisionPath`, `DecisionSource::stream(path)`, and `DecisionStream` provide stable integer/range/boolean/byte decisions. Stream seeds use a versioned Blake3 derivation over the root seed and length-delimited semantic path. Each stream owns an independent draw counter and emits the selected value or alternative.

**Implementation:**

- [x] Write failing golden tests for derivation, repeated-run equality, path isolation, draw counters, and invalid paths.
- [x] Implement deterministic streams with a pinned ChaCha algorithm/version.
- [x] Add production root-seed creation using OS-backed Rand only at construction.
- [x] Plumb a dedicated `endpoint/<id>/noq` seed into `noq_proto::EndpointConfig::rng_seed`.

**Failure behavior:** Empty/invalid/unbounded paths fail construction; range errors return typed errors; crypto material cannot be requested through this API.

**Validation:** `cargo test -p iroh-runtime decision`; a focused Iroh test proves a supplied root seed reaches Noq configuration without exposing cryptographic keys.

### Task 7: Compose and inject `RuntimeContext`

**Resources:** `iroh-runtime/src/context.rs`; `iroh/src/runtime.rs`; `iroh/src/endpoint.rs`; `iroh/src/socket.rs`; relevant builder tests

**Depends on:** Tasks 4–6.

**Interfaces and state:** `RuntimeContext` aggregates clock, wall clock, root task group/executor, decision source, and trace sink. `RuntimeContext::production()` is the only normal-builder default. An unstable internal endpoint construction path accepts an explicit context and unsafe-test marker; it is not selected by an ambient variable or feature switch.

**Implementation:**

- [x] Add failing builder tests proving production defaulting and explicit-context propagation.
- [x] Pass the context through endpoint options into socket construction.
- [x] Make `iroh::runtime::Runtime` a thin Noq adapter over the context and endpoint child group.
- [x] Route Noq `now`, timers, spawns, and RNG seed through the context.
- [x] Preserve wasm behavior with a target-specific production path and portable capability build.

**Failure behavior:** Context construction validates compatible clock/timer/executor domains. Closed context binding returns a typed bind error. Unsafe deterministic crypto use is marked in trace/run identity.

**Validation:** Focused builder/runtime tests, `cargo test -p iroh --all-features`, native no-default-feature check, wasm check, and existing endpoint integration tests.

### Task 8: Migrate core root-task creation without changing behavior

**Resources:** `iroh/src/socket.rs`; `iroh/src/address_lookup/pkarr.rs`; `iroh/src/net_report.rs`; `iroh/src/net_report/reportgen.rs`; `iroh/src/protocol.rs`; `iroh/src/socket/transports/relay.rs`; associated tests

**Depends on:** Task 7 context injection.

**Interfaces and state:** Each endpoint-owned root task receives stable metadata, belongs to the endpoint root group or a named child group, and participates in cancellation/join/resource snapshots. Existing actor message protocols and task bodies remain unchanged.

**Implementation:**

- [x] Add or identify passing characterization tests for the migrated task owners.
- [x] Replace native Noq, socket-actor, relay-actor, and direct-address-report roots with context task-group spawns.
- [x] Preserve abort-on-drop semantics with `OwnedTaskHandle`; leave public router and probe child-set migrations for Stage 6 rather than changing their join-error contracts.
- [x] Update the occurrence baseline after reviewed migrations, never by blanket allowlisting.

**Failure behavior:** Spawn rejection propagates during construction or triggers the existing subsystem shutdown path after construction. No task becomes detached silently.

**Validation:** Focused subsystem tests after each migration; endpoint integration suite; source-policy check shows the intended direct-spawn reductions; final task snapshot is empty after endpoint shutdown.

### Task 9: Establish run manifests, normalized traces, and replay CLI skeleton

**Resources:** new `iroh-sim/Cargo.toml`; new `iroh-sim/src/lib.rs`; new `iroh-sim/src/manifest.rs`; new `iroh-sim/src/trace.rs`; new `iroh-sim/src/bin/cargo-sim.rs`; root `Cargo.toml`; new fixtures under `iroh-sim/tests/fixtures/`

**Depends on:** Tasks 3, 6, and 7.

**Interfaces and state:** Versioned `RunManifest` includes source revision/dirty digest, root seed, scenario ID/hash, simulator/schema versions, normalized config/features, wall-clock epoch, backend capabilities, budgets, scheduling/fault profile, lockfile digest, determinism grade, and escapes. Trace normalization excludes host paths and wall durations. CLI supports `cargo sim replay <manifest>` and rejects unsupported execution with a stable typed status until the Stage 2 backend exists.

**Implementation:**

- [x] Write failing manifest round-trip, normalization, redaction, compatibility, and replay-command tests.
- [x] Implement atomic manifest/trace chunk writing via temp-file rename in an explicit artifact directory.
- [x] Implement compatibility checks and first-divergence reporting contracts.
- [x] Add the CLI dispatch skeleton for `run`, `campaign`, `replay`, `minimize`, `corpus`, and `explain`; unavailable commands fail explicitly rather than pretending success.

**Failure behavior:** Partial artifacts remain diagnosable; incompatible source/schema/config never replay silently; secrets and arbitrary host paths are rejected/redacted.

**Validation:** `cargo test -p iroh-sim`; fixture round trips; induced incompatible-manifest tests; CLI help and expected unsupported-status tests.

### Task 10: Integrate Stage 0/1 gates and update evidence

**Resources:** `.github/workflows/ci.yml`; `docs/testing/determinism-audit.md`; `docs/testing/deterministic-simulation-architecture.md`; new `docs/testing/simulation.md`; benchmark commands/configuration

**Depends on:** Tasks 1–9.

**Interfaces and state:** CI runs the boundary check, runtime/simulator tests, required target checks, and artifact-schema tests. Documentation states the determinism grade honestly and links every Stage 0/1 exit-gate result.

**Implementation:**

- [x] Add CI jobs/steps using existing toolchain/cache conventions.
- [x] Capture non-gating connection-establishment, packet-throughput, and local-relay release samples in `docs/testing/stage1-performance-sample.md` without changing thresholds.
- [x] Document construction, run identity, trace schema, replay limitations, unsafe-test marker, and the next uncontrolled boundaries.
- [x] Update deliverable traceability and audit status only where executable evidence exists.

**Failure behavior:** CI distinguishes source-policy drift, test failure, schema incompatibility, platform unsupported, and performance-data collection failure.

**Validation:** Run formatting, clippy/checks, focused and workspace tests, wasm checks, source-policy check, docs link checks, and a requirement-by-requirement Stage 0/1 completion audit. Do not mark later deliverables complete.

## Execution handoff

Execute this plan in the current session with the `executing-plans` skill. Use `test-driven-development` for Tasks 1 and 3–9, characterization-first refactoring for Tasks 2 and 8, and `verification-before-completion` before every stage-completion claim. Stop and revise the architecture if implementation proves a material interface, security, or production-performance assumption false.
