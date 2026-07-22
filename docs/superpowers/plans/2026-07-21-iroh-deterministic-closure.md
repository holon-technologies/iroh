# Iroh deterministic-closure implementation plan

**Goal:** Graduate new simulator-supported production-endpoint runs from `controlled_runtime` to an
honest byte-deterministic test-TLS lane plus a semantically deterministic production-crypto lane,
then add replayable swarm materialization and stronger realistic-backend evidence.

**Success criteria:** All conditions in
`docs/superpowers/specs/2026-07-21-iroh-deterministic-closure-design.md` pass, current deterministic
manifests contain no escapes, production-crypto manifests contain only the named crypto boundary,
and every required build/test/documentation gate is current.

**Approach:** First characterize the existing production behavior. Add general injected-time and
kernel-driver primitives, migrate supported production actors, then remove the bridge. Introduce
the two crypto lanes and manifest migration after execution is closed. Add swarm materialization and
parity hardening only after replay identity is stable.

**Tradeoffs:** The byte-deterministic lane substitutes a test-only X25519 implementation and records
that fidelity exception. The production-provider lane remains the authority for crypto fidelity and
uses semantic rather than ciphertext equality. Scenario schema v2 remains stable; swarm inputs use
a separate versioned schema.

**Constraints and non-goals:** Preserve secure production defaults, existing user-facing endpoint
behavior, artifact fail-closed semantics, and the dirty worktree. Do not build continuous fleet
automation or a multi-process Vortex equivalent. Do not install a global deterministic Rustls
provider, leak provider state, or hide capability skips.

**Technologies:** Rust, Tokio production adapters, custom deterministic kernel/executor,
Rustls 0.23 provider interfaces, Noq/QUIC, serde JSON schemas, Patchbay fixtures, GitHub Actions,
Criterion.

**Resolved decisions:** kernel-owned root operations; injected time everywhere in supported paths;
dual TLS lanes; three explicit determinism grades; separate `SwarmSpec`; fail-closed parity
freshness/capability checks.

**Blocking open decisions:** none. If Rustls's provider lifetime contract cannot support run-owned
deterministic state without leaking or process-global coupling, stop and revise the approved crypto
design rather than weakening its safety requirements.

Execution requires `superpowers:test-driven-development`, followed by
`superpowers:verification-before-completion`. Use `superpowers:executing-plans` because runtime,
runner, manifest, and replay changes are tightly coupled.

### Task 1: Characterize and guard the current behavioral boundary

**Resources:** `scripts/check-simulation-boundaries.sh`, `docs/testing/determinism-audit.md`,
`iroh-sim/tests/runner.rs`, `iroh-sim/tests/relay.rs`, `iroh-sim/tests/deterministic_runtime.rs`,
`iroh/src/socket/transports/relay/actor.rs`, `iroh/src/socket/remote_map/remote_state.rs`

**Depends on:** approved design

**Interfaces and state:** The boundary inventory classifies production non-test occurrences of
spawn, monotonic time, wall time, entropy, network, filesystem, and external I/O. A checked
allowlist carries path, symbol, classification, owner, and rationale.

**Implementation:**

- [ ] RED: add characterization tests for same-seed direct/relay semantic traces, remote-state idle
  and scheduled-path timing, relay inactivity/ping/flush timing, and shutdown cleanup.
- [ ] RED: extend the checker test so unclassified `tokio::spawn`, `tokio::time`,
  `n0_future::time`, or ambient `Instant::now` in supported modules fails.
- [ ] GREEN: record the current exceptions explicitly without changing behavior.
- [ ] REFACTOR: separate test-only occurrences from production behavioral occurrences and remove
  stale Stage 2 labels.

**Failure behavior:** Inventory parse errors, missing owners, duplicate entries, and unmatched
allowlist rows fail CI. No automatic source rewrite is allowed.

**Validation:** `bash scripts/check-simulation-boundaries.sh`; focused Iroh/iroh-sim actor tests;
store the updated row count and digest in the audit.

### Task 2: Add reusable injected-time futures

**Resources:** `iroh-runtime/src/time.rs`, `iroh-runtime/src/lib.rs`, `iroh/src/runtime.rs`,
`iroh/src/runtime.rs` tests, `iroh-sim/src/kernel.rs`, `iroh-sim/tests/kernel.rs`

**Depends on:** Task 1 characterization

**Interfaces and state:** Add clock-backed one-shot/resettable sleep, interval, and timeout
abstractions. Timeout must distinguish inner completion, elapsed virtual deadline, and clock error.
Intervals retain scheduled cadence and documented burst behavior. All values stay in one
`ClockDomain`.

**Implementation:**

- [ ] RED: tests for first deadline, reset, drop, elapsed timeout, inner-first completion, clock
  failure, overflow, missed-period burst behavior, and trace/resource cleanup.
- [ ] GREEN: implement the smallest generic futures over `Arc<dyn Clock>` and existing `Timer`.
- [ ] GREEN: expose crate-internal constructors through `iroh::runtime` without changing public
  endpoint APIs.
- [ ] REFACTOR: replace duplicate `RuntimeSleep`/`RuntimeInterval` mechanics with the shared
  implementation and document polling/cancellation invariants.

**Failure behavior:** Deadline overflow and backend failure are typed and latched by the owning
runtime. Dropping a timeout drops its timer and inner future without a detached task.

**Validation:** `cargo test -p iroh-runtime`; focused `cargo test -p iroh runtime`; Clippy for both
crates.

### Task 3: Migrate remote-state time and scheduling

**Resources:** `iroh/src/socket/remote_map.rs`,
`iroh/src/socket/remote_map/remote_state.rs`,
`iroh/src/socket/remote_map/remote_state/path_state.rs`, `iroh/src/socket.rs`,
`iroh/src/runtime.rs`

**Depends on:** Task 2

**Interfaces and state:** `RemoteStateActor` and `RemoteState` receive the endpoint runtime clock.
All stored instants and scheduled deadlines belong to that clock. Idle, upgrade, path-open,
hole-punch, source freshness, and retry timers use injected futures.

**Implementation:**

- [ ] RED: convert characterization cases to an explicit virtual clock and prove exact deadline
  transitions without Tokio time.
- [ ] GREEN: thread the runtime/clock through actor construction and replace each production
  ambient-time occurrence.
- [ ] GREEN: preserve biased message-before-timer branch order explicitly.
- [ ] REFACTOR: centralize `now`/deadline helpers so child state cannot regain ambient time.
- [ ] Remove the corresponding boundary allowlist rows only after the checker proves absence.

**Failure behavior:** Clock construction/poll errors terminate the actor through its existing
completion channel and latch a runtime failure. No fallback to wall or Tokio time.

**Validation:** focused remote-map tests; `cargo test -p iroh --all-features --lib
socket::remote_map`; simulator mobility/direct scenarios and same-seed trace replay.

### Task 4: Migrate relay actor and shutdown time

**Resources:** `iroh/src/socket/transports/relay.rs`,
`iroh/src/socket/transports/relay/actor.rs`, `iroh/src/socket.rs`, `iroh/src/runtime.rs`,
`iroh-sim/src/relay.rs`, `iroh-sim/tests/relay.rs`

**Depends on:** Tasks 2–3

**Interfaces and state:** Relay actor options carry the endpoint runtime clock/decisions. Inactivity,
connect delay, ping, undeliverable flush, reconnect, send timeout, and shutdown use injected time.
Simulation relay latency schedules a kernel event/timer instead of Tokio sleep.

**Implementation:**

- [ ] RED: virtual-clock tests for each timer family, simultaneous message/timer ordering, relay
  restart, and shutdown during reconnect.
- [ ] GREEN: replace production time calls while retaining existing constants and actor branch
  priority.
- [ ] GREEN: replace socket shutdown `tokio::time::timeout` with injected timeout and preserve the
  diagnostic task snapshot on expiry.
- [ ] GREEN: move any remaining behavioral relay randomness to named decision streams.
- [ ] REFACTOR: remove the relay/time/shutdown allowlist rows and obsolete escape labels.

**Failure behavior:** Timer or decision failure terminates/latches the owning task. Shutdown expiry
is a typed bounded-cleanup failure; it never silently detaches live tasks.

**Validation:** relay actor unit tests; `cargo test -p iroh --all-features --lib
socket::transports::relay`; `cargo test -p iroh-relay --all-features`; Stage 5 relay scenarios and
benchmarks.

### Task 5: Replace `TokioBridge` with a kernel root-operation driver

**Resources:** `iroh-sim/src/kernel.rs`, `iroh-sim/src/tokio_bridge.rs`, `iroh-sim/src/backend.rs`,
`iroh-sim/src/runner.rs`, `iroh-sim/src/scenario.rs`, `iroh-sim/src/lib.rs`,
`iroh-sim/tests/kernel.rs`, `iroh-sim/tests/runner.rs`, `iroh-sim/tests/scenario.rs`

**Depends on:** Tasks 3–4

**Interfaces and state:** Add a generic kernel driver accepting a `Send + 'static` future and
returning its output or a typed driver error. The root task has stable metadata, participates in
seeded scheduling, and owns a closed task group. Runner pairs are joined as futures without Tokio
task handles.

**Implementation:**

- [ ] RED: driver tests for output, pending wake, timer wake, seeded competing roots/children,
  panic, cancellation, stall, event budget, and cleanup.
- [ ] RED: runner test that fails if a harness operation is absent from kernel task history.
- [ ] GREEN: implement root result publication and step loop using existing `TaskGroup` contracts.
- [ ] GREEN: route bind/connect/exchange/close and scenario helpers through the driver; replace all
  runner `tokio::spawn` pairs with direct structured futures.
- [ ] GREEN: remove Tokio yields and compatibility epochs from behavioral execution.
- [ ] REFACTOR: delete `tokio_bridge.rs`, bridge configuration, `tokio_bridge_runtime_context`,
  imports/exports, and `tokio_harness_tasks` classification.

**Failure behavior:** Root panic, cancellation, no-result quiescence, group cleanup failure, and
kernel failure are distinct. On every failure, retain task/scheduler snapshots and cancel/close the
root group.

**Validation:** full `cargo test -p iroh-sim`; exact rare-ready-order replay; direct and relay
same-seed trace tests; boundary checker shows no simulated scheduler escape.

### Task 6: Implement deterministic test TLS and production-crypto parity

**Resources:** `iroh/src/simulation.rs`, `iroh/src/endpoint.rs`, `iroh/src/tls.rs`,
`iroh/src/tls/misc.rs`, new narrowly scoped simulation-crypto module, `iroh-sim/src/backend.rs`,
`iroh-sim/src/runner.rs`, `iroh-sim/src/trace.rs`, Cargo manifests, crypto tests

**Depends on:** Task 5; Rustls provider lifetime feasibility check

**Interfaces and state:** Add `SimulationCryptoMode::{DeterministicTest, ProductionProvider}` to the
unsafe simulation environment. Deterministic entropy is run/endpoint scoped and domain-separated.
The deterministic provider substitutes Rustls random filling and X25519 only; all other provider
components delegate to the configured production provider.

**Implementation:**

- [ ] SPIKE/RED: prove run-owned provider state satisfies Rustls `'static` trait references without
  leaks, process-global seeds, cross-run coupling, or worker interference. Stop for design revision
  if this cannot be proven.
- [ ] RED: tests for same-seed X25519 public/shared secrets, endpoint separation, run separation,
  concurrent worker isolation, scope rejection, and production-builder inaccessibility.
- [ ] GREEN: implement deterministic secure random and X25519 provider components with zeroization
  where secret intermediates are owned.
- [ ] GREEN: install the provider only through `SimulationEnvironment`; retain normal provider in
  the production-crypto lane.
- [ ] RED/GREEN: raw deterministic trace equality across repeat and child-process runs; normalized
  production-provider equality; cross-lane semantic outcome equality.
- [ ] REFACTOR: stop masking ciphertext in raw mode and keep masking narrowly scoped to semantic
  mode.

**Failure behavior:** Missing scope, exhausted counters, poisoned state, provider mismatch, or
entropy/KX failure aborts endpoint construction or the handshake. Never fall back to OS entropy in
the deterministic lane. Never log derived private material.

**Validation:** focused crypto tests under ring and AWS-LC feature sets; full Iroh/relay/simulator
tests; minimal features; WASM compilation remains unaffected; source audit verifies production
defaults.

### Task 7: Migrate manifests, replay, corpus, and determinism requirements

**Resources:** `iroh-sim/src/manifest.rs`, `iroh-sim/src/backend.rs`, `iroh-sim/src/cli.rs`,
`iroh-sim/src/artifact.rs`, `iroh-sim/src/failure.rs`, `iroh-sim/src/corpus.rs`,
`iroh-sim/src/scenario_model.rs`, `iroh-sim/corpus/**`, manifest/replay/corpus tests

**Depends on:** Task 6

**Interfaces and state:** Version the manifest for the two new grades and immutable trace comparison
mode. Record crypto mode, fidelity exceptions, and escapes. Historical `controlled_runtime`
artifacts remain parseable only under their exact schema/source rules; new runs cannot emit it.

**Implementation:**

- [ ] RED: validation matrix for all grade/crypto/comparison/escape combinations and downgrade
  attacks.
- [ ] GREEN: add schema migration and capability constructors derived from actual backend mode.
- [ ] GREEN: make replay choose raw versus normalized comparison from the manifest and report the
  first divergence in either form.
- [ ] GREEN: migrate corpus metadata/scenarios one entry at a time, retaining provenance and
  reviewed signatures/inventories.
- [ ] REFACTOR: remove Stage 1/2 bridge constructors and stale CLI hard-coding.

**Failure behavior:** Unknown grade/mode, invalid combination, unreviewed corpus migration,
cross-source mismatch, or absent trace form fails closed with a distinct compatibility error.

**Validation:** manifest, CLI, failure replay, artifact, corpus, minimizer, and full corpus tests;
fresh child-process replay for both crypto lanes.

### Task 8: Add strict swarm specifications and materialization

**Resources:** new `iroh-sim/src/swarm.rs`, `iroh-sim/src/scenario_model.rs`,
`iroh-sim/src/campaign.rs`, `iroh-sim/src/cli.rs`, `iroh-sim/src/artifact.rs`, `iroh-sim/src/lib.rs`,
new `iroh-sim/tests/swarm.rs`, campaign/CLI tests, JSON fixtures and schema docs

**Depends on:** Task 7 stable replay identity

**Interfaces and state:** `SwarmSpec` schema v1 references or embeds a canonical base scenario and
defines bounded weighted/ranged choices. `SwarmSelection` records every selected value. Runtime
root seed and materialization seed are domain-separated. `cargo sim campaign --swarm <file>` writes
the template, digest, selection, and materialized scenario per run.

**Implementation:**

- [ ] RED: strict JSON, canonicalization, invalid bounds/weights, unsupported capability, dangling
  reference, duplicate choice, and budget tests.
- [ ] RED: reproducibility, worker-count independence, domain separation, and fixed-seed
  option-coverage tests.
- [ ] GREEN: implement validated choice types and deterministic materializer using existing
  `Scenario::normalized`/builder patterns.
- [ ] GREEN: integrate campaign artifacts and summaries; replay ignores regeneration and minimizer
  retains provenance.
- [ ] GREEN: add reviewed swarm templates for direct, NAT/discovery/mobility, relay lifecycle, and
  ready-order pressure.
- [ ] REFACTOR: share bounded generator utilities without changing legacy `--generated` behavior.

**Failure behavior:** Materialization fails before backend construction. Empty choices, overflow,
unsupported combinations, unbounded output, or noncanonical input are schema errors. Campaign
completion order cannot affect selection or summaries.

**Validation:** swarm/scenario/campaign/CLI tests; fixed validation seeds cover all declared choices;
bounded PR smoke and nightly shards succeed.

### Task 9: Harden realistic-backend parity evidence

**Resources:** `iroh-sim/src/parity.rs`, `iroh-sim/src/parity_catalog.rs`,
`iroh-sim/tests/parity.rs`, `iroh-sim/tests/fixtures/patchbay-public.json`, Patchbay tests/workflow,
`docs/simulation/patchbay-parity.md`, `docs/simulation/relay-parity.md`

**Depends on:** Task 7; may proceed alongside Task 8 only if files do not overlap

**Interfaces and state:** Version parity fixtures with evidence source/run identity, observed
dimensions, capability set, and freshness/compatibility metadata. Catalogue policy identifies
dimensions whose regression from completed/common to skipped is forbidden without an explicit
reviewed capability change.

**Implementation:**

- [ ] RED: stale evidence, false capability, silent-skip regression, missing identity, schema
  mismatch, and unsupported-dimension tests.
- [ ] GREEN: extend fixtures/comparison while preserving explicit infrastructure and capability
  skip classes.
- [ ] GREEN: add scenarios/evidence mappings for every currently executable target dimension;
  retain honest skips for unavailable environments.
- [ ] GREEN: update Patchbay export/import workflow to publish immutable fixture evidence.
- [ ] REFACTOR: generate documentation tables from or validate them against the canonical catalog.

**Failure behavior:** A capability skip never passes parity. Stale/incompatible evidence is a
separate error. A common semantic difference remains a failing comparison with typed dimensions.

**Validation:** parity tests; Patchbay contract test; privileged Patchbay suite when available;
weekly strict export/compare.

### Task 10: Update policy, CI, performance evidence, and documentation

**Resources:** `iroh-sim/operations-policy.json`, `.github/workflows/ci.yml`,
`.github/workflows/simulation-nightly.yml`, `.github/workflows/simulation-weekly.yml`,
`.github/workflows/patchbay.yml`, `docs/testing/simulation.md`,
`docs/testing/determinism-audit.md`, `docs/testing/deterministic-simulation-architecture.md`,
`docs/simulation/operations.md`, performance documents/benches

**Depends on:** Tasks 1–9

**Interfaces and state:** Policy declares accepted new-run grades, crypto lanes, replay modes,
swarm budgets, parity freshness, artifact retention, and triage ownership. Existing bounded
PR/nightly/weekly operation remains; no continuous service is added.

**Implementation:**

- [ ] RED/GREEN: policy validation tests require deterministic and production-crypto gates and
  reject `controlled_runtime` for new runs.
- [ ] Add PR raw-replay smoke, semantic-parity smoke, boundary checks, corpus, and bounded swarm.
- [ ] Add nightly/weekly sharded swarm, both crypto lanes, strict parity, and existing benchmarks.
- [ ] Benchmark root-driver scheduling, injected timers, deterministic TLS setup/handshake, and
  materialization; compare on identical runners/revisions.
- [ ] Update all documentation, commands, schema versions, limitation statements, and current-stage
  headings; remove resolved escape claims.

**Failure behavior:** Infrastructure failures remain distinct from product/simulator/parity failures.
Performance regressions produce evidence and never relax correctness budgets automatically.

**Validation:** operations tests, workflow syntax review, command walkthrough from a fresh checkout,
and benchmark artifact generation.

### Task 11: Full release-grade verification

**Resources:** entire changed workspace; validation commands documented above

**Depends on:** Tasks 1–10

**Interfaces and state:** No code or schema change. This task produces current evidence supporting
the final determinism claims.

**Implementation:**

- [ ] Run formatting and the checked boundary inventory.
- [ ] Run full `iroh-runtime`, `iroh-sim`, `iroh-relay --all-features`, and relevant Iroh
  all-feature library/integration tests.
- [ ] Run corpus, deterministic raw replay in a fresh child process, production-crypto semantic
  replay, cross-lane parity, fixed-seed swarm coverage, minimization, and parity comparison.
- [ ] Run Clippy for changed crates/features, minimal native checks, and required WASM builds.
- [ ] Run relevant Criterion benchmarks and a bounded multi-seed soak under both crypto lanes.
- [ ] Review `git diff --check`, schemas/docs/policy consistency, dirty-worktree preservation, and
  any capability skips.

**Failure behavior:** Do not claim completion while any required gate is failing, skipped without an
approved capability reason, or unexecuted. Record environmental blockers separately from product
failures.

**Validation:** Use `superpowers:verification-before-completion`; include exact commands, counts,
benchmark summaries, remaining limitations, and final manifest grades in the handoff.
