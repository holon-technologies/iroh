# Iroh Deterministic Simulation Stage 3 Implementation Plan

## Goal and exit gate

Turn the Stage 2 named-scenario harness into a versioned declarative and generated scenario
platform with continuous invariants, bounded liveness, reproducible failure signatures,
automatic minimization, and a permanent regression corpus.

Stage 3 is complete only when an intentionally injected multi-cause fault:

- is detected at the first invalid observation by a named invariant;
- produces a typed failure artifact and exactly one working replay command;
- is automatically reduced to a strictly smaller canonical scenario while preserving its failure
  signature;
- is stored as a versioned corpus entry with provenance and compatibility bounds; and
- is enumerated by PR CI while seeded generated campaigns run in scheduled CI.

## Chosen architecture

Use one canonical `Scenario` representation for JSON/YAML, Rust builders, generator output,
replay, minimization, and corpus entries. Actions are declarative data with stable IDs and either
an absolute virtual deadline or an observation trigger. Backend capabilities are declared by the
scenario and checked before execution; unsupported actions never silently degrade.

The deterministic runner remains an adapter around production endpoint operations. It emits
immutable `Observation` values into an `InvariantRegistry`; the registry cannot mutate endpoint
or environment state. Safety checks run after every relevant observation, liveness checks own
bounded obligations, and cleanup checks run after bounded shutdown. Invariant evaluation is
deterministically ordered by invariant name and entity key.

Minimization operates only on canonical scenario data. It uses deterministic ddmin passes and a
memoized candidate digest, reruns candidates from the same root seed, and accepts a reduction only
when the normalized `FailureSignature` is equal. It never treats a crash, timeout, replay
divergence, or different invariant as the original failure.

## Constraints

- Keep Stage 2 scenario files replay-compatible for this development branch through an explicit
  loader/migration path; do not guess at unknown schemas.
- Do not serialize futures or production internal state.
- Do not expose mutation hooks through the observer or invariant APIs.
- Do not use wall time to decide scenario or minimizer behavior.
- Keep cryptographic entropy and the Stage 2 Tokio escapes honestly recorded.
- Bound scenario size, generated actions, invariant obligations, minimizer attempts, corpus input,
  trace memory, virtual time, and packet/task resources.
- Generated scenarios must normalize to the same bytes as an equivalent handwritten scenario.

### Task 1: Define the canonical scenario and action schema

**Resources:** new `iroh-sim/src/scenario/model.rs`; new `iroh-sim/src/scenario/builder.rs`;
new `iroh-sim/src/scenario/generator.rs`; `iroh-sim/src/scenario.rs`; new
`iroh-sim/tests/scenario_model.rs`

**Implementation:**

- [x] Define strict schema v2 metadata, requirements, budgets, topology, endpoints, actions,
  fault rules, fairness assumptions, completion policy, allowed terminals, and enabled invariants.
- [x] Define stable action IDs and the Stage 3 direct-IP vocabulary: endpoint start/stop,
  connect, stream/datagram exchange, connection close, partition/heal, link update, time advance,
  and expected failure. Reserve typed unsupported variants for later-stage capabilities.
- [x] Validate references, unique IDs, canonical ordering, finite/bounded values, action timing,
  capability requirements, and absence of host paths.
- [x] Implement Rust builders and canonical JSON encoding; add YAML only if it can preserve the
  same normalized representation without schema ambiguity.
- [x] Implement a domain-separated bounded generator whose output passes the same validator and
  is byte-identical after parse/encode.
- [x] Migrate Stage 2 fixtures through an explicit v1-to-v2 loader and prove their normalized
  behavior is retained.

**Failure behavior:** malformed JSON/YAML, unknown fields/schema/action, dangling references,
duplicate IDs, invalid timing, unsorted canonical collections, unsupported requirements, and
budget overflow are distinct typed errors.

**Validation:** strict round trips, builder/file equivalence, generator reproducibility and bounds,
mutation tests for every validation rule, and property tests for parse/normalize idempotence.

### Task 2: Add typed observations and continuous invariant evaluation

**Resources:** new `iroh-sim/src/observation.rs`; new `iroh-sim/src/invariant.rs`;
`iroh-runtime/src/trace.rs`; `iroh-sim/src/ledger.rs`; new `iroh-sim/tests/invariants.rs`

**Implementation:**

- [x] Define stable operation, endpoint, connection, stream, packet, path, and invariant entity
  IDs plus immutable observation kinds and causal references.
- [x] Implement a deterministically ordered `InvariantRegistry` with safety, bounded-liveness,
  and cleanup classes, observation filters, evaluation points, fairness predicates, and hard
  obligation limits.
- [x] Implement initial authentication, delivery integrity/misdelivery/order, monotonic lifecycle,
  resource ceiling, shutdown cleanup, and reachable-connect liveness invariants.
- [x] Emit invariant registration/satisfaction/failure events with structured evidence and the
  responsible entities into the global trace sequence.
- [x] Run safety checks after every matching observation and before time advances; expire liveness
  obligations by both virtual deadline and event count; run cleanup checks after bounded shutdown.
- [x] Add negative/mutation fixtures proving transient invalid state is caught even when later
  observations would recover.

**Failure behavior:** invariant failure, obligation limit, duplicate obligation, invalid lifecycle,
unfair/unreachable exemption, observer failure, and cleanup leak remain distinct.

**Validation:** table-driven and property tests for every initial invariant family, exact first
failure sequence tests, and empty-registry/no-op production overhead checks.

### Task 3: Implement reference models and the declarative deterministic runner

**Resources:** new `iroh-sim/src/model.rs`; new `iroh-sim/src/runner.rs`;
`iroh-sim/src/scenario.rs`; `iroh-sim/src/backend.rs`; new `iroh-sim/tests/runner.rs`

**Implementation:**

- [x] Add pure endpoint, connection, stream, delivery, and resource reference models that consume
  actions and observations without modeling QUIC timing.
- [x] Define `ScenarioBackend` capability discovery, prepare, execute-action, observe, quiesce, and
  shutdown contracts; implement the Stage 3 deterministic direct-IP backend.
- [x] Schedule ordered actions by `(deadline, action ID)` and trigger actions by stable observation
  predicates; reject unsatisfied triggers at terminal quiescence.
- [x] Execute real endpoint/Noq/QUIC stream and datagram operations and environment partition/heal,
  link updates, and time advance through existing capabilities.
- [x] Compare production observations with model-permitted states and error classes after every
  action.
- [x] Return a typed terminal report containing observations, invariant snapshot, model state,
  resource high-water values, and allowed/actual terminal state.

**Failure behavior:** unsupported backend capability, action failure, trigger stall, model mismatch,
invariant failure, liveness expiry, kernel limit, bridge watchdog, and cleanup failure are distinct.

**Validation:** equivalent named/declarative scenarios, multi-action lifecycle cases, partition/heal
recovery, deliberate model mismatch, and exact same-seed report/trace reproduction.

### Task 4: Make failures first-class replay artifacts

**Resources:** new `iroh-sim/src/failure.rs`; `iroh-sim/src/manifest.rs`;
`iroh-sim/src/artifact.rs`; `iroh-sim/src/cli.rs`; new `iroh-sim/tests/failure_replay.rs`

**Implementation:**

- [x] Define a versioned `FailureSignature` from invariant name, normalized entities, terminal
  class, and a bounded causal trace suffix digest.
- [x] Write canonical scenario, terminal report, invariant snapshot, failure signature, decision
  prefix, resource snapshot, and trace chunks beside the manifest.
- [x] Make replay reproduce both successful and failing expected terminal results and compare the
  signature before the full normalized trace.
- [x] Detect missing/truncated chunks, scenario/manifest disagreement, different failure,
  disappearance of failure, and first trace divergence separately.
- [x] Ensure every post-manifest run failure prints one artifact path and exactly one replay
  command; pre-manifest usage/input failures print none.

**Validation:** induced invariant/model/action/kernel/artifact failures, tampered signatures and
chunks, failure disappearance, and clean-process replay integration tests.

### Task 5: Implement signature-preserving minimization

**Resources:** new `iroh-sim/src/minimize.rs`; `iroh-sim/src/cli.rs`; new
`iroh-sim/tests/minimize.rs`

**Implementation:**

- [x] Implement deterministic ddmin action deletion, then fault deletion, topology/entity removal,
  scalar reduction, delay/duration/budget reduction, concurrency serialization, and seed
  canonicalization passes.
- [x] Revalidate every candidate, memoize by canonical digest, enforce attempt/event/time budgets,
  and retain only equal `FailureSignature` results.
- [x] Record every attempted transformation and rejection reason in `minimize.jsonl` and write the
  best candidate atomically after each accepted improvement.
- [x] Activate `cargo sim minimize <manifest>` with explicit output, resume, and already-minimal
  behavior.
- [x] Prove one seeded multi-cause fixture loses irrelevant endpoints/actions/faults and strictly
  reduces canonical byte size while retaining the exact signature.

**Failure behavior:** incompatible source, non-failing input, nondeterministic candidate, changed
signature, invalid candidate, budget exhaustion, and artifact I/O are distinct; the best known
valid candidate is retained.

**Validation:** unit tests for each reducer, deterministic attempt order, memoization, budget
termination, idempotent second minimization, and end-to-end CLI reduction/replay.

### Task 6: Add the permanent corpus and campaign engine

**Resources:** new `iroh-sim/src/corpus.rs`; new `iroh-sim/src/campaign.rs`;
new `iroh-sim/corpus/**`; `iroh-sim/src/cli.rs`; `.github/workflows/ci.yml`;
`.github/workflows/simulation-nightly.yml`; new tests

**Implementation:**

- [x] Define strict corpus metadata with stable ID, scenario, seed, failure/success expectation,
  provenance, issue, minimum/maximum schema and simulator compatibility, and review state.
- [x] Activate `cargo sim corpus test` and fail on unenumerated files, duplicates, incompatible
  metadata, missing provenance, changed signature, or replay divergence.
- [x] Implement deterministic seed-range campaign expansion, bounded worker orchestration,
  stable result ordering, fail-fast/continue policy, deduplication by failure signature, and
  per-run artifacts.
- [x] Activate `cargo sim campaign` and machine-readable summaries; never let worker completion
  order affect result order or promoted artifacts.
- [x] Promote the minimized Stage 3 injected failure as the first reviewed corpus entry.
- [x] Run compatible corpus entries and a bounded generated smoke campaign in PR CI; shard larger
  seed ranges in scheduled CI and retain every unique failure artifact.

**Failure behavior:** invalid range, zero jobs, worker panic, run failure, campaign budget,
duplicate signature, corpus incompatibility, and promotion conflict are separately classified.

**Validation:** corpus enumeration/removal guards, sequential/parallel summary equivalence,
campaign repeatability, unique-failure deduplication, and CI-equivalent commands.

### Task 7: Documentation, performance, and Stage 3 exit audit

**Resources:** `docs/testing/simulation.md`; architecture evidence; new scenario authoring,
invariant, minimization, corpus-review, and triage documentation; source-policy baseline

**Implementation:**

- [x] Document canonical schema, builders, generation, capability skips, invariant semantics,
  fairness, failure signatures, minimizer limitations, corpus review, campaign tiers, and triage.
- [x] Add `cargo sim explain` for the Stage 3 artifact subset: causal trace suffix, active/expired
  obligations, resource ledger, action/model state, and replay/minimize commands.
- [x] Measure runner/observer disabled-path overhead and scenario throughput; keep evidence
  non-gating until stable CI distributions exist.
- [x] Classify and refresh every new direct time/spawn/random/filesystem/process boundary.
- [x] Run the requirement-by-requirement Stage 3 audit and all native/wasm/regression/lint gates.

**Validation:** fresh-checkout success and induced-failure walkthroughs, documentation command
tests, full `iroh-runtime`/`iroh-sim`/Iroh regressions, wasm checks, warning-denied Clippy,
boundary-policy contract, CI YAML validation, and the Stage 3 exit fixture.

## Execution handoff

Execute inline using test-driven development. Land Tasks 1–4 before minimization so candidates run
through the same validated runner and failure artifact path. Do not activate corpus promotion until
minimization is signature-stable. Use systematic debugging for production endpoint/fault
integration and verification-before-completion before any Stage 3 completion claim.

## Exit evidence (2026-07-21)

- Canonical v2 builder/file/generator/migration, semantic trigger, invariant, real-QUIC runner,
  failure/replay, minimizer, corpus, campaign, and CLI integration suites pass in `iroh-sim`.
- The seeded multi-cause minimizer fixture removes irrelevant actions, fault rules, endpoints, and
  hosts while retaining the exact normalized signature; a second pass is idempotent.
- The reviewed `stage3-trigger-stall` corpus entry executes with the real runner and matches its
  stored failure signature. Four-worker campaign summaries equal one-worker summaries.
- Native `iroh-runtime`/`iroh-sim` tests and the full Iroh library suite pass (132 passed, one
  ignored upstream flaky test). Native minimal and wasm minimal builds pass.
- Warning-denied all-target/all-feature Clippy, rustfmt, workflow YAML parsing, boundary-checker
  contract, and the reviewed boundary inventory pass.
- The reviewed boundary inventory contains 801 rows with SHA-256
  `a5b844e8be1978be610bd189b7e3d41313a9e659ee9903ba80319f83556787e8`.
