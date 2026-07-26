# Declarative Resource-Exhaustion Simulation Implementation Plan

## Goal and Boundary

Implement the approved schema-v3 resource-exhaustion design in
`docs/superpowers/specs/2026-07-25-iroh-sim-declarative-resource-exhaustion-design.md`.

Success requires typed scenario ceilings, one-way v2 migration, six deterministic resource-limit
failures, exact CLI replay, generator/minimizer preservation, reviewed corpus entries, explicit
nightly coverage, and all Rust/operations checks passing. Production endpoint defaults, Patchbay
behavior, and simulator replacement are out of scope.

The implementation uses Rust 2024/MSRV 1.91, Serde strict schemas, Tokio current-thread tests, the
existing deterministic kernel, and GitHub Actions. Resource admission and failure artifacts remain
bounded, deterministic, and fail-closed. No public field is optional merely to avoid a schema bump.

Resolved decisions are inherited from the approved design: schema v3 with a strict typed resource
object; exact v2-to-v3 derivation; zero permitted only for live-resource ceilings; a declarative
virtual-clock sleep action; relay initialization during runner preparation; typed source-chain
recovery; six corpus entries; and a dedicated nightly replay matrix. There are no blocking product
decisions.

### Task 1: Version the scenario schema and prove migration

**Resources:** `iroh-sim/src/scenario_model.rs`, `iroh-sim/src/lib.rs`,
`iroh-sim/tests/scenario_model.rs`, `iroh-sim/tests/fixtures/schema-v2-ipv4-stream.json`

**Depends on:** Approved design.

**Interfaces and state:** Add public `ScenarioResourceLimits`; embed it as required
`ScenarioBudgets.resources`; set `SCENARIO_SCHEMA_VERSION` to 3. Keep `Scenario::from_json`
strict-current and make `Scenario::from_versioned_json` the only v2 migration entry point.

**Implementation:** First add failing schema tests for strict v3 round-trip, zero live ceilings,
invalid zero scheduled/trace ceilings, unknown resource fields, v2 migration equivalence, and v2
rejection through `from_json`. Add private strict v2 decoder types and conversion. Update the
builder defaults and public re-export.

**Failure and operations:** Migration must derive exactly the former runtime values and reject
malformed/unknown v2 input. No reverse migration.

**Validation:** `cargo test --test scenario_model` from `iroh-sim` after observing the intended RED
failure.

### Task 2: Admit zero live-resource capacities in the kernel

**Resources:** `iroh-sim/src/kernel.rs`, `iroh-sim/tests/kernel.rs`

**Depends on:** Task 1 resource semantics.

**Interfaces and state:** `KernelResourceLimits` accepts zero for timer, socket, connection, stream,
and relay. Kernel cumulative events, scheduled events, tasks, trace events, and virtual time remain
nonzero.

**Implementation:** Add failing tests that zero capacity rejects the first admission with the exact
typed `LedgerError`/`ClockError`, leaves current/high-water at zero, emits no creation trace, and
does not reserve a scheduled event. Remove only the obsolete nonzero-live-limit validation.

**Failure and operations:** No counter may increment on rejection. Existing positive-limit behavior
must remain unchanged.

**Validation:** Focused zero-capacity tests, then `cargo test --test kernel`.

### Task 3: Wire declared limits and replayable runner failures

**Resources:** `iroh-sim/src/runner.rs`, `iroh-sim/src/failure.rs`,
`iroh-sim/src/inventory.rs`, `iroh-sim/tests/runner.rs`, `iroh-sim/tests/failure_replay.rs`

**Depends on:** Tasks 1-2.

**Interfaces and state:** Map `ScenarioResourceLimits` directly into `KernelConfig`; add
`ScenarioAction::Sleep`; add typed clock failure propagation; classify resource entities stably;
move relay admission/construction to `prepare`.

**Implementation:** Add failing runner tests for timer, socket, connection, stream, relay, and trace
limits. Each test runs twice and compares typed signature/trace evidence, checks no post-rejection
effect, and verifies cleanup. Add `sleep_actions` inventory accounting. Recover nested socket
`LedgerError` by walking `std::error::Error::source`, never display text. Refactor the existing
connection/relay boundary tests onto the declarative limit path and remove the internal override if
it is no longer needed.

**Failure and operations:** `run_detailed` must own relay preparation failures and always invoke
shutdown. Primary failures must not be replaced by cleanup unless cleanup independently fails.

**Validation:** Focused runner/failure/inventory tests, then `cargo test --test runner --test
failure_replay`.

### Task 4: Upgrade active scenarios and operational identities to v3

**Resources:** `iroh-sim/tests/fixtures/*.json`, `iroh-sim/corpus/*/scenario.json`,
`iroh-sim/corpus/*/metadata.json`, `iroh-sim/swarms/*.json`, `iroh-sim/src/cli.rs`,
`iroh-sim/operations-policy.json`, `iroh-sim/tests/cli.rs`, `iroh-sim/tests/operations.rs`,
`docs/testing/simulation.md`, `docs/testing/determinism-audit.md`,
`docs/testing/deterministic-simulation-architecture.md`

**Depends on:** Task 3 runtime semantics.

**Interfaces and state:** All checked-in active declarative scenarios become strict v3. CLI v2/v3
input routes through the versioned loader, while v1 retains the legacy harness. New manifests use
`seeded-fair-kernel+root-driver+declarative-v3`.

**Implementation:** Mechanically migrate active JSON with explicit limits equal to old effective
values, update corpus schema ranges and operations policy, then update code/docs/tests that name v2
as current. Keep the dedicated v2 migration fixture unchanged.

**Failure and operations:** Scenario hashes change intentionally with v3. Exact-source old artifacts
remain tied to their source revision; new artifacts contain canonical v3.

**Validation:** Scenario, operations, manifest, swarm, and CLI parsing tests; canonical fixture
round trips; `rg` audit for stale current-schema assumptions.

### Task 5: Preserve limits through generation and minimization

**Resources:** `iroh-sim/src/scenario_model.rs`, `iroh-sim/src/minimize.rs`,
`iroh-sim/src/swarm.rs`, `iroh-sim/tests/scenario_model.rs`, `iroh-sim/tests/minimize.rs`,
`iroh-sim/tests/swarm.rs`

**Depends on:** Task 4 v3 fixtures.

**Interfaces and state:** Generation emits explicit coherent defaults; swarm materialization clones
all limits; minimizer normalization never rewrites `budgets.resources`.

**Implementation:** Add failing preservation tests before adapting generator defaults and any schema
fixtures. Add a resource-failure minimization case that retains the exact resource object while
removing irrelevant behavior.

**Failure and operations:** A minimized candidate that loses the target signature is rejected by the
existing evaluator rather than compensated by changing its ceilings.

**Validation:** `cargo test --test scenario_model --test minimize --test swarm`.

### Task 6: Add reviewed resource corpus and CLI replay evidence

**Resources:** six new `iroh-sim/corpus/resource-*-limit/{scenario.json,metadata.json}` entries,
`iroh-sim/tests/corpus_campaign.rs`, `iroh-sim/tests/cli.rs`

**Depends on:** Tasks 3-5.

**Interfaces and state:** Each entry declares `ExpectedFailure` with the exact generated
`FailureSignature`, reviewed provenance, issue identity, v3 compatibility range, and exact inventory.

**Implementation:** Create scenarios for connection, stream, relay, socket, timer, and trace. Run
each with a fixed seed to capture the actual typed signature, inspect it, and encode it in metadata.
Add a parameterized CLI test that runs and replays all six, and a corpus test asserting their
resource entities are distinct.

**Failure and operations:** Do not hand-invent digests. A corpus mismatch or nonzero live resource
is a hard failure. Generated artifacts stay outside the repository except canonical scenario and
metadata files.

**Validation:** `cargo run --bin cargo-sim -- corpus test corpus`; six explicit `run` then `replay`
pairs; `cargo test --test corpus_campaign --test cli`.

### Task 7: Add bounded nightly resource replay coverage

**Resources:** `.github/workflows/simulation-nightly.yml`,
`scripts/tests/check-simulation-nightly-workflow.sh`,
`scripts/tests/check-v2-release-readiness.sh`

**Depends on:** Task 6 corpus paths.

**Interfaces and state:** A `resource_exhaustion` matrix names all six entries, uses one fixed seed,
runs each expected failure, replays its manifest, and uploads retained artifacts for 14 days.

**Implementation:** Add the failing workflow-contract expectations first, confirm RED, implement the
job without changing the existing five quoted Stage 2 seed entries, then update release-readiness
source assertions.

**Failure and operations:** Matrix jobs are bounded and independent; artifacts upload with
`if: always()` and missing artifacts fail.

**Validation:** `scripts/tests/check-simulation-nightly-workflow.sh` and
`scripts/tests/check-v2-release-readiness.sh`.

### Task 8: Integrated verification and documentation closure

**Resources:** Entire changed diff and commands below.

**Depends on:** Tasks 1-7.

**Interfaces and state:** No unclassified schema, replay, resource, or workflow gap remains within
the approved scope.

**Implementation:** Update the design/audit documentation to record implemented status and the v2
migrator boundary. Inspect the integrated diff for accidental public API or production behavior
changes.

**Failure and operations:** Do not claim hosted workflow execution; only its checked definition and
local contract are evidence. Preserve any unrelated worktree changes.

**Validation:** Run `cargo fmt --all -- --check`, `cargo clippy --all-targets -- -D warnings`,
`RUSTDOCFLAGS='-D warnings' cargo doc --no-deps`, and `cargo test` in `iroh-sim`; run the corpus and
workflow/release scripts; run the relevant root workspace checks for `iroh-runtime`; and finish with
`git diff --check` plus a clean status audit. Use the verification-before-completion workflow before
reporting success.

## Execution

Execute directly in the current workspace with `superpowers:executing-plans`,
`superpowers:test-driven-development`, `tigerstyle:tigerstyle-rust`, and
`superpowers:verification-before-completion`. Tasks are dependency-heavy and mutate the same schema
and fixtures, so parallel subagents are intentionally not used.
