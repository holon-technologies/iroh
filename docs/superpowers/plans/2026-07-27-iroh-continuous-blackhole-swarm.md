# Continuous Blackhole Swarm Implementation Plan

## Boundary

- **User-visible goal:** Continuously explore bounded silent link blackholes in both simulation
  cryptographic-provider lanes, with an explicit fault phase, explicit healing, and bounded
  post-heal liveness evidence.
- **Success criteria:** The checked impairment swarm independently selects brief and sustained
  blackhole durations; a production QUIC datagram is observably dropped during each partition and
  the same connection carries the original 64 KiB workload after healing; every materialized option
  combination executes successfully; the coverage policy credits the blackhole bucket and removes
  its named gap; daily soak digests remain source-bound; documentation and `GOAL.md` evidence match
  the checked behavior.
- **Scope:** `iroh-sim` scenario and swarm schemas, production scenario backend, impairment swarm
  fixture, coverage policy, daily soak identity, affected source-contract tests,
  operations/testing documentation, and goal evidence.
- **Non-goals:** Jitter, explicit firewall rejection, production configuration, new fault-rule
  timing semantics, concurrent action scheduling, new network backends, retries, or broader
  lane-count changes.

## Chosen approach

Add a `SleepDurationNanos` variant to the existing closed `SwarmMutation` enum. It can only target
an existing `ScenarioAction::Sleep`, must be positive, and must not exceed the scenario's declared
maximum virtual time. The impairment base scenario will use dependency-ordered `Partition`,
one-way production `SendDatagram`, `Sleep`, `AssertNoDatagram`, `Heal`, and recovered application
actions. The duration choice varies the bounded interval between the partition and absence
assertion; the existing network partition is the simulator's silent packet blackhole, so no
duplicate fault-window mechanism is introduced.

The base also declares `SafetyLivenessPhases`, FIFO and reachable-network fairness, safety
invariants, and a deadline/event-bounded `ReachableConnectLiveness` invariant. A one-way datagram
send returns without waiting for delivery, the deterministic sleep drives the packet through the
partition, and a 10 ms deterministic receive window fails if the datagram arrives. After heal,
the original connection transfers 64 KiB to preserve the existing impairment workload, then a
separate connection and stream satisfy the declared recovery probe. The runner remains serial;
completion waits for every action and supervised cleanup enforces empty resources.

## Resolved decisions and constraints

- Preserve swarm schema version 1 because the tagged enum remains strictly parsed and the new
  variant is backward compatible for existing documents.
- Preserve scenario schema version 3 because `SendDatagram` and `AssertNoDatagram` are additive
  tagged action variants; existing canonical scenarios remain byte-for-byte compatible.
- Use explicit nanosecond field names, consistent with existing swarm mutations and scenario wire
  types; do not introduce a second duration abstraction only for this schema field.
- Use two sorted weighted options: `brief` at 5 ms with weight 3 and `sustained` at 250 ms with
  weight 1. Both are far below the 60-second virtual-time ceiling and the rare case remains
  deliberately weighted.
- Keep the existing fourteen hosted lanes; the two impairment provider lanes automatically consume
  the expanded source-bound swarm.
- Retain the existing 100,000-event, 10,000-packet, 1,024-task, 64-action, and 60-second bounds. No
  resource ceiling is expanded.
- Invalid JSON or mutation targets fail with the existing typed `SwarmError` classes before backend
  construction. No unsafe code, ambient time, ambient randomness, retry, or detached task is added.
- `SendDatagram` validates its connection and payload against existing scenario bounds.
  `AssertNoDatagram` validates its connection and positive bounded duration, races the production
  server receive future against the injected deterministic clock, succeeds only when the full
  10 ms observation window elapses, and treats delivery or connection error as a typed application
  failure. The window exceeds the fixture's 1 ms link latency plus its maximum 5 ms reorder delay.
- Rollback is one isolated commit: restore the fixture/policy/digests/docs and remove the mutation
  variant and its tests.

## Assumptions and validation

- `Partition` is a silent directional drop between the declared hosts and `Heal` restores it. The
  checked run must contain `dropped:partition`; replacing the partition with a heal must make the
  absence assertion fail, proving that the coverage does not pass without the fault.
- The action executor awaits each backend action before selecting the next one. Therefore the
  probe is a nonblocking one-way datagram followed by a bounded virtual-time hold and bounded
  receive-absence window. No background action or detached task is needed. The exhaustive swarm
  test must prove successful completion and empty-resource invariants; the fail-open regression
  covers 64 independent deterministic seeds with guaranteed reordering enabled.
- Current source-contract scripts discover digest drift. The daily soak and coverage-policy hashes
  will be recomputed with `b3sum` only after the canonical JSON changes are final.

## Task 1: Add the bounded sleep-duration mutation with RED-GREEN evidence

**Resources:** `iroh-sim/src/swarm.rs`, `iroh-sim/tests/swarm.rs`, `SwarmMutation`,
`validate_mutation`, `apply_mutation`
**Depends on:** Approved design
**Interfaces and state:** `SleepDurationNanos { action: String, duration_nanos: u64 }` transforms
only a declared `ScenarioAction::Sleep`; zero, over-budget, dangling, and wrong-action targets are
invalid external input.
**Implementation:** First add a focused test that materializes a valid sleep duration and rejects
all invalid target/bound cases. Run it and observe failure for the missing behavior. Add the enum
variant, validation, and deterministic application using a precise internal invariant assertion.
Do not alter clocks or runner execution.
**Failure and operations:** Validation must fail before materialization or backend construction;
the mutation cannot expand any scenario budget.
**Validation:** `cargo test --manifest-path iroh-sim/Cargo.toml --test swarm
sleep_duration_mutation_is_bounded_and_targets_sleep_actions -- --exact` must fail before and pass
after implementation.

## Task 2: Make blackhole fault/recovery behavior executable in the checked swarm

**Resources:** `iroh-sim/src/scenario_model.rs`, `iroh-sim/src/runner.rs`,
`iroh-sim/swarms/link-impairment.json`, `iroh-sim/tests/swarm.rs`, `ScenarioAction`,
`SafetyLivenessPhases`, production `ScenarioRunner`
**Depends on:** Task 1
**Interfaces and state:** The action graph transitions from connected, to partitioned, through a
one-way datagram send and bounded hold, to asserted nondelivery, healed same-connection delivery,
then a bounded recovered connection and delivery. The selected duration is retained in
`swarm-selection.json` and the materialized scenario.
**Implementation:** First add a focused system contract asserting the action identities,
dependencies, 64 KiB same-connection recovery, exact partition-drop trace, and failure when the
partition is replaced by a heal; observe it fail because the new actions are absent. Add the two
strict action variants, scenario validation, reference-model rules, backend execution, and action
names. Replace the base action graph while preserving the sorted weighted duration, bandwidth,
duplication, queueing, and reordering choices.
**Failure and operations:** Both duration options and all cross-choice combinations must terminate
as `success`; delivery during the blackhole window is a typed run failure; blackhole recovery may
not be classified as expected failure or hidden by retry.
**Validation:** Run the focused behavioral contract, including its negative control, then
`cargo test --manifest-path iroh-sim/Cargo.toml --test swarm
every_checked_domain_option_executes_to_success -- --exact` to execute every combination through
production QUIC.

## Task 3: Promote blackhole coverage and refresh immutable identities

**Resources:** `iroh-sim/coverage-policy.json`, `iroh-sim/soaks/daily.json`,
`iroh-sim/tests/coverage.rs`, `iroh-sim/tests/soak.rs`, affected scripts under `scripts/tests/`
**Depends on:** Task 2 fixture is final
**Interfaces and state:** The `impairment/blackhole` bucket changes from `known_gap` to `continuous`
with evidence bound to `blackhole-duration/sustained`; the higher-order impairment obligation adds
that selection; the obsolete `impairment-blackhole` gap is removed. Daily plan hashes bind the new
policy and swarm bytes.
**Implementation:** Update the policy, compute the canonical file BLAKE3 digests, update both
impairment lane swarm digests and the daily policy digest, and adjust only source contracts whose
authoritative expectations changed.
**Failure and operations:** Any stale digest, missing option, uncovered provider qualification, or
noncanonical obligation must fail closed. Hosted lane counts and execution ceilings remain unchanged.

**Validation:** Run the focused coverage, soak, CLI, daily-workflow, aggregate, and coverage-history
contracts changed by the identities.

## Task 4: Update durable operations and goal evidence

**Resources:** `docs/testing/simulation.md`, `docs/simulation/operations.md`, `GOAL.md`, and any
directly affected determinism/source-boundary inventory
**Depends on:** Tasks 1-3 are green
**Interfaces and state:** Documentation names the explicit partition/heal phase, the bounded
duration choices, both cryptographic providers, current runtime-history snapshot, and unchanged
hosted bounds.
**Implementation:** Update only claims proven by executable behavior and hosted evidence. Keep
remaining known gaps and the 20/20 runtime-history requirement explicit.
**Failure and operations:** Do not claim `GOAL.md` complete; this increment advances coverage and
one authentic PR/main runtime sample only after hosted gates succeed.
**Validation:** `git diff --check`, relevant source-contract scripts, and direct inspection of every
changed evidence claim.

## Task 5: Completion-grade verification and protected integration

**Resources:** Complete branch diff, `iroh-sim` crate, changed shell/YAML/JSON contracts, GitHub PR
and required checks
**Depends on:** Tasks 1-4
**Interfaces and state:** The final commit is reviewable, reproducible, and source-bound; no
untracked artifacts or weakened lint/test policies remain.
**Implementation:** Run formatting, strict all-target/all-feature Clippy, the complete `iroh-sim`
suite, all changed source contracts, and inspect the final diff. Commit, push, open a protected PR,
wait for both required deterministic checks and the full CI workflow, merge, then refresh the live
runtime-SLO audit.
**Failure and operations:** Diagnose any unexplained failure before changing behavior. Do not merge
with a product, determinism, or required-gate failure.
**Validation:** Successful local commands, green hosted PR/main CI evidence, green realistic
network evidence, clean synchronized `main`, and a fresh typed runtime-SLO report.

## Execution brief

Execute directly with `superpowers:executing-plans`, `superpowers:test-driven-development`,
`tigerstyle:tigerstyle-rust`, `superpowers:systematic-debugging` for any unexpected failure, and
`superpowers:verification-before-completion` before integration and handoff. The tasks share one
closed mutation enum and one source-bound fixture, so independent subagent ownership would create
conflicting mutable state rather than useful parallelism.
