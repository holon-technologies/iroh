# Declarative Resource-Exhaustion Simulation Design

Status: Implemented and locally verified, 2026-07-25.

## Outcome

Make simulator resource ceilings part of the canonical scenario and replay identity, then add
permanent, replayable expected-failure coverage for timer, socket, connection, stream, relay, and
trace exhaustion.

Success means:

- a scenario declares every simulator-owned runtime ceiling explicitly;
- v2 scenarios migrate one way to the new schema without changing their effective limits;
- each requested resource family has a deterministic CLI run/replay fixture and reviewed corpus
  expectation;
- rejected admission occurs before the corresponding effect, never exceeds its ceiling, and
  cleanup returns every live resource count to zero;
- generation and minimization retain the declared ceilings; and
- the nightly service executes and replays the resource fixtures.

This milestone does not replace the custom simulator with Turmoil or MadSim, alter production
resource defaults, broaden Patchbay parity, or add production-network behavior.

## Schema and Types

Increment `SCENARIO_SCHEMA_VERSION` from 2 to 3. Schema v3 replaces the standalone
`budgets.max_trace_events` field with a required nested `budgets.resources` object represented by
`ScenarioResourceLimits`:

```text
max_scheduled_events
max_trace_events
max_timers
max_sockets
max_connections
max_streams
max_relays
```

The nested type is public, strictly deserialized with unknown-field rejection, validated in one
place, and re-exported by `iroh-sim`. Scheduled-event and trace limits remain nonzero because they
bound the kernel's ability to execute and report a run. Timer, socket, connection, stream, and
relay limits may be zero: zero is a valid fail-closed capacity that deterministically denies the
first admission and is required to exercise sequential resource paths such as stream round trips.

The maximum trace limit remains 10,000,000. Resource limits are counters, not allocation sizes, so
the other fields do not allocate from their declared maximum. Arithmetic and host-size conversions
remain checked at the existing use sites.

`ScenarioBudgets` continues to own cumulative work, time, task, packet, obligation, action, and
payload bounds. Runtime construction maps the new resource object directly into
`KernelConfig.max_scheduled_events`, `KernelConfig.max_trace_events`, and `KernelResourceLimits`;
resource observations report those exact declared values instead of deriving them again.

## Compatibility and Migration

Add private, strict `ScenarioV2` and `ScenarioBudgetsV2` decoding types. The versioned loader maps
v2 documents to v3 with the exact effective policy used before this change:

- scheduled events, timers, and sockets = `max_events`;
- connections and streams = `max_actions`;
- relays = `max(topology.relays.len(), 1)`; and
- trace events = v2 `max_trace_events`.

The loader then normalizes and validates the v3 result. Schema v1 continues through its existing
Stage 2 migrator, whose builder now emits v3. `Scenario::from_json` remains strict-current-schema;
`Scenario::from_versioned_json` is the only migration entry point.

The CLI routes v1 to the legacy Stage 2 harness and v2/v3 through the versioned declarative loader.
New artifacts always store canonical v3 scenarios and use a `declarative-v3` scheduling identity.
Old exact-source artifacts remain replayable with their original source revision; the new code does
not pretend that an old manifest is a new one. A dedicated v2 fixture proves migration equivalence,
while all active fixtures, corpus scenarios, swarm bases, corpus schema ranges, and operations
policy move to v3.

## Runtime and Failure Flow

Relay environment construction moves from `DeterministicScenarioBackend::new` to the beginning of
`ScenarioBackend::prepare`. This keeps capability discovery and configuration validation in the
constructor, but makes relay admission failure a normal `run_detailed` failure with bounded cleanup,
resource snapshots, trace artifacts, and replay support. Relay tokens are acquired atomically
before `RelayEnvironment` construction; partial acquisition drops all tokens before returning.

Add a declarative `sleep { duration_nanos }` action. It constructs an `iroh_runtime::ClockSleep`
from the injected runtime clock and drives it with the deterministic kernel. It emits no component
observation, advances only virtual time, validates a positive duration within the scenario time
budget, and makes timer admission directly testable without depending on incidental endpoint timer
behavior.

`RunnerError` gains a typed clock variant. Failure-signature classification records a stable
resource entity for limit failures:

- ledger limits use the exact `ResourceKind` spelling;
- clock limits distinguish `timer` and `scheduled_event`;
- trace rejection records `trace_buffer`; and
- nested socket bind errors are walked through the standard error source chain and recovered as
  their original `LedgerError` instead of being flattened to endpoint text.

Non-limit endpoint, clock, network, kernel, and trace errors retain their current terminal classes.
No string parsing is used to recover a resource kind.

## Required Failure Scenarios

Add six reviewed corpus entries, each allowing expected failure and carrying an exact typed
`FailureSignature`:

1. `resource-connection-limit`: retain one live connection and reject a second before dial.
2. `resource-stream-limit`: set stream capacity to zero and reject the first round trip before
   opening a QUIC stream.
3. `resource-relay-limit`: declare two valid relays with capacity one and reject preparation before
   constructing either relay environment.
4. `resource-socket-limit`: retain the first endpoint socket and reject the second endpoint bind,
   preserving the nested typed socket ledger error.
5. `resource-timer-limit`: execute `sleep` with timer capacity zero and reject before scheduling a
   timer.
6. `resource-trace-limit`: use a one-event trace capacity and a no-resource action so the next trace
   admission fails without complicating cleanup.

Every scenario is executed twice at the runner level and once through CLI run/replay coverage.
Assertions cover terminal class and resource entity, identical trace/signature evidence, exact
high-water values where a prior admission exists, no post-rejection effect, and an empty final live
ledger. Corpus metadata remains the authoritative exact signature rather than accepting an arbitrary
failure merely because `expected_failure` is allowed.

## Generation, Minimization, and Inventory

The canonical builder emits explicit resource defaults equivalent to v2 behavior. The scenario
generator updates default connection/stream ceilings when it changes the action budget and otherwise
retains the complete resource object. Swarm materialization clones the v3 base scenario, so selected
mutations cannot silently reset ceilings.

Minimizer normalization may continue tightening cumulative action and payload budgets but must not
rewrite `budgets.resources`; signature-based evaluation decides whether a candidate still reproduces
the failure. Regression tests cover both generated round trips and resource-failure minimization.

Add `sleep_actions` to `ScenarioInventory` with a deserialization default for older inventory
metadata. Existing corpus metadata remains readable; new timer coverage is visible explicitly.

## Nightly and Operations

Add a bounded `resource_exhaustion` matrix job to `simulation-nightly.yml`. It runs each checked
corpus scenario with one fixed quoted seed, replays the produced manifest, and uploads artifacts on
success or failure. The workflow contract test checks the job, all six resource names, run/replay,
and artifact retention without weakening the existing five-seed Stage 2 matrix check.

The permanent corpus continues to run in existing main/nightly/weekly jobs. The explicit nightly
matrix exists to retain per-resource replay artifacts rather than relying only on the corpus's
aggregate pass/fail output.

## Validation and Rollback

Implementation follows RED-GREEN-REFACTOR in this order: schema/migration, kernel zero-capacity
semantics, runner actions and typed failures, minimizer/generator, corpus artifacts, then workflow
contract. Focused tests precede the full `iroh-sim` suite.

Final evidence must include formatting, Clippy with warnings denied, full `iroh-sim` tests and docs,
corpus execution, six CLI run/replay pairs, nightly workflow contract, release-readiness source
contract, and `git diff --check`.

Rollback is source-revision rollback: schema v3 artifacts remain bound to the source that created
them, and v2 source documents remain available to the one-way migrator. No reverse v3-to-v2
conversion is provided.

## Resolved Decisions

- Use scenario schema v3, not optional v2 fields or unrecorded CLI flags, because ceilings change
  behavior and therefore belong in replay identity.
- Keep the public scenario schema explicit rather than exposing the internal kernel configuration.
- Allow zero only for simultaneous live-resource ceilings; retain nonzero cumulative execution and
  evidence bounds.
- Add one general-purpose virtual-clock action instead of depending on incidental production timer
  creation.
- Move relay initialization into runner preparation rather than special-casing constructor failures
  in the CLI.
- Use typed source-chain recovery and existing error enums; do not classify resources by display
  text.
- Promote all six requested resource families to reviewed corpus entries and explicit nightly
  replay jobs.

There are no unresolved implementation or authority decisions.

## Implementation Evidence

The implementation uses strict schema v3 with a dedicated strict v2 migration fixture. Six
reviewed `resource-*-limit` corpus entries carry signatures captured from fixed-seed executions.
Runner tests execute every entry twice, CLI tests run and replay every entry, and the nightly
`resource_exhaustion` matrix retains per-resource artifacts for 14 days. Local workflow contracts
verify the matrix definition; hosted execution remains CI evidence rather than local evidence.
