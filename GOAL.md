# Goal: Coverage-Driven Distributed-Network Testing

- Status: Active — hosted gates and simulation services green; runtime history at 5 main / 4 PR
- Defined: 2026-07-26

## Scope

Establish a unified testing strategy for Iroh as a distributed networking library. The strategy must distinguish tests that deterministically gate changes from campaigns that continuously explore network behavior, while retaining realistic network and platform validation for failures the simulator cannot model faithfully.

This goal covers `iroh-sim`, its scenario and swarm definitions, simulation CI workflows, realistic Netsim and Patchbay checks, campaign evidence, failure triage, and regression promotion.

## Goal

Build a coverage-driven testing system that:

1. deterministically blocks changes that violate known safety, liveness, compatibility, or resource invariants;
2. continuously explores new combinations of network topology, impairment, middlebox behavior, lifecycle events, scheduling, resource pressure, and cryptographic provider;
3. reproduces every simulation product failure from immutable evidence;
4. promotes every confirmed product failure into a minimized permanent regression gate;
5. validates simulator conclusions against real operating-system networks and supported platforms; and
6. uses GitHub-hosted infrastructure as the default execution capacity, with all work explicitly bounded.

The primary success measure is meaningful network-mode and state-transition coverage, not the raw number of simulation runs.

## Non-Goals

- Replacing the custom Iroh simulator with Turmoil or MadSim. The existing simulator owns Iroh-specific NAT, discovery, mobility, relay, scheduling, replay, minimization, and parity semantics.
- Running the complete network-mode state space on every pull request.
- Treating performance thresholds or broad realistic-network matrices as deterministic correctness gates.
- Claiming that deterministic simulation replaces Netsim, Patchbay, cross-platform tests, fuzzing, property tests, benchmarks, or production telemetry.
- Making deterministic cryptographic entropy or simulation-only behavior available through ambient production configuration.

## Operating Model

### 1. Pull-request gate

Every pull request must run a bounded deterministic gate containing:

- the complete reviewed regression corpus;
- model, property, replay, resource-bound, and simulation contract tests;
- a small universal canary across every declared simulation domain and cryptographic provider;
- additional scenarios selected by a versioned code-to-domain impact map; and
- commit-derived seeds whose manifest makes reruns of the same revision identical.

The simulation portion should complete within 15 minutes at the 95th percentile over the latest 20 successful runs. A product failure blocks the change. An infrastructure failure is reported separately and must not be disguised as a passing retry.

### 2. Merge/main confidence gate

Candidate merge commits, or the default branch when a merge queue is not used, must run a broader bounded sample over all declared domains and cryptographic providers plus stable Netsim or Patchbay smoke coverage.

This lane should complete within 30 minutes at the 95th percentile over the latest 20 successful runs. Its evidence is a release prerequisite.

### 3. Continuous deterministic explorer

The existing four-times-daily hosted soak becomes the primary exploratory service. It must:

- allocate non-overlapping seed leases across workflow runs, lanes, and epochs;
- build the source-bound simulator once per workflow run and fan it out to bounded hosted runners;
- explore configuration combinations chosen from the coverage policy rather than repeat fixed seed ranges;
- run every scenario that declares disruptive faults through a fault-injection phase followed by an explicit heal-and-recover phase where liveness is expected;
- continue for a bounded period after failures so that it can collect distinct signatures;
- aggregate coverage, failure, replay, and minimization evidence; and
- create or update deduplicated GitHub issues for confirmed product failures.

Continuous exploration does not retroactively fail an unrelated pull request. An unresolved high-severity failure on the candidate revision blocks release.

### 4. Reality, platform, scale, and performance validation

Netsim, Patchbay, supported operating systems, Android, Wine, scale tests, and performance tests remain independent validation lanes. High-level workloads and semantic oracles should be shared with deterministic simulation where backend capabilities overlap.

Stable, short reality checks may gate changes. Broad, nondeterministic, scale, and performance campaigns run on a scheduled or manual basis and contribute release evidence without being classified as deterministic failures.

## Coverage Contract

A versioned machine-readable policy must define the supported values and coverage obligations for at least these dimensions:

- topology and path selection: direct, relay, fallback, and multi-path transitions;
- addressing: IPv4, IPv6, dual-stack behavior, and interface migration;
- NAT and firewall mapping, filtering, expiry, rebinding, and UDP blocking;
- latency, jitter, loss, duplication, reordering, corruption, bandwidth, queueing, blackholes, and partitions;
- discovery freshness, delay, absence, conflict, rotation, and provider disagreement;
- endpoint, interface, connection, and relay lifecycle events;
- scheduling, cancellation, timeout boundaries, backpressure, and ready-order choices;
- bounded sockets, connections, streams, tasks, timers, mappings, packets, queues, and trace storage; and
- deterministic-test and production cryptographic providers.

The policy must distinguish:

- required individual values;
- required pairwise combinations;
- explicitly selected higher-order combinations for known risky interactions;
- permanent canary and regression cases; and
- weighted exploratory combinations for rare behavior.

Each completed campaign must report configuration-bucket coverage, behavioral state-transition coverage, exercised oracle classes, unique failure signatures, and uncovered obligations. Source code coverage may supplement these measures but is not the primary simulator coverage metric.

## Test Oracles

Every applicable scenario must express both classes of correctness explicitly:

- **Safety during faults:** authentication and identity remain valid, delivered data is intact, protocol transitions remain valid, resource accounting stays bounded, and cleanup invariants hold.
- **Bounded liveness after healing:** after the scenario establishes a viable network and stops disruptive faults, connection, delivery, migration, fallback, or shutdown reaches its required terminal state within explicit virtual-time and event-count bounds.

Where supported, scenarios should also use differential or metamorphic checks between cryptographic providers and between deterministic and realistic backends.

## Failure Lifecycle

A simulation failure must follow this state machine:

```text
discovered
  -> replayed exactly
  -> minimized
  -> classified as product, infrastructure, or expected
  -> deduplicated by stable failure signature
  -> tracked in a GitHub issue when it is a product failure
  -> committed to the reviewed corpus when fixed
  -> required by the pull-request gate
```

The run manifest, source revision, scenario, seed, decision trace, simulator version, runtime provider, failure signature, and one-command replay instruction are immutable evidence. Bounds apply to replay attempts, minimization work, retained artifacts, workflow concurrency, and issue updates.

## Acceptance Criteria

This goal is complete when all of the following are true:

- [x] A checked, versioned coverage policy defines the network-mode dimensions, obligations, lane ownership, and execution bounds.
- [x] Pull-request and merge/main gates have documented inputs, deterministic seed selection, runtime budgets, and required status checks.
- [x] The permanent corpus runs in the pull-request gate and every entry replays with its declared expected result.
- [x] The continuous explorer never intentionally reuses an exploratory seed lease for the same policy revision and records lease ownership in aggregate evidence.
- [x] Every declared individual coverage bucket and required pair is exercised within a rolling seven-day window, or the report names the uncovered obligation and reason.
- [x] Applicable campaigns execute separate fault and recovery phases with safety and bounded-liveness oracles.
- [x] Aggregate reports expose configuration, state-transition, oracle, and failure-signature coverage rather than only run totals.
- [x] Confirmed simulation product failures automatically create or update one deduplicated GitHub issue containing replay evidence.
- [x] A fixed failure cannot be closed until a minimized corpus regression passes in the required pull-request gate.
- [x] Infrastructure, expected resource-exhaustion, product-correctness, determinism, and performance outcomes are distinct typed classifications.
- [x] Nightly and weekly workflows no longer repeat exploratory fixed seed ranges already covered by the continuous service; they run gap-directed, parity, platform, scale, or performance work instead.
- [x] At least one shared semantic workload is continuously checked in both the deterministic simulator and a realistic network backend.
- [x] All workflows have explicit time, concurrency, run-count, artifact-retention, retry, and shutdown bounds.
- [x] Operations documentation explains local replay, triage, issue ownership, corpus promotion, release blocking, and recovery from infrastructure failure.

## Evidence

### Confirmed

- The target deterministic architecture and its production boundaries are documented in [`docs/testing/deterministic-simulation-architecture.md`](docs/testing/deterministic-simulation-architecture.md).
- Simulation use, replay, campaigns, and corpus workflows are documented in [`docs/testing/simulation.md`](docs/testing/simulation.md).
- Determinism requirements and known escape audits are documented in [`docs/testing/determinism-audit.md`](docs/testing/determinism-audit.md).
- The hosted continuous soak already runs fourteen domain/provider lanes four times per day in [`.github/workflows/simulation-daily-soak.yml`](.github/workflows/simulation-daily-soak.yml) and [`iroh-sim/soaks/daily.json`](iroh-sim/soaks/daily.json), including dedicated link-impairment exploration under both cryptographic providers.
- Nightly and weekly roles are separated from continuous exploration in [`.github/workflows/simulation-nightly.yml`](.github/workflows/simulation-nightly.yml) and [`.github/workflows/simulation-weekly.yml`](.github/workflows/simulation-weekly.yml).
- Current retention, replay, corpus, and operational bounds are checked through [`iroh-sim/operations-policy.json`](iroh-sim/operations-policy.json) and documented in [`docs/simulation/operations.md`](docs/simulation/operations.md).
- [`.github/workflows/simulation-issue-closure.yml`](.github/workflows/simulation-issue-closure.yml)
  reopens a tracked failure unless typed promotion evidence, the reviewed corpus, and both
  same-revision deterministic checks pass on the default branch.
- [`.github/workflows/release.yml`](.github/workflows/release.yml) refuses to build or publish a
  pinned candidate without same-revision deterministic and Netsim checks, zero open confirmed
  simulation failures, and fresh successful public Patchbay parity evidence.
- The weekly hosted service now measures the documented pull-request and main P95 runtime targets
  over the latest 20 compatible successful executions, with typed insufficient-history and breach
  outcomes.

### Implemented by this goal

- Coverage obligations and seed leases become first-class checked data. Every promised
  network-mode value has bounded typed evidence, and behavioral transition obligations are
  domain/provider-qualified.
- Pull-request gates use permanent regressions plus universal and change-targeted deterministic canaries.
- Continuous campaigns are gap-directed and include an explicit recovery phase.
- Simulation product failures are automatically deduplicated, tracked, and minimized. Reviewed
  promotion carries immutable typed provenance, and premature issue closure is automatically
  reverted.
- Nightly and weekly capacity shifts from repeated seed ranges to coverage gaps and simulator-to-reality validation.

### Verification on 2026-07-26

- `cargo test --manifest-path iroh-sim/Cargo.toml` passed, including schema-v2 coverage, gate,
  corpus, outcome, replay, minimization, soak, and swarm contracts.
- Strict Clippy passed for `iroh-sim`, `iroh-runtime`, and `iroh` with all targets/features.
- Runtime adapter tests, lexical and semantic determinism inventories, workflow YAML parsing, and
  all 22 simulation workflow/collector/triage/issue source contracts passed.
- A release build executed all 24 fallback-selected pull-request runs (the complete 12-lane
  universal canary plus bounded targeted work) and all 12 reviewed corpus entries locally with zero
  product or infrastructure failures.
- Failure-lifecycle fixtures prove exact replay and minimized-scenario hashing, issue upsert/reopen,
  typed corpus promotion, and rejection of closure when the corpus, signature, digest, provenance,
  or either required same-revision check is absent or invalid.
- Release-readiness fixtures prove that missing candidate checks, open product failures, and stale
  parity evidence independently block the release before build or publication.
- Runtime-SLO fixtures prove the 20-sample P95 calculation, rollout behavior with only 19 samples,
  and an exact one-second pull-request breach.
- Retained explorer failures carry an integrity-indexed, versioned operational outcome bound to the
  normalized signature digest; triage fixtures prove that a non-product class cannot create an
  issue and that replay directories are excluded from source-failure discovery.
- Current simulator-revision hosted evidence is green for commit
  `069ae65167d657d29ec4c22dbdf20fb495f19308`:
  [CI run 30220336402](https://github.com/holon-technologies/iroh/actions/runs/30220336402)
  completed all 34 jobs successfully, including both deterministic simulation checks and the main
  Netsim integration suite, after an intermittent Android emulator timeout passed on the failed-job
  rerun; [Wine run 30220336324](https://github.com/holon-technologies/iroh/actions/runs/30220336324)
  also succeeded.
- The GitHub-hosted simulation services have completed successfully on the activated
  coverage-driven implementation: [nightly run
  30218967522](https://github.com/holon-technologies/iroh/actions/runs/30218967522) and [Patchbay run
  30218967570](https://github.com/holon-technologies/iroh/actions/runs/30218967570) succeeded on the
  first merged revision, while [daily run
  30220349905](https://github.com/holon-technologies/iroh/actions/runs/30220349905) and [weekly run
  30220349987](https://github.com/holon-technologies/iroh/actions/runs/30220349987) succeeded on the
  current corrective revision. The first daily and weekly executions exposed a legacy aggregate-
  artifact naming incompatibility and a stale Patchbay fixture; both regressions were repaired and
  protected by tests in [PR #2](https://github.com/holon-technologies/iroh/pull/2).
- Repository ruleset [Required deterministic simulation gates
  19774422](https://github.com/holon-technologies/iroh/rules/19774422) actively targets `main` with
  no bypass actors. It requires up-to-date successful GitHub Actions checks named `Deterministic
  simulation contracts and corpus` and `Deterministic simulation change gate`; GitHub's effective
  branch-rule response contains both checks and reports `main` as protected.

### Verification on 2026-07-27

- [PR #4](https://github.com/holon-technologies/iroh/pull/4) added the bounded link-impairment
  swarm under both cryptographic providers and passed [pull-request CI run
  30237760490](https://github.com/holon-technologies/iroh/actions/runs/30237760490). Its merged
  revision `749221a530bb128c7bea71604d994f26e70f11d6` passed [main CI run
  30238362389](https://github.com/holon-technologies/iroh/actions/runs/30238362389), [Netsim run
  30238362340](https://github.com/holon-technologies/iroh/actions/runs/30238362340), and [Wine run
  30238362192](https://github.com/holon-technologies/iroh/actions/runs/30238362192).
- The expanded fourteen-lane explorer passed [daily run
  30238451926](https://github.com/holon-technologies/iroh/actions/runs/30238451926), and the
  gap-directed service passed [nightly run
  30243621177](https://github.com/holon-technologies/iroh/actions/runs/30243621177) on that same
  merged revision.
- Local verification passed the complete `iroh-sim` test suite, strict all-target/all-feature
  Clippy, formatting, and all six source contracts changed by the impairment campaign.
- The runtime-SLO job in [weekly run
  30248158565](https://github.com/holon-technologies/iroh/actions/runs/30248158565) succeeded and
  retained typed `insufficient_history` evidence reporting five compatible main samples and four
  compatible pull-request samples.

### Remaining external acceptance

- The live runtime-SLO audit has five compatible successful main executions and four compatible
  successful pull-request executions. Twenty successful compatible executions per tier are required
  before the documented P95 targets can be measured rather than reported as
  `insufficient_history`; this evidence must accrue from real change-gate runs.

## Resolved Implementation Decisions

1. The initial behavioral vocabulary is the typed endpoint, connection, interface, address, host
   power, route, port-mapping, discovery-record, relay, path, and resource transitions in
   `iroh-sim::BehaviorTransition`. Dynamic identifiers and payloads are deliberately excluded.
2. `iroh-sim/change-impact-policy.json` is the source-path authority. Unknown, global, and
   unavailable diffs conservatively select all six domains.
3. Main Netsim supplies the realistic confidence check. The hosted Patchbay `public` case is the
   continuously scheduled shared semantic workload; broader Patchbay matrices remain independent.
4. Every unresolved confirmed `product_correctness` outcome on the candidate revision blocks
   release. Main deterministic and Netsim evidence must match the candidate revision; parity
   evidence has a checked maximum age of 744 hours, although its hosted workload is scheduled daily.
5. Replay, minimization, and issue evidence is retained for 30 days. After reviewed promotion, the
   scenario, signature expectation, issue, and provenance live permanently in the source corpus.

## External Rationale

- [FoundationDB simulation and testing](https://apple.github.io/foundationdb/testing.html) describes deterministic whole-system simulation combined with live performance and hardware failure testing.
- [FoundationDB client testing](https://apple.github.io/foundationdb/client-testing.html) describes seeded replay and workloads shared between simulation and real clusters.
- [TigerBeetle simulation testing for liveness](https://tigerbeetle.com/blog/2023-07-06-simulation-testing-for-liveness/) motivates separating fault injection from a healed phase that must regain progress.
- [TigerBeetle on fuzzer blind spots](https://tigerbeetle.com/blog/2025-06-06-fuzzer-blind-spots-meet-jepsen/) demonstrates why workload and oracle coverage matter more than simulation count alone.
