# Coverage-Driven Simulation Testing Implementation Plan

- Status: Approved goal; implementation in progress
- Specification: [`GOAL.md`](../../../GOAL.md)
- Date: 2026-07-26

## Goal and Success Criteria

Implement the complete testing system defined by `GOAL.md`: deterministic change gates, continuous gap-directed simulation exploration, realistic network validation, GitHub-hosted execution, immutable replay evidence, automatic failure issues, and permanent minimized regressions.

Completion is determined only by the acceptance checklist in `GOAL.md`. Intermediate tasks are independently useful but do not redefine completion.

## Scope and Non-Goals

The implementation covers `iroh-sim`, checked JSON policies, simulation shell tooling, GitHub Actions workflows, failure issue automation, corpus promotion contracts, and operations documentation.

It does not replace the custom simulator with Turmoil or MadSim, make broad realistic tests deterministic gates, expose deterministic crypto to production, or attempt a Cartesian product of all network configurations.

## Chosen Approach

Add a pure, typed coverage model beside the existing scenario inventory. A checked policy binds coverage domains to digest-bound swarms and declares individual, pairwise, higher-order, canary, lane, and execution obligations. Every run produces bounded coverage observations from its swarm selection, scenario invariants, safety/liveness declaration, and stable observation transitions. Deterministic ledgers merge those observations and report missing obligations.

The daily soak remains the high-throughput engine. Its existing source-bound build, bounded epochs, failure signatures, minimizer, and non-overlapping ordinal allocation are extended with policy identity, explicit seed leases, and coverage evidence. Scheduled aggregation combines the current run with retained aggregates from the preceding seven days and directs future campaigns toward uncovered obligations.

Pull requests run the permanent corpus, universal deterministic canaries, and additional commit-derived seeds selected through a checked path-to-domain map. Main runs a broader bounded set. Nightly no longer repeats fixed exploratory ranges; it consumes current coverage gaps. Weekly owns realistic parity, platform, scale, and performance evidence.

Only a confirmed deterministic product failure creates or updates a signature-keyed issue. Replay and minimization are bounded prerequisites. Infrastructure, expected resource exhaustion, determinism, and performance classifications use separate typed paths.

## Resolved Decisions

- Coverage IDs are structured typed data, serialized canonically; free-form strings are accepted only after bounded identifier validation.
- Required individual and cross-choice pair obligations expand from the digest-bound swarm. This avoids duplicating swarm choices while keeping the resulting obligation list explicit in reports.
- Higher-order obligations are explicitly listed in policy because exhaustive higher-order expansion is unbounded and low value.
- Cryptographic provider is part of every configuration obligation, so deterministic-test success cannot conceal production-provider gaps.
- Behavioral coverage uses a closed versioned vocabulary derived from stateful `ObservationKind` variants. Unbounded marker fields and payload identities never become bucket IDs.
- Oracle coverage is derived from declared `InvariantName` values. Safety/liveness phase coverage is credited only when the relevant actions are observed as completed.
- Seed leases use checked half-open ranges keyed by coverage-policy digest, workflow run number, lane index, and epoch. Overlap is a typed infrastructure failure.
- Rolling coverage is reconstructed from immutable GitHub Actions aggregate artifacts for completed runs in the preceding seven days. Missing history or API access is reported as infrastructure evidence, not silently treated as zero coverage.
- Pull-request commit-derived seeds are hashes of policy digest, candidate revision, domain, provider, and ordinal. Identical inputs always produce identical seeds.
- Product failures block their originating deterministic gate. Continuous failures block release health, not unrelated pull requests.
- Issue automation uses a hidden stable signature marker and one bounded update per signature per workflow run. It never closes issues automatically until a reviewed corpus entry names the issue and passes the pull-request corpus gate.

## Global Correctness and Operational Constraints

- All schemas reject unknown fields and unsupported versions.
- Identifiers, collection lengths, counters, artifact sizes, retries, API pages, issue updates, subprocesses, workflow time, and concurrency are explicitly bounded.
- Counter arithmetic and seed-range arithmetic use checked operations.
- Coverage state transitions are pure and deterministic; filesystem, clock, GitHub API, and runner effects remain at adapters.
- Shared concurrent coverage accounting is synchronized, and poisoned ownership is an observable infrastructure error.
- Reports are atomically replaced and contain source revision, policy digest, plan digest, seed lease, and schema versions.
- No successful retry may overwrite or suppress a deterministic product failure.
- Existing manifest, scenario, trace, corpus, and replay compatibility rules remain intact unless explicitly versioned.

## Task 1: Checked Coverage Policy and Typed Ledger

**Resources:** `iroh-sim/src/coverage.rs`, `iroh-sim/src/lib.rs`, `iroh-sim/tests/coverage.rs`, `iroh-sim/coverage-policy.json`, `iroh-sim/swarms/*.json`, `iroh-sim/src/swarm.rs`, `iroh-sim/src/observation.rs`, `iroh-sim/src/scenario_model.rs`

**Depends on:** Existing `SwarmSpec`, `SwarmSelection`, `Scenario`, `Observation`, `InvariantName`, and `CryptoMode` types.

**Interfaces and state:** Introduce versioned `CoveragePolicy`, `CoverageDomainPolicy`, `CoverageLanePolicy`, `CoverageObligations`, `CoverageObservation`, `CoverageLedger`, `CoverageReport`, `CoverageGap`, `CoverageBucket`, `CoveragePair`, `BehaviorTransition`, `OracleCoverage`, and typed `CoverageError`. Keep mutation inside a deterministic ledger object; serialize sorted vectors and maps only.

**Implementation:**

1. Write failing tests for strict parsing, canonical domain ordering, unsupported versions, invalid bounds, unknown swarm/choice/option references, provider expansion, individual and pair expansion, explicitly listed higher-order combinations, deterministic merging, counter overflow, state-transition extraction, oracle extraction, and missing-obligation reporting.
2. Implement bounded policy parsing and validation against loaded digest-bound swarms.
3. Implement pure coverage observation extraction and checked ledger accounting.
4. Add the checked initial policy for the six existing domains and both crypto providers. Declare current missing network modes explicitly as named gaps rather than pretending they are covered.
5. Export the public contract through `iroh-sim/src/lib.rs` and run focused formatting, tests, and Clippy.

**Failure and operations:** Malformed policy, unknown references, excess obligations, arithmetic overflow, or observation/policy mismatch fail closed with typed errors. The ledger has no filesystem, clock, random, or network access.

**Validation:** Observe RED then GREEN with `cargo test --manifest-path iroh-sim/Cargo.toml --test coverage`; run `cargo clippy --manifest-path iroh-sim/Cargo.toml --all-targets --all-features -- -D warnings` after the focused suite.

## Task 2: Seed Leases and Per-Epoch Coverage Evidence

**Resources:** `iroh-sim/src/soak.rs`, `iroh-sim/src/cli.rs`, `iroh-sim/tests/soak.rs`, `iroh-sim/tests/cli.rs`, `iroh-sim/soaks/daily.json`, `scripts/run-daily-simulation-soak.sh`, `scripts/tests/check-daily-simulation-soak.sh`

**Depends on:** Task 1.

**Interfaces and state:** Version the soak plan/report schemas. Bind the plan to `coverage-policy.json` by path and BLAKE3 digest. Add a `SeedLease` containing policy digest, plan digest, window, epoch, lane index, start, end-exclusive, and consumed count. Add the deterministic `CoverageReport` to every atomic epoch checkpoint.

**Implementation:**

1. Write failing Rust and shell contract tests for policy digest drift, lease overlap/overflow, provider/domain mismatch, concurrent accounting, checkpoint contents, and malformed coverage evidence.
2. Load and validate all policy-bound swarms before creating artifacts.
3. Observe every successful and failed run. Include configuration, stable transitions, declared/exercised oracles, phase progress, and failure signatures without retaining success traces.
4. Publish policy identity, lease identity, and coverage in each checkpoint and daily lane summary.
5. Update the strict daily plan and all digests atomically.

**Failure and operations:** Policy drift, invalid lease math, tracker lock failure, or report publication failure is infrastructure failure. Coverage tracking is bounded independently from run and artifact budgets.

**Validation:** Focused `soak`, `cli`, and shell contract tests; a short local two-epoch soak proving disjoint leases and merged coverage.

## Task 3: Rolling Coverage Aggregation and Gap Selection

**Resources:** `scripts/aggregate-daily-simulation-soak.sh`, `scripts/collect-simulation-coverage-history.sh`, `scripts/select-simulation-gaps.sh`, `scripts/tests/check-daily-simulation-aggregate.sh`, new shell contract tests, `.github/workflows/simulation-daily-soak.yml`

**Depends on:** Task 2.

**Interfaces and state:** Aggregate schema includes current leases, duplicate/overlap diagnostics, merged configuration/transition/oracle/failure counts, missing obligations with reasons, and rolling-window bounds. Gap selection emits a bounded canonical campaign matrix tied to policy digest.

**Implementation:**

1. Write failing fixtures for overlapping leases, duplicate reports, missing history, malformed policy identity, incomplete coverage, and complete coverage.
2. Merge current lane evidence deterministically and fail closed on lease overlap or policy mismatch.
3. Fetch a bounded number of completed aggregate artifacts from the preceding seven days using read-only GitHub Actions APIs; verify repository, workflow, source, schema, and policy identity before merging.
4. Report every uncovered obligation and a typed reason. Generate the next bounded gap campaign without changing the policy.
5. Upload the rolling ledger and selected gap matrix as retained workflow artifacts and render a concise job summary.

**Failure and operations:** API pagination, downloads, history age, artifact count, bytes, and merge work are bounded. Inaccessible or malformed history is infrastructure evidence. A new policy revision starts a new rolling window rather than merging incompatible data.

**Validation:** Shell contract suite plus a fixture-based seven-day merge; workflow source-contract test validates permissions, bounds, and artifacts.

## Task 4: Deterministic Pull-Request and Main Gates

**Resources:** `iroh-sim/change-impact-policy.json`, `scripts/select-simulation-gate.sh`, new shell contract tests, `.github/workflows/ci.yml`, `iroh-sim/operations-policy.json`, `iroh-sim/src/operations.rs`, `iroh-sim/tests/operations.rs`, `docs/testing/simulation.md`

**Depends on:** Tasks 1 and 2.

**Interfaces and state:** A strict path-to-domain policy maps repository paths to additional simulation domains. The selector consumes base revision, candidate revision, coverage policy digest, lane tier, and bounded ordinals, then emits canonical domain/provider/seed work. An always-run universal canary is independent of impact selection.

**Implementation:**

1. Write failing tests for identical-input stability, path mapping, rename/delete handling, unknown paths, missing base revisions, and global fallback.
2. Add source-controlled impact mappings and deterministic BLAKE3 seed derivation.
3. Refactor the current simulation contract job into corpus/contracts, universal canary, and targeted campaign steps while retaining the 15-minute simulation budget.
4. Add the broader main sample with a 30-minute budget and stable realistic smoke evidence.
5. Document required status-check names and add workflow-contract validation preventing accidental removal or retry masking.

**Failure and operations:** An unavailable diff or unmatched simulator-affecting path selects all domains. Selection cannot silently reduce the universal canary. Product failures and infrastructure failures remain separate job outputs.

**Validation:** Selector fixtures, operations-policy tests, workflow source-contract tests, and local execution of the emitted smallest gate matrix.

## Task 5: Explorer, Nightly, Weekly, and Reality Role Separation

**Resources:** `.github/workflows/simulation-daily-soak.yml`, `.github/workflows/simulation-nightly.yml`, `.github/workflows/simulation-weekly.yml`, `.github/workflows/netsim.yml`, Patchbay workflows, workflow contract scripts, `iroh-sim/operations-policy.json`

**Depends on:** Tasks 3 and 4.

**Interfaces and state:** Daily owns continuous exploration; nightly consumes gap selections and runs determinism/replay audits; weekly owns corpus service checks, realistic parity, cross-platform/scale, and performance correlation. Every job declares time, concurrency, run count, retention, retries, and shutdown behavior.

**Implementation:**

1. Write failing workflow-contract tests that reject repeated fixed exploratory seed ranges and missing bounds.
2. Replace nightly fixed ranges with the latest compatible gap matrix plus bounded fallback canaries.
3. Remove weekly deterministic exploration duplicated by daily; retain parity, platform, scale, performance, and service-contract work.
4. Ensure one shared semantic scenario continuously runs through deterministic and realistic backends and compares capability-overlap results.
5. Update operations policy and workflow summaries to make each lane's blocking role explicit.

**Failure and operations:** Missing gap evidence uses bounded universal fallback and reports degraded coverage. Nondeterministic reality/performance failures cannot be classified as deterministic replay failures.

**Validation:** All workflow contract scripts, action YAML parsing, operations tests, and manually dispatched bounded smoke workflows when repository authority permits.

## Task 6: Confirmed Failure Issues and Regression Promotion

**Resources:** `iroh-sim/src/failure.rs`, `iroh-sim/src/minimize.rs`, `iroh-sim/src/corpus.rs`, `iroh-sim/src/operations.rs`, `scripts/triage-simulation-failures.sh`, `scripts/upsert-simulation-issues.sh`, shell contract tests, `.github/workflows/simulation-daily-soak.yml`, issue templates, `docs/simulation/operations.md`

**Depends on:** Tasks 2 and 3.

**Interfaces and state:** Introduce an operational outcome enum covering product correctness, infrastructure, expected resource exhaustion, determinism, and performance. Triage emits bounded canonical issue records only after exact replay and signature-preserving minimization. Each record contains a stable hidden signature marker, title, labels, source revision, lane, seed lease, replay command, minimized artifact reference, and corpus status.

**Implementation:**

1. Write failing tests for classification, replay mismatch, minimization failure, duplicate signatures, issue search bounds, safe Markdown escaping, create/update behavior, and infrastructure isolation.
2. Run replay once and bounded minimization for each retained unique product signature using the source-bound simulator.
3. Upsert at most one issue per signature per workflow using `issues: write`; never execute artifact-provided commands or interpolate untrusted fields into shell source.
4. Add corpus metadata and gate checks tying a regression to its issue and minimized provenance.
5. Reopen a recurring unresolved signature when no passing reviewed corpus entry exists. Do not auto-close until the corpus entry passes the required gate.

**Failure and operations:** GitHub API calls, pages, issue count, body bytes, retries, and updates are bounded. API failures are infrastructure failures and retain the local issue record artifact for manual recovery.

**Validation:** Pure fixture tests with a fake GitHub API adapter, CLI/shell contracts, corpus tests, and workflow permissions/source checks. A live issue write requires explicit repository execution through the workflow, not a local development command.

## Task 7: Operations, Release Evidence, and Completion Audit

**Resources:** `GOAL.md`, `docs/simulation/operations.md`, `docs/testing/simulation.md`, `docs/testing/determinism-audit.md`, release checklist, all affected tests and workflows

**Depends on:** Tasks 1 through 6.

**Interfaces and state:** Documentation names exact local commands, artifact schemas, lane responsibilities, freshness/severity rules, replay/minimize/issue/corpus states, release blocking, and infrastructure recovery. `GOAL.md` checkboxes are updated only with direct evidence.

**Implementation:**

1. Document the complete operator path from coverage gap or failure through release decision.
2. Add a checked goal-audit script mapping each acceptance criterion to source and executable evidence.
3. Run focused tests first, then simulator formatting, Clippy, complete simulator tests, shell/workflow contract suites, and relevant repository CI checks.
4. Inspect current GitHub workflow runs after push when repository authority permits; fix failures and rerun bounded jobs.
5. Mark only proven acceptance criteria complete and leave any unsupported criterion open with its evidence gap.

**Failure and operations:** Documentation and audits must not claim live GitHub behavior from source inspection alone. External workflow results are required for hosted-infrastructure claims.

**Validation:** Requirement-by-requirement completion matrix, successful local suites, and current hosted workflow evidence for enabled scheduled/gating behavior.

## Execution Method

Execute this plan in the current checkout using the `superpowers:executing-plans`, `superpowers:test-driven-development`, `tigerstyle:tigerstyle-rust`, and `superpowers:verification-before-completion` workflows. Do not delegate unless the user explicitly requests delegation. Preserve unrelated worktree changes and keep `GOAL.md` active until every acceptance criterion is proven.
