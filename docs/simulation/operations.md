# Deterministic simulation operations

This runbook treats `iroh-sim` as an owned engineering service. The machine-readable authorities
are:

- `iroh-sim/operations-policy.json` for ownership, execution, retry, shutdown, retention, replay,
  and corpus bounds;
- `iroh-sim/coverage-policy.json` for network-mode coverage obligations and lane ownership;
- `iroh-sim/change-impact-policy.json` for source-path-to-domain gate selection; and
- `iroh-sim/soaks/daily.json` for the twelve source-bound continuous lanes and their seed leases.

Changes to those files must update their validation tests, workflows, and this runbook together.
The Iroh connectivity and simulation maintainers own campaign health and must initially classify a
new signature within 24 hours.

## Outcome classes

Automation uses five non-overlapping `OperationalOutcomeClass` values:

- `product_correctness`: a valid scenario violated a production safety or bounded-liveness
  guarantee; only this class is eligible for automatic issue creation;
- `infrastructure`: setup, checkout, compilation, runner, artifact, GitHub API, malformed evidence,
  replay mismatch, or minimization execution failed;
- `expected_resource_exhaustion`: a declared finite resource ceiling was reached with the expected
  typed signature and cleanup behavior;
- `determinism`: repeated execution or cross-provider comparison disagreed with its declared raw or
  semantic replay contract; and
- `performance`: a comparable benchmark regressed; performance is never silently converted into a
  deterministic correctness result.

The daily aggregate's `simulation_failure` is a discovery state, not permission to open an issue.
Each retained soak failure carries a versioned `operational-outcome.json` inside the immutable
failure-artifact index. Triage requires its class and evidence to be `product_correctness` and the
exact normalized signature digest before replay or minimization can produce an issue record. It
then confirms the classification only after immutable-artifact validation and exact replay
preserve that signature. Missing, unindexed, invalid, or non-product typed campaign evidence is
infrastructure even when a subprocess happened to return the simulator's general failure exit
code.

## Execution lanes

| Lane | Purpose | Deterministic work | Bound and evidence |
| --- | --- | --- | --- |
| Pull request / merge queue | Block known regressions and likely change impacts | Full reviewed corpus, all contract/model/property tests, 12 universal domain/provider canaries, then commit-derived targeted work | Required checks `Deterministic simulation contracts and corpus` and `Deterministic simulation change gate`; at most 24 selected runs and 15 minutes |
| Main | Broader candidate confidence | The same universal canary plus four targeted seeds per impacted lane, with all-domain fallback when the diff is unavailable or global | At most 64 selected runs and 30 minutes; `netsim-CI / netsim-release` supplies realistic main evidence |
| Continuous | Discover new network behavior | Twelve domain/provider lanes, eight fresh bounded epochs per lane, coverage and signature aggregation | Four scheduled windows per day; one queued workflow at a time; each lane has 240 simulation minutes, at most 83,328 runs, 16 retained failures, and 256 MiB |
| Nightly | Spend capacity on current gaps and permanent audits | Latest compatible gap-directed lanes, or the 12 universal canaries when no fresh evidence exists; fixed replay and expected-resource audits remain permanent regression checks | At most 64 selected runs, 30-minute gap job, 14-day artifacts; no duplicate fixed exploratory seed ranges |
| Weekly | Service, parity, and performance evidence | Corpus/replay service audit, canonical semantic parity, and correlated component benchmarks | 20-minute service job, 60-minute performance job, 30-day artifacts; no deterministic seed-range explorer |
| Reality | Validate model limits | Daily hosted Patchbay public parity and main Netsim workloads | Patchbay 15 minutes/7 days; Netsim at most 64 cases, 6 workers, 45 minutes, and 3-day artifacts; backend failures remain infrastructure evidence |

GitHub Actions does not automatically retry these jobs (`maximum_retry_attempts` is zero). Every job
has a timeout, timeout is a terminal shutdown condition, and source scripts have finite loop/run
bounds. Concurrency groups serialize recurring services without cancelling evidence-bearing runs;
PR CI cancels superseded revisions. Artifact upload occurs before the final typed status is
propagated. A human may manually dispatch a new run after diagnosing infrastructure, but that run
does not overwrite or reinterpret the failed attempt.

The weekly runtime-SLO audit queries at most 40 successful CI candidates for each of pull-request
and main events, then inspects at most 100 jobs per run. It selects the latest 20 runs containing
both current deterministic simulation jobs and computes nearest-rank P95 over their combined wall
interval. Pull requests must remain at or below 900 seconds and main at or below 1,800 seconds. A
measured breach fails the weekly job; fewer than 20 post-rollout compatible samples publishes
`insufficient_history` without inventing a percentile. Malformed or failed GitHub API evidence is
an infrastructure failure. The report is retained for 30 days before status propagation.

The check names above are the intended branch-protection inputs. Repository administrators must
configure them as required checks; source-controlled workflow names cannot prove the external
branch-rule setting.

## Coverage and seed leases

Coverage is measured from semantic configuration buckets, required cross-choice pairs, selected
higher-order interactions, behavioral state transitions, safety/liveness/cleanup/model oracles,
and normalized failure signatures. Source line coverage is supplemental.

The daily workflow derives a `SeedLease` from coverage-policy digest, workflow run number, lane,
epoch, and half-open ordinal range. Aggregation rejects overlap within the run. The rolling
seven-day merger rejects duplicate run IDs and overlapping compatible leases across runs. A policy
digest change starts a new window; well-formed reports for another policy and legacy reports that
predate policy provenance are skipped, while malformed current-policy evidence is infrastructure.

Coverage-policy schema v2 also enumerates every promised addressing, topology, middlebox,
impairment, discovery, lifecycle, scheduling, resource, and cryptography value. Each value has
bounded typed evidence identifying its swarm option, domain-qualified behavior transition,
provider, permanent case, or known gap. A known gap must appear exactly once. Transition evidence
is provider-qualified, so one provider cannot accidentally satisfy another provider's obligation.

`rolling-coverage.json` reports every unmet individual, pairwise, higher-order, transition, oracle,
and phase obligation with a typed reason. `gap-selection.json` maps those gaps back to at most twelve lanes.
Nightly uses the latest compatible selection no older than 48 hours; absent evidence deliberately
falls back to the universal canary, while GitHub API or malformed-artifact failures fail the job.

The relay lifecycle swarm declares the currently applicable disruptive phase contract: continuous
safety during relay outage, an explicit matching recovery, then a dependency-ordered connection
probe bounded by virtual time and event count. Other swarms report configuration and transition
coverage without pretending to have a fault/recovery phase they do not declare.

## Local gate and replay

Build once and derive exactly the gate selection CI would use:

```bash
cargo build --release --manifest-path iroh-sim/Cargo.toml --bin cargo-sim
base_revision="$(git rev-parse HEAD^)"
candidate_revision="$(git rev-parse HEAD)"
gate_root="$(mktemp -d /tmp/iroh-sim-gate.XXXXXX)"

scripts/select-simulation-gate.sh \
  --base-revision "$base_revision" \
  --candidate-revision "$candidate_revision" \
  --tier pull-request \
  --impact-policy iroh-sim/change-impact-policy.json \
  --coverage-policy iroh-sim/coverage-policy.json \
  --sim-bin iroh-sim/target/release/cargo-sim \
  --output "$gate_root/selection.json"

iroh-sim/target/release/cargo-sim corpus test iroh-sim/corpus
scripts/run-simulation-gate.sh \
  --selection "$gate_root/selection.json" \
  --sim-bin iroh-sim/target/release/cargo-sim \
  --artifacts "$gate_root/artifacts" \
  --jobs 2
```

The selector reads forward and reverse NUL-delimited Git diffs so renames and deletes are included.
Documentation-only paths are ignored; unknown, global, or unavailable diffs select every domain.
BLAKE3 domain separation binds every seed to candidate revision, coverage and impact policy,
domain/provider lane, work kind, and ordinal. Rerunning the same selection is identical.

For one immutable artifact:

```bash
cargo run --manifest-path iroh-sim/Cargo.toml --bin cargo-sim -- \
  explain /tmp/iroh-sim-failure/manifest.json
cargo run --manifest-path iroh-sim/Cargo.toml --bin cargo-sim -- \
  replay /tmp/iroh-sim-failure/manifest.json
cargo run --manifest-path iroh-sim/Cargo.toml --bin cargo-sim -- \
  minimize /tmp/iroh-sim-failure/manifest.json \
  --output /tmp/iroh-sim-minimized --max-attempts 512
```

Never edit the original artifact directory. Replay requires its exact source identity, simulator,
schemas, scenario digest, Cargo lockfile, feature/configuration identity, provider lane, budgets,
and comparison mode.

## Automated failure lifecycle

The daily aggregate performs this bounded sequence after all lanes finish:

1. Discover at most 16 distinct retained signatures. Signatures beyond the retention bound remain
   counted in aggregate evidence.
2. Require an indexed, versioned `operational-outcome.json` whose `product_correctness` evidence is
   the failure-signature digest, validate the complete bundle with `cargo sim explain`, then invoke
   the source-SHA-bound binary directly. Artifact-provided shell scripts are evidence only and are
   never executed by hosted triage.
3. Replay once and require the exact normalized `failure-signature.json`. Disappearance, changed
   signature, invalid evidence, or a replay execution error is infrastructure/determinism triage,
   not a confirmed product failure.
4. Minimize with at most 512 candidates, require `best.scenario.json`, and record its SHA-256.
5. Emit one bounded issue record per confirmed signature. `upsert-simulation-issues.sh` performs
   one signature-scoped search per record, examines fewer than 100 results, and creates, updates, or
   reopens exactly one issue carrying
   `<!-- iroh-sim-signature:<digest> -->`. Duplicate markers or GitHub API failures are
   infrastructure failures. A search that reaches its 100-result limit is treated as possibly
   truncated and fails closed. The bot never closes issues.
6. A maintainer reviews the minimized case, adds it with its issue URL to
   `iroh-sim/corpus/<stable-id>/`, and opens a fix. Corpus schema v2 distinguishes historical fixture
   references from GitHub issue URLs. A GitHub-linked entry additionally requires the normalized
   signature, minimized-scenario SHA-256, discovery revision and workflow run, exact-replay state,
   and signature-preserving minimization state.
7. Closing a tracked simulation issue invokes `Simulation Issue Closure Guard` on the protected
   default branch. It requires exactly one reviewed corpus entry linked to the issue and signature,
   verifies the minimized scenario digest, executes the complete corpus, and requires successful
   same-revision `Deterministic simulation contracts and corpus` and `Deterministic simulation
   change gate` checks from GitHub Actions. Missing, duplicate, stale, or unsuccessful evidence
   reopens the issue. The promoted expectation must not preserve the original normalized product
   failure, and the corpus bytes must match the SHA-256 recorded in the issue. A recurrence also
   reopens the same signature issue.

Run the two hosted automation stages locally against downloaded evidence with:

```bash
triage_root="$(mktemp -d /tmp/iroh-sim-triage.XXXXXX)"
scripts/triage-simulation-failures.sh \
  --artifacts /tmp/downloaded-lanes \
  --aggregate /tmp/downloaded-aggregate/daily-soak-aggregate.json \
  --sim-bin iroh-sim/target/release/cargo-sim \
  --source-revision "$(git rev-parse HEAD)" \
  --workflow-run-id 123456 \
  --repository OWNER/REPO \
  --output "$triage_root"

GH_TOKEN=... scripts/upsert-simulation-issues.sh \
  --records "$triage_root/issue-records" \
  --repository OWNER/REPO \
  --output "$triage_root/issue-upsert-summary.json"
```

The second command mutates GitHub issues; inspect the records before running it outside CI.

## Infrastructure recovery and release blocking

For infrastructure failure, preserve the failed run and diagnose checkout/source identity,
artifact availability and size, runner disk, compilation, GitHub API response, and workflow
permissions. Retry only as a separate attempt after the cause is understood. Do not copy successful
evidence from another source revision, extend a lease, or relabel the result as product success.

Pull-request product failures block immediately. The `Release candidate` workflow runs
`check-simulation-release-readiness.sh` before starting any build or package job. For the exact
pinned release revision it requires successful GitHub Actions checks named `Deterministic
simulation contracts and corpus`, `Deterministic simulation change gate`, and `netsim-release /
Netsim`. It also requires zero open simulation issues carrying a normalized failure marker and one
successful public Patchbay parity run no older than 744 hours. Queries are bounded to 100 latest
check runs, 100 issue results, and eight parity runs; truncated, duplicate, malformed, missing, or
API-failed evidence is infrastructure failure rather than release approval. The typed report is
uploaded before its status is propagated.

Performance and broad realistic results remain separately reviewed release evidence, not
deterministic correctness failures.

## Cross-backend parity

Patchbay jobs emit strict `ParityFixture` documents and compare only their declared capability
intersection with a same-revision deterministic fixture:

```bash
parity_root="$(mktemp -d /tmp/iroh-parity.XXXXXX)"
cargo run --manifest-path iroh-sim/Cargo.toml --bin cargo-sim -- parity export public \
  --seed 7777777777777777777777777777777777777777777777777777777777777777 \
  --source-revision "$(git rev-parse HEAD)" \
  --observed-at-unix-secs "$(date +%s)" \
  --output "$parity_root/deterministic.json"
cargo run --manifest-path iroh-sim/Cargo.toml --bin cargo-sim -- parity compare \
  "$parity_root/deterministic.json" \
  iroh-sim/tests/fixtures/patchbay-public.json \
  --output "$parity_root/comparison.json"
```

A capability skip remains a skip and strict comparison exits nonzero. Realistic backends do not
promise virtual timestamps, packet-decision identity, or kernel scheduling equality. Netsim,
Patchbay, supported platforms, Android, Wine, interoperability, scale, fuzz, and production
telemetry remain necessary because the deterministic model cannot validate every operating-system,
router, or internet behavior.

## Schema migration

Manifest, scenario, trace, failure, coverage, gate-selection, corpus, parity, and operations-policy
schemas are independent. Bump only the changed schema, keep unknown-field rejection and
exact-source replay fail-closed, add fixture tests, and use an explicit one-way converter when an
old artifact must migrate. Never reinterpret old JSON in place. Preserve the source checkout or
binary for the 30-day replay compatibility window.
