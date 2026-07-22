# Deterministic simulation operations

This runbook turns `iroh-sim` into an owned engineering service. The machine-readable authority is
`iroh-sim/operations-policy.json`; changes to budgets, retention, replay rules, or corpus review
must update that file, its validation tests, workflows, and this document together.

## Service objectives and ownership

The Iroh connectivity and simulation maintainers own deterministic failures, fixture schemas, and
campaign health. A new unique failure must receive an initial classification within 24 hours.
Pull-request, main, and nightly run artifacts are retained for 14 days. Weekly soak, parity, and
performance evidence is retained for 30 days. Exact-source replay is required throughout that
window; cross-version replay is never inferred from matching schema numbers alone.

The service reports four distinct classes:

- product failure: a production invariant or liveness guarantee failed under a valid scenario;
- simulator failure: model, scheduler, replay, artifact, or resource accounting is inconsistent;
- realistic-backend difference: Patchbay/platform semantics differ on a declared common dimension;
- infrastructure failure: a runner, privileged namespace, disk, compiler, or artifact service failed.

Do not convert an infrastructure failure or capability skip into a parity match.

## Fresh-checkout workflow

From the repository root:

```bash
cargo test -p iroh-runtime
cargo test -p iroh-sim
cargo run -p iroh-sim --bin cargo-sim -- corpus test iroh-sim/corpus

run_dir="$(mktemp -d /tmp/iroh-sim-run.XXXXXX)"
cargo run -p iroh-sim --bin cargo-sim -- run \
  iroh-sim/corpus/stage6-rare-ready-order/scenario.json \
  --seed 9b36bee1fa03258374d80340d7ad18d849164bf15abf2ddb859a42e9f131f434 \
  --artifacts "$run_dir"
cargo run -p iroh-sim --bin cargo-sim -- replay "$run_dir/manifest.json"
```

The run prints the only supported replay command. Do not edit a run directory: artifacts are
immutable and indexed. Copy it before exploratory analysis.

## Failure triage

1. Preserve the complete artifact directory and source revision. Run `cargo sim explain` on its
   manifest and record the terminal class, invariant, entities, scheduler snapshot, task graph,
   resource ledger, and first divergence.
2. At the recorded checkout, run `cargo sim replay <manifest>`. A replay mismatch is a simulator or
   source-identity incident before it is evidence of a product failure.
3. For a replaying failure, run `cargo sim minimize <manifest> --output <new-directory>`. Review the
   journal; minimization must preserve the exact normalized failure signature. The original root
   seed remains fixed.
4. Classify the failure using the four service classes above. File an issue for product,
   simulator, or unexplained parity failures. Include no private keys, environment variables, or
   raw external credentials.
5. Promote a minimized, reviewed scenario into `iroh-sim/corpus/<stable-id>/`. Metadata must include
   the seed, exact expectation/signature, provenance, issue, compatibility bounds, reviewed state,
   and exact inventory. `cargo sim corpus test` must pass before merge.

Removing or weakening a corpus entry requires the same review as adding it and an explanation in
the associated issue. A pending entry may remain pending for at most 14 days.

## Cross-backend parity

Backend jobs emit strict `ParityFixture` documents. Generate deterministic evidence and compare it
without packet-timeline coupling:

```bash
parity_dir="$(mktemp -d /tmp/iroh-parity.XXXXXX)"
cargo run -p iroh-sim --bin cargo-sim -- parity export public \
  --seed 7777777777777777777777777777777777777777777777777777777777777777 \
  --source-revision "$(git rev-parse HEAD)" \
  --observed-at-unix-secs "$(date +%s)" \
  --output "$parity_dir/deterministic.json"
cargo run -p iroh-sim --bin cargo-sim -- parity compare \
  "$parity_dir/deterministic.json" \
  iroh-sim/tests/fixtures/patchbay-public.json \
  --output "$parity_dir/comparison.json"
```

Comparison is case-scoped, freshness-checked, and uses only the sorted capability intersection. A
semantic difference exits 66. A declared capability skip remains `skipped` and the strict command
also exits nonzero. The privileged Patchbay workflow first imports the receipt emitted by the
successful test with `cargo sim parity import-patchbay`; a scenario-digest mismatch fails before
semantic comparison. Patchbay,
local-OS, platform, interoperability, and real-router jobs may publish the same envelope, but they
retain their own setup/timeout failure classes.

Realistic backends deliberately do not promise virtual timestamps, packet decision identity, or
kernel scheduling equality. Current checked evidence covers representative Patchbay NAT and
mobility classes plus relay semantic mappings. Double-NAT, multi-relay deployments, diverse home
routers, captive portals, and IPv6 transition networks require additional realistic fixtures before
their simulator results can be treated as predictive.

## Schema and replay migration

Manifest, scenario, trace, failure, corpus, parity, and operations-policy schemas are independent.
When one changes:

1. bump only the affected schema constant;
2. update its golden round-trip and unknown-field rejection tests;
3. keep exact-source replay fail-closed;
4. if old artifacts must migrate, add an explicit one-way converter with source/target versions and
   fixture tests—never reinterpret old JSON in place;
5. update corpus minimum/maximum compatibility and the operations policy;
6. retain the old source checkout or binary for the 30-day compatibility window.

Opaque encrypted packet hashes are the only normalized trace masking currently permitted. Adding a
normalization rule requires a schema review proving it cannot hide a protocol, scheduling, routing,
or invariant difference.

## Campaign and performance operation

PR campaigns are capped at 8 runs, main at 64, nightly at 256, and weekly at 1024 per declared
domain. Workers and crypto lanes may change throughput but not sorted results, seed identity,
fail-fast batch boundaries, or failure deduplication. The weekly workflow shards direct and relay
ready-order soaks under both `deterministic-test` and `production-provider`, records
`crypto-mode.txt`, and retains every per-seed report. Strict swarm materialization is capped at 128
choices and 128 options per choice; PR runs four materializations and nightly runs 256 per shard,
retaining every selection. Checked direct, NAT, discovery, mobility, relay-lifecycle, and
ready-order templates are under `iroh-sim/swarms/`. Compact templates bind workspace-relative
scenarios by BLAKE3; traversal, absolute/host paths, digest drift, and symlink escape fail before
endpoint construction.

The relay-lifecycle template declares an explicit safety-to-liveness transition: relay outage,
matching recovery, and a dependency-ordered connect probe. Validation requires continuous safety
invariants, FIFO/reachable-network fairness, and a connect obligation bounded by both virtual time
and event count. Every run retains this declaration in `swarm-selection.json`.

Criterion measurements isolate environment dispatch, production relay routing, seeded scheduler,
swarm materialization, root-driver, injected-timer, and deterministic/production TLS scenario
overhead. Correlate a regression only on the same runner class, compiler, feature set, command, and
base revision. The 2026-07-21 local ten-sample closure baseline was approximately 6.44 µs for
materialization, 351 ns for a ready root, 935 ns for an injected timer, 1.19 ms for deterministic
TLS scenario setup/handshake, and 1.17 ms for the production-provider equivalent. These are
evidence, not thresholds. Simulator component speed does not replace Iroh endpoint/throughput, Patchbay,
interoperability, or internet-canary measurements. Treat a statistically meaningful regression in
either layer as its own issue; do not tune correctness budgets to conceal it.

## Recurring gates

- PR: boundary policy, runtime/simulator tests, corpus, bounded campaigns, minimal build, Clippy.
- Nightly: 256-seed direct/NAT/discovery/mobility/relay/ready-order swarm shards and component benchmarks.
- Weekly: 1024-seed direct/relay schedule soaks under both crypto lanes, strict parity export/compare, and correlated
  component benchmarks.
- Patchbay: privileged namespace tests, fresh receipt import, and same-revision semantic comparison,
  with infrastructure failures kept separate from deterministic runner failures.

The platform complements existing unit, property, fuzz, Patchbay, cross-platform,
interoperability, benchmark, soak, and production-assertion layers; it does not waive any of them.
