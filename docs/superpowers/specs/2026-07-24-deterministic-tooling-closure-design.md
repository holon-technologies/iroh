# Deterministic Tooling Closure Design

## Outcome

Close the seven tooling and deterministic-testing gaps exposed by the production resource canary:

1. exercise production-duration lifecycle deadlines under virtual time;
2. retain recurring realistic kernel-boundary evidence without making pull-request CI host-sensitive;
3. make exact workload conservation and driven-client ownership reusable contracts;
4. retain structured failure state for every canary lane;
5. supplement the line-sensitive lexical boundary inventory with a Rust-syntax-aware stable inventory;
6. add bounded fuzz targets with deterministic regression corpora and fixed CI budgets; and
7. make the determinism audit and operational guide describe one current boundary state.

Success means each gap has an executable regression gate, bounded failure behavior, operator
documentation, and a focused validation command. This work does not raise production limits,
replace the realistic Patchbay/backend layers, make host performance a pull-request gate, or make
production cryptographic entropy deterministic.

## Chosen Approach

### Lifecycle and load contracts

Keep the canary's real production protocols, but extract pure accounting types for offered,
admitted, rejected, and transport-failed outcomes. Construction validates that every count fits a
bounded workload; finalization succeeds only when the counts conserve exactly. Retained relay
clients remain owned by bounded driver tasks until explicit shutdown.

Use Tokio paused time for deadline behavior that does not require kernel progress. Add a
production-horizon relay regression that advances beyond the keepalive interval while the
in-memory client/server session remains continuously driven. Keep the existing short loopback
tests for protocol integration. Resource sampling uses absolute deadlines and receives a
multi-minute virtual-time cadence regression.

### Realistic canary service

Add a scheduled and manually dispatchable workflow for an explicitly labelled, dedicated Linux
x86-64 runner. Preflight remains the authority for CPU, memory, descriptor, storage, and
contamination requirements. The job builds the optimized release canary, runs the exact evidence
profile, always uploads bounded artifacts, and never runs for pull requests. A missing or
undersized dedicated runner is an operational failure, not permission to weaken preflight.

### Failure artifacts

Every lane failure writes a bounded diagnostic object before returning. It includes lane, phase,
error class/message, elapsed/deadline state, the latest resource sample, and lane counters captured
through a watch channel. No peer-provided labels, payloads, keys, or addresses enter the artifact.
Partial reports use the same schema as successful lane diagnostics so automation never receives a
`null` lane without a reason and last-known state.

### Determinism enforcement

Retain the existing `rg` inventory as a broad backstop. Add a small unpublished Rust syntax
checker using `syn` that:

- ignores comments and string literals;
- resolves file-local `use ... as ...` aliases for named effect APIs;
- records the enclosing module/item owner instead of a source line;
- emits stable category, path, owner, API, and same-owner ordinal identities; and
- compares those identities with a reviewed semantic baseline.

The syntax checker is intentionally not a full compiler/HIR lint. The lexical and syntax-aware
checks fail closed together; a future compiler lint can replace the syntax layer without changing
the reviewed classification format.

### Fuzzing

Add an excluded `fuzz/` cargo-fuzz package. Four targets call narrow public, test-only-safe
adapters for DoH extraction, pkarr body validation, relay segmentation arithmetic, and validated
configuration deserialization. Inputs are rejected above named byte limits before allocation or
decode. Seed corpora contain only synthetic public data. Pull-request CI runs deterministic corpus
regressions plus a short fixed-budget smoke; nightly CI runs longer fixed budgets with bounded
artifact retention. Fuzzing supplements deterministic regressions and is never the only test for a
known bug.

### Documentation ownership

The simulation guide is the current-state summary. The audit retains historical discovery only
when explicitly labelled and moves unresolved items into one generated/checkable current-gap
table. Tests reject contradictory active/retired boundary labels.

## Invariants and Bounds

- For every workload, `offered = admitted + rejected + transport_failed`; checked arithmetic is
  mandatory.
- A successful saturation lane reaches its configured high-water and observes the exact expected
  admission rejection count.
- Every spawned driver has an owner, bounded command channel, cancellation path, join deadline,
  and observable failure.
- Sampling follows absolute cadence; collection cost cannot accumulate into the next deadline.
- Diagnostic snapshots have fixed field sets and bounded counter/event collections.
- Fuzz inputs, run time, RSS, corpus size, and artifact retention are explicitly bounded.
- Semantic boundary identities do not change from source-line movement alone.
- Secure production entropy and real OS adapters remain outside byte-exact deterministic replay.

## Failure and Recovery

- Contract violations return typed errors and retain diagnostics.
- A failed canary workflow uploads preflight, partial reports, samples, and manifests before
  failing the job.
- A syntax parse failure is a determinism-check failure; malformed baselines are rejected.
- Fuzz crashes retain the input and target identity; promotion to the checked regression corpus is
  manual and privacy-reviewed.
- CI workflow rollout is additive and can be disabled independently without changing production
  behavior.

## Validation

- Focused RED/GREEN tests for conservation, long-horizon lifecycle, absolute cadence, failure
  snapshots, alias-aware boundary detection, and bounded fuzz adapters.
- Existing canary smoke lanes and deterministic boundary checker contracts.
- `cargo fmt`, strict Clippy for affected crates, affected crate tests, workflow/config validation,
  and documentation link/consistency checks.
- The full production evidence profile is not rerun on an arbitrary shared host; the scheduled
  dedicated-runner workflow owns recurring evidence.
