# Iroh TigerStyle Exit Audit

**Date:** 2026-07-24
**Scope:** the Rust workspace resource-hardening changes based on
`2026-07-22-iroh-tigerstyle-hardening.md`,
`2026-07-22-iroh-tigerstyle-remediation.md`,
`2026-07-23-iroh-production-task-bounds-design.md`, and
`2026-07-24-iroh-fallible-public-construction-design.md`.

## Scope

This audit covers production task, connection, actor, queue, input, arithmetic, shutdown,
determinism, unsafe, and validation boundaries in `iroh`, `iroh-runtime`, `iroh-base`,
`iroh-dns`, `iroh-dns-server`, `iroh-relay`, `iroh-sim`, and the vendored Noq patch.

## Goals

- Confirm that remotely influenced work has enforceable finite bounds.
- Confirm that invalid caller or network input returns typed errors rather than relying on
  production panics.
- Confirm that asynchronous work has ownership, cancellation, failure observation, and bounded
  shutdown behavior.
- Confirm that arithmetic, determinism, unsafe, and lint policies are mechanically enforced.
- Record repeatable verification evidence and residual operational risk.

## Non-Goals

- This audit does not replace Android emulator execution or internet-canary testing.
- It does not claim source compatibility for the explicitly approved fallible-constructor changes.

## Result

**Raw score: 97/100 — Exemplary.**

No TigerStyle safety gate applies. There are no unresolved Critical or High findings in the
audited scope.

| Category | Score | Evidence |
| --- | ---: | --- |
| Illegal states and transitions | 15/15 | `EndpointLimits` uses nonzero capacities and validates aggregate task headroom before construction (`iroh/src/endpoint/limits.rs:22`, `iroh/src/endpoint/limits.rs:74`). Endpoint addresses have bounded fallible construction and untrusted deserialization revalidates the complete value (`iroh-base/src/endpoint_addr.rs:145`, `iroh-base/src/endpoint_addr.rs:175`, `iroh-base/src/endpoint_addr.rs:272`). |
| Invariants, errors, and panic boundaries | 9/10 | Resource saturation and invalid public construction have typed errors (`iroh-runtime/src/task.rs:584`, `iroh/src/socket/remote_map.rs:177`, `iroh-relay/src/quic.rs:499`). One point is deducted because Android system-DNS fallback still depends on catching an upstream panic and cannot recover under `panic = "abort"` (`iroh-dns/src/android.rs:10`, `iroh-dns/src/dns.rs:283`). |
| Bounded work and resources | 15/15 | Runtime tasks, endpoint connections, remote actors, active relays, QAD connections, DNS records, ACME/config files, and Noq event items/bytes have explicit finite ceilings. Representative construction boundaries are `iroh-runtime/src/task.rs:30`, `iroh/src/endpoint/limits.rs:22`, `iroh-dns/src/dns.rs:44`, and `vendor/noq-1.1.0/src/event_queue.rs:28`. Private Noq unbounded senders are guarded by owned item/byte/control permits before enqueue; tests prove exact-limit acceptance, first-over rejection, and recovery. |
| Arithmetic and conversions | 10/10 | Workspace Clippy denies truncating, wrapping, and sign-loss casts (`Cargo.toml:55`). Aggregate task capacity and admission counters use checked arithmetic (`iroh/src/endpoint/limits.rs:78`, `iroh/src/endpoint/limits.rs:174`); wire and queue conversions are fallible (`vendor/noq-1.1.0/src/event_queue.rs:218`, `vendor/noq-1.1.0/src/event_queue.rs:329`). |
| Determinism and effect isolation | 10/10 | Clock, entropy, scheduling, external-state, spawn, and unordered-collection boundaries are inventoried in `docs/testing/determinism-audit.md` and mechanically checked by `scripts/check-determinism-boundaries.sh`. Runtime and simulator tests prove seeded replay and byte-identical normalized traces. |
| Structured concurrency | 10/10 | Runtime groups reject before polling at capacity, conserve permits through completion and panic, and observe task outcomes (`iroh-runtime/src/task.rs:359`, `iroh-runtime/tests/task.rs:49`, `iroh-runtime/tests/task.rs:179`). DNS, relay, endpoint, and Noq supervisors own cancellation and join paths; shutdown tests pass under saturation. |
| Unsafe discipline | 10/10 | Workspace policy denies unsafe code (`Cargo.toml:37`); safe crate roots forbid it. The only project unsafe boundary is the Android JNI handoff, isolated behind a module allowance with a public caller contract and an adjacent safety proof (`iroh-dns/src/lib.rs:9`, `iroh-dns/src/android.rs:80`, `iroh-dns/src/android.rs:89`). The Android CI matrix cross-compiles and executes the affected crate on an emulator (`.github/workflows/ci.yml:189`). Miri is not applicable to the JNI VM operation itself. |
| System testing | 13/15 | Native unit/integration/property tests, deterministic simulation, Patchbay network namespaces, browser-target Wasm execution, documentation tests, three Android compile targets, and a retained final-tree production-host 2x canary cover the primary invariants. Two points are deducted because dedicated bounded fuzz targets and a fresh local Android emulator run are not present. |
| Auditability and lint enforcement | 5/5 | Every workspace member inherits the lint policy; correctness, suspicious behavior, checked casts, unsafe operations, and unused results are denied (`Cargo.toml:36`, `Cargo.toml:50`). Determinism drift and strict `-D warnings` Clippy matrices are enforced and green. |

Calculation: `15 + 9 + 15 + 10 + 10 + 10 + 10 + 13 + 5 = 97` out of 100
applicable points.

## Confirmed Invariants

- Admission accepts exactly the configured live-work limit, rejects the first excess item without
  waiting or spawning, and recovers after the owner releases its permit.
- Runtime task rejection does not poll the future or consume a task identity.
- Connection and actor permits remain owned for the full resource lifetime, including failure,
  cancellation, panic, clone/drop, and shutdown paths.
- Noq packet saturation has loss semantics; reliable control, terminal, completion, and lifetime
  accounting remains conserved.
- DNS address iteration cannot expose more than 64 IPv4 or 64 IPv6 records per lookup.
- Configuration and public construction validate before listeners, stores, tasks, or threads are
  started.
- Shutdown cancels before joining and uses finite deadlines; drop paths do not wait indefinitely.
- Seeded scheduling and effect boundaries remain replayable.

## Verification Evidence

The following commands passed on the final relevant source state:

- `cargo fmt --all -- --check`
- `git diff --check`
- `scripts/tests/check-determinism-boundaries.sh`
- `scripts/check-determinism-boundaries.sh --check`
- all-feature, default-feature, and no-default-feature workspace Clippy matrices with
  `-D warnings`
- `cargo test --workspace --all-features --tests -- --test-threads=1` through the privileged
  `iroh-test-env` runner, including 46 enabled Patchbay tests
- focused runtime, endpoint-address, DNS, DNS-server, relay, Noq, and capacity tests
- `cargo test --workspace --all-features --doc`
- `cargo doc --workspace --all-features --no-deps --document-private-items`
- `cargo deny --workspace --all-features check`
- no-default-feature optional-dependency absence checks
- all four Wasm CI builds, both forbidden-`env` import scans, and the Wasm integration test
- full aarch64 and armv7 Android workspace builds, plus the four x86_64 Android test-binary builds
- the clean release production resource canary at 2x offered load, with exact 30/300/30
  one-second sampling and immutable artifacts under `docs/testing/resource-canary/2026-07-24`

`cargo semver-checks` was not used as an acceptance gate because the user approved the coordinated
source-breaking fallible-constructor change. The change is documented in the changelog and
migration guidance.

## Residual Findings

### Medium: dedicated fuzz smoke targets are absent

Property tests cover relay frame decoding and arithmetic, but the planned bounded cargo-fuzz smoke
targets for DoH extraction, pkarr bodies, relay segmentation, and configuration deserialization
are not present.

**Repair:** add short, input-size-limited fuzz targets with persisted regression seeds; keep the
deterministic boundary tests as the primary regression protection.

### Low: Android fallback depends on unwinding an upstream panic

If Android JNI context is not installed and the binary uses `panic = "abort"`, the system-DNS
fallback cannot catch the upstream panic.

**Repair:** prefer an upstream fallible initialization/query API, or add an explicit initialization
state check before entering the upstream system-configuration reader.

## Acceptance Criteria

- No safety cap applies: **met**.
- No unresolved Critical or High finding: **met**.
- Raw score is at least 80: **met (97)**.
- Formatting, deterministic-boundary checks, strict linting, workspace tests, docs, dependency
  policy, Wasm execution, and Android cross-compilation pass: **met**.
- Production-host 2x load/canary evidence exists before raising defaults: **met**.
- Android JNI behavior executes on the CI emulator: **open for the next CI run**.

## Evidence Map

- Runtime task bounds: `iroh-runtime/src/task.rs`, `iroh-runtime/tests/task.rs`
- Endpoint admission and diagnostics: `iroh/src/endpoint/limits.rs`, `iroh/src/endpoint.rs`
- Actor bounds: `iroh/src/socket/remote_map.rs`,
  `iroh/src/socket/transports/relay/actor.rs`
- Queue bounds: `vendor/noq-1.1.0/src/event_queue.rs`,
  `vendor/noq-1.1.0/src/lifetime.rs`
- DNS/input bounds: `iroh-dns/src/dns.rs`, `iroh-base/src/endpoint_addr.rs`
- DNS-server ingress and lifecycle: `iroh-dns-server/src/config.rs`,
  `iroh-dns-server/src/http/transport.rs`, `iroh-dns-server/src/store/signed_packets.rs`
- Relay admission and lifecycle: `iroh-relay/src/server/admission.rs`,
  `iroh-relay/src/quic.rs`, `iroh-relay/src/server.rs`
- Deterministic verification: `docs/testing/determinism-audit.md`, `iroh-sim/tests`
- Platform verification: `.github/workflows/ci.yml`
- Production capacity evidence: `docs/testing/production-resource-canary.md`,
  `docs/testing/resource-canary/2026-07-24`

## Open Questions

1. Should the four bounded fuzz targets land with this hardening series or in a dedicated
   follow-up change?
