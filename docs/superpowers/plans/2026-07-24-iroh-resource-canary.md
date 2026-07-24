# Iroh Production Resource Canary Implementation Plan

**Goal:** Add and run a bounded, loopback-only 2x resource canary for DNS-server, relay, and
endpoint admission, retaining evidence for the TigerStyle exit audit.

**Success criteria:** The harness rejects contaminated hosts, validates all work and timing bounds,
exercises all three production ownership boundaries, exports complete resource/admission evidence,
drains all work within the deadline, and produces a passing report on the documented minimum host.

**Scope:** Feature-gated benchmark tooling, narrow read-only diagnostic exposure, focused tests,
operator documentation, and retained evidence. No production default or behavior changes, external
traffic, or CI gating.

**Approach:** Extend the existing unpublished `iroh-bench` crate with a `resource-canary` feature
and binary. Keep validation and acceptance arithmetic in a deterministic library module; keep host,
clock, filesystem, and network effects in the binary. Expose the endpoint task-capacity snapshot and
relay default constants needed to derive and verify production headroom. Gate the DNS hold controls
behind the canary-only `test-utils` feature while leaving production admission middleware
unchanged.

**Global constraints:** Rust 2024, workspace lints, `#![forbid(unsafe_code)]`, checked arithmetic,
bounded task sets and channels, loopback address validation, absolute operation/shutdown deadlines,
and JSON artifacts without secrets or peer-provided labels.

**Resolved decisions:** The minimum profile and workload are defined in
`docs/superpowers/specs/2026-07-24-iroh-resource-canary-design.md`. A reduced smoke run is useful for
verification but is never capacity evidence. The workload and service share a host, making host
resource results conservative.

### Task 1: Deterministic configuration and acceptance model

**Resources:** `iroh/bench/src/canary.rs`, `iroh/bench/src/lib.rs`, `iroh/bench/Cargo.toml`

**Depends on:** Approved design.

**Interfaces and state:** Add validated timing, host-profile, workload, and headroom types; explicit
`Evidence` versus `Smoke` mode; typed validation and acceptance failures; serializable samples and
lane summaries. Derive workload capacities from production defaults, double them with checked
arithmetic, and check all counts and durations against absolute ceilings.

**Implementation:** RED tests first for zero/oversized values, checked 2x arithmetic, evidence-mode
timing, loopback rejection, exactly-70% thresholds, admission saturation semantics, and incomplete
samples. Implement only the pure model required by those tests, then refactor shared percentage and
headroom calculations.

**Failure and operations:** Invalid CLI or report data returns typed errors before a listener,
task, or artifact is created. Arithmetic overflow fails closed.

**Validation:** `cargo test -p iroh-bench canary`

### Task 2: Host preflight and resource sampler

**Resources:** `iroh/bench/src/bin/resource-canary.rs`, Linux `/proc`, `target/resource-canary/`

**Depends on:** Task 1.

**Interfaces and state:** Parse the static host profile and two baseline `/proc/stat` samples,
enumerate process RSS/CPU contamination, and sample host CPU, memory, process RSS, descriptors,
threads/tasks, and lifecycle phase once per second. The sampler is owned by the active lane and
returns a bounded sample vector.

**Implementation:** RED fixture tests for `/proc` parsers and every preflight rejection. Implement
read-only Linux sampling with checked parsing. Validate the output directory before load and write
artifacts only beneath it.

**Failure and operations:** Missing or malformed kernel data, too many samples, storage pressure,
or baseline contamination aborts before load. Partial evidence records the typed failure.

**Validation:** Focused parser tests plus a reduced `preflight` invocation on the current host.

### Task 3: DNS-server 2x lane

**Resources:** `iroh-dns-server::{Server, Config, Metrics}`, Tokio TCP/UDP, canary binary

**Depends on:** Tasks 1–2.

**Interfaces and state:** Start a loopback-only DNS/HTTP server with production limits, ephemeral
ports, local persistence, and mainline disabled. Bounded UDP, TCP, HTTP-connection, and HTTP/2
request workers offer the design counts/rate and report operations, status classes, split
successful/rejected latency, and errors.

**Implementation:** RED smoke test at injected small limits proving overload, service continuity,
metrics conservation, and deadline shutdown. Implement fixed DNS wire messages and bounded HTTP
requests without unbounded response buffering. Pace UDP requests against absolute deadlines, hold
the first capacity-sized set through a feature-gated reserved query, and send the excess through
Hickory's unchanged rejection path. Hold admitted HTTP/2 requests behind a feature-gated local test
route so exactly the production request ceiling remains in flight while excess requests traverse
the production rejection path.

**Failure and operations:** Any non-loopback bind, worker panic, store background failure, missing
overload evidence, or shutdown timeout fails the lane. Always cancel and drain workers first.

**Validation:** Focused small-limit integration test and reduced smoke lane.

### Task 4: Relay 2x lane

**Resources:** `iroh-relay::server`, `iroh-relay::client`, relay metrics, canary binary

**Depends on:** Tasks 1–2.

**Interfaces and state:** Start the production relay protocol on loopback with default admission.
Derive bounded deterministic keys, enforce at most four sessions per identity, pace fill attempts
at 200/s and overload at 400/s using absolute deadlines, retain accepted clients for measurement,
service their keepalive traffic, and count each typed rejection.

**Implementation:** RED small-limit test for global and per-identity saturation, recovery, and
deadline shutdown. Give every retained client one bounded driver and one-slot command channel so
server pings are answered while the continuity client remains controllable. Use bounded
`JoinSet`s; no detached connections or random/global key source.

**Failure and operations:** Timeout, rate-limit, protocol, per-identity, global-capacity, and
session-campaign pending-establishment results are classified separately and conserved against
attempts. Successful upgrade handles remain owned until the matching server classification is
observed. Missing global saturation, session growth beyond the configured maximum, unexpected
protocol failure, or incomplete drain fails the lane.

**Validation:** Focused integration test and reduced smoke lane.

### Task 5: Endpoint 2x lane

**Resources:** `iroh::{Endpoint, EndpointLimits}`, connection and Noq queue snapshots,
`vendor/noq-1.1.0/src/event_queue.rs`, canary binary

**Depends on:** Tasks 1–2.

**Interfaces and state:** Bind client and server endpoints to direct loopback transport, offer 4,096
connections through bounded work, retain accepted connection pairs, and capture endpoint admission,
runtime task capacity, task rejection/exhaustion, and Noq queue diagnostics.

**Implementation:** RED small-limit test proving exact saturation, rejection, recovery after one
close, queue bounds, and deadline shutdown. Extend Noq's read-only statistics with the maximum
packet-event depth observed on any one connection so its per-connection semaphore has the correct
headroom denominator. Build deterministic addresses from bound loopback sockets and reject any
non-loopback path.

**Failure and operations:** Unexpected resolution/relay use, queue growth beyond bounds, counter
exhaustion, missing rejection, or shutdown timeout fails the lane.

**Validation:** Focused integration test and reduced smoke lane.

### Task 6: Evidence run and audit closure

**Resources:** canary artifact directory,
`docs/testing/production-resource-canary.md`,
`docs/superpowers/audits/2026-07-24-iroh-tigerstyle-exit-audit.md`

**Depends on:** Tasks 1–5 and a clean documented host.

**Interfaces and state:** Run preflight, warm-up, measurement, cooldown, acceptance evaluation, and
shutdown sequentially. Require a clean optimized release build for evidence. Retain the raw
JSON/samples, a SHA-256 manifest, and a human-readable evidence summary that independently
identifies its source revision and manifest digest.

**Implementation:** Gracefully stop the user-authorized competing VM, wait for a clean baseline,
build release tooling, execute the evidence profile, and evaluate every threshold. Update the exit
audit only when the final-tree report passes.

**Failure and operations:** Do not weaken thresholds or relabel a smoke run. On failure, retain
artifacts, restore no external state automatically, and report the exact lane and invariant.

**Validation:** Focused tests, `cargo fmt --all --check`, feature-gated Clippy, the affected crate
tests, a reduced smoke run, then the full release evidence run.

Execution uses the `superpowers:executing-plans`, `superpowers:test-driven-development`,
`tigerstyle:tigerstyle-rust`, and `superpowers:verification-before-completion` workflows.
