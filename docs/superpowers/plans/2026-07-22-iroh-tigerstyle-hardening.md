# Iroh TigerStyle Hardening Implementation Plan

**Status:** approved decisions; ready for RED implementation

## Goal and success criteria

Close every gap from the 2026-07-22 TigerStyle audit without weakening protocol compatibility,
deterministic simulation, or existing test coverage. The work is complete when:

- remote relay traffic cannot create unbounded socket, handshake, session, duplicate-client, queue,
  or task growth;
- endpoint/address-lookup input cannot create unbounded address bytes, candidate paths, pending
  resolves, or lookup work;
- corrupt persistent state produces typed, observable failures instead of panics or silently dead
  maintenance threads;
- DNS jitter and relay restart duration arithmetic is defined for the complete input domain and
  cannot wrap, truncate, divide, or take a remainder invalidly;
- endpoint, relay, DNS, HTTP, and persistence shutdown completes within a configured deadline or
  returns a typed diagnostic describing what remains live;
- unsafe code and correctness-sensitive Clippy rules are enforced consistently across workspace
  members; and
- regression, property, fault-injection, concurrency, fuzz, and platform checks exercise each
  repaired boundary.

The exit target is a repeat TigerStyle score above 75 with no safety cap.

## Chosen approach

Deliver the hardening as small reviewable changes, each beginning with a failing regression test.
Introduce validated domain types at configuration and wire boundaries, then pass validated values
into existing actors. Keep transport, persistence, clock, and randomness effects outside pure
validation and accounting logic so the same policies can run in production and deterministic
simulation.

Admission uses two owned leases: one bounds sockets still establishing, and one bounds registered
relay sessions for their full actor lifetime. Path handling uses deterministic admission and
eviction outcomes rather than inserting first and hoping later pruning establishes a bound.
Persistent rows are decoded and cross-checked before they can enter domain types. Shutdown gains an
explicit budget and observable timeout result; `Drop` remains best-effort and never becomes the
primary shutdown mechanism.

Lint enforcement is deliberately last. Known correctness failures are fixed first, then the
workspace is ratcheted so equivalent code cannot re-enter.

## Critical invariants

1. Every accepted relay socket owns an establishment lease until it terminates or becomes a
   registered session; every registered session owns a session lease until its actor and registry
   entry terminate.
2. Relay overload is explicit and observable. It never creates an untracked task or an unbounded
   wait queue.
3. Per-endpoint duplicate sessions and `sent_to` relationships have hard limits and deterministic
   full-capacity behavior.
4. Remote path state never exceeds configured total, per-kind, per-source, byte, pending-resolve,
   or lookup-item bounds. Selected and open paths are never silently evicted.
5. Persisted key bytes are a validated `PublicKey` before formatting, lookup, or deletion. Stored
   packets are checked and match the table key.
6. Background thread/task failure is latched once, surfaced through service health and operations,
   and observed during explicit shutdown.
7. Public APIs do not panic for valid input. Wire-unit conversion is checked or deliberately
   saturated at a named protocol maximum.
8. Shutdown has a nonzero budget, cancels before waiting, reports remaining owned work on timeout,
   and never blocks indefinitely inside `Drop`.
9. Safe crates forbid unsafe code. The Android JNI boundary remains the only reviewed exception,
   with `unsafe_op_in_unsafe_fn` denied and its safety contract tested as far as the platform allows.

## Constraints and non-goals

- Do not change relay frame bytes for values already representable by the current protocol.
- Do not make overload behavior depend on scheduler timing or hash-map iteration order.
- Do not record secret keys, authentication material, raw packet contents, or JNI pointers in
  metrics, errors, traces, or fuzz artifacts.
- Do not use panics to reject configuration, network, persistence, or public API input.
- Do not replace bounded backpressure with unbounded queues.
- Do not count the pure relay simulator oracle as production relay admission coverage.
- Do not rewrite the relay, path, or persistence architecture beyond what is needed to establish
  ownership, validation, and bounds.
- Preserve the old signed-packet storage format and relay protocol decoding compatibility.

## Affected technology and services

Rust 2024, Tokio, `tokio_util::TaskTracker`, Hyper/Axum WebSockets, Redb, Iroh relay protocol,
Iroh endpoint path management, deterministic `iroh-runtime`/`iroh-sim`, Cargo workspace lints,
GitHub Actions, cargo-fuzz, and Android JNI integration.

## Resolved production decisions

These choices favor bounded failure, operational continuity, and a compatible migration path. The
numeric defaults are initial enforced production limits, not promises of maximum supported scale;
Task 8 may lower them if the minimum-host load gate fails, while raising them requires equivalent
capacity evidence.

1. **Capacity-derived relay admission with safe defaults.** The default profile is 256 pending
   establishments, 4,096 registered sessions, four sessions per endpoint identity, and a global
   token bucket of 200 accepted connections per second with a burst of 400. The production binary
   requires an effective file-descriptor limit of at least 8,192 for this profile, load-tests it on
   the documented minimum host at 2x offered capacity, and must retain at least 30% measured memory,
   CPU, and descriptor headroom; operators may select a lower validated profile or explicitly raise
   limits with their own capacity evidence, but no production profile may be unlimited.
2. **Two-release `CustomAddr` migration.** Add bounded, fallible constructors and custom bounded
   deserialization at every untrusted ingress now, deprecate the infallible constructors, and remove
   them in the next semver-major release. Existing in-process callers retain source compatibility
   during the migration, but network, persistence, and lookup input never passes through the legacy
   unbounded path.
3. **Deterministic path and address limits.** Enforce at most 34 retained paths per remote: four
   relay paths and 30 non-relay paths, of which no more than eight may be custom; also enforce 30
   candidates per source, 16 distinct source attributions, eight attributions per path, 32 pending
   resolves, 64 emitted lookup items, and a 15-second lookup deadline. Limit each custom address to
   512 opaque bytes, each relay URL encoding to 2,048 bytes, and one `EndpointAddr` to 16 KiB total;
   count duplicates against lookup work even when they do not consume another retained-path slot.
   Selected/open paths rank first, then usable/inactive paths, then unknown paths, then unusable
   paths; within a rank prefer explicit application input over fresher lookup data, and break all
   remaining ties by stable admission sequence followed by canonical address bytes. A protected
   path is never silently evicted: admission rejects the new candidate if retaining it would exceed
   a hard bound.
4. **Deadline-bounded shutdown with process-boundary escalation.** Defaults use one absolute
   deadline per operation: 10 seconds for an endpoint, 20 seconds for a relay server, 20 seconds for
   a DNS server, and five seconds for a persistence thread; child phases receive only the remaining
   parent budget. Libraries cancel owned work and return a typed timeout diagnostic, detaching a
   Rust thread only when it cannot be stopped safely; production relay/DNS binaries emit the bounded
   diagnostic and terminate nonzero if owned persistence work is still live at the outer 25-second
   hard deadline, leaving five seconds of a conventional 30-second orchestrator grace period.
5. **Transactional row quarantine with degraded health.** A corrupt row fails closed for its key,
   is copied to a bounded quarantine table and removed from active indexes in one transaction, and
   makes readiness unhealthy while liveness and independently validated rows continue. Health
   returns to ready only after explicit operator repair/acknowledgement; corruption that prevents a
   safe transaction, invalidates database-wide structure, or fills the quarantine limit of 1,024
   rows or 16 MiB makes the entire store unavailable instead of attempting partial service.

---

### Task 1: Bounded relay admission and duplicate-session ownership

**Resources:** `iroh-relay/src/server.rs::Limits`, `Server::spawn`; `iroh-relay/src/server/http_server.rs::ServerBuilder`, listener loop, `RelayService::accept_framed`; `iroh-relay/src/server/clients.rs::Clients`, `ClientState`, `register`, `unregister`; `iroh-relay/src/server/client.rs::Client`; `iroh-relay/src/server/metrics.rs`; new `iroh-relay/tests/admission.rs`; relay configuration parsing in `iroh-relay/src/main.rs`.

**Depends on:** resolved production decision 1.

**Interfaces and state:**

- Add validated `AdmissionPolicy` and `AdmissionPolicyError`. Convert legacy
  `accept_conn_limit: Option<f64>` and `accept_conn_burst: Option<usize>` once during server
  construction; reject NaN, infinity, non-positive rates, zero burst, and incomplete pairs.
- Extend `Limits` with named hard bounds for pending establishments, registered sessions, and
  sessions per endpoint. Use `NonZeroUsize` internally.
- Model admission as `EstablishmentLease` and `SessionLease` owned wrappers around semaphore
  permits. Leases are not boolean flags and cannot be cloned accidentally.
- Define explicit outcomes: accepted, rate-limited, pending-capacity-full, global-session-full, and
  endpoint-session-full.

**Implementation:**

- [ ] RED: add configuration tests proving invalid rates/bursts and zero limits return typed spawn
  errors, and that currently ignored rate/burst settings affect admission.
- [ ] RED: add a bounded flood test that holds establishment sockets open and proves accepted tasks,
  task-set length, and file descriptors do not exceed the pending limit.
- [ ] RED: add authenticated-session tests proving global and per-endpoint limits, deterministic
  duplicate replacement/rejection, permit release after disconnect/panic/cancellation, and no
  growth of `ClientState::inactive`.
- [ ] Build the validated admission policy at `Server::spawn`; do not pass raw `f64` or `usize`
  values into the listener or registry.
- [ ] Acquire establishment capacity before spawning a connection task. On full capacity, close the
  accepted socket immediately and increment a reason-labelled rejection metric; never await a
  semaphore in the accept loop.
- [ ] Acquire session capacity after authentication/authorization but before `Client::new`. Move the
  `SessionLease` into `Client` so it covers the actor, stream, and registry entry until termination.
- [ ] Reserve the per-endpoint slot atomically with registry mutation so concurrent registrations
  cannot pass the limit independently.
- [ ] Replace unbounded inactive duplicate storage with a bounded collection whose full behavior is
  defined by policy. Do not spawn a client actor that cannot be registered.
- [ ] Bound or expire `sent_to` relationships per source and expose dropped/pruned counters.
- [ ] REFACTOR: extract pure admission transitions from Tokio/HTTP effects and property-test
  `active + available == limit` across accept, promote, unregister, panic, and cancellation events.

**Failure behavior:** invalid configuration prevents startup with `SpawnError`; overload closes or
rejects only the new connection, preserves existing sessions, increments metrics, and never panics.
Permit leakage is an internal invariant failure with a release assertion in tests and diagnostic
snapshot in production.

**Validation:**

- `cargo test -p iroh-relay --test admission`
- `cargo test -p iroh-relay server`
- A seeded simulation case covering overload, duplicate identities, cancellation, and reconnect.
- A load test demonstrating bounded resident memory, task count, and descriptors at 2x configured
  capacity.

---

### Task 2: Bounded endpoint addresses, lookup streams, and path state

**Resources:** `iroh-base/src/endpoint_addr.rs::{EndpointAddr, CustomAddr}`;
`iroh/src/socket/remote_map/remote_state/path_state.rs::{RemotePathState, insert_multiple,
prune_paths}`; `iroh/src/socket/remote_map/remote_state.rs::{handle_msg_resolve_remote,
handle_address_lookup_item, trigger_address_lookup}`; address-lookup traits and tests under
`iroh/src/address_lookup*`; `iroh/src/socket/metrics.rs`; `iroh-sim/src/scenario_model.rs` and
runner scenarios.

**Depends on:** resolved production decisions 2 and 3.

**Interfaces and state:**

- Introduce validated `AddressLimits`/`PathLimits` containing total, kind, source, byte,
  pending-resolve, lookup-item, and lookup-duration bounds.
- Add fallible `CustomAddr::try_from_parts` and `EndpointAddr::try_from_parts` with typed
  `AddressLimitError`. Apply the compatibility strategy chosen above to existing constructors.
- Change candidate insertion to return `PathAdmissionOutcome::{Inserted, Updated, Evicted,
  Rejected}`. Rejection and eviction identify the bound and path kind without exposing user data.
- Define a deterministic priority/order independent of `FxHashMap` iteration. Protect selected and
  currently open paths; reject a new candidate rather than exceeding the bound when all retained
  entries are protected.

**Implementation:**

- [ ] RED: test oversized custom address bytes, excessive endpoint address counts, and deserialization
  paths before using the new validated constructors.
- [ ] RED: replace tests that intentionally preserve unlimited relay/unknown paths with tests proving
  total and per-kind limits, deterministic survivors, and selected/open-path protection.
- [ ] RED: use a custom address lookup that emits unique candidates forever; prove the actor stops or
  rejects at the item/deadline bound and path memory remains constant.
- [ ] RED: issue more pending resolves than allowed for an unresolved endpoint and verify typed
  backpressure rather than queue growth.
- [ ] Validate address byte/count limits before converting or cloning into transport/path maps.
- [ ] Make `insert_multiple` bounded per call and cumulative per source. Do not collect an unbounded
  iterator before applying the limit.
- [ ] Track source freshness and admission order explicitly with stable counters/timestamps supplied
  by the runtime; never derive eviction order from map iteration.
- [ ] Bound address-lookup stream duration and item count using the endpoint-owned clock. Cancel and
  drain the lookup on completion, overflow, endpoint shutdown, or source failure.
- [ ] Emit metrics for rejected bytes, candidates, resolve requests, lookup items, and evictions.
- [ ] REFACTOR: property-test that every transition preserves all configured cardinality bounds and
  deterministic replay yields the same retained paths.

**Failure behavior:** public construction and deserialization return typed limit errors. Address
lookup overflow fails that lookup source, not the endpoint; existing usable paths remain. If every
retained path is protected, the newest candidate is rejected explicitly.

**Validation:**

- `cargo test -p iroh-base endpoint_addr`
- `cargo test -p iroh --all-features socket::remote_map::remote_state::path_state`
- New deterministic simulation scenarios for lookup floods, relay floods, duplicate candidates,
  cancellation, and replay identity.
- Benchmark connection establishment at the configured maximum to detect path-selection regressions.

---

### Task 3: Typed persistent corruption handling and supervised store threads

**Resources:** `iroh-dns-server/src/util.rs::PublicKeyBytes`; `iroh-dns-server/src/store/signed_packets.rs::{deserialize, get_packet, evict_task_inner, IoThread, SignedPacketStore}`;
`iroh-dns-server/src/store.rs`; `iroh-dns-server/src/server.rs`; `iroh-dns/src/pkarr.rs::SignedPacket`;
DNS-server metrics and health response.

**Depends on:** resolved production decision 5; coordinate the final shutdown API with Task 5.

**Interfaces and state:**

- Replace logical-unsafe `PublicKeyBytes::new_unchecked` at persistence boundaries with
  `TryFrom<[u8; 32]>` and a typed `PersistentKeyError`.
- Add `StoreCorruptionError` variants for invalid key, invalid packet, key/packet mismatch, malformed
  legacy row, and inconsistent update-time index.
- Add latched `StoreBackgroundFailure` and a completion signal for every IO thread. Expose store
  health to the server supervisor and `/healthz` without exposing row contents.

**Implementation:**

- [ ] RED: inject an invalid Ed25519 key into `update_time`; assert eviction returns/latches a typed
  corruption error and never formats or panics on the key.
- [ ] RED: inject truncated, signature-invalid, and table-key-mismatched packet rows in both current
  and legacy layouts; assert reads fail closed and valid legacy rows remain compatible.
- [ ] RED: force write and eviction thread errors/panics; assert service health changes, waiting API
  calls fail, and explicit shutdown observes the cause.
- [ ] Decode stored packets with the checked `SignedPacket` path and verify the packet public key
  equals the Redb table key before returning domain data.
- [ ] Validate multimap keys before logging, lookup, or deletion. Quarantine or remove corrupt index
  rows according to an explicit repair transaction; never silently treat them as valid.
- [ ] Make actor and eviction futures return `Result`; latch the first failure, cancel peers, close
  request channels, and notify server supervision.
- [ ] Replace ignored `JoinHandle::join` results with explicit completion/error handling. `Drop`
  requests cancellation and records an unclean-drop diagnostic but does not hide the result of the
  normal explicit shutdown path.
- [ ] Add corruption/failure metrics with bounded labels and document operator recovery steps.
- [ ] REFACTOR: separate pure row validation from Redb transactions and formatting so it can be
  fuzzed without opening a database.

**Failure behavior:** corruption never panics. Reads and maintenance fail closed with row-category
metadata, the store becomes unhealthy, and the server either continues in an explicitly degraded
read policy or shuts down according to configuration. Valid rows are not deleted during detection;
repair is transactional and separately observable.

**Validation:**

- `cargo test -p iroh-dns-server store::signed_packets`
- Fault-injection tests reopening Redb after corrupt rows and after interrupted repair transactions.
- Crash/restart test proving current and legacy valid data survives detection and repair.
- Fuzz target from Task 7 for current/legacy row parsing and key/packet consistency.

---

### Task 4: Total arithmetic and conversion semantics

**Resources:** `iroh-dns/src/dns.rs::{DnsRuntime, stagger_call, add_jitter}`;
`iroh-relay/src/protos/relay.rs::{RelayToClientMsg::Restarting, write_to, from_bytes}`; relevant
property tests in both modules.

**Depends on:** none.

**Interfaces and state:**

- Define a pure jitter calculation over validated milliseconds plus an explicit random draw. Keep
  randomness in `ProductionDnsRuntime` and seeded simulation runtime implementations.
- Add a named maximum number of staggered attempts and checked capacity calculation.
- Define `MAX_RESTART_DURATION_MILLIS = u32::MAX` and deliberate saturation for the existing
  infallible relay encoder, preserving the public message shape and all representable wire bytes.

**Implementation:**

- [ ] RED: add table/property tests for delay values `0`, `1`, `2`, percentage rounding boundaries,
  `u64::MAX`, and arbitrary values. Assert no panic and a documented bounded output interval.
- [ ] RED: test the maximum stagger list and one-over-limit behavior without allocating one future
  beyond the limit.
- [ ] Move random draw generation out of arithmetic. Use checked/saturating operations only where
  the chosen semantics are documented, and avoid modulo by a computed zero range.
- [ ] Make excessive stagger configuration return a typed external-input error. If this requires a
  public error-shape change, record it in release notes and preserve source compatibility with a new
  method plus deprecation wrapper.
- [ ] RED: add relay round-trip tests at `u32::MAX - 1`, `u32::MAX`, and `u32::MAX + 1` milliseconds.
- [ ] Saturate restart durations at the named wire maximum and expose a metric/log at the producer
  boundary when saturation occurs; decoding remains unchanged.
- [ ] REFACTOR: add narrowly justified lint exceptions only where a proof makes a cast infallible.

**Failure behavior:** all valid public inputs return a value or typed error; no input triggers a
panic. Relay durations above the wire domain encode as the documented maximum rather than wrapping.

**Validation:**

- `cargo test -p iroh-dns dns::tests`
- `cargo test -p iroh-relay --all-features protos::relay`
- Property tests with persisted seeds for arithmetic boundaries and encode/decode compatibility.

---

### Task 5: Deadline-bounded, observable shutdown

**Resources:** `iroh-runtime/src/task.rs::{TaskGroup, TaskGroupSnapshot}` and time abstractions;
`iroh-runtime/tests/task.rs`; `iroh/src/runtime.rs::Runtime`; endpoint close paths in
`iroh/src/endpoint.rs`; relay shutdown in `iroh-relay/src/server.rs`, `server/clients.rs`, and
`server/http_server.rs`; DNS shutdown in `iroh-dns-server/src/http.rs`, `server.rs`, and
`store/signed_packets.rs`.

**Depends on:** resolved production decision 4 and Task 3's background-completion contract.

**Interfaces and state:**

- Add validated `ShutdownBudget` and `ShutdownError::{TimedOut, TaskFailure, ThreadFailure}`.
- Keep existing convenience `shutdown`/`close` methods but route them through named default budgets;
  add explicit budget-taking methods for operators and deterministic tests.
- A timeout includes bounded task metadata/counts, subsystem name, and deadline, never future or
  secret contents.

**Implementation:**

- [ ] RED: spawn a child that never completes naturally; prove cancellation drops it and shutdown
  finishes. Then inject a backend/thread that ignores cancellation; prove shutdown returns
  `TimedOut` within the budget with a stable snapshot.
- [ ] RED: test cancellation racing normal completion, child panic, trace failure, repeated shutdown,
  and zero/overflow budget rejection.
- [ ] Add a clock-driven bounded join helper without weakening `TaskGroup::join` semantics. Use the
  injected clock so simulator timeout/replay remains deterministic.
- [ ] Update endpoint runtime shutdown to cancel, close, bounded-join, latch failure, and return an
  observable result to endpoint close/supervision instead of waiting indefinitely.
- [ ] Carry session shutdown budgets through relay clients and server supervision. Bound concurrent
  client joins rather than `join_all` over an unbounded set.
- [ ] Replace DNS HTTP `abort_all` as the normal path with server handles that stop accepting, drain
  within budget, then abort remaining owned work and report it.
- [ ] Add explicit `SignedPacketStore::shutdown` that waits on completion signals within budget.
  Ensure `Drop` cannot perform an unbounded blocking join.
- [ ] Define binary policy for a persistence thread still live after timeout; implement the approved
  detach-or-terminate behavior at the process boundary, not inside the library.
- [ ] REFACTOR: use one common shutdown diagnostic format and metrics family across endpoint, relay,
  DNS HTTP, and persistence services.

**Failure behavior:** shutdown either completes cleanly or returns a typed, bounded diagnostic.
Timeout triggers cancellation/abort according to ownership policy and never silently reports
success. Repeated shutdown is idempotent.

**Validation:**

- `cargo test -p iroh-runtime --test task`
- Targeted endpoint close, relay server shutdown, DNS server shutdown, and store thread tests.
- Deterministic simulation scenarios for shutdown during connect, reconnect, lookup, relay outage,
  packet-store work, and child panic.
- Loom/model test for cancellation versus completion if the state transition cannot be proven by
  ordinary Tokio tests alone.

---

### Task 6: Workspace unsafe and correctness-lint ratchet

**Resources:** root `Cargo.toml`; every workspace member `Cargo.toml`, especially
`iroh/bench/Cargo.toml`; crate roots; `iroh-dns/src/android.rs`; `.github/workflows/ci.yml` and
`.github/workflows/tests.yaml`; lint documentation under `docs/`.

**Depends on:** Tasks 1-5 green, so lints ratchet repaired patterns rather than obscure them.

**Interfaces and state:** no runtime API change. Every lint exception requires a `reason` naming the
local proof or platform boundary.

**Implementation:**

- [ ] Add `[lints] workspace = true` to `iroh-bench` and verify every workspace member inherits the
  shared policy.
- [ ] Add workspace Rust enforcement for `unsafe_op_in_unsafe_fn = "deny"` and
  `unused_must_use = "deny"`; retain existing documentation/config lints.
- [ ] Add `#![forbid(unsafe_code)]` to safe crate roots. Keep `iroh-dns` as the reviewed Android
  exception, deny unsafe operations in unsafe functions there, and add a `SAFETY:` proof directly
  on the JNI call.
- [ ] Enable Clippy `correctness` and `suspicious` as deny; add `perf` and `complexity` as warn.
- [ ] Ratchet `unwrap_used`, `expect_used`, `panic`, `integer_division`, `arithmetic_side_effects`,
  truncation/sign/wrap casts, large futures/stack arrays, `todo`, and `unimplemented` per production
  crate. Tests may use narrow `cfg(test)` allowances; production exceptions require reasons.
- [ ] Remove or justify every new diagnostic without blanket module/crate allowances. Do not change
  arithmetic to wrapping/saturating merely to silence a lint.
- [ ] Run all three existing CI feature matrices with `-D warnings`; add a check that every workspace
  member declares workspace lints.
- [ ] Add Android cross-compile coverage for the JNI module. Miri-test safe pointer-independent
  helpers where applicable; document why the real JNI call requires platform instrumentation
  rather than Miri.

**Failure behavior:** lint violations fail CI. Platform-specific unsafe remains isolated and cannot
expand without a reviewed crate-root policy change.

**Validation:**

- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
- Existing no-default/default/all-feature Clippy matrices.
- `cargo test --workspace --all-features`
- Android target check and applicable Miri tests.
- Script test proving every workspace member inherits the lint policy.

---

### Task 7: Adversarial system, fuzz, and fault-injection coverage

**Resources:** new `fuzz/` cargo-fuzz package excluded from the main workspace; targets for relay
frames, endpoint addresses, and signed-packet storage rows; `iroh-sim` scenarios/corpus; CI/nightly
workflows; testing documentation.

**Depends on:** Tasks 1-6 stable interfaces.

**Interfaces and state:** fuzz inputs are size-limited before decode, random seeds are retained, and
artifacts are scrubbed of addresses, endpoint secrets, packet payloads, and JNI pointers before
upload.

**Implementation:**

- [ ] Add `relay_frame_decode` fuzzing for arbitrary/truncated/oversized frames, version mismatches,
  datagram batches, and restart-duration boundaries. Assert decode never panics and re-encoding a
  valid frame preserves semantics.
- [ ] Add `endpoint_addr_decode` fuzzing for address count/byte limits, custom address encodings,
  duplicates, and canonical serialization.
- [ ] Add `signed_packet_row_decode` fuzzing for current/legacy rows, invalid keys/signatures,
  key/packet mismatch, and corrupt length prefixes.
- [ ] Add deterministic simulation corpus cases for connection floods, duplicate-session churn,
  lookup/path floods, overload recovery, and shutdown during each actor phase.
- [ ] Add Redb fault-injection/crash-restart tests and a long-running bounded admission/path soak.
- [ ] Seed fuzz corpora from existing valid protocol/storage fixtures and persist every minimized
  regression with its originating target and seed.
- [ ] Run short deterministic fuzz smoke checks in PR CI and longer fixed-budget jobs nightly; cap
  time, RSS, artifact count, and retained corpus size.
- [ ] Publish a runbook for reproduction, minimization, corpus promotion, and privacy review.

**Failure behavior:** every harness has explicit input, time, memory, task, and artifact limits.
Crashes, timeouts, and invariant failures retain a reproducible seed and minimized input.

**Validation:**

- Each fuzz target runs for a fixed local smoke budget with zero crashes.
- Nightly workflow syntax and artifact-retention tests pass.
- Every audit regression is represented by at least one deterministic non-fuzz test; fuzzing is
  additional protection, never the only regression test.

---

### Task 8: Integrated rollout, compatibility, and TigerStyle exit audit

**Resources:** release notes/changelog; operator configuration examples; metrics dashboards;
benchmark baselines; all files and workflows above; TigerStyle rating rubric.

**Depends on:** Tasks 1-7.

**Interfaces and state:** configuration and protocol compatibility decisions are documented with
upgrade behavior. New limits expose current usage, configured maximum, rejection reason, and
shutdown/corruption state through bounded metrics.

**Implementation:**

- [ ] Run configuration migration tests for omitted, legacy, invalid, and explicit limit settings.
- [ ] Verify existing representable relay frames and valid current/legacy database rows remain
  compatible.
- [ ] Stage production admission/path defaults behind metrics-only observation if capacity evidence
  requires a canary; never deploy an unlimited fallback.
- [ ] Compare relay throughput, connection latency, endpoint path selection, memory, descriptors,
  task counts, DNS latency, and shutdown duration against the pre-change baseline.
- [ ] Update operator docs for limit tuning, overload signals, corruption recovery, shutdown
  timeout handling, and rollback.
- [ ] Run formatting, all Clippy feature matrices, workspace tests/docs, Wasm/Android/platform
  checks, deterministic replay/corpus/parity jobs, fuzz smoke, fault injection, and load tests.
- [ ] Repeat the TigerStyle audit with file/line evidence. Require no safety gate, no Critical/High
  unresolved finding, and raw score above 75 before closing the hardening program.

**Failure behavior:** rollout can revert configuration/default activation without reverting storage
compatibility or regression tests. Any canary limit rejection or shutdown timeout is visible before
enforcement expands.

**Validation:** command logs, load/benchmark report, compatibility fixtures, metrics screenshots or
exported samples, deterministic seeds, fuzz summaries, platform build matrix, and final TigerStyle
score calculation are all required evidence.

## Task ordering and review boundaries

1. The five production decisions above are approved and form the implementation contract.
2. Tasks 1-4 may proceed as separate reviewable branches.
3. Task 5 follows Task 3's store supervision contract but may develop runtime/endpoint shutdown in
   parallel.
4. Task 6 begins only when Tasks 1-5 are green.
5. Task 7 targets stable interfaces from Tasks 1-6.
6. Task 8 is the release and audit gate.

Each task should be one focused PR unless its RED tests and implementation cannot be reviewed
independently. Preserve failing regression commits or clearly show RED output in the PR description,
then GREEN and REFACTOR evidence.

## Final verification matrix

- Focused unit/property tests for every validated constructor, transition, arithmetic boundary, and
  failure result.
- Integration tests for relay admission/overload, endpoint lookup/path bounds, persistent
  corruption, and bounded shutdown.
- Deterministic simulation for ordering, cancellation, overload recovery, replay, and liveness.
- Fault-injection and crash/restart tests for Redb and actor/thread failure.
- Fuzzing for network, address, and persistent decoders.
- No-default/default/all-feature Clippy, documentation, native, Wasm, Android, and supported OS
  checks.
- Load and soak evidence proving resource usage stays within configured limits.

## Execution handoff

Use `superpowers:subagent-driven-development` if Tasks 1-4 are executed concurrently with isolated
review ownership; otherwise use `superpowers:executing-plans` for sequential implementation. Every
Rust implementation/review task must also use `tigerstyle:tigerstyle-rust`, and behavior changes
must use `superpowers:test-driven-development`. Treat the approved decisions as fixed implementation
inputs; if RED tests or capacity evidence invalidate one, revise and approve that decision in this
plan before continuing GREEN implementation.
