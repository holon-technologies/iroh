# Iroh Post-Hardening TigerStyle Remediation Plan

**Status:** core remediation implemented and verified on 2026-07-22

**Operational follow-up:** run the documented 2x production-host load/canary measurement and
platform-specific Android/Wasm jobs in CI. The local all-feature workspace matrix exhausted the
host filesystem while compiling every example; affected-package suites, the strict workspace
all-target Clippy matrix, determinism checks, and focused 10x saturation tests completed
successfully.

**Baseline:** `4c837d7ca3dddf8aaf5102ee74181bcb57440956`

**Supersedes:** only the unfinished portions of
`2026-07-22-iroh-tigerstyle-hardening.md`; completed relay admission, endpoint path bounding, and
persistent-row validation work remains intact.

## Goal and success criteria

Remove the remaining TigerStyle safety cap and close the post-hardening audit findings without
changing DNS, DoH, pkarr, relay-wire, or persisted-data compatibility for currently valid inputs.

The work is complete when:

- DNS UDP requests and DNS TCP, HTTP, and HTTPS connections acquire finite capacity before a task
  is spawned;
- HTTP/2 streams, in-flight HTTP requests, request bodies, per-IP rate-limit state, and shutdown
  time are bounded by validated configuration;
- overload has a deterministic, observable outcome and never waits in an unbounded admission
  queue;
- every DNS-server background task or thread has an owner, cancellation path, join path, and
  observable failure result;
- zero or unsupported store/admission configuration is rejected before any listener, database,
  thread, or task is started;
- public datagram segmentation is total over the complete `usize` input domain;
- the determinism boundary check, formatting, workspace Clippy, focused tests, and workspace tests
  are green;
- safe crates mechanically forbid unsafe code, while the Android JNI exception has an explicit
  local proof and dedicated platform validation; and
- a repeat TigerStyle audit has no safety cap, no Critical or High finding, and a raw score of at
  least 80.

## Scope

### In scope

- `iroh-dns-server` configuration, UDP/TCP DNS transport, HTTP/HTTPS transport, DoH/pkarr route
  admission, rate-limit storage, TLS/ACME lifecycle, metrics, health, and shutdown.
- A narrow vendored `hickory-server` patch because both the pinned 0.26.1 implementation and the
  current upstream server accept loop spawn work before application handlers can enforce a limit.
- `iroh-relay::protos::relay::Datagrams::take_segments` arithmetic.
- Workspace determinism inventory, lint policy, unsafe containment, and adversarial tests.
- A source-compatible deprecation stage for `EndpointAddr`; field privacy is reserved for the next
  semver-major release.

### Non-goals

- Reworking the already bounded relay admission/session implementation.
- Replacing the DNS authority/catalog or changing DNS answer semantics.
- Introducing distributed rate limiting across multiple DNS-server processes.
- Treating per-IP rate limits as a substitute for global hard capacity limits.
- Guaranteeing service availability against link saturation or volumetric attacks outside the
  process. This plan bounds process-owned work after packets or sockets reach the application.
- Making `EndpointAddr` fields private in a 1.x-compatible release.
- Updating a determinism baseline without reviewing and classifying each changed occurrence.

## Chosen architecture

1. Validate the complete configuration into private runtime policy types before the first side
   effect. Public serde-facing structs remain source/config compatible; runtime code receives
   `NonZero*` values and finite rates only.
2. Use non-blocking admission. Listener loops call `try_acquire_owned` after receive/accept and
   before spawn. Full capacity drops a UDP request or closes a newly accepted socket immediately;
   it never awaits a semaphore and therefore never creates a waiter queue.
3. Patch the pinned Hickory transport narrowly. A request-handler middleware cannot solve the task
   bound because Hickory has already spawned the request task by then. Keep the patch isolated,
   documented, tested in the vendored crate, and suitable for submission upstream.
4. Replace `axum_server::Server::serve` with an iroh-owned Hyper accept loop modeled on
   `iroh-relay/src/server/http_server.rs`. Axum Server likewise spawns a task before its acceptor is
   invoked; an acceptor wrapper cannot provide pre-spawn admission.
5. Retain Axum for routing/extractors. Each accepted HTTP(S) connection owns a connection lease,
   and every resource route obtains an in-flight request lease without waiting. Hyper's HTTP/2
   concurrent-stream setting provides a per-connection ceiling.
6. Replace the governor cleanup thread with a bounded in-process LRU of per-IP token buckets. The
   map cannot exceed its configured key count and needs no garbage-collection worker.
7. Give HTTP listeners, connection sets, TLS handshakes, ACME maintenance, and DNS transport one
   explicit supervisor rooted in `Server`; cancellation precedes bounded join.
8. Ratchet lints after behavioral fixes, so the new policy prevents regressions instead of
   producing broad temporary exceptions.

## Critical invariants

1. `active_udp_requests <= max_udp_requests` at every observable point.
2. `active_dns_tcp_connections <= max_dns_tcp_connections` at every observable point.
3. `active_http_connections <= max_http_connections` across HTTP and HTTPS combined.
4. `active_http_requests <= max_http_requests`, and one HTTP/2 connection cannot exceed
   `max_http2_streams_per_connection` active streams.
5. Capacity is acquired before spawn and is owned by the spawned future until completion,
   cancellation, or panic unwinding releases it.
6. Overload does not wait: UDP is dropped, DNS TCP and HTTP sockets are closed, admitted HTTP
   requests receive `503 Service Unavailable`, and per-IP rate rejection receives `429 Too Many
   Requests`.
7. Disabling per-IP rate limiting never disables global connection, task, request, stream, body, or
   shutdown limits.
8. No user-provided zero, non-finite rate, unsupported semaphore capacity, or oversized batch can
   reach a runtime loop.
9. Every listener and maintenance future is present in one owned task set. The first unexpected
   worker failure cancels siblings and is returned by `join` or `shutdown`.
10. Valid existing TOML files continue to load through serde defaults, and valid DNS/pkarr wire
    messages remain compatible.
11. Public APIs do not panic for valid caller input; arithmetic overflow has named checked or
    saturating semantics.

## Validated defaults and compatibility decisions

Add a top-level `limits` table with `#[serde(default)]`; omission preserves config-file
compatibility while activating finite defaults:

| Limit | Default | Validation |
| --- | ---: | --- |
| DNS UDP requests in flight | 1,024 | nonzero, at most `Semaphore::MAX_PERMITS` |
| DNS TCP connections | 256 | nonzero, at most `Semaphore::MAX_PERMITS` |
| HTTP + HTTPS connections | 512 | nonzero, at most `Semaphore::MAX_PERMITS` |
| HTTP requests in flight | 1,024 | nonzero, at most `Semaphore::MAX_PERMITS` |
| HTTP/2 streams per connection | 32 | nonzero `u32` |
| New HTTP(S) connections | 200/second, burst 400 | finite positive rate, nonzero burst |
| Per-IP rate-limit entries | 4,096 | nonzero, hard LRU capacity |
| General HTTP request body | 65,535 bytes | nonzero; DNS-over-TCP wire maximum |
| `PUT /pkarr` body | `SignedPacket::MAX_RELAY_PAYLOAD_BYTES` (1,072) | new compile-time protocol constant |
| Graceful shutdown | 20 seconds | nonzero duration |

The query limiter defaults to 100 requests/second with a burst of 200 per retained IP. The publish
limiter retains the current effective policy of four requests/second with a burst of two. Existing
`pkarr_put_rate_limit = "disabled" | "simple" | "smart"` continues to select/disable only the
per-IP publish policy. `smart` may be used only with an explicitly configured trusted reverse-proxy
CIDR; otherwise validation rejects it to prevent spoofed forwarding headers. Health endpoints skip
per-IP limiting but remain subject to global connection/request limits.

Store validation accepts:

- `max_batch_size` in `1..=65_536`;
- nonzero `max_batch_time`, `eviction`, and `eviction_interval`;
- existing defaults unchanged.

Values outside these domains return typed configuration errors before the database is opened.
Raising a production ingress default requires a load result showing at least 30% remaining CPU,
memory, and descriptor headroom at twice the configured offered load.

---

### Task 1: Validate configuration before side effects

**Resources:** `iroh-dns-server/src/config.rs::{Config, StoreConfig}`;
`iroh-dns-server/src/dns.rs::DnsConfig`; `iroh-dns-server/src/http.rs::{HttpConfig, HttpsConfig}`;
`iroh-dns-server/src/store/signed_packets.rs::Options`;
`iroh-dns-server/src/server.rs::Server::bind`; `iroh-dns-server/config.dev.toml`;
`iroh-dns-server/config.prod.toml`; `iroh-dns-server/README.md`.

**Depends on:** none.

**Interfaces and state:**

- Add serde-facing `LimitsConfig` using primitive values for TOML compatibility.
- Add private `ValidatedConfig`, `IngressPolicy`, and validated store `Options`. Use
  `NonZeroUsize`, `NonZeroU32`, and a nonzero duration wrapper internally.
- Add a typed, non-exhaustive `ConfigError` with field name, supplied value, and supported domain;
  do not collapse validation failures into strings.
- Implement `TryFrom<Config> for ValidatedConfig` and `TryFrom<StoreConfig> for Options`. Remove the
  current infallible `From<StoreConfig>` conversion.

**Implementation:**

- [ ] RED: parse current development/production examples and configs omitting `limits`; assert the
  validated defaults above.
- [ ] RED: table-test zero limits, incomplete rate/burst pairs, NaN/infinite/non-positive rates,
  semaphore overflow, zero durations, zero batch size, and batch size 65,537.
- [ ] RED: instrument a test store/listener factory and prove invalid config returns before any
  directory, database, socket, task, or thread is created.
- [ ] Convert public config exactly once at the start of `Server::bind`; pass only validated policy
  into store, DNS, HTTP, and TLS constructors.
- [ ] Keep `Config::load` responsible only for reading/parsing; expose `Config::validate` for tools
  that want a no-side-effect preflight.
- [ ] Update example TOML and README with defaults, overload semantics, trusted-proxy requirements,
  and explicit tuning guidance.
- [ ] REFACTOR: property-test that every accepted policy satisfies all nonzero/capacity invariants.

**Failure and operations:** invalid configuration prevents startup with a stable typed cause.
Existing valid configs continue to parse. No automatic clamping is allowed because it would hide an
operator mistake.

**Validation:**

- `cargo test -p iroh-dns-server config`
- `cargo test -p iroh-dns-server store::signed_packets`
- `cargo test -p iroh-dns-server --doc`

---

### Task 2: Enforce DNS UDP/TCP admission before Hickory spawns

**Resources:** root `Cargo.toml` and `Cargo.lock`; new
`vendor/hickory-server-0.26.1/`; `iroh-dns-server/src/dns.rs::{DnsServer, DnsHandler}`;
`iroh-dns-server/src/metrics.rs`; vendored Hickory `src/server/mod.rs`; vendor-delta documentation
and licenses.

**Depends on:** Task 1's `IngressPolicy`.

**Interfaces and state:**

- Add vendored Hickory `ServerLimits` containing nonzero UDP-request and TCP-connection capacities.
- Add `AdmissionRejection::{UdpRequestCapacity, TcpConnectionCapacity}` and a small
  `AdmissionObserver` trait/callback. `iroh-dns-server::Metrics` implements the observer without
  making Hickory depend on `iroh-metrics`.
- Hickory request/connection tasks own an `OwnedSemaphorePermit`; the permit is not clonable and
  releases on every return, cancellation, and unwind path.
- `DnsServer` receives validated limits and exposes only the already-bound address and owned server
  lifecycle.

**Implementation:**

- [ ] Copy exactly the locked `hickory-server` 0.26.1 source and licenses into `vendor/`; document
  the narrow delta, upstream commit/version, update procedure, and reason a handler wrapper is
  insufficient.
- [ ] Add the path patch and workspace exclusion in root `Cargo.toml`; update `Cargo.lock` without
  changing unrelated dependency versions.
- [ ] RED in the vendored crate: block a fake UDP handler, send more than the limit, and prove
  started/live tasks never exceed capacity while rejection callbacks account for excess input.
- [ ] RED in the vendored crate: hold TCP sessions open past capacity and prove excess accepted
  sockets close without a spawned connection task.
- [ ] RED: test permit release after normal completion, handler panic, peer close, listener error,
  and shutdown cancellation.
- [ ] In `handle_udp`, call `try_acquire_owned` before `JoinSet::spawn`; on full, notify and drop the
  datagram. Never await the semaphore.
- [ ] In `handle_tcp`, call `try_acquire_owned` immediately after accept and sanitization but before
  spawn; on full, notify and drop the stream.
- [ ] Bound the join-set cardinality by construction and assert it does not exceed the corresponding
  capacity in test builds.
- [ ] Wire rejected/active metrics into `iroh-dns-server` using fixed labels or separate counters;
  never use peer-controlled values as metric labels.
- [ ] Prepare the vendor delta as an upstreamable Hickory change, but do not make merge acceptance
  a release dependency.

**Failure and operations:** UDP overload is a silent packet drop, matching normal UDP loss. TCP
overload closes only the new socket. Existing admitted work is never evicted. Observer failure is
impossible by contract because observation is synchronous and infallible.

**Validation:**

- `cargo test --manifest-path vendor/hickory-server-0.26.1/Cargo.toml server::`
- `cargo test -p iroh-dns-server dns`
- A loopback saturation test offering at least 10x each configured limit while the handler is
  blocked; active gauges must never cross the limit and must return to zero.

---

### Task 3: Own and bound HTTP/HTTPS transport and route work

**Resources:** `iroh-dns-server/Cargo.toml`; `iroh-dns-server/src/http.rs`;
new `iroh-dns-server/src/http/transport.rs`; new `iroh-dns-server/src/admission.rs`;
`iroh-dns-server/src/http/{doh,pkarr,rate_limiting}.rs`;
`iroh-dns-server/src/http/doh/extract.rs`; `iroh-dns-server/src/metrics.rs`;
reference pattern `iroh-relay/src/server/{admission,http_server}.rs`.

**Depends on:** Task 1.

**Interfaces and state:**

- Add private `AdmissionControl` with a shared HTTP connection semaphore, request semaphore,
  deterministic token bucket for global accepts, and bounded LRU per-IP limiters.
- Model capacity as `HttpConnectionLease` and `HttpRequestLease`. They own permits and cannot be
  constructed without admission.
- Define `ConnectionAdmission::{Accepted, RateLimited, CapacityFull}` and
  `RequestAdmission::{Accepted, CapacityFull, IpRateLimited}`.
- Add a low-level `serve_connection` that receives a stream, peer address, Axum router, optional TLS
  acceptor, cancellation token, and connection lease.

**Implementation:**

- [ ] RED: hold HTTP/1 connections before request completion and prove only
  `max_http_connections` tasks exist across HTTP and HTTPS combined.
- [ ] RED: multiplex HTTP/2 requests on one connection and prove both the per-connection stream cap
  and global request cap; excess requests receive `503` without waiting.
- [ ] RED: send excessive/chunked bodies to DoH and pkarr. Assert general requests stop at 65,535
  bytes and `PUT /pkarr` stops at `SignedPacket::MAX_RELAY_PAYLOAD_BYTES` before buffering or
  decoding. Add that associated constant in `iroh-dns/src/pkarr.rs` as
  `SignedPacket::MAX_BYTES - PublicKey::LENGTH` and test that it equals every valid
  `to_relay_payload().len()` upper bound.
- [ ] RED: generate more unique client IPs than `max_rate_limit_entries`; assert the LRU cardinality
  remains fixed and deterministic eviction does not disable global limits.
- [ ] RED: verify `Simple`, trusted `Smart`, and `Disabled` compatibility, including rejection of
  `Smart` without trusted proxy CIDRs.
- [ ] Replace `axum_server::serve` with an owned Tokio accept loop and Hyper connection builder,
  following the relay server's established listener/JoinSet pattern.
- [ ] Acquire a connection lease and global accept token before spawning. Drop new sockets on
  rejection and increment reason-specific counters.
- [ ] Explicitly inject `ConnectInfo<SocketAddr>` into each connection service rather than relying
  on Axum Server's make-service wrapper.
- [ ] Configure HTTP/1 header limits/timeouts and HTTP/2 `max_concurrent_streams` from validated
  policy. Preserve HTTP/1 and HTTP/2 ALPN behavior.
- [ ] Add outer request middleware that calls non-blocking admission before body extraction or
  route execution. Apply bounded per-IP query limiting to DoH and pkarr GET, and the stricter
  publish limiter to pkarr PUT.
- [ ] Replace tower-governor storage and its GC thread with the bounded LRU token-bucket
  implementation; remove `tower_governor` if no longer used.
- [ ] Emit active/rejected HTTP connection/request counters, per-IP rate rejection counters, and
  body-limit rejection counters with bounded labels.
- [ ] REFACTOR: make token-bucket transitions pure over `(state, now, request)` and property-test
  refill, burst, eviction, clock non-regression, and deterministic replay.

**Failure and operations:** connection overload closes the new socket; request overload returns
`503` with `Retry-After`; per-IP rejection returns `429`; oversized bodies return `413`. Existing
admitted requests are allowed to finish unless server shutdown reaches its deadline.

**Validation:**

- `cargo test -p iroh-dns-server http::`
- `cargo test -p iroh-dns-server --test ingress_limits`
- Existing DoH, HTTP, HTTPS, self-signed, manual-certificate, and Let's Encrypt acceptor tests.
- A 10x-capacity HTTP/1 + HTTP/2 loopback saturation test with fixed task/gauge ceilings.

---

### Task 4: Supervise TLS, ACME, listeners, and shutdown

**Resources:** `iroh-dns-server/src/http/tls.rs`; `iroh-dns-server/src/http.rs::HttpServer`;
`iroh-dns-server/src/dns.rs::DnsServer`; `iroh-dns-server/src/server.rs::Server`;
`iroh-dns-server/src/store/signed_packets.rs::IoThread`; `iroh-runtime/src/task.rs` where reusable;
`iroh-dns-server/src/metrics.rs`.

**Depends on:** Tasks 2 and 3.

**Interfaces and state:**

- Change TLS construction to return a `TlsRuntime` containing the acceptor/config plus an optional
  ACME maintenance future. Construction never calls `tokio::spawn`.
- `HttpServer` owns cancellation plus listener, connection, and maintenance task sets.
- Add typed `ServerRunError` variants for DNS listener failure, HTTP listener failure, TLS/ACME
  maintenance failure, task panic, store failure, and shutdown timeout.
- Add validated `ShutdownBudget`; one absolute deadline is shared across child shutdown phases so
  sequential waits cannot each consume the full budget.

**Implementation:**

- [ ] RED: make the rate-limiter/ACME maintenance future fail and prove `Server::join` returns the
  cause after cancelling and draining siblings.
- [ ] RED: hold an HTTP request, TLS handshake, DNS handler, and store operation open; prove shutdown
  stops admission, cancels/drains owned work, and completes or returns `TimedOut` within 20 seconds.
- [ ] RED: test normal completion racing cancellation, child panic, repeated cancellation, and
  permit/gauge release after abort.
- [ ] Move the Let's Encrypt state loop out of `TlsAcceptor::letsencrypt`; return it to the HTTP
  supervisor and eliminate the detached `tokio::spawn`.
- [ ] On listener or maintenance failure, latch the first cause, cancel all sibling admission, and
  drain owned tasks before returning. Do not silently return merely because one `select!` branch
  completed.
- [ ] Replace HTTP `abort_all` as the normal shutdown path: stop accepting, signal graceful Hyper
  shutdown, drain until the shared deadline, then abort remaining tasks and return a diagnostic
  containing bounded counts by subsystem.
- [ ] Ensure Hickory shutdown and `IoThread` completion consume only the remaining parent budget.
  Never add an unbounded blocking join to `Drop`.
- [ ] Expose shutdown duration, timeouts, worker failures, and remaining-task counts through fixed
  metrics and health state.
- [ ] REFACTOR: use one supervisor result-folding helper so task errors and panics cannot be dropped
  accidentally.

**Failure and operations:** graceful shutdown returns success only after all owned work terminates.
Timeout returns a typed bounded diagnostic after aborting abort-safe async work; a still-live native
store thread is surfaced to the binary, which logs the cause and exits nonzero rather than claiming
clean shutdown.

**Validation:**

- `cargo test -p iroh-dns-server server::shutdown`
- `cargo test -p iroh-dns-server http::tls`
- `cargo test -p iroh-runtime --test task`
- Integration test asserting no task/thread/gauge remains after repeated bind-shutdown cycles.

---

### Task 5: Make remaining arithmetic and public state boundaries total

**Resources:** `iroh-relay/src/protos/relay.rs::Datagrams::take_segments`;
`iroh-base/src/endpoint_addr.rs::{EndpointAddr, CustomAddr}`; internal `EndpointAddr` construction
sites; crate changelogs and migration documentation.

**Depends on:** none; may run independently of Tasks 1-4.

**Interfaces and state:**

- Keep `take_segments` infallible and define multiplication as saturating because the byte count is
  subsequently capped to the available datagram bytes. Document that `usize::MAX` means "take all
  available complete segments."
- Add/retain validated `EndpointAddr` constructors and a public `validate` method returning typed
  `AddressLimitError` for compatibility-period callers.
- Preserve public fields in 1.x. Record field privacy and removal of deprecated infallible
  constructors as an explicit next-major migration.

**Implementation:**

- [ ] RED: property-test `take_segments` over arbitrary segment size, available length, and
  `num_segments`, including zero and `usize::MAX`; assert no panic and output never exceeds input.
- [ ] Replace unchecked multiplication with `saturating_mul`; add a comment explaining why
  saturation, rather than a new error return, preserves the method's existing semantics.
- [ ] RED: construct invalid `EndpointAddr` values through public 1.x fields and verify every
  network, persistence, lookup, and remote-map boundary calls validation before cloning/storing.
- [ ] Add accessors and validated mutation methods required by internal callers; migrate internal
  struct-literal construction away from public fields.
- [ ] Deprecate remaining infallible validation-bypassing constructors with replacements and
  migration examples. Add a next-major checklist to the changelog; do not claim the illegal state
  is unrepresentable until fields become private.

**Failure and operations:** valid callers see no wire or source behavior change. Invalid addresses
constructed through legacy public fields fail at the first system boundary with a typed error.

**Validation:**

- `cargo test -p iroh-relay --all-features protos::relay`
- `cargo test -p iroh-base --all-features endpoint_addr`
- `cargo test -p iroh --all-features remote_map`
- `cargo semver-checks` for the current compatibility stage.

---

### Task 6: Restore deterministic-boundary and lint enforcement

**Resources:** `scripts/check-determinism-boundaries.sh`;
`scripts/determinism-boundaries.txt`; `docs/testing/determinism-audit.md`; root `Cargo.toml`;
workspace member manifests and crate roots; `iroh-dns/src/android.rs`; `.github/workflows/ci.yml`;
`.github/workflows/tests.yaml`.

**Depends on:** Tasks 1-5 green so the inventory and lint baseline describe final behavior.

**Interfaces and state:** no protocol behavior change. Every unsafe or lint exception names a local
proof with `reason = "..."`; no blanket workspace suppression is permitted.

**Implementation:**

- [ ] Run the determinism checker before updating anything. Classify each added/removed clock,
  entropy, spawn, external-state, and unordered-collection occurrence in the audit document.
- [ ] Confirm the new token bucket accepts an explicit `Instant`/clock input and its pure transition
  has no ambient time or scheduler dependency.
- [ ] Remove obsolete entries for the governor thread and detached ACME spawn; document remaining
  real-server effects as supervised production boundaries.
- [ ] Update `scripts/determinism-boundaries.txt` only after the narrative review is complete; prove
  both checker self-tests and repository `--check` pass.
- [ ] Add `unsafe_op_in_unsafe_fn = "deny"` and `unused_must_use = "deny"` to workspace policy.
- [ ] Add `#![forbid(unsafe_code)]` to crates without an approved unsafe boundary. Keep `iroh-dns`
  as the Android exception and put a `// SAFETY:` proof immediately above the JNI operation.
- [ ] Ensure every workspace member, including `iroh/bench`, declares `[lints] workspace = true`.
- [ ] Enable Clippy `correctness` and `suspicious` as deny; stage `unwrap_used`, `expect_used`,
  `panic`, arithmetic, cast, large-future, `todo`, and `unimplemented` lints per production crate.
  Test-only allowances must be scoped with `cfg(test)` and production exceptions need reasons.
- [ ] Add an Android target check for the JNI module and Miri coverage for safe pointer-independent
  helpers. Document why the actual JNI VM call requires Android instrumentation rather than Miri.

**Failure and operations:** determinism or lint drift fails CI. The baseline cannot be regenerated as
an unexplained mechanical update.

**Validation:**

- `scripts/tests/check-determinism-boundaries.sh`
- `scripts/check-determinism-boundaries.sh --check`
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
- Existing default/no-default/all-feature Clippy matrices and Android target job.
- Applicable `cargo +nightly miri test` targets.

---

### Task 7: Adversarial verification, rollout, and exit audit

**Resources:** new bounded ingress integration tests under `iroh-dns-server/tests/`; optional
`fuzz/` targets excluded from the workspace; CI/weekly workflows; `iroh-dns-server/README.md` and
changelog; TigerStyle rating rubric.

**Depends on:** Tasks 1-6.

**Interfaces and state:** test harnesses expose only fixed counters/gauges and seeded inputs. Every
load/fuzz process has explicit time, memory, connection, task, corpus, and artifact limits.

**Implementation:**

- [ ] Add a blocking fake store/DHT and simultaneously flood UDP, DNS TCP, HTTP/1, and HTTP/2 at
  10x configured capacity. Assert each live gauge stays within its limit, rejection accounting is
  exact, memory reaches a plateau, and all permits return after release.
- [ ] Add recovery tests: saturate, release the blocked dependency, admit new valid work, then
  shutdown. Existing connections must survive overload and the service must not remain wedged.
- [ ] Add deterministic/property tests for admission transitions, token buckets, store config,
  segmentation arithmetic, cancellation, and permit conservation.
- [ ] Add short fuzz targets for DoH extraction, pkarr body boundaries, relay datagram segmentation,
  and validated config deserialization. Fuzzing is additional protection; every audit regression
  also has a deterministic test.
- [ ] Run a documented minimum-host load test at twice each configured production limit. Record
  CPU, RSS, descriptors, tasks, latency, rejection counts, and shutdown duration; require 30%
  headroom before raising any default.
- [ ] Update operator documentation for all limits, overload responses, trusted proxies, metrics,
  tuning, graceful shutdown, and rollback.
- [ ] Run the complete verification matrix below on the final tree and retain command output in the
  PR/release evidence.
- [ ] Repeat the TigerStyle audit. Require no safety cap, no unresolved Critical/High finding, raw
  score at least 80, and an explicit residual-risk section.

**Failure and operations:** rollout may lower limits or revert the new HTTP implementation, but it
must never restore an unlimited mode. The vendored Hickory patch and validated config remain part
of rollback unless replaced by an upstream release with equivalent tested guarantees.

**Validation:**

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`
- `cargo test -p iroh-runtime`
- `cargo test -p iroh-sim`
- `cargo test -p iroh-base --all-features`
- `cargo test -p iroh-relay --all-features`
- `cargo test -p iroh-dns-server --all-features`
- Workspace default/no-default/all-feature and documentation matrices from CI.
- Determinism checker, Android/Wasm/platform jobs, bounded fuzz smoke, and the ingress load report.

## Task ordering and review boundaries

1. Task 1 lands first because every later task consumes validated policy.
2. Tasks 2 and 3 may develop in parallel after Task 1, but each must independently prove
   pre-spawn admission for its transport.
3. Task 4 integrates the owned DNS and HTTP transports and is the safety-cap removal gate.
4. Task 5 is independent and may land while transport work proceeds.
5. Task 6 runs after behavioral code stabilizes so the inventory/lints describe the intended
   architecture.
6. Task 7 is the integration, rollout, and audit gate.

Prefer one focused PR per task. For Tasks 2 and 3, preserve RED evidence showing that the old
listener exceeds the configured live-task ceiling, followed by GREEN evidence from the same test.
Do not combine a baseline regeneration with unrelated behavior changes.

## Rollout and rollback

1. Ship metrics and finite defaults together; there is no metrics-only unlimited mode.
2. Canary one DNS-server instance and compare answer success, latency, active capacity, rejections,
   CPU, RSS, and descriptors with the existing instance.
3. Treat unexpected sustained capacity rejection as a sizing or dependency-latency incident. Raise
   a limit only with the required headroom evidence; otherwise repair the slow dependency.
4. Roll back by routing traffic to the previous binary while retaining compatible config fields.
   Do not deploy the previous unbounded listener on a public endpoint as the steady-state fix.
5. If upstream Hickory accepts an equivalent API, replace the vendor patch in a dedicated PR that
   reruns the exact saturation and lifecycle suite before removing `vendor/hickory-server-0.26.1`.

## Execution handoff

Use `superpowers:executing-plans` for sequential implementation. Tasks 2 and 3 are sufficiently
isolated for `superpowers:subagent-driven-development` only if separate branches/worktrees and
independent review ownership are explicitly requested. Every Rust task must also use
`tigerstyle:tigerstyle-rust`; every behavior change must use
`superpowers:test-driven-development`; completion claims must use
`superpowers:verification-before-completion`.

The limits, overload outcomes, compatibility behavior, and vendoring decision in this document are
implementation inputs. If RED tests or measured capacity invalidate one, amend and review this plan
before changing GREEN behavior.
