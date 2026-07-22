# Iroh Deterministic Simulation Stage 5 Implementation Plan

## Goal and exit gate

Run Iroh's production relay actor, client authentication/framing, server authentication/session,
client registry, and routing logic over simulator-owned connections. Stage 5 is complete when
relay-only, restart/outage, direct-upgrade, direct-failure/fallback, and multiple-relay scenarios
continuously validate authenticated routing, delivery, lifecycle, liveness, and cleanup without OS
TCP, DNS, TLS, or HTTP listeners in the deterministic backend.

## Chosen architecture

Add one simulation-only `RelayConnector` capability to the existing coherent endpoint environment.
The production default remains `iroh_relay::client::ClientBuilder::connect`; only an explicitly
installed simulation environment can supply another connector. The connector returns the same
concrete production relay `Client` consumed by Iroh's existing relay actor.

Lift the existing in-memory relay test path into a hidden `iroh-relay/test-utils` API. A synthetic
listener uses an in-memory byte pipe but runs the production WebSocket framing, challenge/signature
authentication, authorization, `RelayedStream`, server client actor, registry, and packet routing.
Lifecycle and admission controls belong to the simulator's relay environment; relay protocol state
does not. The lightweight routing oracle remains separate and cannot satisfy production-relay
coverage.

### Task 1: Transport-independent production relay sessions

- [x] Add failing client/server tests for an authenticated in-memory production session, routing
  between identities, unknown-destination isolation, duplicate identity behavior, shutdown, and
  protocol-version compatibility.
- [x] Generalize the existing test-only duplex wrapper behind `iroh-relay/test-utils` without adding
  dispatch or allocation to the normal network relay hot path.
- [x] Expose hidden constructors that run production WebSocket framing and challenge authentication
  on simulator-owned IO and register the resulting production server session.
- [x] Add explicit session ownership and bounded shutdown so server actors and registry entries
  cannot outlive the in-memory relay service.
- [x] Verify the existing native relay client/server suite and capture disabled-path performance.

### Task 2: Iroh relay connector seam

- [x] Add a native-only hidden `RelayConnector` contract with an owned request and typed connection
  failure, and install it through `SimulationEnvironment`/endpoint/socket configuration.
- [x] Keep normal actor construction and `ClientBuilder::connect` byte-for-byte on the production
  branch; dispatch to the injected connector only when explicitly configured.
- [x] Preserve URL, endpoint secret, authentication token, protocol version, local-address semantics,
  home-relay status, reconnect behavior, and cancellation across both branches.
- [x] Add actor/endpoint tests proving injected construction, failure/recovery, stale connection
  closure, and no invocation when the capability is absent.
- [x] Keep browser Wasm and native minimal-feature builds valid without enabling server code in the
  production Iroh dependency graph.

### Task 3: Relay topology, environment, and lifecycle faults

- [x] Add strict relay topology schema for stable ID/URL, initial online state, capacity, protocol
  version, admission policy, and optional deterministic connection/frame impairment.
- [x] Implement a bounded deterministic relay environment with independent relays, lifecycle
  generations, connection/session resource tokens, production session services, and a smaller pure
  routing oracle for differential checks.
- [x] Activate `relay_lifecycle` actions for outage, restart, and recovery; reject unknown relays and
  incompatible capability declarations during schema validation.
- [x] Trace dial/auth/connect/disconnect/restart/route/drop/overload transitions with stable relay and
  endpoint identities and no secret material.
- [x] Add unit/property tests for identity isolation, destination correctness, capacity/overload,
  restart invalidation, multi-relay separation, deterministic ordering, and empty cleanup.

### Task 4: Production endpoint scenarios and relay invariants

- [x] Configure production endpoints with canonical custom relay maps and simulator connectors; allow
  connections to use identity plus relay addresses without adding a direct address.
- [x] Add backend-independent relay state/path observations and continuous invariants for
  authenticated source, intended destination, no cross-relay delivery, valid relay/direct path,
  bounded reconnect, and relay resource cleanup.
- [x] Run production QUIC stream/datagram traffic through relay-only, outage/recovery, restart,
  relay-to-direct upgrade, direct degradation/failure with relay fallback, and multiple-relay cases.
- [x] Exercise stale relay configuration, unavailable home relay, duplicate endpoint sessions,
  overload/backpressure, cancellation, endpoint restart, and shutdown during reconnect.
- [x] Prove the production client actor, client protocol, server protocol, server client actor, and
  server registry are all present in trace/coverage evidence for exit-gate scenarios.

### Task 5: Common semantics, parity, and minimization

- [x] Define semantic relay outcomes and typed capability skips for deterministic, production-local,
  and Patchbay fixture backends without comparing packet timing.
- [x] Compare the pure routing oracle against production sessions for accepted routing, isolation,
  lifecycle, and overload cases; document every intentional difference.
- [x] Extend reducers to remove relays, relay actions/configuration, impairment rules, and redundant
  path transitions while preserving the exact failure signature.
- [x] Add reviewed relay-restart and direct-fallback failures to the permanent corpus and ensure
  replay/minimization retain relay inventory and trace context.

### Task 6: Operations, performance, and exit audit

- [x] Add PR relay smoke campaigns and sharded nightly relay/lifecycle/path campaigns with retained
  unique failures and bounded time/resource budgets.
- [x] Benchmark production connector-disabled construction/dial dispatch and in-memory production
  relay routing; compare native relay throughput/connection baselines before accepting the seam.
- [x] Refresh scenario inventory, artifacts, `cargo sim explain`, docs, parity tables, and the
  determinism-boundary classification for relay connection/session code.
- [x] Run relay crate tests, full simulation tests, targeted Iroh relay regressions, strict clippy,
  native minimal-feature checks, browser Wasm checks, corpus/campaign replay, workflow contracts,
  boundary baseline, and diff hygiene.
- [x] Complete a scenario-by-scenario exit audit demonstrating relay-only, direct upgrade, direct
  failure, and fallback identity/data/liveness invariants on production client and server state
  machines.

## Constraints

- The pure routing oracle never counts as production relay coverage.
- Synthetic transport may replace TCP/TLS/HTTP listener mechanics, but never relay framing,
  authentication, authorization, session, registry, routing, reconnect, or QUIC behavior.
- Secure endpoint identity material remains deterministic test material only and is never recorded.
- Lifecycle generations must make pre-restart connections stale and unable to deliver.
- All queues, sessions, relays, retries, and artifacts are bounded and resource-accounted.
- Stage 5 may inventory existing Tokio timer/randomness inside production relay handlers; Stage 6
  must control it. Stage 5 scenarios must not rely on those values for seeded semantic outcomes.
