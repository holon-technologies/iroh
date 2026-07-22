# Iroh Deterministic Simulation Stage 2 Implementation Plan

## Goal and success criteria

Deliver the deterministic kernel and synthetic direct-IP substrate required by the approved architecture, while running real Iroh/Noq/QUIC code over the injected socket boundary.

This stage is complete when:

- `iroh-sim` owns a deterministic event loop, virtual monotonic and wall clocks, FIFO ready-task scheduling, stable event identities, hard budgets, and a resource ledger;
- the shared runtime contracts permit a non-Tokio executor without leaking Tokio-specific ownership types;
- Iroh's production IP transport binds through an injected `IpSocketFactory`, with the normal builder retaining the current `netwatch` implementation;
- the synthetic network supports IPv4 and IPv6 hosts/interfaces/routes, deterministic latency and serialization delay, bounded queues, MTU rejection, loss, duplication, reordering, corruption, partitions, and socket rebind/closure;
- production Noq/QUIC stream and datagram operations execute over those synthetic IP sockets;
- repeated same-seed runs have byte-identical normalized traces and terminal observations, long virtual durations do not sleep in wall time, and successful shutdown leaves the Stage 2 ledger empty;
- every remaining Tokio clock/scheduler or OS-environment bridge is detected, recorded in the manifest, and prevents a `fully_deterministic` grade.

## Chosen approach and tradeoffs

Use one single-threaded simulator kernel with queues ordered by `(deadline, event class, stable event ID)`. Runtime tasks use explicit wake-based ready queues; time advances only when no task is runnable. Network delivery is a kernel event, not an async sleep. The scheduler policy in Stage 2 is deterministic FIFO; seeded legal-choice scheduling remains Stage 6 work.

Generalize Iroh's existing IP transport rather than routing simulation through `CustomTransport`. The new internal capability mirrors the real `netwatch` socket behavior closely enough that production routing, path selection, and Noq's abstract UDP socket continue to run unchanged. Normal builders install a concrete `netwatch` factory and pay no packet-hot trait dispatch beyond the injected socket boundary already required by the design.

The current socket actor still contains direct Tokio intervals and ambient monotonic reads. Stage 2 therefore has two execution lanes:

1. kernel-native component tests for the executor, timers, wall clock, event queue, and synthetic network;
2. a current-thread Tokio paused-time bridge for the first production Iroh/Noq direct-IP scenarios.

The bridge is an explicit escape in every run manifest and cannot claim `fully_deterministic`. It is retained only until Stage 6 migrates the remaining socket/path child timers and tasks onto the kernel. This is not a second architecture or a silent approximation.

## Constraints and non-goals

- Do not simulate QUIC, endpoint state machines, connection state, or path selection.
- Preserve normal `Endpoint::builder(...).bind()` behavior and production cryptographic entropy.
- Simulation-only sockets, monitor state, identities, and crypto material require an explicit unsafe-test marker; no ambient variable or behavior feature flag selects them.
- Packet payloads are hashed in traces and are never logged by default.
- Queue overflow, no route, partition, MTU rejection, closed socket, and budget exhaustion remain distinct outcomes.
- NAT/firewall state machines, dynamic discovery, relay streams, generated scenarios, invariant minimization, and controlled rare scheduling belong to later stages.
- No Stage 2 run is labeled fully deterministic while the Tokio bridge or any OS monitor/DNS/socket escape is present.

## Affected technologies

Rust 2024, object-safe runtime traits, `Wake`/`Waker`, Tokio synchronization and paused time, Noq UDP metadata/transmits, `netwatch` production sockets, `n0-watcher`, IP routing types, Blake3 packet hashes, versioned trace/manifests, and GitHub Actions.

## Resolved decisions

- The kernel is single-threaded and deterministic by construction; simulator APIs are `Send + Sync` only where shared production contracts require it.
- Event ordering is deadline, then an explicit stable class rank, then monotonic event ID.
- The virtual clock uses a process-local `Instant` anchor only as an opaque representation; all decisions, ordering, traces, and wall time use run-relative integer nanoseconds.
- Synthetic ephemeral ports are allocated monotonically per host/address family and never delegated to the OS.
- Routes use longest-prefix match, then stable route ID. Equal ambiguous routes are rejected at scenario construction.
- Link serialization uses integer nanoseconds and checked arithmetic; fractional throughput rounds up so positive payloads always consume time.
- Packet fault decisions use semantic decision paths and record the rule/outcome before delivery scheduling.
- The Stage 2 production-code bridge is recorded as `tokio_scheduler` and `tokio_socket_actor_time`; exact trace replay is required despite the lower determinism grade.

## Blocking open decisions

None for Stage 2. Operational budgets remain configuration values until campaign data supports repository defaults.

### Task 1: Make shared task and clock contracts backend-neutral

**Resources:** `iroh-runtime/src/time.rs`; `iroh-runtime/src/task.rs`; `iroh-runtime/src/lib.rs`; `iroh-runtime/tests/time.rs`; `iroh-runtime/tests/task.rs`

**Depends on:** completed Stage 1 contracts.

**Interfaces and state:** Expose allocation of a process-local `ClockDomain`. Replace the Tokio-specific cancellation stored by `OwnedTaskHandle` with an object-safe `TaskControl`; retain the existing public abort/detach/join behavior and Tokio implementation.

**Implementation:**

- [x] Add compile-time and behavioral tests implementing a minimal non-Tokio owned handle boundary.
- [x] Expose a safe fresh clock-domain constructor whose identity never enters portable artifacts.
- [x] Introduce backend-neutral owned-task control/completion construction and migrate `TokioTaskGroup` without changing behavior.
- [x] Keep wasm exports and existing runtime behavior unchanged.

**Failure behavior:** Handle completion loss remains typed; abort is idempotent; custom backends cannot forge task IDs or bypass handle drop cancellation accidentally.

**Validation:** `cargo test -p iroh-runtime`; native no-default check; wasm check; Clippy with warnings denied.

### Task 2: Implement deterministic kernel, virtual clocks, and resource ledger

**Resources:** new `iroh-sim/src/kernel.rs`; new `iroh-sim/src/ledger.rs`; `iroh-sim/src/lib.rs`; new `iroh-sim/tests/kernel.rs`

**Depends on:** Task 1 backend-neutral contracts.

**Interfaces and state:** `Kernel`, `KernelHandle`, `VirtualClock`, `VirtualWallClock`, `KernelExecutor`, `KernelRun`, `RunLimit`, `Quiescence`, stable `EventId`, and `ResourceLedger`. Ready tasks are queued once per wake. Timers and environment events share the ordered event queue. The ledger counts live tasks, timers, sockets, and queued packets with current/high-water values.

**Implementation:**

- [x] Write failing tests for FIFO wake order, parent/ordinal identity, timer order/reset/drop, automatic time advance, simultaneous class/ID order, cancellation/join, panic containment, deadlock/quiescence, budget exhaustion, and empty final ledger.
- [x] Implement wake-driven task storage and deterministic polling without Tokio task spawning.
- [x] Implement resettable virtual timers with generation-based stale-event rejection and balanced ledger entries.
- [x] Implement wall time as checked `epoch + virtual elapsed`.
- [x] Add event-count and virtual-time limits plus typed terminal classifications.

**Failure behavior:** ID/timeline arithmetic, event budget, time budget, trace failure, task panic, deadlock, and leaked resources are distinct errors. Kernel locks are never held while polling user futures or invoking environment events.

**Validation:** `cargo test -p iroh-sim --test kernel`; repeated clean-process golden trace test; a simulated multi-day timer completes without wall sleep.

### Task 3: Introduce the injected Iroh IP socket and stable monitor capabilities

**Resources:** `iroh/src/endpoint.rs`; `iroh/src/socket.rs`; `iroh/src/socket/transports.rs`; `iroh/src/socket/transports/ip.rs`; new `iroh/src/simulation.rs`; focused Iroh transport tests

**Depends on:** Stage 1 explicit runtime-context constructor.

**Interfaces and state:** Internal unstable `IpSocketFactory`, `IpSocket`, `IpSocketSender`, and `NetworkMonitor` traits cover bind, local address/watch, receive, sender creation, GSO/GRO, fragmentation, rebind, interface state, and refresh. `SimulationEnvironment` bundles these capabilities with `RuntimeContext` and deterministic crypto bytes behind `UnsafeTestOnly`.

**Implementation:**

- [x] Add characterization tests for production bind/rebind/send/receive metadata and default builder selection.
- [x] Add failing injection tests proving no OS UDP bind or OS monitor construction occurs with a supplied environment.
- [x] Refactor `IpTransport` to the capability while preserving address canonicalization, metrics, route selection, and watcher behavior.
- [x] Add concrete `netwatch`/OS adapters as the sole normal-builder defaults.
- [x] Derive simulation token/reset keys through a separate crypto-material capability and mark the endpoint/run unsafe-test-only.

**Failure behavior:** Required binds fail construction; optional-family binds remain skippable; duplicate default routes fail; rebind errors preserve the old advertised address; capability mismatch is a typed bind error.

**Validation:** focused transport/builder tests, full Iroh library suite, native and wasm checks, performance sample comparison.

### Task 4: Implement the synthetic IP/UDP network graph

**Resources:** new `iroh-sim/src/network.rs`; new `iroh-sim/src/network/socket.rs`; new `iroh-sim/src/network/topology.rs`; new `iroh-sim/src/network/fault.rs`; new `iroh-sim/tests/network.rs`

**Depends on:** Tasks 2 and 3.

**Interfaces and state:** Versioned hosts, interfaces, addresses, routes, directional links, queues, sockets, and packets. `SyntheticIpSocketFactory` binds one configured host. Packets retain stable ID, source/destination, ECN, segment metadata, payload hash, and optional private payload bytes required for delivery.

**Implementation:**

- [x] Write failing IPv4/IPv6 bind, ephemeral-port, same-host, routed multi-hop, longest-prefix, no-route, source-selection, socket-close, and rebind tests.
- [x] Add latency, bandwidth serialization, bounded queue, MTU, and directional partition behavior.
- [x] Add deterministic loss, duplication, reorder-window, and corruption rules using semantic decision streams.
- [x] Implement `IpSocket` receive wakers and independent sender wakers with Noq-compatible batch metadata.
- [x] Trace packet creation, hop scheduling, fault decisions, delivery/drop reason, and ledger balance without raw payload disclosure.

**Failure behavior:** Invalid/ambiguous topology is rejected before execution. Port conflicts, family mismatch, invalid source, closed socket, oversized datagram, queue overflow, partition, no route, and budget exhaustion are distinguishable and traced.

**Validation:** `cargo test -p iroh-sim --test network`; property tests for route determinism and queue bounds; repeated normalized traces; mutation tests for every drop reason.

### Task 5: Run production Iroh/Noq/QUIC over synthetic IP

**Resources:** `iroh-sim/src/backend.rs`; `iroh-sim/src/tokio_bridge.rs`; new `iroh-sim/tests/production_ip.rs`; Iroh hidden simulation constructor

**Depends on:** Tasks 2–4.

**Interfaces and state:** `DeterministicBackend` constructs endpoint environments from one root seed and topology. The initial endpoint lane uses current-thread Tokio paused time for remaining socket-actor timers, but every UDP packet traverses the synthetic IP graph and real Noq/QUIC. Backend capabilities and escapes are computed from actual installed capabilities rather than caller claims.

**Implementation:**

- [x] Write a failing two-endpoint IPv4 stream scenario, then IPv6 and QUIC datagram scenarios.
- [x] Use fixed simulation identities and explicit addresses; disable relay, port mapping, external discovery, and net-report probes.
- [x] Drive paused Tokio time and synthetic network deadlines to quiescence with deterministic tie-breaking.
- [x] Prove traces contain production endpoint/Noq task activity plus synthetic packet events.
- [x] Close endpoints through production APIs and reconcile runtime/network ledgers.

**Failure behavior:** A Tokio/OS escape, trace divergence, stalled driver, budget exhaustion, connection error, data mismatch, or cleanup leak has a distinct run result and artifact classification.

**Validation:** repeated runs of IPv4 stream, IPv6 stream, and datagram scenarios are byte-identical; corrupt/loss fixtures fail or recover as specified; all successful runs end with an empty ledger.

### Task 6: Activate Stage 2 CLI, replay, CI, and documentation

**Resources:** `iroh-sim/src/cli.rs`; `iroh-sim/src/manifest.rs`; `.github/workflows/ci.yml`; `docs/testing/simulation.md`; `docs/testing/deterministic-simulation-architecture.md`; new Stage 2 scenario fixtures

**Depends on:** Tasks 2–5.

**Interfaces and state:** `cargo sim run` executes versioned Stage 2 named scenarios; `replay` verifies identity and compares normalized traces; unsupported later-stage capabilities return machine-readable skips. Manifests derive capabilities, grade, and escapes from the backend.

**Implementation:**

- [x] Replace the blanket Stage 2 unavailable result for `run`/`replay` with real execution while preserving explicit errors for later commands.
- [x] Write the manifest before execution, append atomic trace chunks, and print exactly one replay command on failure.
- [x] Add Stage 2 smoke/replay/cleanup gates to PR CI and deterministic repeated-run checks to scheduled CI.
- [x] Document topology construction, supported faults, bridge limitations, trace interpretation, and remaining nondeterministic boundaries.
- [x] Refresh the source-policy baseline only after classifying every new boundary.

**Failure behavior:** Invalid scenario/schema, unsupported capability, backend escape, run failure, replay incompatibility, trace divergence, and artifact I/O failure use separate exit classifications.

**Validation:** CLI integration tests from a temporary artifact root; CI-equivalent command set; fresh-checkout walkthrough; requirement-by-requirement Stage 2 exit-gate audit.

## Execution handoff

Execute this plan inline with the `executing-plans` skill because the kernel, runtime contracts, socket seam, and first production integration are tightly coupled. Use `test-driven-development` for every new behavior, characterization-first tests for production socket refactors, `systematic-debugging` for integration failures, and `verification-before-completion` before claiming the Stage 2 exit gate.
