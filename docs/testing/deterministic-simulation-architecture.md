# Deterministic Simulation Platform Architecture

Status: Proposed; awaiting architecture approval

## Scope

This document proposes the long-term architecture for a deterministic simulation and adversarial testing platform for Iroh. It covers controlled runtime services, real production endpoint/QUIC/path logic, synthetic networking, NAT/firewall/relay/discovery models, scenario execution, invariants, replay, minimization, cross-backend validation, and continuous operation.

The design is intentionally broader than an initial two-endpoint proof of concept. Implementation must remain staged and reversible, but completion means the testing platform can evolve with Iroh's production protocol and supported environments.

The authoritative source is the complete 2026-07-20 specification with SHA-256 `7a5f50cfc7e7b504e0e92c721d7f61d2506b760c8e9f2bdac91c1a5e3aeb048a`. Confirmed repository evidence is separated from proposed design below.

## Goals

- Run production Iroh endpoint, connection, path-management, discovery aggregation, relay client/server, and QUIC behavior inside controlled environments wherever technically feasible.
- Control all behaviorally relevant time, scheduling, randomness, network delivery, DNS/discovery, interface events, NAT/firewall state, port mapping, lifecycle, and resource limits.
- Give every run a stable identity and one-command replay instruction.
- Evaluate safety, bounded-liveness, and cleanup invariants continuously.
- Minimize failures into readable scenarios and a permanent regression corpus.
- Execute the same high-level scenarios through deterministic, Patchbay, local-OS, cross-platform, interoperability, and internet-canary backends where their capabilities overlap.
- Operate quick pull-request gates and increasingly large continuous campaigns without weakening production cryptography.
- Preserve production behavior and avoid statistically significant regressions in existing endpoint, packet, and relay benchmarks.

## Non-Goals

- Reimplementing QUIC, endpoint, connection, path-selection, discovery aggregation, retry, relay, or shutdown state machines in the simulator.
- Replacing Patchbay, fuzzing, property tests, interoperability tests, benchmarks, soak tests, or production telemetry.
- Making deterministic cryptographic entropy a production option.
- Requiring all Tokio-based dependencies to run on the final deterministic executor in the first stage.
- Serializing arbitrary Rust futures as simulator snapshots. Replay from a versioned scenario plus decision trace is the portable source of truth.

## Current Architecture

The production endpoint constructs several independent environment-bound subsystems:

```text
Endpoint::Builder
  -> TLS keys and token material        (platform entropy)
  -> Socket::bind
       -> IP transports                 (netwatch UDP bind/rebind)
       -> relay transport actor         (Tokio + TCP/TLS/WebSocket + DNS)
       -> network monitor               (netwatch OS state)
       -> port mapper                    (OS/router protocols)
       -> net reporter                   (DNS, QUIC, HTTPS, timers)
       -> remote/path actors             (Tokio tasks and timers)
  -> noq::Endpoint
       -> abstract Iroh Transport        (good injection seam)
       -> iroh Runtime                   (Noq-only task/timer seam)
```

The present `TestNetwork` proves that real Noq/QUIC can operate over an in-memory custom transport, but its Tokio channels, custom addresses, real clock, and lack of topology/fault modeling make it a test utility rather than the target simulator.

## Options Considered

### Option A: Extend the existing custom test transport and Tokio paused time

This is the shortest route to a fast prototype. It can exercise production QUIC and application streams with packet loss/delay added around Tokio channels.

It is not the target architecture because it bypasses IP/NAT/interface behavior, does not own scheduling, and cannot prevent production code from escaping to real time or Tokio tasks.

### Option B: Capability-based environment plus a dedicated simulator kernel

Introduce narrow runtime and environment capabilities, keep production implementations as defaults, and build a deterministic executor/network/scenario engine in a new workspace crate. Migrate subsystems incrementally and forbid direct runtime services in simulator-supported paths.

This is the recommended design. It provides architectural determinism without forcing a simultaneous rewrite of every dependency.

### Option C: Run complete binaries inside a deterministic virtual machine or syscall interposer

This maximizes production fidelity at the process boundary, but portable deterministic control of kernel networking, clocks, entropy, scheduling, filesystems, and external TLS/DNS stacks would be substantially more complex and slower. It also gives weaker internal invariant and task-ownership visibility.

Use process/network virtualization only as a complementary realistic backend, not the primary deterministic platform.

## Recommendation

Adopt Option B, preserving Option A only as an early characterization bridge and Option C through Patchbay/`chuck`/platform runners.

The central rule is: simulation-aware production code receives capabilities at construction; it never queries a global simulator, ambient seed, environment variable, or thread-local mode.

## Target Components

### 1. Shared runtime capabilities

A small lockstep-published workspace crate, provisionally `iroh-runtime`, owns internal contracts used by `iroh`, `iroh-dns`, and `iroh-relay`:

- `Clock`: monotonic `now`, cancellable timer creation, and interval construction.
- `WallClock`: certificate-validation time, signed-record timestamps, expiry, and calendar boundaries; production uses system time while simulation derives it from an explicit epoch plus virtual monotonic time.
- `Timer`: poll, reset, deadline, and stable timer ID.
- `Executor`: spawn with task metadata, child group creation, cancellation, join, and task snapshots.
- `TaskGroup`: structured ownership for dynamically spawned children.
- `DecisionSource`: create a domain-separated behavioral random stream from a semantic path.
- `TraceSink`: accept structured environment and component events with a correlation context.
- `RuntimeContext`: aggregate the above capabilities and expose a production Tokio implementation.

Because the published Iroh crates consume these contracts, the crate must be published at the same version rather than relying on an unpublished path dependency. It is not a new end-user configuration surface. Once the contracts stabilize, coordinated changes may move their generic portions into `n0-future` or Noq; the source specification explicitly permits such dependency changes. Starting in Iroh keeps the first migration reviewable and avoids coupling the design to an unproven upstream API.

Injection happens at construction boundaries. Runtime calls that are not packet-hot may use trait objects; packet send/receive and trace-disabled observation paths use the existing Noq socket abstraction, concrete adapters, or static/enum dispatch so the production path does not acquire an avoidable allocation or virtual call per packet.

`iroh::runtime::Runtime` becomes a Noq adapter backed by `RuntimeContext`. It must implement `noq::Runtime::now` explicitly and delegate timers/spawns to the same clock/executor used by the rest of the endpoint.

### 2. Iroh environment capabilities

`iroh` composes runtime services with networking-specific capabilities:

- `IpSocketFactory` / `IpSocket`: bind, poll receive, create sender, rebind, address, GSO/GRO, and fragmentation properties.
- `NetworkMonitor`: current interface state, deterministic change stream, and explicit refresh.
- `PortMapper`: request/deactivate mapping and watch external address.
- `Dns`: the existing resolver response interface plus environment-owned time/reset behavior.
- `RelayConnector`: construct relay sessions without hard-coding TCP/TLS/WebSocket in the relay actor.
- `CryptoMaterial`: secure reset/token/challenge material. Production construction always installs the operating-system entropy implementation; only the explicit simulation environment can install deterministic material.
- `ComponentObserver`: emit endpoint, connection, path, discovery, relay, and resource state transitions.

`Endpoint::Builder::bind` uses the production environment by default. A deliberately separate, documented-as-unstable internal constructor accepts an explicit environment for `iroh-sim` and repository tests. Environment selection cannot be triggered by ambient environment variables or a production behavior feature flag. The constructor requires an unsafe-test marker that is recorded in the run manifest whenever deterministic cryptographic material is present.

### 3. Deterministic simulator kernel

A new `iroh-sim` workspace crate owns the virtual clock and deterministic scheduler:

- a single logical monotonic timeline represented as integer nanoseconds from a run epoch;
- an explicit wall-clock epoch, advanced only with logical time and recorded in the run manifest;
- an event queue ordered by `(deadline, event class, stable event ID)`;
- a ready-task queue with FIFO and seeded legal-choice scheduling modes;
- stable task IDs derived from parent ID and child creation ordinal;
- stable timer, packet, interface, mapping, relay, operation, and invariant IDs;
- automatic advance to the next event only when no task is runnable;
- event-count and virtual-time budgets;
- quiescence, deadlock, stalled-progress, livelock, and timer/task leak detection;
- a resource ledger for live tasks, timers, sockets, mappings, connections, streams, queued packets, discovery records, and trace buffers.

Stage 1 may use a current-thread Tokio bridge for code not yet migrated, but every bridge escape is recorded and disqualifies a run from `fully_deterministic`. The final supported core path runs on the kernel executor.

### 4. Domain-separated decisions

The run starts with a root seed. Subsystems request streams using stable semantic paths such as:

```text
scenario
scheduler
endpoint/A/noq
endpoint/A/restun
endpoint/B/noq
network/link/public-a
nat/home-a/mapping
relay/r1/client/A/reconnect
discovery/provider/dns
application/client-1
```

Streams use a documented derivation algorithm and per-stream draw counter. A trace records `(path, draw index, sampled value or selected alternative)`. Adding a draw to one path cannot perturb another path.

Cryptographic randomness is never obtained from `DecisionSource`. Deterministic test identities and protocol secrets are derived through a separate simulation-only constructor and are labeled unsafe outside simulation.

A simulator-owned `FaultController` turns normalized scenario rules into explicit events. It operates only through environment capabilities and supports:

- network decisions: loss, delay, duplication, corruption, partition, reorder-window placement, and MTU rejection;
- runtime decisions: legal ready-task selection, cancellation injection at declared lifecycle points, and deterministic resolution of timer/completion races;
- infrastructure transitions: relay crash/restart/outage, DNS/discovery failure/recovery, interface and route changes, NAT expiry/rebind/public-address change, and sleep/resume.

Every injected fault records its rule ID, eligible event, decision stream/draw, outcome, and causal children. A fault cannot call into a production component through a test-only mutation hook; it changes the environment observed by production code.

### 5. Synthetic IP network

The synthetic network implements Iroh's `IpSocket` boundary and operates on IP/UDP datagrams while real Noq implements QUIC.

State includes:

- hosts, interfaces, addresses, routes, links, and gateways;
- IPv4, IPv6, dual-stack, and broken/partial IPv6 behavior;
- latency, bandwidth token buckets, bounded queues, MTU, congestion, and directional reachability;
- loss, duplication, reordering, corruption, partitions, and temporary outages;
- interface addition/removal, route/address replacement, mobility, sleep/resume, and service restart;
- multi-hop forwarding and relay-reachable topologies.

Each outbound datagram becomes a traceable packet entity. Fault rules make deterministic decisions before scheduling zero or more delivery events. Queue overflow, no-route, firewall rejection, MTU rejection, and socket closure have distinct outcomes.

IP fragmentation is modeled only to the degree exposed at the UDP/socket boundary. The simulator does not implement QUIC semantics.

### 6. NAT and firewall state machines

NAT/firewall nodes are independent behavioral modules in the network graph. A NAT mapping key and inbound filter key are configured separately to cover endpoint-independent, address-dependent, and address-and-port-dependent behavior.

The model includes port preservation/randomization, collision resolution, expiry, rebinding, hairpinning, public address changes, nested/double NAT, carrier-grade NAT, stateful firewall rules, UDP blocking, and family-specific reachability.

Every mapping create/refresh/expire/collision/rebind event is traced. Mapping and filtering behavior receives scenario/fault streams rather than global randomness.

Simulator NAT models require parity scenarios against Patchbay and documented real-router observations before they are trusted as predictors.

### 7. Relay execution

Relay support is delivered in three explicit fidelity levels:

1. **Reference routing model:** a pure forwarding model acts as an oracle for routing correctness and enables topology work before transport-independent relay handlers are extracted. It never satisfies production-relay coverage or relay invariants by itself.
2. **Production client protocol:** `RelayConnector` supplies a synthetic framed stream so the real Iroh relay actor, reconnect, authentication, and client framing run in simulation.
3. **Production client and server:** extract transport-independent relay connection/session handlers from Hyper/Tokio listeners. Synthetic listeners run the same client/server protocol code; OS TCP/TLS/WebSocket adapters remain production defaults.

The platform does not claim relay coverage at level 1. The model remains useful long term for differential checks against levels 2 and 3; it is not a temporary fake implementation. Target scenarios cover relay-only connection, distinct relays, discovery/selection, restart/outage/partial loss, delay/drop/overload/rate limiting, stale configuration, direct upgrade/failure, and fallback.

### 8. Discovery and DNS

Deterministic `AddressLookup` and `iroh_dns::Resolver` providers schedule versioned records through the simulator clock. They support success, delay, absence, stale/conflicting/partial records, duplicates, reordering, disagreement, outage, negative cache behavior, expiry, and resolver replacement.

Production `AddressLookupServices`, update aggregation, source tracking, expiry, and path selection remain unchanged and are observed through component events. Production DNS/Pkarr/mDNS/Mainline implementations retain separate integration suites.

### 9. Scenario model

The scenario schema is versioned and serializable. A scenario contains:

- metadata and schema version;
- topology, hosts, interfaces, routes, links, NATs, firewalls, relays, and discovery providers;
- endpoint identity/configuration and feature flags;
- ordered or trigger-based application actions;
- fault profiles and scheduling mode;
- fairness assumptions;
- virtual-time, event, task, memory, queue, packet, and connection limits;
- completion conditions and allowed terminal states;
- enabled invariants and their bounds.

The action vocabulary includes every action listed in the source specification: endpoint create/start/stop/restart; address publish/remove; dial/cancel/accept/reject; stream and datagram operations; connection close; interface/address/route/NAT changes; relay lifecycle; partition/heal; packet faults; link parameter changes; time advance; and component crash/restore.

Handwritten scenarios use Rust builders and a human-editable YAML or JSON representation. Generated scenarios produce the same normalized representation. Unknown fields are rejected for a given schema version.

### 10. Scenario backends

`ScenarioBackend` exposes capability discovery and lifecycle/action execution. Backends are:

- `DeterministicBackend`: full synthetic environment and invariant observation.
- `PatchbayBackend`: Linux namespaces, production sockets, and real relay/DNS processes for supported topology/actions.
- `LocalOsBackend`: real loopback/local sockets for transport interoperability and lifecycle checks.
- `PlatformBackend`: remote Windows/macOS/Android/wasm runners for portable scenario subsets.
- `InternetCanaryBackend`: explicitly allowlisted, low-rate production-like probes.

A scenario declares required capabilities. Unsupported backends skip with a machine-readable reason; they never silently approximate an action. Cross-backend parity compares high-level observations and terminal outcomes, not packet-for-packet traces.

### 11. Observation and invariant framework

Production components emit immutable observations through a no-op-by-default observer. Observation is not a mutation/control API.

An invariant definition contains:

- stable name and schema version;
- global or entity-local scope;
- required observation kinds;
- safety, bounded-liveness, or cleanup class;
- evaluation points;
- related entity IDs;
- fairness assumptions;
- virtual-time and event-count bounds;
- structured failure evidence.

Safety invariants run after every relevant state transition and before quiescence advances time. Liveness invariants register obligations and deadlines; they pass only after the required event and fail when a bound expires under satisfied fairness assumptions. Cleanup invariants run after completion and bounded shutdown.

Initial invariant families cover all available source requirements:

- authentication and immutable remote identity;
- correct endpoint/connection/stream delivery, byte integrity, ordering, and reset/stop semantics;
- valid monotonic connection lifecycle and eventual termination visibility;
- valid path ownership/selection/counts and convergent relay/direct transitions;
- endpoint shutdown completion, task cleanup, and release of sockets, timers, connections, streams, mappings, and queued packets;
- relay routing correctness: a relay never crosses authenticated source/destination identities or delivers to an unaddressed endpoint;
- discovery convergence and eventual expiry of stale records under declared provider/time assumptions;
- resource ceilings and absence of leaked tasks/timers/sockets/connections/streams/packets;
- bounded connection, usable-path migration, retry, and shutdown progress under stable reachable topology and declared fairness.

### 12. Reference models

Reference models are pure, smaller state machines for endpoint, connection, stream, address set, path eligibility, discovery expiry, relay availability, and resource ownership. They consume scenario operations and externally observable results only.

They define allowed result sets and state transitions, not protocol timing or internal packet behavior. Generated operation sequences compare production observations with model-permitted states, error classes, idempotency, cleanup, and visibility.

### 13. Run identity, trace, replay, and snapshots

Every run emits a versioned manifest containing at least:

- source revision and dirty-worktree digest;
- root seed and scenario ID/hash;
- simulator and schema versions;
- normalized configuration and feature flags;
- virtual wall-clock epoch and time-zone-independent calendar policy;
- platform assumptions and backend capability set;
- maximum virtual duration and event count;
- fault profile and scheduling mode;
- dependency lockfile digest;
- determinism grade and any recorded environment escapes.

Trace records have a global sequence number, virtual timestamp, event kind/version, causal parent, decision reference, and typed optional references for task, endpoint, connection, stream, packet, relay, NAT, interface, and invariant entities. State transitions and fault decisions are first-class event kinds. Large packet/application payloads are hashed and optionally retained separately.

On failure the CLI prints exactly one local replay command, for example:

```text
cargo sim replay artifacts/run.json
```

Replay verifies source/config compatibility, reuses the normalized scenario and decision trace, and fails immediately on event-sequence divergence.

Portable snapshots consist of normalized scenario state, simulator world state, resource ledger, and decision prefix. Arbitrary futures are not serialized; replay restarts production tasks from the beginning and fast-forwards deterministically. A later restartable-component checkpoint format may optimize very long runs without becoming the canonical reproducer.

### 14. Failure minimization and corpus

The minimizer repeatedly replays a failure signature while attempting, in order:

- action deletion and subsequence reduction;
- fault-rule deletion and probability simplification;
- endpoint, relay, NAT, interface, link, and provider removal;
- packet, payload, operation-count, delay, duration, and budget reduction;
- concurrent-operation serialization and schedule-choice prefix reduction;
- seed canonicalization where the same decisions remain reachable.

A failure signature includes invariant name, normalized responsible entities, terminal error class, and a bounded causal trace suffix. Minimized scenarios are reviewed into a versioned corpus. CI runs both named scenarios and historical seeds; corpus entries record the original issue and minimum simulator/schema compatibility.

### 15. CLI and developer workflow

The dedicated CLI supports:

```text
cargo sim run <scenario> --seed <seed>
cargo sim campaign <scenario-set> --seeds <range> --jobs <n>
cargo sim replay <run-manifest>
cargo sim minimize <run-manifest>
cargo sim corpus test
cargo sim explain <run-manifest>
```

All failure exits print the artifact directory and replay command. `explain` renders the causal event slice, outstanding liveness obligations, resource ledger, task tree, timers, routes, NAT mappings, and active paths.

### 16. Continuous operation

Campaign tiers are proposed as:

- Pull requests: deterministic smoke scenarios plus permanent corpus, bounded by a small event budget.
- Main branch: broader topology/fault/schedule matrix and cross-backend parity subset.
- Nightly: randomized generated scenarios, rare scheduling mode, minimization, and Patchbay comparisons.
- Continuous dedicated runners: sharded unbounded seed ranges with simulator-version/source identity and durable failure artifacts.
- Weekly/platform: expanded Windows/macOS/Android/wasm subsets, QUIC interoperability, soak, and performance regressions.

Promotion rules move every unique minimized failure into the permanent corpus. Simulator flakiness is itself a release-blocking correctness defect: replay divergence stores both traces and the first mismatching event.

## Security

- Production cryptographic entropy remains the default and cannot be selected from behavioral seeds.
- Simulation crypto providers are reachable only through the explicit internal simulation-environment constructor and emit an unsafe-test-only marker in every manifest and trace; no behavior-selection feature flag can enable them on the normal builder path.
- Scenario files cannot request arbitrary filesystem paths, processes, or internet destinations in hermetic CI.
- Traces redact production secrets and default to payload hashes.
- Internet canaries use allowlists, rate limits, isolated credentials, and separate workflows.
- Fault injection operates on simulator-owned objects; it cannot mutate unrelated host resources.

## Reliability and Failure Handling

- A simulator panic, invariant failure, resource-limit breach, deadlock, livelock, timeout, escape, and backend infrastructure failure have distinct exit classifications.
- The runner writes its manifest before executing actions and appends trace chunks atomically so crashes preserve a replayable prefix.
- Deterministic backend runs must not use wall-clock time for correctness. Wall-clock watchdogs only terminate hung harness processes and are reported separately.
- Event queues, packet queues, trace buffers, tasks, timers, paths, mappings, and connections have explicit limits and high-water observations.
- Version mismatch never silently replays with changed semantics; migration tooling produces a new manifest and records the conversion.

## Deliverable Traceability

| Source deliverable | Owning component / stage | Acceptance evidence |
| --- | --- | --- |
| 1. Repository audit | `docs/testing/determinism-audit.md`, Stage 0 | Revision-pinned occurrence baseline, classifications, and source-policy check pass. |
| 2. Architecture proposal | This document | Complete design approval with no blocking open decision. |
| 3. Runtime abstraction | `iroh-runtime`, Stages 1 and 6 | Production and deterministic adapters pass shared clock/task/cancellation contracts; no core executor escapes. |
| 4. Deterministic clock | Simulator kernel, Stages 1 and 2 | Timer ordering/reset/cancel/leak tests and long virtual-duration scenarios replay exactly. |
| 5. Synthetic networking | Virtual IP/UDP graph, Stage 2 | Production Noq/QUIC passes IPv4, IPv6, routing, link-fault, MTU, bandwidth, and mobility scenarios. |
| 6. Relay simulation | Relay connector/session extraction, Stage 5 | Production client/server handlers pass relay-only, restart, outage, upgrade, direct-upgrade, fallback, and multi-relay invariants. |
| 7. NAT simulation | NAT/firewall nodes, Stage 4 | Public, endpoint-independent, address-dependent, address-and-port-dependent, expiry, hairpin, double-NAT, CGNAT, and rebinding parity suite passes. |
| 8. Discovery simulation | Deterministic DNS/address providers, Stage 4 | Delayed, stale, conflicting, missing, DNS-failure, and provider-failure scenarios exercise production aggregation and expiry. |
| 9. Fault injection | Decision streams and network/runtime/infrastructure controllers, Stages 2–5 | Every specified fault is traceable and same-run replay reproduces its decisions. |
| 10. Invariant framework | Observer, obligation engine, resource ledger, Stage 3 | Mutation/negative tests prove continuous authentication, delivery, lifecycle, path, endpoint, relay, discovery, resource, and liveness checks. |
| 11. Replay system | Run manifest and replay engine, Stages 1 and 3 | Every induced failure emits one command that reproduces the normalized failure and detects divergence. |
| 12. Trace system | Versioned structured trace, Stage 1 | Schema contains all required entity/fault/state fields; normalized traces are identical for same revision/config/seed. |
| 13. Scenario engine | Schema, generators, and backends, Stages 3–7 | Handwritten and generated scenarios normalize identically and capability-compatible subsets run on deterministic and Patchbay backends. |
| 14. Shrinker | Failure-signature minimizer, Stage 3 | Seeded multi-cause fixtures reduce endpoints, relays, actions, packets, delays, and concurrency while preserving failure. |
| 15. Regression corpus | Versioned scenario/seed corpus, Stage 3 | CI enumerates every compatible entry; unique minimized failures are promoted with provenance. |
| 16. CI integration | PR/main/scheduled workflows, Stages 3 and 7 | Required tier gates, artifacts, replay commands, and campaign sharding operate within approved budgets. |
| 17. Documentation | Audit, architecture, scenario/replay/triage/runbook docs, all stages | Fresh-checkout developer and operator walkthroughs pass without undocumented state. |

The maintained testing stack remains broader than these deliverables. Unit, property, fuzz, deterministic simulation, Patchbay, cross-platform, interoperability, benchmark, soak, and production-assertion layers each retain distinct owners and failure semantics.

## Migration Plan

### Stage 0: Audit, contracts, and guards

- Freeze the living audit baseline against the complete source requirements.
- Add characterization tests around endpoint construction/shutdown, runtime time, task ownership, path ties/pruning, DNS reset/timeouts, and relay jitter.
- Characterize Noq TLS time-source plumbing, memory-address timestamps, relay daily counters, and signed-packet expiry before changing wall-clock providers.
- Introduce source-policy checks for new direct spawn/time/random/bind calls in simulator-supported modules.

Exit gate: every known nondeterministic dependency is classified and new occurrences fail CI unless allowlisted.

### Stage 1: Shared runtime and run identity

- Add runtime capability contracts and the production Tokio implementation.
- Route core Iroh/Noq monotonic clocks, wall clocks, and root tasks through one context.
- Plumb Noq RNG seeds and explicit deterministic test identities.
- Implement run manifest, normalized scenario metadata, trace schema, and replay CLI skeleton.

Exit gate: a timer/task/lifecycle scenario has byte-identical normalized traces across repeated local runs.

### Stage 2: Deterministic executor and synthetic direct IP

- Implement event/ready queues, stable IDs, virtual clock, timer cancellation/leak checks, and deterministic UDP sockets.
- Generalize `IpTransport` socket creation/rebind.
- Run real endpoint/Noq/QUIC stream and datagram operations over IPv4/IPv6 synthetic links.
- Detect uncontrolled executor/time/socket escapes.

Exit gate: repeated multi-endpoint runs with long virtual durations reproduce event-for-event and leave an empty resource ledger.

### Stage 3: Scenario, faults, invariants, minimization, and corpus

- Add the declarative action model and generated scenarios.
- Add packet/link faults and resource limits.
- Implement invariant registry, liveness obligations, reference-model harness, failure signature, minimizer, and corpus.
- Add pull-request and nightly campaign workflows.

Exit gate: an intentionally injected bug/fault yields one-command replay and a smaller permanent regression scenario.

### Stage 4: NAT, firewall, discovery, and mobility

- Implement all specified NAT/filtering/firewall/family behaviors.
- Add deterministic DNS/discovery providers and expiry/update ordering.
- Inject interface monitoring, port mapping, route/address changes, and sleep/resume.
- Port representative Patchbay NAT, degradation, outage, and switch-uplink scenarios to the common model.

Exit gate: scenario outcome parity is documented across deterministic and Patchbay backends for the agreed matrix.

### Stage 5: Relay production paths

- Add relay connector/session seams and routing-model coverage.
- Run production relay client protocol on synthetic streams.
- Extract and run production server session logic; add overload/rate-limit/restart/fallback scenarios.
- Validate the simplified adapter against the production server until it can be retired.

Exit gate: relay-only, direct upgrade, direct failure, and relay fallback scenarios continuously check identity/data/liveness invariants using production client/server state machines.

Status: implemented. The selected boundary bypasses only DNS/TCP/TLS/HTTP listener mechanics;
production WebSocket framing, authentication, authorization, client/server actors, registry,
routing, reconnect, path selection, and QUIC execute. The permanent pure routing oracle is retained
for differential checks and is excluded from production coverage.

### Stage 6: Controlled scheduling and resource ownership

- Migrate remaining core child task sets.
- Add seed-controlled ready-task choices, fairness accounting, task ownership graphs, deadlock/stall/livelock detection, and accidental Tokio-spawn detection.
- Document and gate any dependency that remains outside controlled scheduling.

Exit gate: all declared simulator-supported code paths have no silent executor escape and rare-schedule campaigns are replayable.

Status: implemented for simulator-supported paths. Production endpoint/Noq/socket/relay roots and
native active-relay/remote-state children run on `KernelExecutor`; causal ready waves use the
seeded `kernel/ready-task` stream with bounded fairness, ownership snapshots, and distinct
stalled/runnable-budget diagnostics. Socket, remote-map, relay-client, relay-server, lifecycle,
and shutdown timing are kernel-owned. Manifest schema 3 gives the deterministic-test lane a
`fully_deterministic` grade with raw replay and the production-provider lane a
`semantically_deterministic` grade with semantic replay.

### Stage 7: Cross-backend and operational maturity

- Complete Patchbay/local/platform/internet adapters for supported actions.
- Add interoperability, real-router observation fixtures, soak, and performance correlation.
- Establish campaign sharding, artifact retention, triage, corpus review, schema migration, and simulator self-tests.

Exit gate: the platform is an owned engineering service with documented SLOs, triage workflow, and recurring parity reports.

Status: implemented for the currently declared capability overlap. Strict parity fixtures now
carry deterministic, production-local, Patchbay, or platform semantic evidence with source/run
identity, scenario digest, observed dimensions, and bounded freshness; `cargo sim parity` exports
immutable deterministic fixtures, compares only common capabilities, and fails strict automation
on differences, skips, or stale evidence. A checked operations policy fixes tier and swarm budgets,
retention, a 24-hour triage SLO, exact-source replay, and corpus review.
PR/nightly/weekly workflows execute bounded campaigns, parity reports, soaks, and correlated
component benchmarks. Unsupported realistic-backend dimensions remain explicit skips and are
tracked in the operator runbook rather than approximated.

## Verification Plan

| Requirement | Evidence required |
| --- | --- |
| Same seed/config/revision is deterministic | Repeated clean-process runs produce the same normalized event sequence and terminal result on each supported host architecture. |
| Production code is exercised | Coverage and trace evidence show production endpoint, Noq, path, discovery aggregation, and stage-appropriate relay code in the call path. |
| No core escape | Runtime instrumentation and source policy report zero unapproved direct time/spawn/socket/random calls. |
| Virtual time is complete | Long-duration timer scenarios complete without corresponding wall-clock sleeps; timer create/reset/cancel/fire/leak events balance. |
| Wall time is controlled | Certificate checks, signed-record freshness, address-update timestamps, storage expiry, and relay calendar boundaries derive from the manifest epoch. |
| Faults are deterministic | Every fault references a named decision and replay reproduces packet outcomes. |
| Invariants are continuous | Mutation tests that create transient invalid states fail at the relevant event, even if the final state recovers. |
| Liveness is bounded and fair | Obligation tests distinguish unreachable/unfair runs from reachable stalled runs and include both time/event bounds. |
| Cleanup is complete | Successful and failed scenarios end with allowed resource-ledger contents only. |
| Replay works | Every failure artifact prints and passes a clean one-command replay at the recorded source revision. |
| Minimization works | Synthetic multi-cause failures reduce while preserving their normalized failure signature. |
| Corpus is permanent | CI enumerates and runs every compatible corpus entry; removal requires explicit metadata/change review. |
| NAT/relay models are credible | Parity suites compare deterministic observations with Patchbay/real implementations and track known divergences. |
| Cross-platform layers complement simulation | Platform and interoperability workflows execute capability-compatible shared scenarios and publish comparable outcomes. |
| Production performance is preserved | Existing endpoint, packet-throughput, connection-establishment, and relay benchmarks show no statistically significant regression; any changed baseline requires explicit performance review. |

## Acceptance Criteria

The long-term objective is achieved only when all stages' exit gates pass and every requirement from the complete source specification has authoritative evidence. A two-endpoint connection, a virtual clock alone, a deterministic network model that bypasses production state machines, or a passing fixed seed set is insufficient.

## Evidence

- **Implemented (Stage 0–1):** the reviewed boundary manifest and CI drift gate cover production crates, `iroh-runtime`, and `iroh-sim`.
- **Implemented (Stage 1):** Iroh and Noq use an explicitly injected runtime context for native monotonic time, timers, wall time, behavioral RNG seed, structured root tasks, cancellation, and trace sequencing; normal builders retain secure production defaults.
- **Implemented (Stage 2, since extended):** strict `cargo sim run` and `replay` execute named IPv4/IPv6 stream, IPv6 datagram, loss-recovery, and corruption-failure scenarios; write the manifest before execution plus crash-preserving atomic trace chunks and final raw/normalized traces; and verify source/config/backend identity. Schema 3 replay now compares the manifest-selected raw or semantic trace.
- **Implemented (Stage 2):** a single-thread kernel owns FIFO task polling, virtual monotonic/wall clocks, stable event ordering, timer reset/drop semantics, hard event/time/task/packet bounds, quiescence classification, and resource ledgers.
- **Implemented (Stage 2):** production Iroh/Noq/QUIC uses injected production-compatible IP socket and monitor capabilities over a routed synthetic IPv4/IPv6 network with bandwidth, latency, MTU, bounded queues, partitions, loss, duplication, corruption, reordering, rebind, and structured packet creation/hop/outcome events.
- **Verified (Stage 2 exit gate):** production IPv4 and IPv6 QUIC streams plus IPv6 QUIC datagrams exchange application data over synthetic IP; seeded loss recovers and seeded corruption reaches its specified authenticated failure; repeated normalized traces match; multi-day virtual timers do not sleep; and successful or expected-failure shutdown reconciles Stage 2 resources to zero.
- **Resolved (deterministic closure):** the deterministic-test lane owns TLS/KX, QUIC connection-ID, and relay-challenge entropy, records zero escapes, and requires raw replay. The production-provider lane retains only production cryptographic entropy and requires semantic replay.
- **Verified (Stage 1 exit gate):** repeated fixed-seed timer/task/lifecycle runs produce byte-identical normalized traces and endpoint shutdown leaves the migrated structured task snapshot empty.
- **Confirmed:** Noq runtime/socket/RNG seams exist in locked versions; see `docs/testing/determinism-audit.md`.
- **Confirmed:** Iroh already has custom transports, discovery provider traits, DNS resolver traits, endpoint hooks, path observers, Patchbay scenarios, external process netsim, and cross-platform workflows.
- **Confirmed:** Production defaults retain OS socket, relay, DNS, network-monitor, and port-mapper adapters; simulator-supported paths select explicit injected capabilities.
- **Implemented through Stage 3:** strict declarative/generated actions, continuous typed observations and ordered invariants, reference-model execution, first-class failure signatures/artifacts, exact-signature minimization, reviewed corpus enforcement, deterministic campaign batching, and PR/nightly campaign tiers.
- **Implemented through Stage 6 task ownership:** NAT/discovery/mobility capabilities, production relay client/server sessions, seeded fair kernel scheduling, task/scheduler artifacts, direct and relay schedule replay, runtime-owned active-relay and remote-state actors, relay lifecycle/path scenarios, relay minimization/corpus/CI, and semantic parity contracts.
- **Implemented (Stage 7):** strict fixture-to-fixture semantic comparison, immutable deterministic parity export, a validated engineering-service policy, PR/nightly/weekly campaign tiers, 14/30-day artifact retention, 24-hour triage SLO, exact-source/schema migration rules, corpus promotion, recurring soaks, and performance correlation.
- **Remaining declared boundary:** production cryptographic entropy is intentional and isolated to the `semantically_deterministic` production-provider lane; realistic backends publish only capabilities they actually observe.
- **Confirmed by source specification:** coordinated internal-dependency changes are permitted when needed for maintainable abstractions.
- **Resolved operational defaults:** `iroh-sim/operations-policy.json` defines campaign budgets, artifact retention, the exact-source replay window, and corpus review requirements.

## Open Questions

1. Which additional Patchbay, platform, interoperability, and real-router jobs should gain semantic fixture exporters as their observations become stable?
2. Which additional simulator-supported production subsystems should be admitted only after their executor, time, environment, and entropy boundaries satisfy the same grade matrix?

## Review Resolution

- Resolved: complete endpoint, relay, discovery, resource, and liveness invariant requirements are now explicit.
- Resolved: the lightweight relay model is a permanent differential oracle and cannot satisfy production-relay coverage.
- Resolved: production/simulation selection uses constructor injection, not ambient state or behavior-selection feature flags.
- Resolved: all 17 deliverables now map to an owner, migration stage, and observable acceptance evidence.
- Resolved: internal dependency changes are allowed; the recommended first boundary is a lockstep-published `iroh-runtime` crate, with later upstreaming based on proven contracts.
- Resolved: operational budgets, retention, triage, corpus review, and replay compatibility are checked policy rather than undocumented runner assumptions.

## Change Summary

- Reconciled the architecture with the complete hash-pinned source specification.
- Added production-performance constraints, exact invariant coverage, typed trace entities, and explicit shrink dimensions.
- Added end-to-end deliverable traceability and removed all truncated-source assumptions.
