# Deterministic Simulation

Iroh's simulation platform is built around capability injection: production and simulation run the same endpoint and Noq code while supplying different clocks, executors, behavioral decisions, sockets, and infrastructure. The source audit and approved architecture are in [`determinism-audit.md`](determinism-audit.md) and [`deterministic-simulation-architecture.md`](deterministic-simulation-architecture.md).

## Current support: deterministic closure

Stage 2 runs production Iroh, Noq, TLS, QUIC stream, and QUIC datagram code over an in-memory IPv4/IPv6 packet network. The simulator owns link latency and bandwidth, MTU and queue bounds, routes, partitions, deterministic packet faults, virtual Iroh clocks, behavioral decisions, and resource accounting.

Stage 3 adds one strict declarative schema shared by JSON, Rust builders, deterministic generation, replay, minimization, and the permanent corpus. The runner executes those actions through the same production endpoint/Noq/TLS/QUIC path, continuously feeds typed observations to ordered safety/liveness/cleanup invariants, and checks action outcomes against a pure reference model.

Stage 4 activates stateful IPv4 NAT and ordered firewalls, double NAT/CGNAT chains, deterministic
port mapping, mapping expiry/rebind, mutable interfaces/addresses/routes, sleep/resume, bounded
discovery providers, and injected DNS timeout/stagger jitter. Production QUIC, endpoint identity,
address aggregation, socket rebind, and monitor consumption remain the real implementations.
Capability requirements still fail closed.

Stage 5 runs the production Iroh relay actor plus production relay client/server WebSocket framing,
challenge authentication, authorization, client actor, registry, and routing over bounded
simulator-owned byte pipes. The synthetic boundary replaces only DNS/TCP/TLS/HTTP listener setup.
Relay-only, restart/outage, initially unavailable home relay, direct upgrade, direct failure and
fallback, multiple-relay isolation, endpoint reincarnation, overload, duplicate identity, and
shutdown-during-reconnect cases retain production QUIC above the relay path. Per-relay coverage
observations prove connection attempts, authenticated sessions, and forwarded frames. A separate
pure routing oracle is used only for differential checks and never satisfies production coverage.

Stage 6 moves production endpoint, Noq, socket-actor, and relay-actor roots onto the deterministic
kernel executor. A `kernel/ready-task` stream selects eligible tasks within causal ready waves;
the scheduler reports decisions, maximum wait, and fairness-forced choices, and forces an eligible
waiter after 32 selections. Trace schema 2 records `task_scheduled` events with the selected task
and ownership metadata. Terminal reports and failure artifacts include scheduler and historical
task-ownership snapshots, while runnable budget exhaustion is distinct from blocked quiescence.
The socket actor's periodic re-STUN and network-change timers use the injected clock, re-STUN
jitter uses a per-endpoint decision stream, and internal multi-ready selection has an explicit
branch order. Same-seed direct and relay production-QUIC replay are regression-tested.

- `iroh-runtime` defines stable IDs, a monotonic `Clock`, `WallClock`, resettable timers, structured task groups, domain-separated decision streams, the global trace schema, and `RuntimeContext`.
- Normal `Endpoint::builder(...).bind()` installs Tokio, system wall time, an OS-backed behavioral root seed, and a no-op trace sink. Endpoint identities, TLS token keys, and QUIC reset keys still use cryptographic randomness.
- The explicit, doc-hidden `Builder::runtime_context_for_test` path requires `UnsafeTestOnly::acknowledge()`. It is constructor injection, never an environment-variable or feature selection. The marker means “not a production default”; it does not weaken Rust memory safety.
- Iroh's Noq adapter delegates `now`, timers, and task spawning to one context. The endpoint supplies Noq with a behavioral RNG seed from `endpoint/<endpoint-id>/noq`. Token validity uses the context wall clock.
- Noq, socket, relay, direct-address report, active-relay, and remote-state actors run under the injected runtime and participate in structured cancellation and shutdown snapshots.

The production-endpoint lanes drive harness roots directly around kernel steps; they no
longer spawns paired Tokio harness tasks. Remote-map, relay-client, relay-impairment, net-report,
and shutdown deadlines use the injected clock, and relay ping/backoff choices use named decision
streams. Relay-server client actors now use the same injected executor, clock, wall clock, and
decision source as the endpoints. A narrow workspace Rustls 0.23.41 fork changes provider
component ownership from static references to owned `Arc`s. This permits run-owned,
endpoint-scoped deterministic random/X25519 components without leaks, process globals, or worker
coupling. Simulation-only QUIC connection IDs and relay authentication challenges are likewise
domain-separated from the run seed.

Manifest schema 3 records two explicit lanes. `deterministic_test` has no escapes, records
`deterministic_test_crypto` as a fidelity exception, receives `fully_deterministic`, and requires
raw trace equality. `production_provider` retains exactly `production_crypto_entropy`, receives
`semantically_deterministic`, and requires normalized replay masking only opaque ciphertext.

## Run identity

`iroh-sim::RunManifest` is strict JSON with unknown-field rejection. It records:

- source revision and dirty-tree digest;
- behavioral root seed;
- normalized scenario ID and digest;
- simulator and schema versions;
- sorted feature/configuration identity and Cargo.lock digest;
- deterministic wall-clock epoch;
- backend capabilities, determinism grade, crypto mode, and trace-comparison mode;
- sorted fidelity exceptions and observed escapes;
- event, virtual-time, task, and packet budgets;
- scheduling/fault profiles, unsafe-test marker, and explicit escapes.

Seeds and digests are lowercase fixed-width hexadecimal. Lists are sorted and unique. Host paths are rejected. Exact replay checks schema, simulator, source, dirty tree, scenario, features/configuration, and lockfile before execution; mismatches never silently proceed.

## Traces and artifacts

Runtime events contain a global sequence, run-relative virtual timestamp, typed entity references, and a versioned payload. Task spawn/completion/cancellation/panic/rejection, timer create/reset/fire/drop, decisions, state transitions, packet creation/per-hop scheduling/terminal outcomes, and fault observations have stable serialized forms.

`ArtifactStore` requires an explicit absolute directory internally; the CLI resolves relative paths before construction. It writes immutable `manifest.json`, normalized `trace.jsonl`, and forensic `trace.raw.jsonl` artifacts through a same-directory temporary file, `sync_all`, and atomic rename. During execution it also publishes bounded `trace.chunk.*.jsonl` and `trace.raw.chunk.*.jsonl` prefixes atomically, so a harness crash retains every completed chunk. It never overwrites an existing artifact. Trace normalization recursively redacts absolute host paths and opaque encrypted packet hashes. Replay uses the immutable manifest mode: deterministic-test artifacts compare raw events, while production-provider artifacts compare normalized events. Repeated direct and relay runs assert byte equality; production-provider repeats and cross-lane runs assert semantic equality.

## Command surface

Build or inspect the command with:

```bash
cargo run -p iroh-sim --bin cargo-sim -- --help
```

The stable command surface is `run`, `campaign`, `replay`, `minimize`, `corpus`, and `explain`.
Stage 5 activates all six commands for direct IP, NAT/firewall, discovery, mobility, relay
lifecycle, and relay/direct path scenarios.

Run either checked-in Stage 2 scenario with an explicit behavioral seed:

```bash
cargo run -p iroh-sim --bin cargo-sim -- run \
  iroh-sim/tests/fixtures/ipv4-stream.json \
  --seed 1111111111111111111111111111111111111111111111111111111111111111 \
  --artifacts /tmp/iroh-sim-ipv4

cargo run -p iroh-sim --bin cargo-sim -- replay \
  /tmp/iroh-sim-ipv4/manifest.json

# Exercise the production cryptographic provider with semantic replay.
cargo run -p iroh-sim --bin cargo-sim -- run \
  iroh-sim/tests/fixtures/ipv4-stream.json \
  --seed 2222222222222222222222222222222222222222222222222222222222222222 \
  --crypto production-provider \
  --artifacts /tmp/iroh-sim-ipv4-production-crypto

cargo run -p iroh-sim --bin cargo-sim -- replay \
  /tmp/iroh-sim-ipv4-production-crypto/manifest.json
```

Run a declarative scenario, test the reviewed corpus, and execute a bounded campaign:

```bash
cargo run -p iroh-sim --bin cargo-sim -- run \
  iroh-sim/tests/fixtures/v2-ipv4-stream.json \
  --seed 1212121212121212121212121212121212121212121212121212121212121212 \
  --artifacts /tmp/iroh-sim-v2

cargo run -p iroh-sim --bin cargo-sim -- corpus test iroh-sim/corpus

cargo run -p iroh-sim --bin cargo-sim -- campaign \
  iroh-sim/tests/fixtures/v2-ipv4-stream.json \
  --seeds 0..100 --jobs 4 --generated --continue-on-failure \
  --artifacts /tmp/iroh-sim-campaign

cargo run -p iroh-sim --bin cargo-sim -- campaign \
  iroh-sim/corpus/stage4-nat-rebind-expiry/scenario.json \
  --seeds 0..100 --jobs 4 --continue-on-failure \
  --artifacts /tmp/iroh-sim-nat-campaign

cargo run -p iroh-sim --bin cargo-sim -- campaign \
  iroh-sim/corpus/stage5-relay-restart/scenario.json \
  --seeds 0..100 --jobs 4 --continue-on-failure \
  --artifacts /tmp/iroh-sim-relay-campaign

cargo run -p iroh-sim --bin cargo-sim -- campaign \
  --swarm iroh-sim/swarms/direct-smoke.json \
  --seeds 0..100 --jobs 4 --continue-on-failure --max-runs 100 \
  --artifacts /tmp/iroh-sim-swarm-campaign
```

Scenario JSON is strict and currently supports `direct-ip/ipv4-stream`, `direct-ip/ipv4-stream-loss`, `direct-ip/ipv4-stream-corruption`, `direct-ip/ipv6-stream`, and `direct-ip/ipv6-datagram`. The checked-in loss fixture and seed demonstrate QUIC recovery after real packet loss. The corruption fixture requires the injected corruption to occur and treats the resulting authenticated-transport failure as its expected terminal result. Unknown fields, schemas, and scenario IDs fail closed. `run` writes the manifest before endpoint execution and prints one replay command. `replay` verifies source revision, dirty-tree digest, dependency lockfile, simulator/schema version, scenario digest, normalized configuration, features, backend identity, crypto/grade/comparison matrix, budgets, and seed before comparing the manifest-selected raw or semantic trace.

### Declarative schema and invariants

Schema v2 contains metadata, exact backend requirements, hard budgets, hosts/interfaces/links, endpoints, stable action IDs, schedules, fault rules, fairness assumptions, completion policy, allowed terminals, and enabled invariants. Canonical encoding sorts set-like collections and rejects duplicates, dangling references, host paths, unbounded values, unknown fields, and unsupported schemas. Schema v1 named fixtures migrate only through the explicit loader.

Actions may start/stop endpoints, connect, exchange a stream or datagram, close, partition/heal,
update a link, advance virtual time, rebind a NAT, request a port mapping, mutate discovery records,
change relay lifecycle, change interface/address/route state, or sleep/resume a host. Observation-triggered actions use
endpoint, connection, or satisfied-invariant predicates. The invariant families cover authenticated
peer identity, delivery integrity and misdelivery, per-stream ordering, monotonic lifecycle,
relay routing, resource ceilings, shutdown cleanup, and fairness-qualified reachable-connect liveness. Safety
checks run on the first matching observation; liveness is bounded by virtual time and event count.

### Strict swarm materialization

Swarm schema v1 embeds a canonical scenario or references a workspace-relative, BLAKE3-bound base
and declares a sorted, bounded set of weighted choices. Supported mutations cover payload size,
link latency and MTU, packet-fault probability, relay availability/impairment, NAT behavior,
discovery timing/state, mobility action timing, and co-scheduled ready pressure. Empty choices,
zero or excessive weights, invalid bounds, dangling targets, path traversal, digest drift, unknown
fields, and noncanonical ordering fail before backend construction. The materialization
seed is domain-separated from the runtime seed. Each campaign run stores its selected option for
every choice in `swarm-selection.json` beside the fully materialized `scenario.json`; replay and
triage therefore consume the artifact rather than regenerating it. Checked templates cover direct,
NAT, discovery, mobility, relay lifecycle, and ready-order pressure. The relay template records an
explicit outage-to-recovery transition and dependency-ordered, fairness-qualified bounded liveness
probe. Campaigns accept either crypto lane and retain the selection in `crypto-mode.txt`.

### Failure artifacts and minimization

A failing declarative run stores the canonical scenario, terminal report, invariant and resource snapshots, scenario-domain inventory, normalized `FailureSignature`, decision prefix, raw/normalized traces, and contiguous immutable chunks. The signature uses the invariant name when present, normalized responsible entities, typed terminal class, and a bounded causal-suffix digest. Replay verifies artifact integrity and the signature before applying the manifest-selected raw or semantic comparison, so disappearance, a different failure, a missing/truncated chunk, and trace divergence remain distinct.

Minimize a failure and resume an interrupted reduction with:

```bash
cargo run -p iroh-sim --bin cargo-sim -- minimize /tmp/iroh-sim-failure/manifest.json \
  --output /tmp/iroh-sim-minimized --max-attempts 10000

cargo run -p iroh-sim --bin cargo-sim -- minimize /tmp/iroh-sim-failure/manifest.json \
  --output /tmp/iroh-sim-minimized --resume --max-attempts 10000
```

The reducer deterministically deletes action/fault chunks, NATs, firewall rules, discovery
providers/records, relays and relay lifecycle actions, interfaces and routes; prunes unused topology and endpoints; and reduces domain
scalars and representation budgets. Every candidate is revalidated and memoized by canonical
digest. Only an exact signature match is accepted. `minimize.jsonl` is synced after each attempt
and `best.scenario.json` is atomically replaced after every improvement, so budget exhaustion
retains the best valid candidate.

### Corpus, campaigns, and triage

Each directory below `iroh-sim/corpus` must contain exactly `metadata.json` and `scenario.json`. Metadata records seed, expected terminal/signature, provenance, issue, schema/simulator compatibility, review state, and an exact `ScenarioInventory`. Unenumerated files, duplicate IDs, incompatibility, missing provenance, changed domain counts, and changed signatures fail `corpus test`. The reviewed entries cover NAT rebind/expiry, discovery conflict/expiry/refresh, relay restart, direct-to-relay fallback, and a four-way production-task ready-order seed promoted from the Stage 6 scheduler campaign.

Campaigns execute half-open seed ranges in deterministic worker batches. Results are sorted by seed, failure signatures are deduplicated independent of completion order, fail-fast stops only at a stable batch boundary, and every run gets its own artifact directory. Campaign summaries retain the template inventory. PR CI runs the corpus, generated production-QUIC smoke, and bounded environment/relay campaigns. Nightly CI shards 256 seeds independently across the Stage 4 environment domains and both Stage 5 relay domains, retaining artifacts and unique-failure summaries.

For a compact terminal, obligation, resource, causal-suffix, and command summary:

```bash
cargo run -p iroh-sim --bin cargo-sim -- explain /tmp/iroh-sim-failure/manifest.json
```

Cross-backend fixtures use `cargo sim parity export` and `cargo sim parity compare`. The complete
service SLO, retention, triage, corpus-promotion, schema-migration, realistic-backend, soak, and
performance-correlation runbook is [`../simulation/operations.md`](../simulation/operations.md).

## Validation

Run the deterministic-closure gates with:

```bash
scripts/tests/check-determinism-boundaries.sh
scripts/check-determinism-boundaries.sh --check
cargo test -p iroh-runtime
cargo test -p iroh-dns --lib
cargo test -p iroh-relay --all-features
cargo test -p iroh-sim
cargo test -p iroh-sim --test swarm
cargo test -p iroh --lib --all-features
cargo clippy -p iroh-runtime -p iroh-sim -p iroh --all-targets --all-features -- -D warnings
cargo check -p iroh --no-default-features
```

CI also builds the portable `iroh-runtime` contracts and Iroh for `wasm32-unknown-unknown`.
Patchbay remains the privileged realistic Linux backend and is intentionally separate from these
in-process contracts. The versioned semantic importer, canonical case catalog, and outcome matrix
are documented in [`../simulation/patchbay-parity.md`](../simulation/patchbay-parity.md).

## Synthetic network semantics

Topology construction rejects duplicate hosts, links, addresses, interfaces, ports, explicit routes, and equal connected-route prefixes. Routing is longest-prefix and multi-hop with loop detection. Source selection respects the bound family and host-owned addresses. Link serialization uses checked integer nanoseconds and rounds positive fractional transmission time upward.

Loss, duplication, corruption, and reorder delay have independent semantic decision streams per link. Partitions, queue overflow, MTU rejection, no route, invalid source, closed destination, and simulator budget failures retain distinct outcomes. Packet delivery, timers, tasks, sockets, and queued copies use RAII ledger ownership; successful endpoint shutdown must reconcile the ledger to zero.

## Remaining uncontrolled boundaries

Stage 6 scenarios inject synthetic UDP sockets, mutable monitor state, NAT/firewall/port-mapping
capabilities, discovery providers, DNS behavioral time, and relay connectivity. They do not
construct the corresponding OS adapters or relay DNS/TCP/TLS/HTTP/QAD adapters. The paired runner
compatibility tasks, core client-side Tokio timers, and relay-server actor roots have been retired.
The deterministic-test lane owns TLS, QUIC connection-ID, and relay-challenge entropy and compares
raw traces. The production-provider lane intentionally retains secure production entropy as its
only escape and masks only opaque ciphertext payload hashes for semantic comparison.
Real net-report HTTP/STUN probes and platform interfaces remain realistic-backend coverage.

## Performance evidence

Stage 2 adds capability dispatch at IP socket construction and send/receive boundaries only when the transport is constructed; normal builders still install the concrete `netwatch` adapter and secure entropy. The production default uses a no-op trace sink. Existing connection, packet-throughput, and relay benchmark commands remain the authority for performance review; no threshold is changed by Stage 2. Record machine identity, revision, feature set, command line, and raw output before accepting a new baseline.

Stage 3 adds no observer branch to the production Iroh crate: `ScenarioRunner`, reference models, invariants, corpus, and minimization live in the separate non-published `iroh-sim` crate, so an application that does not construct the simulator has no Stage 3 runner/observer path to disable. A non-gating 2026-07-21 container measurement on this worktree ran 32 generated production-QUIC scenarios with four workers in 4.26 seconds wall time (7.51 scenarios/second; 7.11 seconds user, 0.18 seconds system):

```bash
/usr/bin/time -p target/debug/cargo-sim campaign \
  iroh-sim/tests/fixtures/v2-ipv4-stream.json \
  --seeds 100..132 --jobs 4 --generated --continue-on-failure \
  --artifacts /tmp/iroh-sim-throughput
```

This is evidence, not a CI threshold: production crypto entropy makes host-to-host timing
comparisons unsuitable until stable runner distributions exist.

Stage 4 adds Criterion guardrails for NAT mapping reuse, ordered firewall decisions, discovery
replace/withdraw, and production builder construction with simulator hooks disabled. The measured
reference ranges, interpretation limits, and nightly retention policy are in
[`../simulation/stage4-performance.md`](../simulation/stage4-performance.md).

Stage 5 adds connector-disabled construction, production in-memory authentication/session, and
relay datagram-routing guardrails described in
[`../simulation/stage5-performance.md`](../simulation/stage5-performance.md). Relay semantic parity
and intentional backend differences are in
[`../simulation/relay-parity.md`](../simulation/relay-parity.md).

Stage 6 adds a FIFO-versus-seeded scheduler microbenchmark, nightly reports, and a measured 3.1%
median overhead on the 256-ready-task reference workload. Method and raw interpretation limits are
in [`../simulation/stage6-performance.md`](../simulation/stage6-performance.md).
