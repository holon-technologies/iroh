# Iroh Determinism and Testability Audit

Status: Living audit reviewed through deterministic tooling closure, 2026-07-26

## Scope

This is the living audit required before implementing Iroh's deterministic simulation platform. It covers the complete workspace, with special attention to endpoint and connection lifecycle, QUIC integration, sockets, relay, discovery, DNS, network monitoring, port mapping, path management, task ownership, existing tests, and CI.

The canonical classifications required by the source specification are:

- **Production randomness**: security-sensitive entropy or unavoidable production-environment input. It must remain secure/real by default; deterministic material is allowed only through an explicit simulation construction path.
- **Behavioral randomness**: time, ordering, scheduling, retry, selection, or resource behavior that can change an observable outcome and must be controlled in simulation.
- **Injectable dependency**: an existing or newly required construction seam through which production and simulation implementations can be supplied.
- **Acceptable nondeterminism**: test/benchmark measurement, diagnostics, or behavior outside the declared deterministic execution boundary that cannot influence simulated protocol results.
- **Architectural problem**: behaviorally relevant nondeterminism with no adequate ownership or injection seam. It requires a refactor, wrapper, or coordinated dependency change.

Longer phrases in the tables are scoped forms of these five categories. For example, “behavioral nondeterminism to inject” means **Behavioral randomness**, while “known limitation” or “required dependency seam” means **Architectural problem** until that seam exists.

The authoritative source specification is the complete 2026-07-20 attachment with SHA-256 `7a5f50cfc7e7b504e0e92c721d7f61d2506b760c8e9f2bdac91c1a5e3aeb048a`. It explicitly permits coordinated changes to internal dependencies, including Noq, where a durable abstraction requires them.

## Audit Method

The audit is based on source, test, manifest, and workflow inspection. Re-run these searches whenever the architecture changes:

```bash
rg -n 'tokio::spawn|tokio::task::spawn|n0_future::task::spawn|task::spawn' \
  iroh iroh-base iroh-dns iroh-dns-server iroh-relay iroh-runtime iroh-sim --glob '*.rs'
rg -n 'tokio::time|n0_future::time|Instant::now|SystemTime::now' \
  iroh iroh-base iroh-dns iroh-dns-server iroh-relay iroh-runtime iroh-sim --glob '*.rs'
rg -n 'rand::random|rand::rng\(\)|thread_rng|OsRng|getrandom|with_jitter' \
  iroh iroh-base iroh-dns iroh-dns-server iroh-relay iroh-runtime iroh-sim --glob '*.rs'
rg -n '(UdpSocket|TcpListener)::bind|resolve_host|lookup_|netmon::|interfaces::|portmapper' \
  iroh iroh-base iroh-dns iroh-dns-server iroh-relay iroh-runtime iroh-sim --glob '*.rs'
rg -n 'std::fs|tokio::fs|std::env|env::var|Command::new|thread::spawn|spawn_blocking' \
  iroh iroh-base iroh-dns iroh-dns-server iroh-relay iroh-runtime iroh-sim --glob '*.rs'
rg -n 'HashMap|HashSet|FxHashMap|FxHashSet' \
  iroh iroh-base iroh-dns iroh-dns-server iroh-relay iroh-runtime iroh-sim --glob '*.rs'

scripts/tests/check-determinism-boundaries.sh
scripts/tests/check-determinism-semantic.sh
scripts/check-determinism-boundaries.sh --check
scripts/check-determinism-semantic.sh --check
```

Search results are classified by executable context, not merely by filename. Code below `#[cfg(test)] mod tests`, files under `tests/`, and benchmark/example binaries are test-only unless a simulator backend deliberately executes them.

The historical Stage 0 revision contained the following raw search matches. Counts intentionally
include imports, types, test-only code, and false positives; they record the discovery state and
are not claims about the current tree.

| Search family | Matches | Files | Classification rule |
| --- | ---: | ---: | --- |
| spawn/task ownership | 164 | 45 | Production core paths are **Behavioral randomness** or an **Architectural problem**; test/example roots are **Acceptable nondeterminism**. |
| clocks/timers | 227 | 58 | Behavior-affecting deadlines are **Behavioral randomness**; system-time security inputs are **Production randomness**; pure measurements are **Acceptable nondeterminism**. |
| entropy/random selection | 44 | 25 | Cryptographic material is **Production randomness**; retry/path/probe choices are **Behavioral randomness**; seeded fixtures are **Acceptable nondeterminism**. |
| sockets/DNS/interfaces/port mapping | 259 | 44 | Existing traits are **Injectable dependencies**; direct OS construction in simulator-supported paths is an **Architectural problem**. |
| filesystem/environment/process/thread | 59 | 18 | Explicit process configuration outside the deterministic backend is **Acceptable nondeterminism**; unmanaged production lifecycle work is an **Architectural problem**. |
| unordered maps/sets | 66 | 15 | Keyed membership is **Acceptable nondeterminism**; behavior-affecting iteration is **Behavioral randomness** that must be stabilized or recorded. |

These counts are an audit baseline, not a permanent allowlist. Stage 0 converts the searches into a checked occurrence manifest so additions require an explicit classification in review.

The legacy executable occurrence manifest is `scripts/determinism-boundaries.txt`.
`scripts/check-determinism-boundaries.sh --check` deliberately remains line-sensitive and fails CI
on any addition, removal, line movement, or matched-source change. It is retained as a broad
lexical backstop.

The authoritative stable review identity is `scripts/determinism-boundaries.semantic.txt`.
`scripts/check-determinism-semantic.sh --check` parses Rust with `syn`, ignores comments and string
literals, resolves file-local `use` aliases, and records category, path, enclosing owner, API, and
same-owner ordinal. Source-line movement alone therefore does not create semantic drift. Both
inventories fail closed together; parse failure or drift requires explicit review and `--update`.

The 2026-07-21 Stage 1 review added the `iroh-runtime` production adapters and moved existing Iroh occurrences as context plumbing and tests were introduced. `TokioClock` and `SystemWallClock` are classified as production implementations behind injectable clock traits; `RootSeed::random` is the single production behavioral-seed boundary; and `EndpointConfig::rng_seed` is now supplied from the explicit per-endpoint `endpoint/<id>/noq` decision stream. Endpoint identities, TLS token keys, and QUIC reset keys continue to use cryptographic entropy and were not routed through behavioral decisions.

The 2026-07-21 parity refresh added one test-only environment read in
`iroh/tests/patchbay/nat.rs`. `IROH_PATCHBAY_PARITY_RECEIPT` selects only the immutable output path
for evidence after the privileged Patchbay assertions pass; it cannot select endpoint, protocol,
network, clock, scheduler, or production behavior. Other row changes in this refresh are line moves
from strict parity/campaign CLI tests and remain orchestration or test-process boundaries.

The final closure audit moved seven existing `Command::new`/`temp_dir` matches in
`iroh-sim/tests/cli.rs` while bounding and asserting the seeded zero-time-livelock regression.
They remain **Acceptable nondeterminism** in child-test orchestration; the simulated scenario,
seed, virtual clock, and scheduler are explicit and unaffected.

The 2026-07-23 TigerStyle lifecycle review classifies the DNS-server drift before refreshing the
manifest. HTTP admission and rate limiting sample `Instant` only in the real-server adapter; the
token-bucket transition still receives that value explicitly. TLS handshake and top-level cleanup
timeouts are finite production-runtime bounds owned by the HTTP/server supervisors. They are
**Acceptable nondeterminism in the real-server backend** and remain outside the deterministic DNS
simulation boundary. Persistent-store batching, eviction, and row timestamps still use the
documented ambient production clock and remain an **Architectural problem** only for future
full-server simulation. The store's two native workers now have cancellation, typed completion,
explicit join, and nonblocking fallback drop; their production thread-construction match is an
owned real-server boundary. New timeouts, wall-clock measurements, entropy, loopback binds, and the
release helper thread below `#[cfg(test)]` are **Acceptable nondeterminism in regression-test
orchestration**. The remaining Iroh address-lookup and path-state changes are reviewed line moves or
bounded production-clock transitions with deterministic-runtime coverage described below; adding
the crate-root unsafe prohibition only moves the existing `portmapper` match. Extending the same
unsafe prohibition to the benchmark library/binary and `cargo-sim` binary moves only existing
benchmark timer/thread/task orchestration and CLI argument-reading matches; it does not introduce
a new behavioral nondeterminism boundary.

The 2026-07-24 relay arithmetic review replaces unchecked duration narrowing in the production
token bucket with explicit wide arithmetic, saturation at the bucket boundary, and a
constructor-validated timer horizon. The matched clock/timer lines remain the existing
real-server rate-limit boundary; regression tests use paused time and exercise maximum refill
rates, long elapsed intervals, and refill periods beyond 32-bit millisecond range.

The same arithmetic pass makes possible truncation, sign loss, and signed wrapping hard workspace
Clippy errors for every target. Production timestamp, metric, framing, deterministic-seed,
duration, path-limit, and simulator conversions now use fallible, infallible, or explicitly
saturating boundaries. Relay GSO segment sizes return `InvalidInput` instead of truncating their
wire value; negative Mainline sequences return a typed timestamp error; pkarr monotonic timestamp
exhaustion is explicit and tested. Benchmark/example presentation uses bounded conversion helpers
and does not affect protocol behavior. Occurrence-manifest changes from this pass are reviewed line
movement in already-classified clocks, entropy streams, unordered collections, and test
orchestration; no new ambient input or scheduling source was added.

The 2026-07-24 TigerStyle allocation and retry pass adds no new behavioral input. Pkarr publish
retry delay is now saturating and capped at five minutes; `publish_deadline` samples the same
production Tokio clock already owned by that publisher and converts an otherwise overflowing
duration to the runtime's far-future timer. Its additional matched lines are therefore an existing
**Behavioral randomness / production-runtime timer** plus regression-test orchestration. DNS and
relay configuration loading, manual and periodically reloaded TLS certificate/private-key
loading, the relay's extra ACME CA loading, and DNS/relay ACME account and certificate cache
loading now open and read explicit operator-selected files through a 1 MiB bounded reader. The
ACME adapters also reject oversized cache writes while preserving the dependency's existing cache
filenames. These filesystem occurrences replace unbounded reads and remain **Acceptable
nondeterminism in executable startup and certificate maintenance**, outside the simulated
protocol. The manual certificate path retains its existing startup-owned `spawn_blocking`
boundary, while the supervised reload task retains its existing production timer/task boundary.
ACME cache fixtures and compatibility tests are **Acceptable nondeterminism in regression-test
orchestration**. The other manifest changes are line movement caused by bounded HTTP response
collectors and their tests; they introduce no clock, entropy, scheduling, or external-state
dependency.

The DNS jitter regression test now checks the deterministic sampler's exact inclusive ±20%
endpoints instead of drawing ambient randomness 100 times. The resulting manifest drift is only
line movement in the adjacent custom-resolver test; it removes probabilistic test behavior and
does not change the production jitter source or network boundary.

The simulator CLI, corpus, replay verifier, and failure-artifact reader now route operator-selected
files through one 64 MiB bounded reader. Corpus enumeration rejects the first entry above 4,096
and the first per-entry file above its exact two-file schema; replay validates that the declared
chunk count equals the finite indexed chunk set before iterating. These are **Acceptable
nondeterminism in simulator process orchestration** and cannot affect a simulated protocol
decision. The occurrence checker now recognizes imported `File::open` and `OpenOptions` spellings
as external-state boundaries, closing a prior manifest blind spot. New fixture writes are
**Acceptable nondeterminism in regression-test orchestration**; other changed rows are line
movement from routing reads through the bounded helper.

The production-capacity pass bounds endpoint, router, remote-state, active-relay, QUIC accept,
captive-portal, and runtime task ownership before work is spawned or protocol state is allocated.
New matched task and timeout lines are either capacity-accounted production supervisors or
**Acceptable nondeterminism in regression-test orchestration** exercising exact saturation and
recovery. The simulator kernel mirrors the runtime task-group ceiling; its `Instant` construction
is the already classified injected runtime-clock boundary. Fallible DNS, Pkarr, and QUIC
construction adds no behavioral input. The remaining manifest differences are reviewed line
movement from admission plumbing, bounded DNS collection, and constructor-error propagation.

The 2026-07-24 Rust 1.97.1 toolchain refresh regrouped imports, reformatted one documentation
example, and expressed invariant ordering with `sort_by_key` instead of an equivalent comparator.
The invariant key is the same ordered `InvariantName`; no ordering semantics changed. The refresh
changed no timing or entropy sources, task creation, external-state access, network boundaries, or
unordered-iteration semantics. Every added/removed boundary occurrence pair is the same matched
text shifted by import grouping or line layout, so its existing classification remains unchanged.
This is a toolchain-compatibility baseline refresh, not a new behavioral boundary.

The generated-campaign regression adds one CLI process invocation under
**Acceptable nondeterminism in regression-test orchestration**; the other changed CLI rows are
line movement from that test. Its production change retains the same seeded decision stream while
deterministically bounding datagram payloads and limiting recovery fault generation to reliable
streams. It adds no clock, entropy, scheduler, external-state, or network-environment input.

The 2026-07-25 GitHub-hosted resource-observation profile makes host qualification an explicit
canary input and permanently excludes the smaller hosted profile from production-evidence
classification. The resulting lexical-manifest changes are line movement in existing benchmark
clock, task, process, filesystem, and platform-observation boundaries. It adds no protocol input,
ambient dependency, scheduling source, or simulator escape.

The 2026-07-25 daily deterministic soak adds process wall-time measurement, atomic checkpoint
replacement, strict plan/swarm reads, bounded failure-directory writes, and fresh child-process
orchestration. These are **Acceptable nondeterminism in executable orchestration**: elapsed host
time determines only which fixed batch is the final batch, never a seed, simulated event, or
within-run choice. Every completed run keeps a deterministic seed identity and sorted accounting.
Worker completion order is discarded by the existing fixed-batch campaign contract. Plan and
swarm bytes are schema-validated and digest-pinned before endpoint construction. Artifact locks
serialize rare failure retention only and cannot affect simulation scheduling. The workflow is a
checked service definition; only an uploaded run report is execution evidence.

The 2026-07-25 declarative resource-exhaustion closure makes scheduled-event, trace, timer, socket,
connection, stream, and relay ceilings explicit schema-v3 replay inputs. Zero capacity is valid
only for live resources and rejects before side effects. A virtual-clock `sleep` action exercises
timer admission without ambient time, while socket-bind source-chain recovery preserves the typed
ledger failure without parsing display text. Six fixed-seed reviewed corpus cases replay their
typed failures twice with empty live ledgers. The nightly matrix is a checked service definition;
its hosted artifact is execution evidence, while local workflow validation is definition evidence.

The 2026-07-26 GitHub-hosted soak fan-out adds an optional CLI lane selector only after the full
fourteen-lane plan has passed its existing schema, ordering, path, and digest checks. The selector
does not introduce an effect source: it bounds execution to one declared lane while retaining that
lane's canonical index in deterministic seed derivation. The related `Command::new`, temporary
directory, and filesystem occurrences are **Acceptable nondeterminism in regression-test
orchestration**. The inventory refresh also incorporates line movement from the already reviewed
typed runtime-clock and resource-exhaustion changes, the renamed versioned CLI replay test, and its
new resource-corpus process invocations; these retain their classifications above.

The 2026-07-26 coverage-driven service adds strict coverage and change-impact policy reads to the
simulator CLI and checked fixture reads to its integration tests. These are **Acceptable
nondeterminism in executable or regression-test orchestration**: bounded canonical files are
validated and hashed before selection, and their digest becomes explicit seed and evidence
identity. They cannot introduce ambient input after a scenario starts. Gate tests invoke the
source-bound CLI in temporary directories, while added CLI `Instant`/`SystemTime`, Git, current
directory, and atomic-file rows are line movement of the already classified wall-budget,
realistic-evidence, source-identity, path-resolution, and artifact-publication boundaries. No new
behavioral clock, entropy, scheduler, network-environment, or unordered-iteration escape is
accepted by this inventory refresh.

Coverage-policy schema v2 and corpus-metadata schema v2 add only bounded canonical metadata reads
before execution. Domain/provider-qualified transition obligations and typed corpus-promotion
evidence do not influence the simulated scheduler, clock, entropy, or network. The issue closure
guard performs host filesystem hashing, child-process corpus execution, and GitHub check lookup in
workflow orchestration after simulation; these are **Acceptable nondeterminism in executable
orchestration** and cannot change a scenario outcome.

The 2026-07-26 hosted CI portability review moves four existing paused-Tokio timer occurrences in
the resource-canary regression tests while making artifact permission assertions portable to
Windows. They remain **Acceptable nondeterminism in regression-test orchestration** and do not add
or change any production or simulation clock boundary.

The 2026-07-26 Android address-lookup regression review replaces a paused-Tokio sleep and timeout
with an explicit `Notify` handoff and two finite real-time bounds. The test binds real operating-
system UDP sockets, so allowing Tokio's paused clock to auto-advance while Android emulator I/O is
externally pending could expire the assertion before packets were scheduled. These bounds are
**Acceptable nondeterminism in regression-test orchestration**: they determine only whether the
hosted test reports a liveness failure and cannot influence production or simulated protocol
behavior. The shared endpoint fixture also injects a fixed loopback DNS nameserver, removing the
test's ambient Android JNI/DNS dependency. Remaining address-lookup manifest changes are reviewed
line movement caused by this test-only synchronization and fixture plumbing.

The 2026-07-27 continuous blackhole campaign adds a bounded datagram-absence action driven by the
existing injected simulator clock. Its timeout duration is validated as positive and within the
scenario virtual-time budget, so it adds no ambient clock or scheduler input. The lexical inventory
changes are line movement in the already classified CLI Git/current-directory orchestration,
coverage-fixture filesystem read, and disabled production port-mapper construction. No new
external-state or network-environment boundary is introduced, and the syntax-aware inventory is
unchanged.

The final Stage 1 baseline additionally removes native direct-spawn roots for Noq, the socket actor, relay actor, and direct-address report runner; the matched fallback calls that remain at those sites are wasm-specific, while test-module spawns remain acceptable test orchestration. `iroh-sim` reads CLI arguments and writes only through an explicit absolute artifact root; those process/filesystem boundaries are run orchestration, not simulated behavior. Its Tokio `advance` occurrence is the deterministic runtime contract test itself.

The 2026-07-21 Stage 2 review added a kernel-owned virtual clock, task executor, event queue, resource ledger, synthetic IPv4/IPv6 UDP graph, and explicit Iroh `IpSocketFactory`/`NetworkMonitor` capabilities. Normal endpoints retain `netwatch` sockets and monitor construction as **Production randomness / environment input** behind those injectable dependencies; Stage 2 scenarios inject synthetic sockets and a static state, disable port mapping, relay, discovery, and external probes, and never construct the OS adapters. At that stage, token and reset keys were explicit unsafe-test-only simulation crypto material while Rustls/key-exchange entropy remained **Production randomness**. The deterministic-closure update below supersedes that historical replay-grade limitation.

Stage 2 endpoint scenarios deliberately use `tokio::spawn` and paused Tokio time as a documented **Architectural problem / temporary bridge**, recorded as `tokio_scheduler` and `tokio_socket_actor_time`. The kernel returns control after every virtual event so woken production tasks run before later deadlines, but this is not a fully deterministic scheduler claim; Stage 6 removes it. Direct socket-actor `Instant`/interval occurrences remain assigned to Stage 6. Kernel-native component and packet-network tests use no Tokio task scheduling.

The activated CLI invokes `git` and reads the current directory only to capture source/lockfile identity and resolve explicit artifact paths. This is **Acceptable nondeterminism in executable orchestration**: those values are validated before replay and cannot affect the scenario after construction. CLI integration-test processes and temporary directories are likewise test orchestration. `State::fake()` is deterministic simulation input despite matching the network-environment search family. The synthetic network's `lookup_socket` name is a false-positive keyed in-memory lookup, not DNS or OS access.

The 2026-07-21 Stage 3 review adds strict scenario/corpus/artifact filesystem enumeration and atomic progress publication in the `cargo-sim` orchestration layer. These are **Acceptable nondeterminism in executable orchestration**: file content is canonical, hashed, compatibility-checked, and never consulted by the simulated protocol after construction. `std::thread::scope` is used only by the campaign coordinator in fixed seed batches; worker completion order is discarded and results are sorted by seed, so it is not a simulated scheduling source. Production endpoint actions still execute through the documented paused current-thread Tokio bridge and retain the Stage 2 `controlled_runtime` grade.

Stage 3's `SystemTime::UNIX_EPOCH` uses are fixed deterministic epochs, not ambient clock reads. `BTreeMap`/`BTreeSet` collections define canonical ordering for scenarios, observations, minimizer attempts, corpus entries, and campaign failure deduplication. The new filesystem/process occurrences in tests create explicit temporary fixtures or child CLI processes and remain **Acceptable nondeterminism** outside behavioral execution.

The 2026-07-21 Stage 4 review adds simulator-owned stateful NAT, firewall, port mapping,
interface/address/route mobility, deterministic discovery, and DNS timing/jitter injection. NAT
allocation uses a named seeded decision stream; mappings, firewall state, record generations,
expiry, cancellation, and resources use virtual kernel time and stable ordered collections. The
new `lookup_*` matches in `iroh-sim` are in-memory synthetic socket or scripted resolver lookups,
not ambient DNS. `State::fake()` constructs explicit monitor input. These are **Injectable
dependencies exercised by deterministic implementations**.

`iroh-dns::DnsRuntime` now owns DNS sleep and retry-stagger behavior. The production
implementation deliberately retains Tokio time and OS-seeded `rand::random`; these remain
**Production randomness / production runtime behavior**. Supported simulations inject
`DeterministicDnsRuntime`, whose sleeps are cancellable kernel events and whose jitter is drawn from
a domain-separated decision stream. Production address aggregation continues unchanged. The new
production `OsNetworkMonitor`, OS socket, and real port-mapper occurrences remain **Production
environment input behind injectable dependencies**; normal endpoint builders never select a
simulation implementation.

The Stage 4 canonical runner still has six `tokio::spawn` roots for paired production QUIC
accept/connect and application exchange. They are the already-declared **Architectural problem /
temporary Tokio bridge** and keep the manifest at `controlled_runtime`; Stage 6 owns their removal.
The endpoint/socket time and spawn matches outside simulator-injected capabilities likewise remain
assigned to Stage 6.

New filesystem/process matches are CLI artifact/source-identity orchestration or test temporary
directories and remain **Acceptable nondeterminism**. The Stage 4 Criterion benchmark's
`portmapper` text is measurement-only and cannot influence a simulation. Benchmark wall time is
also acceptable measurement nondeterminism. The reviewed baseline was regenerated only after
classifying these changes. The Stage 4 baseline contains 812 normalized rows and has SHA-256
`1485814a3287e8783b85100d8bb3563fae1a8d092b8c7ee81a1f6c23b4f17043`.

The 2026-07-21 Stage 5 review introduces an explicit native `RelayConnector` capability and lifts
the existing duplex transport into a hidden `iroh-relay/test-utils` session API. In deterministic
scenarios, DNS/TCP/TLS/HTTP upgrade and listeners are replaced by a bounded in-memory byte pipe;
production WebSocket framing, challenge/signature authentication, authorization, client/server
actors, registry, routing, and Iroh relay reconnect/path logic still execute. These are
**Injectable dependencies exercised by production protocol handlers**. An injected connector also
suppresses net-report QAD/HTTPS probing of synthetic relay URLs, preventing an OS-I/O escape while
leaving the production default unchanged.

Relay service lifecycle, admission, generations, and resource ownership belong to `iroh-sim`.
The separate `RelayRoutingOracle` is a pure differential model and cannot count as production
coverage. Production coverage observations record connection attempts, authenticated sessions,
and routed frames without secret key material. Relay actor reconnect backoff, ping cadence,
inactivity timers, server rate-limiter time, handshake challenge entropy, and remaining Tokio child
tasks are still **Behavioral randomness / Architectural problems** assigned to Stage 6. Stage 5
therefore retains the honest `controlled_runtime` grade.

The 2026-07-21 Stage 6 review moves the native production endpoint, Noq, socket, and relay root
tasks from the temporary Tokio executor onto `KernelExecutor`. Every kernel task poll now consumes
one value from the domain-separated `kernel/ready-task` stream. Scheduling is restricted to the
oldest causal ready wave, varies legal peers by seed, and forces a waiter after 32 eligible
selections. `task_scheduled` trace events include the chosen task and eligible ownership metadata;
terminal reports, success artifacts, and failure bundles retain scheduler accounting and the full
historical task graph. Blocked quiescence and a still-runnable task-poll budget terminal are
separate, so the latter is reported as possible livelock rather than a deadlock.

The production socket actor's periodic re-STUN timer, its 20–26 second behavioral jitter, and
network-change retry sleep now use the injected runtime clock and endpoint decision stream. The
actor's multi-ready `tokio::select!` policy is explicitly `biased`; without that declaration,
Tokio's hidden per-poll branch RNG caused same-seed task-ready divergence even while the kernel's
draw stream remained identical. This is **Behavioral randomness retired through an injectable
dependency and explicit ordering policy**. Direct and relay same-seed production-QUIC traces are
regression-tested, and root-seed campaign shards exercise rare kernel ready orders.

The deterministic closure pass removes the paired harness compatibility scheduler and client-side
timer rows. Harness roots are readiness-driven by `KernelDriver`; remote-state, path-state,
active-relay, relay impairment, net-report, shutdown, and relay lifecycle transitions use the
injected clock and driver; relay pings and reconnect jitter use named decision streams. The
in-memory relay server's per-client actors use the same run-owned executor, monotonic clock, wall
clock, and decision source.

The isolated, non-published `iroh-sim` workspace applies a narrow Rustls 0.23.41 fork that stores
`SecureRandom` and `SupportedKxGroup` components in owned `Arc`s. The deterministic provider
implementation now lives inside `iroh-sim`; published Iroh packages compile against public Rustls
and merely accept an already constructed provider through the hidden simulation environment. The
deterministic-test lane uses run- and endpoint-scoped deterministic random/X25519 components,
deterministic Noq local and Initial connection IDs, and deterministic relay authentication
challenges. These inputs are independently domain-separated and require no leaked state,
process-global dispatch, or worker coupling.

The 2026-07-25 publishable-fork boundary moved that deterministic provider implementation from
`iroh` into `iroh-sim` and shortened the adjacent production simulation capability module. The
resulting lexical inventory changes are reviewed line movement in existing network-environment
adapters; `State::fake()` remains explicit deterministic simulation input, and the Iroh
`netwatch` adapters remain production environment input behind injectable dependencies. No new
clock, entropy, scheduler, external-state, network, or unordered-iteration source was added.

Manifest schema 3 therefore distinguishes two honest lanes. `deterministic_test` has zero escapes,
records `deterministic_test_crypto` as a fidelity exception, is graded `fully_deterministic`, and
requires raw trace equality. `production_provider` intentionally retains exactly
`production_crypto_entropy`, is graded `semantically_deterministic`, and compares normalized traces
that mask only opaque ciphertext. Relay-server timeout/sleep matches confined to test modules remain
**Acceptable nondeterminism in test orchestration**.

The closure baseline drift is predominantly line movement from runtime-context plumbing. Its new
entropy matches are classified explicitly: `handshake::serverside` and `Clients::default` retain
secure OS-seeded challenges for production, while simulation calls the injected challenge path;
the socket's production branches retain random reset keys, Noq seeds, token keys, and jitter, while
the deterministic-test construction supplies scoped replacements before those branches execute.
The former relay-client ambient reconnect delay was removed in favor of a named decision stream.
The parity CLI's `SystemTime::now` call validates realistic-backend evidence outside the simulated
protocol; the producing backend supplies its observation epoch explicitly. This is **Acceptable
nondeterminism in executable orchestration**: the value cannot affect a scenario, and its only role
is to reject stale or implausibly future-dated parity fixtures. Swarm selection itself uses an
explicit domain-separated materialization seed.

## Existing Test Stack

| Layer | Confirmed current role | Determinism assessment |
| --- | --- | --- |
| Unit tests | Workspace-wide module tests, including Tokio paused-time tests | Useful local coverage; scheduling, entropy, and environment are not globally controlled. |
| Property tests | Relay protocol codec/property tests in `iroh-relay/src/protos/relay.rs` | Narrow protocol serialization coverage; no stateful networking model. |
| Endpoint integration | `iroh/tests/integration.rs` plus extensive in-module endpoint/socket tests | Runs production endpoint and QUIC code, usually over real local sockets. |
| In-memory custom transport | `iroh/src/test_utils/test_transport.rs` | Runs production QUIC over Tokio channels, but has no virtual time, seeded scheduler, topology, NAT, fault trace, or replay identity. |
| Patchbay | `iroh/tests/patchbay.rs` and `iroh/tests/patchbay/*` | Real Linux namespaces and kernel networking. Covers NAT matrices, degradation, outage recovery, and interface switching. Must remain the realistic Linux layer. |
| External netsim | `.github/workflows/netsim*.y*ml` and `.github/sims/**` | Runs real processes through the external `chuck` repository. Valuable integration/performance coverage, but not deterministic in-process simulation and not self-contained at a pinned source revision. |
| Cross-platform CI | `.github/workflows/ci.yml`, `tests.yaml`, `wine.yaml` | Linux, macOS, Windows, Android, wasm, and cross-build coverage exists. |
| Flake detection | `.github/workflows/flaky.yaml` | Daily repeated conventional tests; no seed corpus or deterministic replay. |
| Fuzzing / concurrency exploration | Four bounded cargo-fuzz targets cover DoH, pkarr, relay segmentation, and configuration parsing; the seeded deterministic scheduler explores actor-ready ordering. | PR smoke and scheduled fuzz campaigns are executable gates; the simulator remains the actor-level concurrency authority. |

## Historical Stage 0 Findings

The runtime, time, entropy, network, and dependency sections below preserve the pre-implementation
discovery that motivated Stages 1–6. Their “required action” and “gap” language is historical.
The authoritative current state is the [Current High-Risk Gaps](#current-high-risk-gaps) section
and the simulation guide.

### Runtime and Task Scheduling

#### Confirmed seams

- `iroh/src/runtime.rs` wraps `noq::Runtime`, owns Noq tasks with `TaskTracker`, assigns per-endpoint numeric task IDs, and coordinates cancellation.
- `noq::Runtime` already injects timer creation, `now()`, task spawning, and UDP wrapping. `noq::Endpoint::new_with_abstract_socket` accepts both an abstract socket and runtime.
- `noq_proto::EndpointConfig::rng_seed` already allows deterministic QUIC behavioral randomness, but Iroh never supplies it.

#### Occurrence classification

| Occurrence group | Classification | Required action |
| --- | --- | --- |
| `iroh/src/runtime.rs`: `noq::TokioRuntime.new_timer`, default `Runtime::now`, `TaskTracker::spawn` | **Architectural problem** | Make the Iroh runtime delegate clock and executor behavior to an explicit environment. Trace task creation/completion/cancellation and timer lifecycle. |
| `iroh/src/socket.rs:816,1098`; `address_lookup/pkarr.rs:324`; `net_report.rs:862,931`; `net_report/reportgen.rs:141`; `protocol.rs:614`; `socket/transports/relay.rs:63` | **Architectural problem** | Route all core-path root task creation through the environment with stable IDs and ownership metadata. |
| `RemoteMap`, `RemoteStateActor`, net-report, protocol router, and relay actor `JoinSet::spawn` calls | **Architectural problem** | Replace direct Tokio `JoinSet` ownership in simulator-supported paths with an environment-owned task group abstraction. |
| `iroh-relay/src/client/tls.rs:200`, `quic.rs:124`, `server.rs:772,810,860`, `server/client.rs:146`, `server/http_server.rs:471,495,631`, `server/resolver.rs:79` | **Architectural problem** | Add relay runtime/task capabilities before claiming deterministic relay coverage. |
| DNS/HTTP server task sets and `iroh-dns-server/src/http/transport.rs` | **Acceptable nondeterminism** in the real-server backend | Listener and connection work is now owned by supervisors, bounded before spawn, and cancelled/drained on shutdown. Runtime/I/O injection remains required before full DNS-server simulation. |
| Direct spawns in `#[cfg(test)]` regions, `tests/`, `examples/`, and `iroh/bench` | **Acceptable nondeterminism** | Do not route through production environment unless the scenario runner reuses that code. |
| `iroh-relay/src/main.rs:627` certificate file `spawn_blocking` | **Acceptable nondeterminism** | Keep in production binary; exclude from in-process simulation. |
| DNS-server bounded per-IP token buckets | **Behavioral randomness** with explicit transition input | The LRU has a validated hard capacity; token transitions receive `Instant` explicitly. Only the HTTP middleware samples the production clock. There is no GC thread. |

#### Gaps

- Stable task IDs exist only for tasks spawned by Noq through one endpoint runtime. Socket actors, discovery publishers, relay tasks, net-report probes, and application protocol tasks are outside that graph.
- Tokio current-thread execution and paused time are useful bootstrap tools, but they do not provide seed-controlled legal task ordering or protection against accidental executor escape.
- There is no deadlock/stalled-progress detector, ready-queue trace, task ownership graph, or end-of-scenario task leak assertion.

### Time

`n0_future::time` is a native re-export of `tokio::time`; it is not an injectable clock. Pausing Tokio time therefore does not control code running on another executor and cannot provide a simulator-owned event queue.

| Subsystem / occurrences | Classification | Notes |
| --- | --- | --- |
| `iroh/src/socket.rs`: net-report timeout, 100 ms shutdown grace, re-STUN interval, network-change backoff | **Architectural problem** | Affects liveness, retries, address discovery, and cleanup. |
| `iroh/src/socket/remote_map/remote_state.rs`: idle timeout, upgrade interval, hole-punch retry scheduling | **Architectural problem** | Core path and connection behavior. All `Instant::now()` calls must use the same clock as timers. |
| `iroh/src/socket/remote_map/remote_state/path_state.rs`: path source timestamps and inactive pruning | **Architectural problem** | Affects which paths remain eligible. |
| `iroh/src/socket/transports/relay/actor.rs`: connection timeout, retry sleeps, ping interval/timeouts, inactivity, datagram expiry | **Architectural problem** | Core relay liveness behavior. |
| `iroh/src/net_report.rs` and `net_report/reportgen.rs`: probe deadlines, stagger, history age, captive portal delay | **Architectural problem** | Must use virtual time when net-report aggregation is in scope. Real HTTP probes remain a backend boundary. |
| `iroh-dns/src/dns.rs`: lookup timeout and stagger; `iroh/src/address_lookup/pkarr.rs`: retry and republish | **Architectural problem** | Custom DNS responses alone are insufficient while wrapper time remains Tokio-owned. |
| `iroh-relay/src/client/tls.rs`, `server/client.rs`, `server/streams.rs`, `ping_tracker.rs`, certificate reload interval | **Architectural problem** | Includes Happy Eyeballs, rate limiting, ping cadence, and timeout behavior. |
| `iroh/src/endpoint/quic.rs:703-712` Noq TLS `TimeSource` | **Injectable dependency** | Set the production source to `noq::StdSystemTime`; derive the simulation source from the same deterministic wall clock used for certificates and signed records. |
| `iroh-dns/src/pkarr.rs` wall-clock signed-packet timestamps | **Production randomness** | Production freshness uses real wall time. Simulation identities/records need an explicit deterministic wall clock without changing production security. |
| `iroh/src/address_lookup/memory.rs:172,185` update timestamps | **Architectural problem** | These timestamps are observable through address-lookup items; use the environment wall clock so update ordering and snapshots replay. |
| `iroh-relay/src/server/client.rs:520,527` daily unique-client reset | **Architectural problem** | Inject a relay-server wall clock or a counter policy. Hash-set membership itself is not order sensitive. |
| `iroh-dns-server/src/store/signed_packets.rs:223,388` and `iroh-dns-server/src/lib.rs:136` | **Architectural problem** | Eviction and stored timestamps require a wall-clock provider before deterministic server lifecycle claims. The occurrence at `signed_packets.rs:446` is test-only. |
| `iroh-dns-server/src/http.rs:290` request latency | **Acceptable nondeterminism** | It does not affect request behavior; source it from the runtime clock if deterministic metrics/trace equality is required. |
| Test, example, and benchmark sleeps/timeouts/measurements | **Acceptable nondeterminism** | Existing test timeouts remain watchdogs; simulator correctness must use virtual bounds. |

### Randomness

#### Secure or cryptographic randomness

| Occurrence | Classification | Required action |
| --- | --- | --- |
| `iroh-base/src/key.rs:319` (`SecretKey::generate`) | **Production randomness** | Never replace the production default. Scenarios pass explicitly derived test-only keys. |
| `iroh/src/endpoint.rs:225-236` TLS token key and `iroh/src/socket.rs:1013-1014` QUIC reset key | **Production randomness** | Production entropy remains mandatory. A simulation-only crypto-material factory may supply deterministic test keys through an explicit internal constructor. |
| `iroh-relay/src/protos/handshake.rs:452` server challenge | **Production randomness** | Add an explicit simulation/test challenge source only when real relay handshake code is executed in simulation. |
| Crypto crates' internal `getrandom` / `OsRng` | **Production randomness**; **Architectural problem** if reached implicitly by simulation | Do not globally override platform entropy. Inject deterministic identities and protocol configuration at construction boundaries. |

#### Behavioral randomness

| Occurrence | Classification | Required action |
| --- | --- | --- |
| `iroh/src/socket.rs:2004-2017` re-STUN interval | **Behavioral randomness** | Use a named per-endpoint stream. |
| `iroh/src/socket/transports/relay/actor.rs:350-356` Backon jitter | **Behavioral randomness** | Backon supports `with_jitter_seed`; seed it from a named relay stream or replace with an environment backoff policy. |
| `iroh/src/net_report/reportgen.rs:589` captive-portal relay choice | **Behavioral randomness** | Use the net-report stream and record the choice. |
| `iroh-dns/src/dns.rs:978` DNS retry jitter | **Behavioral randomness** | Use a DNS-domain stream. |
| `iroh-relay/src/server/client.rs:338` randomized ping cadence | **Behavioral randomness** | Use a per-client relay-server stream. |
| `iroh-relay/src/ping_tracker.rs:57` ping payload | **Behavioral randomness** | Not cryptographic authentication; deterministic per-session values are appropriate in simulation. |
| `noq_proto::EndpointConfig::rng_seed` left unset by `iroh/src/socket.rs` | **Injectable dependency** currently carrying uncontrolled **Behavioral randomness** | Derive a dedicated Noq endpoint seed from the root seed. No dependency change is required. |
| Seeded `ChaCha8Rng` uses in tests | **Acceptable nondeterminism** already controlled | Preserve or migrate into named scenario streams where tests become scenarios. |

One shared mutable RNG is insufficient: adding a decision in one subsystem would perturb every later decision. Simulation must derive named streams from `(root seed, semantic path)` and trace both the path and per-stream draw index.

### Datagram and Stream Networking

| Occurrence | Classification | Required action |
| --- | --- | --- |
| `iroh/src/socket/transports/ip.rs:171-184` direct `netwatch::UdpSocket::bind_full` | **Architectural problem** | Introduce an IP socket factory and socket trait that preserve the current netwatch implementation in production and accept synthetic sockets in simulation. |
| `IpNetworkChangeSender::rebind` | **Injectable dependency** requiring a simulation implementation | Simulation rebind must update virtual interfaces/NAT state and retain traceable old/new local addresses. |
| `iroh/src/test_utils/test_transport.rs` Tokio-channel network | **Acceptable nondeterminism** and reusable test foundation | Reuse its production-QUIC proof, but do not build the final network on `CustomAddr`: doing so would bypass IP routing, NAT, interface, and IP path behavior. |
| `noq::AsyncUdpSocket` and `UdpSender` | **Injectable dependency** | Synthetic Iroh IP transports can feed real Noq/QUIC without simulating QUIC. |
| Relay client TCP/TLS/WebSocket dial in `iroh-relay/src/client/tls.rs` | **Production environment adapter behind an injectable dependency** | Deterministic endpoints install `RelayConnector`; normal endpoints retain the existing concrete dial without connector dispatch. |
| Relay server `TcpListener::bind` and QAD `UdpSocket::bind` | **Production environment adapters** | Deterministic relay sessions enter below these mechanics; production and Patchbay preserve them. Injected connectors suppress QAD probes of synthetic relay URLs. |
| DNS server UDP/TCP binds in `iroh-dns-server/src/dns.rs` | **Architectural problem** for full server simulation | Simulated DNS provider covers aggregation logic first; real server parity remains an integration backend. |

### DNS, Discovery, and Address Management

- **Injectable dependency:** `iroh_dns::dns::Resolver` already supports custom IPv4, IPv6, and TXT lookup futures plus cache reset. This is the correct response injection seam.
- **Architectural problem:** `DnsResolver::Inner::op` owns Tokio notification selection and `n0_future` timeout; deterministic response providers do not make its timing deterministic.
- **Injectable dependency:** `AddressLookup` is a public streaming provider abstraction, and `AddressLookupServices` aggregates multiple services. Deterministic providers can model delay, stale/conflicting records, duplicates, and errors without copying aggregation logic.
- **Architectural problem:** service task spawning, update ordering, expiry, Pkarr retry/republish, and address-source timestamps remain runtime-owned.
- **Acceptable nondeterminism outside the deterministic backend:** external mDNS and Mainline address-lookup crates retain production integration/contract suites while the simulator exercises Iroh aggregation through controlled providers.

### Network Monitoring, Interfaces, Net Reports, and Port Mapping

| Occurrence | Classification | Required action |
| --- | --- | --- |
| `iroh/src/socket.rs:1035-1088` concrete `netmon::Monitor` construction and watcher ownership | **Architectural problem** | Add a monitor capability with production and simulation implementations. |
| `iroh/src/socket.rs:1760-1800` interface-change handling | **Injectable dependency** once its input is abstracted | Feed real logic with simulated state changes; do not create a separate simulated state machine. |
| `iroh/src/socket.rs:1932+` `LocalAddresses` enumeration | **Architectural problem** | Source interface/address state from the environment. |
| `iroh/src/socket/transports/relay/actor.rs:1302` direct `interfaces::State::new()` | **Architectural problem** | Relay address-family selection must use the same environment view. |
| `iroh/src/portmapper.rs` concrete enabled client / disabled stub | **Injectable dependency** with an incomplete simulation seam | Generalize the existing wrapper into a port-mapper capability; simulated mappings and expiry remain in the virtual network model. |
| Net-report QAD/HTTPS probes | **Injectable dependency** for QAD; **Architectural problem** for HTTPS | QAD over synthetic UDP can run in simulation. HTTPS/captive-portal checks require a synthetic HTTP connector or a controlled result provider until stream networking exists. |

### Retry and Backoff

All retry/backoff that affects connection establishment, discovery, relay reconnection, network-change recovery, probing, address publication, or shutdown is **Behavioral randomness**. Direct ownership by Tokio rather than an injected clock is additionally an **Architectural problem**. The primary production sites are:

- relay reconnect exponential backoff and jitter in `socket/transports/relay/actor.rs`;
- socket network-change exponential polling in `socket.rs`;
- QUIC timers controlled through `noq::Runtime`;
- DNS staggering and jitter in `iroh-dns/src/dns.rs`;
- Pkarr publish retry in `address_lookup/pkarr.rs`;
- relay Happy Eyeballs delays in `iroh-relay/src/client/tls.rs`;
- net-report probe staggering and timeout logic.

Every retry policy needs an observable attempt number, next deadline, decision-stream name, cancellation event, and terminal classification in the simulator trace.

### Filesystem, Environment, Processes, and Threads

| Occurrence group | Classification | Required action |
| --- | --- | --- |
| Endpoint proxy variables and `IROH_FORCE_STAGING_RELAYS` in `iroh/src/endpoint.rs` | **Architectural problem** if read by simulation; otherwise explicit production configuration | Resolve environment-derived defaults before constructing the simulation identity; simulation must never read ambient environment implicitly. |
| Relay binary access tokens, ACME variables, config/cert files in `iroh-relay/src/main.rs` | **Acceptable nondeterminism** in real-process backends | Controlled process backends record explicit config and fixtures. |
| DNS-server config/database/cert filesystem in `iroh-dns-server/src/**` | **Acceptable nondeterminism** until full server lifecycle enters deterministic scope | Use temporary explicit fixtures in integration tests; add a storage capability if the deterministic backend owns the complete DNS server. |
| Example secrets, qlog paths, trace output | **Acceptable nondeterminism** | Scenario identity specifies artifact paths; event semantics must not depend on them. |
| `chuck` workflow cloning and Python/process execution | **Acceptable nondeterminism** in a controlled real-network backend | Pin the external revision and record it in run identity; it cannot be the deterministic backend. |
| Benchmark threads | **Acceptable nondeterminism** | Keep as performance-layer measurement. |
| DNS-server HTTP/ACME supervision | **Acceptable nondeterminism** in the real-server backend | ACME maintenance, listeners, and connections are supervisor-owned; shutdown cancellation and its validated deadline are explicit. |

No Rust `std::process::Command` use was found in production library code. Process nondeterminism currently lives primarily in CI workflows and executable orchestration.

### Unordered Collections and Ordering

Unordered collection use is not automatically a defect. It is **Behavioral randomness** when iteration chooses a path, operation, eviction victim, trace order, or task order; such choices must be stabilized or explicitly recorded.

| Occurrence | Classification | Required action |
| --- | --- | --- |
| `iroh/src/socket/biased_rtt_path_selector.rs` connection/path iteration | **Deterministic boundary** | `PathTieBreak` provides a total address identity key after tier and biased RTT, with reversal-tested exact ties. |
| `iroh/src/socket/remote_map/remote_state/path_state.rs` failed-path collection and truncation | **Deterministic boundary** | Failed addresses sort before truncation, inactive ties use addresses, production retention uses stable sequence/address keys, and reversed insertion order is tested. |
| `iroh/src/socket/remote_map/remote_state.rs` connection/path scans | **Deterministic boundary** for side effects; **Acceptable nondeterminism** for membership/counts | `sorted_map_keys` orders connection and path effects by stable IDs; remote address snapshots sort by canonical address. Tests cover both canonicalizers. |
| `iroh/src/socket/remote_map.rs::RemoteMap::on_network_change` broadcast | **Deterministic boundary** | `ReadOnlyMap::snapshot_sorted_by_key` snapshots and sorts endpoint/sender pairs before capacity-sensitive delivery. |
| `iroh-relay/src/server/clients.rs::Clients::shutdown` DashMap collection | **Deterministic boundary** | `sorted_endpoint_ids` canonicalizes ascending endpoint IDs before concurrent shutdown futures start. |
| `iroh-relay/src/server/clients.rs::Clients::unregister` `HashSet` peer-gone notifications | **Deterministic boundary** | `sorted_endpoint_ids` canonicalizes ascending endpoint IDs before capacity-sensitive notification attempts. |
| `iroh-relay/src/server/client.rs` daily-client `HashSet` | **Acceptable nondeterminism** | Only membership and insertion-result semantics are used. |
| `iroh-dns/src/endpoint_info.rs` address `HashSet` | **Acceptable nondeterminism** | The set is used only for membership while a separate `Vec` retains public address order. |
| `iroh-relay/src/server/http_server.rs` handler `HashMap` | **Acceptable nondeterminism** | Runtime dispatch is keyed lookup. Sort only if stable debug/trace output becomes an artifact requirement. |
| `iroh/src/socket.rs` local-address `FxHashSet` | **Acceptable nondeterminism** | It represents membership in `NetworkChangeHint`; no choice depends on iteration order. |
| `iroh/src/socket/mapped_addrs.rs` maps | **Acceptable nondeterminism** | Allocation and resolution are keyed operations; no production behavior iterates the maps. |
| Hash maps/sets below `#[cfg(test)]`, in `tests/`, examples, or benchmarks | **Acceptable nondeterminism** unless imported by a scenario | Stable-sort output in simulator-facing test helpers. |

`BTreeMap`/`BTreeSet` use in published addresses, relay maps, and test-network registration already supplies stable key order and should be preserved.

The 2026-07-24 relay ordering hardening routes both order-sensitive collection paths through one
tested canonicalizer. Remote-map network-change fanout now likewise uses a tested sorted snapshot
instead of unordered map values. Remote-state actor effects use sorted connection/path key
snapshots, while initial datagram fan-out and published remote-address lists use canonical address
order. Exact path-selection ties now use a canonical network-path key instead of retaining the
first hash-map iteration item. The associated manifest drift is line movement in existing
production entropy/map boundaries, explicit saturating duration arithmetic, and timeout-based test
orchestration; it adds no ambient effect source.

The 2026-07-27 architecture cut moves the existing generic DNS effect seam from
`iroh-dns/src/dns.rs` into `iroh-resolver`. The production Hickory adapter remains a realistic
network boundary, while `Resolver` and `DnsRuntime` preserve deterministic lookup, timeout,
reset, and retry injection. `iroh-dns::dns::EndpointDnsResolver` only composes endpoint-record
parsing over that generic seam. New resolver inventory entries are therefore relocated reviewed
effects, not new ambient access. The same inventory update includes line movement from bounded
relay admission tests, explicit production challenge entropy, and endpoint/DNS integration tests;
each is test-only or an already classified production boundary.

The 2026-07-28 cross-platform feature repair removes a redundant Android JNI re-export from the
private `iroh-resolver::dns` module; the public re-export remains in `iroh-resolver::lib`. Every
network-environment row in `iroh-resolver/src/dns.rs` therefore shifts upward by two lines while
its matched source, owner, execution path, and existing **Injectable dependency** or production
Hickory boundary classification remains unchanged. No clock, entropy, scheduling, network,
filesystem, or unordered-iteration effect is added or removed.

The follow-up TLS/doctest repair makes rcgen crypto follow the explicitly selected relay TLS
provider and documents that the illustrative metrics-service example needs the separately owned
`iroh-metrics/service` feature. That documentation clarification moves the existing
`tokio::spawn(endpoint.closed()...)` example in `iroh/src/endpoint/handle.rs` down by one line. Its
matched source, owner, execution path, and documentation-only classification are unchanged; no
production spawn or other ambient effect is added or removed.

The 2026-07-27 simulation-environment cut replaces partial endpoint injection with one validated
**Injectable dependency**. `SimulationEnvironment` now rejects socket factories that do not name
an owning clock domain or that belong to a different runtime clock domain, before sockets bind or
tasks spawn. New `netmon::State::fake` occurrences in `iroh/src/endpoint.rs` and
`iroh/src/simulation.rs` are validation fixtures below `#[cfg(test)]`. The relay metrics listener
and its owned connection tasks are **Acceptable nondeterminism** in the real relay-server backend;
they are bounded by an abort-on-drop supervisor and do not enter the deterministic simulator.
Remaining relay/endpoint inventory movement comes from the explicit TLS provider cut and relocated
tests, not from new simulator-visible ambient effects.

The 2026-07-27 architecture hard cut then moved the already-classified effects into responsibility
modules without changing their execution paths: endpoint construction/handle/tests, socket
actor/inner/direct-address/tests, relay actor session/connect/message handling, relay server and
HTTP listener/connection/service/tests, and simulator CLI/runner/scenario domains. The DNS-server
clock and entropy entries moved from the crate-root test module into the private store unit test
and public package-boundary tests. Syntax-aware owner names and qualified API spellings therefore
change, but the effect counts and classifications remain the same except for those explicit test
boundary moves. Full simulator replay, production package tests, relay golden/live compatibility,
and resource/shutdown tests characterize the move; it introduces no new simulator-supported
ambient clock, entropy, task, network, filesystem, or unordered-collection escape.

The 2026-07-27 DNS shutdown correction adds `tokio::time::Instant` and `timeout_at` occurrences in
the production DNS-server supervisor. These are **Acceptable nondeterminism** at the realistic
server boundary: DNS, HTTP, and store cancellation is broadcast before any component is awaited,
and one absolute configured deadline bounds observation of all workers. The change neither enters
the deterministic simulator nor changes protocol behavior. The remaining DNS-server inventory
movement in this update is line relocation caused by the new `start_shutdown` methods; existing
test-only sleeps, entropy, native-thread fixtures, and network metrics retain their prior
classifications. The no-default-feature Patchbay fix only conditionally removes metrics collection;
its timeout, entropy, and spawned path-watch entries shift lines without changing behavior or
classification.

### Dependency Assessment

| Dependency | Finding | Action |
| --- | --- | --- |
| `noq` / `noq-proto` 1.1.0 | Runtime, abstract UDP, `now()`, and RNG seed seams already exist. | No initial fork. Add Iroh construction plumbing; propose upstream additions only if task metadata or escape detection cannot be layered. |
| `n0-future` 0.3.2 | Native time/task APIs are direct Tokio re-exports. | Stop using them in simulator-supported production paths or add an upstream runtime-context abstraction. |
| `netwatch` 0.19.1 | Concrete monitor, interface state, and UDP socket bind/rebind are embedded. | Wrap behind Iroh capabilities first; upstream generic adapters may reduce maintenance later. |
| `portmapper` 0.19.1 | Concrete client creates OS/network behavior internally. | Keep behind Iroh wrapper and generalize wrapper to a trait/capability. |
| `backon` 1.6.0 | Supports explicit jitter seeds. | Supply a named-stream seed; no fork required. |
| Hickory resolver | Uses Tokio runtime and real network in production. | Use existing `Resolver` trait for deterministic providers; keep Hickory in production and integration backends. |
| Tokio | Synchronization types and `select!` can be polled by a custom executor, but spawning, timers, I/O, and task sets bind to Tokio. | Permit Tokio synchronization where deterministic semantics are verified; ban direct runtime services in simulator-supported paths. |
| Hyper / tokio-websockets / reqwest | Real stream I/O and runtime behavior. | Introduce connector/session boundaries before real relay/HTTP code can run in deterministic simulation. |

## Current High-Risk Gaps

1. Production cryptographic entropy is intentionally outside the seeded scheduler stream;
   normalized replay may mask only opaque encrypted payload hashes.
2. Net-report HTTP/STUN probes, real DNS/TCP/TLS listener mechanics, and platform interfaces remain
   realistic-backend coverage rather than synthetic-backend behavior.
3. Patchbay/local/platform/interoperability fixture coverage is capability-scoped; double-NAT,
   multi-relay deployments, captive portals, diverse home routers, and IPv6 transition networks
   still need stable realistic observations.
4. Exact-source replay is guaranteed for the checked 30-day window; cross-schema conversion is
   intentionally unavailable until an explicit one-way migrator and fixture suite are added.
5. The weekly GitHub-hosted resource observation, daily deterministic soak, daily bounded fuzz
   workflow, and scheduled/manual GitHub-hosted Patchbay public smoke are checked service
   definitions, not execution evidence. Their first retained runs still require the GitHub service;
   a workflow definition must never be reported as a passed run. The hosted Patchbay smoke is
   limited to `nat::nat_none_x_none` and must fail when its user-namespace preflight or semantic
   parity comparison fails. The hosted resource profile is explicitly non-evidence, so recurring
   production-capacity qualification still requires an 8-core/30-GiB host outside that free service
   tier.

## Audit Exit Criteria

This audit remains current only when:

- every newly introduced direct clock, spawn, entropy, bind, resolver, monitor, port-mapper, filesystem, process, thread, or ordering-sensitive collection use is classified in this document;
- simulator-supported modules contain no unapproved escape from environment capabilities;
- the lexical and syntax-aware source checks jointly enforce the agreed direct-use policy;
- every known limitation names the stage and evidence that will retire it.

## Evidence Map

- Confirmed runtime seam: `iroh/src/runtime.rs`; `noq-1.1.0/src/runtime/mod.rs` in the locked Cargo source.
- Confirmed endpoint construction: `iroh/src/endpoint.rs:120-270`; `iroh/src/socket.rs:874-1117`.
- Confirmed concrete IP socket: `iroh/src/socket/transports/ip.rs:170-184`.
- Confirmed custom in-memory transport: `iroh/src/test_utils/test_transport.rs:1-320`.
- Confirmed DNS provider seam: `iroh-resolver/src/dns.rs`; production adapter:
  `iroh-resolver/src/hickory.rs`; endpoint composition: `iroh-dns/src/dns.rs`.
- Confirmed concrete network monitor: `iroh/src/socket.rs:1035-1088,1450-1800`.
- Confirmed port-mapper wrapper: `iroh/src/portmapper.rs`.
- Confirmed relay bindings: `iroh-relay/src/client/tls.rs`; `iroh-relay/src/server.rs:691-878`; `iroh-relay/src/server/http_server.rs:441-640`; `iroh-relay/src/quic.rs:97-200`.
- Confirmed path-state ordering risks: `iroh/src/socket/biased_rtt_path_selector.rs`; `iroh/src/socket/remote_map/remote_state/path_state.rs`.
- Confirmed realistic test layers: `iroh/tests/patchbay*`; `.github/workflows/netsim*.y*ml`; `.github/sims/**`.
- Confirmed recurring hosted Patchbay public-parity definition:
  `.github/workflows/patchbay-hosted-smoke.yml`;
  `scripts/tests/check-patchbay-hosted-smoke-workflow.sh`.
- Confirmed stable effect inventory: `tools/determinism-checker`;
  `scripts/check-determinism-semantic.sh`; `scripts/determinism-boundaries.semantic.txt`.
- Confirmed bounded parser/framing fuzzing: `fuzz/fuzz_targets`; `scripts/run-bounded-fuzz.sh`;
  `.github/workflows/fuzz.yml`.
- Confirmed recurring hosted resource-observation definition: `.github/workflows/resource-canary.yml`;
  `scripts/tests/check-resource-canary-workflow.sh`.
- Confirmed recurring daily deterministic-soak definition:
  `.github/workflows/simulation-daily-soak.yml`; `iroh-sim/soaks/daily.json`;
  `scripts/run-daily-simulation-soak.sh`; `scripts/aggregate-daily-simulation-soak.sh`;
  `scripts/tests/check-daily-simulation-workflow.sh`.

## Open Questions

1. Which realistic backend should next export a stable semantic fixture for the currently deferred dimensions?
2. Which schema transition should justify the first explicit one-way replay migrator?

## Review Resolution

- Resolved: the replacement specification supplies complete endpoint, relay, discovery, resource, and liveness invariants; the invariant architecture now covers all listed families.
- Resolved: internal dependency changes, including Noq, are authorized when required for maintainable injection seams.
- Resolved: the specification's five classification names are canonicalized above and mapped to every grouped occurrence.
- Resolved: CI budgets, retention, triage, corpus review, and exact-source replay compatibility are
  validated by `iroh-sim/operations-policy.json` and documented in the operations runbook.
- Resolved: production-duration lifecycle, exact load conservation, structured canary diagnostics,
  scheduled realistic evidence, stable semantic boundary identities, and bounded protocol fuzzing
  now have executable gates.

## Change Summary

- Replaced the truncated-source warning with a hash-pinned complete source reference.
- Added a reproducible search baseline and exhaustive context-classification rules.
- Preserved the secure distinction between production entropy and deterministic behavioral decisions.
