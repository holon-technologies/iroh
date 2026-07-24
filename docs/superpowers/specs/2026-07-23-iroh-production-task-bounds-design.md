# RFC: Bound Production Tasks, Connections, Actors, and Event Queues

## Status

Approved by the user on 2026-07-24; implemented on 2026-07-24.

## Scope

This RFC closes the remaining TigerStyle safety gate in production connection, task, actor, and
queue ownership:

- native `iroh-runtime::TokioTaskGroup` live-task accounting;
- native and browser endpoint active-connection admission before Noq creates a connection driver;
- native and browser endpoint remote-state actor admission;
- native and browser active-relay actor admission;
- native remote-state and active-relay completion queues;
- browser Noq task spawning through `noq::Runtime`;
- relay QUIC address-discovery connection/task admission;
- the relay server's independent plain-HTTP captive-portal connection tasks;
- DNS address-result cardinality before relay dialing or net-report collection; and
- the network-fed Noq endpoint-to-connection and connection-to-endpoint event queues.

It does not change protocol wire formats, persisted data, address/path limits, the already-bounded
main relay HTTP/session or DNS admission paths, or simulator budgets. It adds overload errors and
a validated public endpoint-limits configuration, without changing valid below-limit connection
behavior.

## Context

### Confirmed current behavior

- The deterministic kernel rejects task creation above `KernelConfig::max_tasks` with
  `SpawnError::ResourceLimit` (`iroh-sim/src/kernel.rs:1008`).
- The production Tokio task group inserts every accepted task into an unbounded `BTreeMap` and has
  no live-task capacity check (`iroh-runtime/src/task.rs:266`).
- Each distinct endpoint ID can cause `RemoteMap::send_to_actor` to create another
  `RemoteStateActor`; the sender map has no global actor limit
  (`iroh/src/socket/remote_map.rs:335`).
- Native remote-state completions use `mpsc::unbounded_channel`
  (`iroh/src/socket/remote_map.rs:159`, `iroh/src/socket/remote_map.rs:183`).
- Each distinct relay URL can create another `ActiveRelayActor`; native completions also use an
  unbounded channel (`iroh/src/socket/transports/relay/actor.rs:1201`,
  `iroh/src/socket/transports/relay/actor.rs:1367`).
- `Endpoint::accept` and `Endpoint::connect_with_opts` create Noq connection drivers without an
  endpoint-wide active-connection limit (`iroh/src/endpoint.rs:1239`,
  `iroh/src/endpoint.rs:1307`, `iroh/src/endpoint/connection.rs:147`).
- `Router` creates one `JoinSet` task per incoming connection without separate admission
  (`iroh/src/protocol.rs:557`, `iroh/src/protocol.rs:590`). Connection lifetime alone is
  insufficient because custom protocol code can drop its connection and remain pending.
- Relay QUIC address discovery creates one `JoinSet` task per accepted connection and retains it
  until handshake failure or peer close, with no active-connection ceiling
  (`iroh-relay/src/quic.rs:124`, `iroh-relay/src/quic.rs:143`).
- When relay TLS is enabled, its separate plain-HTTP captive-portal listener creates one `JoinSet`
  task per TCP connection without using relay-session admission
  (`iroh-relay/src/server.rs:1267`, `iroh-relay/src/server.rs:1287`).
- Noq's pending-incoming set is finite by default, but its endpoint-to-connection and
  connection-to-endpoint Tokio channels are unbounded. Network datagrams feed the former directly
  (`noq-1.1.0/src/endpoint.rs:770`, `noq-1.1.0/src/endpoint.rs:844`,
  `noq-1.1.0/src/endpoint.rs:982`).
- Browser Noq tasks call `wasm_bindgen_futures::spawn_local` without accounting or rejection
  (`iroh/src/runtime.rs:180`).
- `DnsResolver` exposes address iterators without an Iroh-owned record ceiling.
  `resolve_host_all` extends a `VecDeque` with every result, relay Happy Eyeballs retains that
  queue while starting dials, and net-report collects the same results into `Vec`s
  (`iroh-dns/src/dns.rs:624`, `iroh-relay/src/client/tls.rs:323`,
  `iroh/src/net_report/reportgen.rs:604`).

### Failure scenario

A remote or discovery-controlled stream of distinct endpoint identities, relay URLs, valid
connections, or connection datagrams can cause production task or event-queue state to grow until
memory exhaustion. Per-actor inbox, path, pending-incoming, and relay-session limits do not bound
all of these independent dimensions. Native structured ownership makes some tasks cancellable but
does not make their cardinality or Noq queue depth finite. These paths satisfy the TigerStyle
safety-gate condition “remote input can directly cause uncontrolled memory/task growth.”

## Goals

- Every production connection, task, actor, and event-queue family affected by network input has a
  visible, enforceable finite ceiling.
- Capacity is acquired before task creation; rejected work creates no waiter and does not allocate
  task metadata, inboxes, or actor state.
- Endpoint active-connection capacity is acquired before Noq creates a connection driver; the same
  configured ceiling also drives a separate task-lifetime `Router` handler ledger.
- Native completion queues are bounded and use task completion itself as backpressure.
- Network event saturation drops only packet-derived work for which QUIC loss recovery is valid.
  Packet backlog has both item and byte ceilings; control or terminal events are never silently
  lost.
- Subsystem resource-limit rejection is deterministic, observable, and recoverable. Exhausting the
  larger catch-all runtime ceiling is an internal capacity-invariant violation and fails the
  endpoint closed.
- Native, browser, and deterministic-simulation behavior have equivalent capacity invariants.
- Existing wire, persistence, and valid below-limit behavior remain compatible.

## Non-Goals

- Evicting a live actor to admit a new peer.
- Treating the catch-all runtime ceiling as a substitute for subsystem admission.
- Guaranteeing availability against link saturation or CPU exhaustion before packets reach Iroh.
- Changing the simulator's scenario-provided `max_tasks`.
- Redesigning Noq protocol state machines or wire behavior; the dependency patch is limited to
  queue accounting, saturation behavior, and tests.

## Options

### Option A: Production executor ceiling only

Add a live-task limit to `TokioTaskGroup` and reject the next spawn.

Benefits:

- smallest code change;
- appears to catch Noq, socket, remote-state, relay, and future task families; and
- reuses the simulator's existing typed `SpawnError::ResourceLimit`.

Costs and risks:

- overload semantics are too coarse;
- actor code currently assumes spawn succeeds or reports completion later;
- `noq::Runtime::spawn` returns `()`, and Noq inserts connection state before calling it; dropping
  a rejected driver future can strand connection state instead of cleanly rejecting admission;
- it does not bound Noq's event channels or relay QAD's independent Tokio task set;
- browser execution remains unbounded; and
- reaching the catch-all ceiling can reject unrelated critical tasks.

### Option B: First-party subsystem ceilings only

Bound endpoint connections, remote-state actors, active-relay actors, relay QAD connections, and
first-party completion channels, but leave Noq's internal event channels unchanged.

Benefits:

- deterministic overload behavior at the source;
- preserves capacity for critical runtime tasks;
- works on native and browser targets; and
- prevents legitimate Noq connection creation from reaching the runtime backstop.

Costs and risks:

- Noq's network-fed event channels remain unbounded;
- every new task family must remember to add its own limit; and
- no defense-in-depth if an admission invariant regresses.

### Option C: Layered admission, bounded Noq queues, and runtime backstop

Add explicit connection and actor ceilings below a larger runtime-group ceiling, bound completion
and Noq event queues, bound relay QAD, and add browser task accounting.

Benefits:

- overload is handled where domain context exists;
- Noq packet overload has protocol-correct loss semantics while control/terminal events retain
  delivery guarantees;
- the runtime cap catches regressions and unclassified task families;
- native/browser invariants match; and
- saturation in one actor family preserves headroom for shutdown and supervision.

Costs:

- requires a narrow vendored Noq patch plus changes in `iroh-runtime`, `iroh`, and `iroh-relay`;
- requires more lifecycle tests; and
- introduces finite defaults that need canary observation.

## Recommendation

Choose Option C.

The alternative of one catch-all ceiling is unsafe for Noq's infallible spawn contract and cannot
bound its event queues. Admission before connection/actor creation supplies deterministic overload
behavior; queue budgets bound packet-driven memory; the larger runtime ceiling is a fail-closed
proof that an overlooked task family cannot restore unbounded growth.

## Design

### Named capacities

Use these conservative 1.x defaults:

| Resource | Limit | Rationale |
| --- | ---: | --- |
| Live tasks per native runtime group | 4,096 | Defense-in-depth ceiling above the checked endpoint minimum and equal to the existing relay session maximum |
| Browser Noq tasks per endpoint runtime | 4,096 | Native parity for the task family that bypasses `TaskGroup` |
| Active Noq connections/Router handlers per endpoint | 2,048 each | Configures separate driver-lifetime and task-lifetime ledgers while allowing multiple connections per remote actor |
| Pending Noq incoming attempts per endpoint | 2,048 | Replaces Noq's generic 65,536-attempt default with the endpoint's declared connection policy |
| Remote-state actors per endpoint | 1,024 | Bounds distinct peer state while retaining runtime headroom |
| Active-relay actors per endpoint | 64 | Far above ordinary relay maps and below the existing 64-address endpoint limit |
| Remote-state completion queue | 1,024 | At most one completion per admitted remote actor |
| Active-relay completion queue | 64 | At most one completion per admitted relay actor |
| Relay QAD active connections/tasks | 1,024 | Bounds the independent QAD Noq endpoint and its handler `JoinSet` |
| Relay captive-portal handlers | 256 | Reuses the configured pending-establishment ceiling in a separate ledger |
| DNS address records per family per lookup | 64 | Explicitly bounds custom/network resolver iterators and downstream dial/report queues |
| Noq packet events per connection | 32 | Bounds packet memory; saturation is ordinary QUIC packet loss |
| Noq packet bytes per endpoint | 64 MiB | Bounds variable-sized/GRO packet storage across all connection queues |
| Noq bidirectional normal/control events | 4,096 | One conserved pool bounds connection events and their generated endpoint responses |
| Noq terminal-event reserve | 4,096 | Two terminal transitions for each of 2,048 admitted connections |

All capacities are nonzero validated types at construction. Checked arithmetic proves the default
endpoint runtime budget is greater than or equal to one Noq driver per active connection + remote
actors + relay actors + 64 fixed supervisor/Noq tasks. `Router` handlers use a separate ledger and
do not run in that runtime group. Tests use smaller injected limits.

Add a public `EndpointLimits` value with private fields, `Default`, nonzero setters, and
`Builder::limits`. This is an additive 1.x API and gives operators one validated place to tune the
task, connection, remote-actor, and active-relay ceilings. Completion, pending-incoming, and Noq
queue capacities are derived from those ceilings and remain internal. `QuicConfig` gains an
additive `max_connections` setting because QAD can run without the relay HTTP server.

### Native task-group backstop

Add `TaskGroupLimits` with private fields and a validated nonzero task-count constructor. Preserve
`TokioExecutor::new` and `TokioExecutor::with_clock`; they use
`DEFAULT_MAX_LIVE_TASKS_PER_GROUP`. Add an explicit constructor accepting default
`TaskGroupLimits` for tests and operators constructing `RuntimeContext::from_parts`.

Add a provided `Executor::new_group_with_limits(parent, limits)` method whose compatibility default
delegates to `new_group`. The built-in Tokio executor honors the requested per-group ceiling. The
simulator enforces both the requested per-group ceiling and its stricter scenario-wide task ledger.
The endpoint uses this method with `EndpointLimits`; existing relay-server call sites keep
`new_group` and the executor default.

`TokioTaskGroup::spawn_owned` checks `state.tasks.len()` while holding the existing group-state
mutex and before allocating an ID, ordinal, task metadata, or executor task. At capacity it:

1. drops the unpolled future;
2. returns `SpawnError::ResourceLimit { resource: "live_tasks", limit }`;
3. increments a checked rejection counter in group state; and
4. records a bounded rejection observation without allocating rejected-task metadata or using
   peer-controlled labels.

Normal completion or cancellation removes the task before later admissions, so capacity is
reusable. The simulator retains its stricter scenario-supplied limit.

Do not add fields to the public `TaskGroupSnapshot`, because downstream code can construct that
public struct and a new field would be a 1.x source break. Add a provided
`TaskGroup::capacity_snapshot` method instead; external task-group implementations inherit an
`Unreported` result, while the built-in Tokio and simulator groups report their configured maximum,
current live count, high-water count, and total checked rejection count. Counter overflow latches
`TaskGroupError` and closes the group rather than wrapping.

The endpoint validates that its declared connection/actor capacities plus fixed supervisor
headroom fit below the task-group limit, then requests that exact limit when constructing its task
group. This prevents normal below-limit Noq work from reaching an API that cannot report spawn
rejection.

### Endpoint connection admission

`EndpointInner` owns a native/browser `Arc<AtomicUsize>` active-connection ledger. A checked
compare-exchange acquires one non-clonable RAII token:

- by `Accept::poll` before returning an `Incoming`; and
- by `Endpoint::connect_with_opts` before calling Noq's `connect_with`.

The vendored Noq patch adds an additive opaque `ConnectionLifetimeToken` and guarded variants of
its connect/accept entry points. The Iroh token moves through `Incoming` and address resolution,
then is consumed by the guarded Noq entry point and stored in the Noq connection's shared inner
state. It releases only after both driver and user-visible connection-state ownership end. This is
deliberately stricter than tying it to Iroh's outer `Connection` handle: dropping that handle while
Noq is still draining cannot free a slot and admit an additional driver. Failed resolution,
handshakes, rejected hooks, cancellation, and panic unwinding release it automatically.

Noq's pending `proto::Incoming` buffer does not create a connection driver. The Iroh `Accept`
wrapper therefore acquires its token after polling that pending value but before any public caller
can invoke the guarded Noq accept operation that creates the driver. A source check requires every
Iroh and relay-QAD driver-creation call site to use the guarded variants; the original Noq methods
remain source-compatible but are not used by production code in this repository.

The endpoint's internal net-report QAD probes use the same ledger even though they call the shared
Noq endpoint directly rather than `Endpoint::connect_with_opts`. The net-report `QuicConfig`
receives a ledger clone, each probe acquires before `QuicClient::create_conn`, and `QadConn` owns
the guarded Noq connection whose inner state owns the token. A full ledger skips/counts that
probe; it cannot exceed the endpoint total through an internal bypass.

Incoming saturation never creates a waiter. `Accept::poll` refuses at most a fixed batch
of over-capacity Noq `Incoming` values per poll, records each refusal, then self-wakes if more work
may remain. Outgoing saturation returns a new typed
`ConnectWithOptsError::ConnectionCapacityFull`; it does not start address resolution or create a
Noq connection driver.

`StaticConfig::create_server_config` sets Noq `max_incoming` to the endpoint's pending-attempt
limit. That existing Noq guard bounds state before the Iroh accept layer sees it.

`Router` separately owns a nonblocking handler-task ledger whose maximum is derived from the
endpoint connection limit. It acquires before `JoinSet::spawn`, refuses the `Incoming` at capacity,
and holds the handler permit until the task exits. This separate permit is required because custom
protocol code can drop its `Connection` and remain pending; connection lifetime alone must not
allow replacement traffic to grow the Router task set. The Router limit is derived rather than
independently tunable, so endpoint connection and handler ceilings cannot drift.

### Remote-state admission

Introduce `RemoteStateLimits` containing a nonzero actor limit and completion capacity. `RemoteMap`
owns the policy and a rejection metric.

`send_to_actor` becomes fallible. If the endpoint ID is not already present and the actor count is
at capacity, it returns `RemoteStateAdmissionError::CapacityFull` before constructing an inbox or
future. `RemoteStateActor::start` also becomes fallible: the sender enters `senders` only after the
native runtime or browser join set accepts the actor. Runtime spawn rejection therefore cannot
leave a dead sender behind or enter the current completion/restart loop.

Call-site behavior is deterministic:

- address resolution completes with a typed `AddressLookupFailed::ActorCapacityFull`;
- a newly established connection is rejected through an internal typed result and its connection
  handle is dropped;
- a datagram for an unknown, over-capacity remote is dropped and counted; and
- existing actors continue to receive work and are never evicted by overload.

Actor completion frees capacity only after the owning `RemoteMap` processes the completion and
removes the sender, preventing two actors for one capacity slot during restart races. A terminating
actor still consumes capacity until that cleanup transition completes; this is deliberately
conservative.

Native completions use `mpsc::channel(max_remote_state_actors)`. Completion futures await
`send`; that wait is owned by the still-live actor task and therefore remains covered by both the
subsystem and runtime ceilings. Cancellation closes the receiver and releases blocked senders.
Spawn rejection is returned directly and never synthesizes a completion, avoiding queue-dependent
deadlock.

Browser `JoinSet` admission uses the same actor-count invariant.

### Active-relay admission

Introduce `ActiveRelayLimits` with a 64-actor default and a bounded completion channel.

Creating a relay already present in `active_relays` remains free. At capacity, a new relay URL is
rejected before inboxes, datagram channels, or a task are created. Existing relays and the current
home relay are not evicted. `start_active_relay` returns a typed result, and a handle is inserted
only after actor construction and task admission both succeed.

If net-report selects a new home relay while capacity is full, the preferred URL remains published
but its state becomes `Disconnected` with the capacity error rather than remaining falsely
`Connecting`. Existing relay actors are not evicted. `reap_active_relays` retries the preferred
home after any actor exits, so capacity recovery does not require an endpoint restart. Datagram
senders drop and count an item whose requested relay cannot be admitted; they may continue using
direct paths or an already-active relay that knows the endpoint.

Native completion sends await bounded queue capacity. Browser `JoinSet` length uses the same
ceiling. Shutdown cancels actors, drains completions within the existing absolute runtime timeout,
and reports remaining counts on timeout.

### Relay QUIC address-discovery admission

`QuicConfig::max_connections` defaults to 1,024 and validates as nonzero before binding a socket.
`QuicServer::spawn` sets Noq `max_incoming` to the same ceiling and owns a nonblocking semaphore.
The accept loop calls `try_acquire_owned` before `JoinSet::spawn`; full capacity calls
`Incoming::refuse`, increments a fixed QAD rejection metric, and creates no connection driver or
handler task. The permit is moved into Noq through the guarded accept operation, so it remains live
from handler-task admission through handshake failure, peer close, cancellation, panic, or final
connection-state drop.

The QAD `JoinSet`, Noq active connection set, and handler-task count therefore share one conserved
capacity. QAD shutdown stops admission, closes the endpoint, and drains the bounded task set within
the relay server's existing supervisor deadline.

### Relay captive-portal admission

The TLS configuration's plain-HTTP captive-portal listener is independent of the admitted relay
HTTP listener, so it receives its own nonblocking semaphore. Its maximum is derived from the
validated `Limits::max_pending_establishments` value (256 by default) but it does not share permits
with relay-session establishment; captive-portal traffic therefore cannot consume the main relay
admission pool.

The accept loop calls `try_acquire_owned` before `JoinSet::spawn`. At capacity it drops the newly
accepted TCP stream, increments a fixed captive-portal rejection counter, and creates no handler
task. The task owns the permit across HTTP keep-alive/upgrades and releases it on completion,
cancellation, or panic. Shutdown stops admission and drains or aborts at most the configured
number of tasks under the existing relay supervisor.

### DNS result admission

Add a shared `MAX_DNS_ADDRESS_RECORDS_PER_FAMILY` limit of 64. Each IPv4 or IPv6 lookup consumes at
most 65 iterator items: the first 64 are retained, and observing item 65 returns a typed
`DnsError::TooManyAddressRecords` instead of silently truncating. The check wraps every resolver,
including custom implementations, before `lookup_ipv4_ipv6`, `resolve_host_all`, relay Happy
Eyeballs, or net-report can queue or collect results.

Literal IP URL hosts remain a single-item result. A dual-family lookup can therefore expose at
most 128 addresses in total, while each DNS question and custom-resolver iterator has its own
visible conserved ceiling. No dial future is created for a rejected oversized lookup.

### Bounded Noq event queues

Vendor the locked `noq` 1.1.0 crate with its licenses and a documented narrow delta, as already
done for Hickory and rustls. The patch replaces unrestricted use of the two internal unbounded
event channels with private budgeted queue wrappers; raw senders are not exposed outside those
wrappers.

Add outer-runtime `EventQueueLimits` to the vendored Noq crate rather than changing the
`noq-proto::EndpointConfig` protocol type. Existing Noq endpoint constructors delegate to new
explicit-limit constructors with finite defaults. Iroh's abstract-socket constructor and QAD's
server helper use the explicit form, deriving the terminal reserve from `EndpointLimits` or
`QuicConfig::max_connections`.

Endpoint-to-connection packet queues have both a 32-event per-connection budget and a shared
64-MiB endpoint byte budget. The network-receive call site charges the received buffer length
before ownership moves into the opaque protocol event. If either budget is full, it drops the new
datagram event and increments fixed item/byte rejection counters, so QUIC treats it as network loss
and retransmits reliable data. Charging bytes as well as events is required because receive
segments and configured UDP payload size make event allocation variable.

Connection-to-endpoint nonterminal events and endpoint-generated protocol responses share one
4,096-token pool. A connection event acquires a token before enqueue. When
`Endpoint::handle_event` consumes it, the endpoint either releases the token if there is no
response or transfers that exact token with the generated response into the destination
connection's control queue. The response therefore cannot lose an admission race after protocol
state has allocated it, and the combined two-direction backlog never exceeds 4,096. Generated
responses are not assumed to be safely coalescible. The vendored state-machine test asserts the
current invariant that terminal transitions generate no response.

If a connection cannot acquire a normal control token, that connection closes with a typed local
resource-limit reason and publishes terminal events through its reserved credits. Synchronous
`Close`, `Rebind`, and `LocalAddressChanged` use reserved/coalesced per-connection state. The
connection driver drains control in priority order: `Close`, latest `Rebind`, latest local-address
change, generated protocol responses, then packet events. `Close` has a dedicated slot and is never
silently lost.

Connection-to-endpoint delivery therefore has:

- the shared 4,096-token pool for reset-token, identifier, retirement, and generated response
  events; and
- a separate terminal reserve of two events per admitted connection for `Draining` and `Drained`.

Every enqueued item owns a non-clonable budget token released by receive/drop. If a nonterminal
event cannot acquire capacity, that connection transitions to a typed local resource-limit close
and publishes its terminal events through the reserve. Each admitted connection receives exactly
two non-clonable terminal credits at driver creation, rather than racing for a shared reserve at
shutdown. The aggregate reserve is sized with checked multiplication and an assertion proves one
connection cannot publish more than its `Draining` and `Drained` transitions. Queue closure wakes
and terminates both drivers.

The budget wrappers may retain Tokio's unbounded transport primitive internally only because the
non-clonable tokens make enqueue cardinality finite before allocation. Tests exercise every wrapper
API and source search/visibility checks prove there is no raw sender bypass. This preserves the
poll-based Noq architecture without blocking an executor thread or dropping protocol-control
transitions.

### Browser Noq task budget

The browser `Runtime` owns `Arc<AtomicUsize>` live-task accounting with a nonzero limit. Atomic
accounting is required even on the browser build because `noq::Runtime` has a
`Send + Sync + 'static` contract. Its `noq::Runtime::spawn` implementation uses a
compare-exchange admission loop:

1. checks capacity before `spawn_local`;
2. drops and records rejected futures without polling;
3. wraps accepted futures in a guard that decrements the checked count on completion, cancellation,
   or unwind; and
4. asserts that decrement cannot underflow.

The Noq trait returns `()`, so browser and native Noq rejection cannot be returned to that caller.
Normal peer overload is rejected earlier by connection and actor admission and remains recoverable.
Reaching the larger Noq/runtime ceiling therefore means a capacity invariant regressed: the runtime
latches a typed failure, signals endpoint shutdown, and prevents any further admission. It does not
continue with a Noq connection whose driver was dropped. Native task families whose internal API
returns `Result` still receive `SpawnError::ResourceLimit` directly.

The browser socket/remote/relay subsystem limits remain necessary because those actors do not all
enter `noq::Runtime::spawn`.

### Arithmetic and failure rules

- Capacity comparisons use `usize` without casts.
- Rejection counters use `checked_add`; exhaustion closes/latches the relevant supervisor.
- Connection, actor, and QAD admission use nonblocking acquisition and create no capacity waiter.
- The runtime owns a capacity-failure cancellation signal observed by the endpoint supervisor.
  Catch-all exhaustion closes admission and the Noq endpoint before sibling teardown; subsystem
  saturation does not trigger this signal.
- No peer-controlled ID or URL becomes a metric label.
- Internal count underflow or actor-count divergence is a release `assert!` with the violated
  invariant in its message.
- Failed actor construction or runtime admission never inserts a handle or synthesizes a
  completion.
- Checked addition/multiplication validates the relationship between connection, actor, queue,
  terminal-reserve, and runtime ceilings before endpoint or QAD socket bind.
- Public callers never panic because of capacity exhaustion.

## Compatibility

- Existing constructors keep their signatures and receive finite defaults.
- `EndpointLimits`, `Builder::limits`, and `QuicConfig::max_connections` are additive public API.
- Existing public snapshot structs keep their fields; capacity diagnostics use a new provided
  trait method to avoid a downstream struct-literal break.
- Below-limit behavior and all protocol bytes are unchanged.
- New capacity variants are added only to already non-exhaustive endpoint/address error models.
- Rejection replaces process growth only at previously unbounded overload levels.
- No feature flag or “unlimited” sentinel is introduced.
- The Noq patch keeps its public wire and connection APIs compatible; new queue-limit configuration
  is additive and defaults finite.

## Observability and operations

Add fixed counters for:

- runtime live-task rejections;
- endpoint incoming/outgoing connection-capacity rejections;
- remote-state actor capacity rejections; and
- active-relay actor capacity rejections;
- QAD connection-capacity rejections;
- Noq packet events dropped at queue capacity; and
- Noq connections closed because a nonterminal control-event budget was exhausted.

Existing runtime snapshots keep their stable shape. The new capacity snapshot reports maximum,
current, high-water, and rejection count. Endpoint diagnostics report the same bounded values for
connections and actors. Debug logs include configured maximum and current count, never
remote-provided labels.

Before raising a default, run a 2x offered-load canary and retain at least 30% CPU, RSS, descriptor,
task, and queue headroom. Rollback may lower a limit or replace the vendored Noq patch with an
upstream release that has equivalent tested bounds; it must not restore an unlimited production
executor or event queue.

## Verification Plan

Use test-driven development:

1. `iroh-runtime`: with a test limit of two, prove the third future is dropped unpolled with typed
   `ResourceLimit`; no ID or ordinal is consumed by rejection; completing one task permits exactly
   one later spawn; cancellation and panic conserve capacity; concurrent spawn attempts never
   exceed the limit; and capacity diagnostics retain 1.x snapshot compatibility.
2. `iroh` endpoint: inject a two-connection limit; prove outgoing third-connect rejection occurs
   before resolution/driver spawn, incoming overload is refused without a handler task, permit
   conservation holds through handshake failure, zero-RTT, outer-handle drop while the Noq driver
   drains, clone/drop, panic, and shutdown. Prove `Router` tasks never exceed two even when a
   protocol handler drops its connection and remains pending. Exercise an internal net-report QAD
   probe against the same ledger and prove it cannot bypass the total.
3. `iroh` remote map: inject a two-actor limit, admit two distinct IDs, reject the third with each
   call-site-specific outcome, complete one actor, and admit another. Test spawn rejection, absence
   of dead sender insertion, restart races, and queue saturation.
4. `iroh` relay actor: inject a two-relay limit, preserve existing/home relays at saturation, reject
   a new URL, publish a capacity error for a newly preferred home, release one, and recover that
   preferred home automatically.
5. Noq vendor tests: flood one connection's packet queue and the shared endpoint event queue;
   prove exact item and byte high-water ceilings, packet-drop accounting, reliable recovery,
   token transfer conserves the combined bidirectional control ceiling, normal-control saturation
   closes only the affected connection, control-state coalescing, terminal delivery,
   lifetime-token conservation on driver/handle drop, counter conservation on panic/drop, and no
   raw sender or unguarded production connection bypass.
6. Relay QAD: inject a two-connection limit, hold two valid connections open, refuse excess
   handshakes before spawn, release one, recover, and deadline-bound saturated shutdown.
7. Relay captive portal: inject a two-handler limit, hold two keep-alive connections open, reject
   the third before spawn, release one, recover, and deadline-bound saturated shutdown without
   consuming main relay-establishment permits.
8. Browser: compile and run Wasm tests proving connection, actor, queue, and Noq task counts never
   exceed injected limits under concurrent admission attempts and capacity returns after
   completion/drop.
9. Deterministic simulation: use low connection/kernel/task budgets and assert the same terminal
   rejection class and reproducible trace.
10. DNS: inject exactly 64 and then 65 IPv4/IPv6 records through a custom resolver; prove exact
    limits are accepted, item 65 returns `TooManyAddressRecords`, and relay/net-report queues never
    observe the oversized iterator.
11. Run formatting, determinism inventory/self-tests, strict workspace all-target Clippy,
   vendored Noq, `iroh-runtime`, `iroh`, `iroh-sim`, relay tests, and Android/Wasm CI jobs.
12. Run a bounded 2x-limit load scenario and repeat `/rate-tigerstyle`; removal of both remote
    task-growth and queue-growth safety gates is mandatory.

## Acceptance Criteria

- No production task group can contain more than its configured live-task maximum.
- No endpoint or relay QAD server can own more active Noq connections than its configured maximum.
- No relay captive-portal listener can own more handler tasks than its derived maximum.
- No endpoint can own more remote-state or active-relay actors than its configured maximum.
- No DNS lookup can retain or expose more than 64 records per address family.
- Completion and Noq event queue item/byte capacity is finite; no control, terminal, or completion
  event required for cleanup can be lost.
- Packet-event saturation is counted and behaves as QUIC loss; reliable traffic recovers after
  capacity returns.
- Saturation does not evict existing work, await admission, panic a public caller, or poison an
  endpoint merely because a subsystem is full.
- A runtime or actor spawn failure cannot leave a dead handle in an actor map.
- A newly preferred home relay that cannot be admitted reports `Disconnected`, then retries after
  capacity becomes available.
- Releasing capacity permits recovery without restarting the endpoint.
- Catch-all runtime exhaustion fails the endpoint closed and reports the violated capacity
  invariant instead of continuing with an unowned Noq driver.
- Shutdown remains deadline-bounded with saturated connection, actor, completion, and event queues.
- Native, browser, QAD, Noq-vendor, and simulator tests prove the same count-conservation invariant.

## Evidence

- Confirmed: native task metadata is unbounded at `iroh-runtime/src/task.rs:266`.
- Confirmed: simulator live tasks are bounded at `iroh-sim/src/kernel.rs:1008`.
- Confirmed: remote actors and completions are unbounded at
  `iroh/src/socket/remote_map.rs:159` and `iroh/src/socket/remote_map.rs:335`.
- Confirmed: active relay actors and completions are unbounded at
  `iroh/src/socket/transports/relay/actor.rs:1201` and
  `iroh/src/socket/transports/relay/actor.rs:1367`.
- Confirmed: endpoint accepts/connects and Router handler spawning have no active-connection/task
  ceiling at `iroh/src/endpoint.rs:1239`, `iroh/src/endpoint.rs:1307`, and
  `iroh/src/protocol.rs:590`.
- Confirmed: QAD handler tasks have no active ceiling at `iroh-relay/src/quic.rs:124`.
- Confirmed: the separate relay captive-portal listener has no handler ceiling at
  `iroh-relay/src/server.rs:1287`.
- Confirmed: Noq uses network-fed unbounded event channels at
  `noq-1.1.0/src/endpoint.rs:770`, `noq-1.1.0/src/endpoint.rs:844`, and
  `noq-1.1.0/src/endpoint.rs:982`.
- Confirmed: Noq pending incoming attempts are already finite, with a configurable default of
  65,536 at `noq-proto-1.1.0/src/config/mod.rs:254`; this is not the active-connection/task bound.
- Confirmed: browser Noq spawning bypasses structured ownership at `iroh/src/runtime.rs:180`.
- Confirmed: DNS address iterators feed relay/net-report queues without an Iroh-owned record limit
  at `iroh-dns/src/dns.rs:624`, `iroh-relay/src/client/tls.rs:323`, and
  `iroh/src/net_report/reportgen.rs:604`.
- Confirmed: `noq::Runtime::spawn` returns `()` and therefore cannot communicate admission
  rejection to Noq at `noq-1.1.0/src/runtime/mod.rs:18`.
- Rejected finding: `ClientCounter.clients` in `iroh-relay/src/server/client.rs:600` is constructed
  per admitted client actor and receives only that actor's own endpoint ID; it is bounded by relay
  session admission and is not a separate remote-growth path.
- Proposed: layered defaults and overload behavior in this RFC.

## Open Questions

None. The user approved Option C and its proposed defaults on 2026-07-24. The separate
public-constructor fallibility RFC was approved at the same time.

## Review Resolution

- Resolved: browser `Rc<Cell<_>>` violated Noq's `Send + Sync` contract -> use atomic accounting.
- Resolved: adding fields to `TaskGroupSnapshot` would break 1.x struct literals -> add a provided
  capacity-snapshot trait method.
- Resolved: actor spawn failure could leave a dead sender/handle -> insertion follows successful
  construction and admission.
- Resolved: a newly preferred home relay could remain falsely `Connecting` at capacity -> publish
  a capacity-backed `Disconnected` state and retry on reap.
- Resolved: runtime-only rejection is unsafe for Noq's infallible spawn -> acquire connection
  capacity before Noq state/driver creation and fail closed only if the larger backstop is reached.
- Resolved: first-party actor bounds did not cover QAD, Router, or Noq event queues -> include each
  path with a conserved limit and saturation test.
- Resolved: tying connection capacity to Iroh's outer handle could release before the Noq driver
  drained -> store an opaque lifetime token in vendored Noq's shared connection state.
- Resolved: a protocol handler can drop its connection and remain pending -> give Router handler
  tasks a separate derived ledger held for the entire task.
- Resolved: an event count alone permitted excessive variable-size/GRO packet memory -> add a
  shared packet-byte ceiling.
- Resolved: endpoint-generated CID responses are not safely coalescible and cannot race for
  capacity after allocation -> transfer the consumed connection-event token with its response.
- Resolved: main relay admission did not cover the TLS configuration's independent captive-portal
  listener -> give it a separate ledger derived from the validated pending-establishment limit.

## Change Summary

- Expanded the RFC from actor tasks to all confirmed remote-controlled connection, task, and event
  queue growth paths.
- Added additive endpoint/QAD configuration, explicit overload outcomes, dependency-patch scope,
  compatibility constraints, and risk-matched tests.
- Kept the capacity product decision to approval of Option C and its finite defaults; public
  constructor fallibility is tracked in a separate approval-gated RFC.
