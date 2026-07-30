# Migrating from Krikos 1.x to 2.0

Krikos 2.0 makes construction at external and resource-admission boundaries
fallible. Most applications only need to propagate the new errors with `?`.
No wire-format migration is required by the changes below.

## Architecture hard cut

The fork's v2 architecture work intentionally permits Rust source breaks in crate dependencies,
module paths, Cargo features, endpoint test construction, and simulator APIs. Each implemented
break is recorded in this guide before the architecture cut is declared ready.

The hard cut does **not** change relay V1/V2 wire behavior. Fork clients and servers remain
bidirectionally compatible with upstream `v1.0.3` as specified in
[`../relay-compatibility.md`](../relay-compatibility.md).

Migration entries for implemented architecture cuts:

- generic DNS types moved from `krikos_dns::dns` to the `krikos_resolver` crate;
- endpoint-aware DNS lookup moved to `krikos_dns::dns::EndpointDnsResolver`;
- relay server feature selection becomes explicit with `server-ring` or `server-aws-lc-rs`;
- individual simulation builder setters are replaced by one validated simulation environment;
- flat `krikos-sim` root exports move under domain modules.

This is a deliberate major-version source cut. There is no compatibility module that restores the
old Rust paths. Relay V1/V2 bytes and negotiation remain compatible; Rust imports, Cargo features,
and test-only construction code must be migrated.

## Blob protocol workspace port

`krikos-blobs` v0.103.0 is now preserved under `protocols/krikos-blobs` and ported as the private
workspace crate `krikos-blobs` 2.0. Rust source compatibility is not guaranteed, but the imported
ALPN, wire requests, range encoding, hash semantics, ticket strings, and filesystem metadata remain
frozen by compatibility fixtures.

The crate now uses the local `krikos` v2 endpoint facade directly. It no longer depends on
`krikos-util`, `iroh-tickets`, or the Krikos 1.x core graph. `BlobTicket` keeps the canonical `blob`
prefix and v0.103 lowercase unpadded-base32 bytes; its parse error is now
`krikos_blobs::ticket::ParseError` rather than `iroh_tickets::ParseError`.

The imported `mdns-address-lookup` example now demonstrates explicit direct-address discovery.
The external `iroh-mdns-address-lookup` adapter targets Krikos 1.x and cannot be mixed with v2
endpoint types. Applications can supply a custom v2 discovery implementation or construct a
bounded `EndpointAddr` with `EndpointAddr::try_from_parts`.

Blob providers and stores now enforce finite defaults for request bytes, range complexity,
multi-blob count, provider connections, queued actor commands, active store/import/download work,
progress queues, and graceful shutdown. Treat limit rejection as recoverable overload and split
large application requests instead of increasing all limits together.

Run `scripts/tests/check-blobs-v0-interop.sh` to exercise a live transfer in both directions between
the crates.io v0.103.0 stack and the local v2 port. The driver is an excluded compatibility crate;
its Krikos 1.x dependencies never enter the production workspace graph.

## Gossip protocol workspace port

`krikos-gossip` v0.101.0 is preserved under `protocols/krikos-gossip` and ported as the private
workspace crate `krikos-gossip` 2.0. The ALPN remains `/iroh-gossip/1`; topic IDs, HyParView control
messages, Plumtree payload/control messages, and outer envelopes are frozen by v0.101 byte
fixtures. The pure membership and broadcast state machines remain independent of endpoint I/O and
wall-clock scheduling.

The optional network adapter now uses the local v2 `Endpoint` and `Router` directly. Invalid
configuration has an explicit `Config::validate`/`Builder::try_spawn` path, while `Builder::spawn`
retains the existing convenience API and reports invalid configuration as a named invariant panic.
Finite limits cover frames, views, shuffle fanout, topics, subscriptions, pending messages and
sends, duplicate/payload caches, graft retries, streams, dials, connection handlers, and graceful
shutdown.

Run `scripts/tests/check-gossip-v0-interop.sh` for a live bidirectional broadcast between crates.io
`krikos-gossip` v0.101.0 on exact Krikos v1.0.3 and the local v2 port. The compatibility driver is
excluded from the production workspace so the Krikos 1.x graph cannot enter a release build.

The endpoint implementation is now split behind a narrow `krikos::endpoint` facade. Public endpoint
imports (`krikos::Endpoint`, `krikos::endpoint::Builder`, connection types, relay status, and lifecycle
types) are unchanged by that structural move; the new `endpoint::{builder,handle,lifecycle,
relay_status}` modules are private implementation owners and are not migration targets.

The same rule applies to the socket, relay actor, relay server, and relay HTTP splits: those are
private ownership changes, not new public import paths. Code using private fork internals must move
to the supported facade or maintain its own fork-local adapter.

## Simulator domain modules

`krikos-sim` no longer reexports its complete API from the crate root. Import from the owning domain:

| Before | After | Responsibility |
| --- | --- | --- |
| `krikos_sim::Kernel` | `krikos_sim::engine::Kernel` | kernel, network, NAT, relay, discovery |
| `krikos_sim::Scenario` | `krikos_sim::model::Scenario` | schemas, observations, inventory, invariants |
| `krikos_sim::ScenarioRunner` | `krikos_sim::execution::ScenarioRunner` | backends, runners, campaigns, minimization |
| `krikos_sim::RunManifest` | `krikos_sim::evidence::RunManifest` | manifests, traces, artifacts, failures, parity |
| `krikos_sim::OperationsPolicy` | `krikos_sim::operations::OperationsPolicy` | gates, soak, swarm, operational policy |
| `krikos_sim::cli::Cli` | unchanged | stable `cargo sim` parsing and dispatch facade |

The serialized scenario, manifest, trace, corpus, parity, and failure formats did not change as a
result of these moves. Scenario schema parsing/migration and runner implementation modules are
private; consumers use the domain facade rather than their internal file layout.

## `krikos-base` feature implications

`krikos-base` keeps `default = ["relay"]`. Selecting `key` also selects `relay`, because key-facing
endpoint/address types require relay URL support. For a minimal build, disable defaults explicitly
and enable only the required feature:

```toml
krikos-base = { version = "2", default-features = false }
```

## Explicit relay TLS provider

The `krikos-relay/server` feature is now provider-neutral and intended for embedded library builds.
Runnable relay binaries must select exactly one complete bundle:

| Purpose | Feature |
| --- | --- |
| Ring relay server | `server-ring` |
| AWS-LC relay server | `server-aws-lc-rs` |
| Provider-neutral embedded server API | `server` |

For example, replace `cargo run -p krikos-relay --features server` with
`cargo run -p krikos-relay --no-default-features --features server-ring`. A providerless binary now
fails at compile time. The internal `relay-bin` target marker is supplied by both provider bundles
so workspace feature unification cannot select the binary accidentally. Embedded users that select
only `server` must install a Rustls provider before starting TLS and must enable `tls-ring` or
`tls-aws-lc-rs` if they start QUIC address discovery.

## Atomic simulation environment

The hidden endpoint methods `runtime_context_for_test`, `ip_socket_factory_for_test`,
`network_monitor_for_test`, and `simulation_crypto_for_test` were removed. Repository simulation
code must construct a complete `krikos::simulation::SimulationEnvironment` and install it with the
single `simulation_environment_for_test` entry point plus `UnsafeTestOnly` acknowledgement.

`SimulationEnvironment::new` is now fallible. A simulation socket factory must report the same
`ClockDomain` as the supplied runtime; missing ownership and mixed runtime/socket environments are
rejected before endpoint tasks spawn or sockets bind. These APIs remain hidden, test-only
infrastructure and are not a supported production customization surface.

## Fallible Pkarr construction

`PkarrRelayClient::new`, `PkarrRelayClientBuilder::build`,
`PkarrPublisherBuilder::build`, and `PkarrResolverBuilder::build` now return
`Result`. Construction can fail when the HTTP client cannot be built.

```rust
let client = PkarrRelayClient::new(pkarr_relay_url)?;
let publisher = publisher_builder.build(secret_key, tls_config)?;
let resolver = resolver_builder.build(tls_config)?;
```

Handle `PkarrError::HttpClient` explicitly when retry or configuration
diagnostics are preferable to propagation.

## Fallible DNS resolver construction

Generic resolution is now independent from endpoint-record discovery. Add `krikos-resolver` when
using these types directly. `krikos` continues to reexport the generic crate as `krikos::dns`.

| Before | After |
| --- | --- |
| `krikos_dns::dns::DnsResolver` | `krikos_resolver::DnsResolver` |
| `krikos_dns::dns::Resolver` | `krikos_resolver::Resolver` |
| `krikos_dns::dns::DnsRuntime` | `krikos_resolver::DnsRuntime` |
| `krikos_dns::dns::Builder` | `krikos_resolver::Builder` |
| `krikos_dns::dns::DnsProtocol` | `krikos_resolver::DnsProtocol` |
| `krikos_dns::dns::DnsError` | `krikos_resolver::DnsError` |
| `krikos_dns::dns::StaggeredError` | `krikos_resolver::StaggeredError` |
| `krikos_dns::dns::TxtRecordData` | `krikos_resolver::TxtRecordData` |
| `krikos_dns::dns::DNS_TIMEOUT` | `krikos_resolver::DNS_TIMEOUT` |
| `krikos_dns::dns::install_android_jni_context` | `krikos_resolver::install_android_jni_context` |
| `krikos_dns::install_android_jni_context` | `krikos_resolver::install_android_jni_context` |
| `DnsResolver::lookup_endpoint_by_id` | `EndpointDnsResolver::new(resolver).lookup_by_id` |
| `DnsResolver::lookup_endpoint_by_domain_name` | `EndpointDnsResolver::new(resolver).lookup_by_domain_name` |

`krikos_resolver::Builder::build` returns `Result<DnsResolver, BuildError>`.

```rust
let resolver = dns_builder.build()?;
```

The error reports resolver initialization failures that were previously hidden
inside an infallible constructor.

The `krikos-dns` `tls-ring` and `tls-aws-lc-rs` features now forward to `krikos-resolver`. Relay
integrations should depend on `krikos-resolver` directly; doing so no longer pulls endpoint-record
parsing or `simple-dns` into relay clients and servers.

## `krikos-resolver`

`krikos-resolver` is a new lockstep-published implementation dependency. It owns provider-neutral
A, AAAA, TXT, and host resolution, bounded address results, atomic network-change reset, and
deterministic timeout/stagger runtime injection. It intentionally has no dependency on
`krikos-base`, endpoint records, pkarr, or DNS publication.

## Fallible relay QUIC client construction

`quic::QuicClient::new` now returns
`Result<QuicClient, QuicClientBuildError>`.

```rust
let client = QuicClient::new(endpoint, tls_config)?;
```

This rejects a caller-supplied Rustls configuration whose cryptographic
provider is incompatible with the relay QUIC configuration.

## Relay-session admission

`server::clients::Clients::register` now returns `Result<(), RegisterError>`.
Callers embedding the low-level relay server must handle global capacity,
per-endpoint capacity, and runtime task-admission failures.

```rust
clients.register(client_config, metrics)?;
```

Treat capacity errors as recoverable overload, not process-fatal errors.

## Bounded endpoint addresses

Untrusted `EndpointAddr` and `CustomAddr` parsing and deserialization now reject
values above finite count and byte limits. Prefer
`EndpointAddr::try_from_parts` and `CustomAddr::try_from_parts`.

The old `from_parts` constructors remain source-compatible for now but are
deprecated because they do not enforce boundary limits. Existing serialized
addresses within the published limits remain accepted.

## Server resource limits

The DNS and relay servers now apply finite defaults to accepted connections,
requests, tasks, sessions, request bodies, retained limiter state, and shutdown
time. Review deployments that intentionally need higher concurrency:

- copy the documented production configuration;
- change one limit at a time;
- load-test at twice the proposed capacity; and
- retain saturation, latency, memory, file-descriptor, and task-count evidence.

Capacity rejection is an expected overload response. Do not replace finite
limits with unbounded values.

## `krikos-runtime`

`krikos-runtime` is a new published implementation dependency. Cargo resolves it
transitively for normal `krikos` and `krikos-relay` users. Direct dependencies are
only needed for custom runtime, tracing, or deterministic simulation
integrations.

## Local-first protocol crates

The fork now owns `krikos-blobs`, `krikos-gossip`, and `krikos-docs` in the same workspace on the v2
version line. Applications should use the workspace-compatible `2.0.0` crates together; mixing
their Rust APIs with the upstream 0.x protocol crates is unsupported.

The hard cut does not change the frozen protocol and persistent formats:

- blobs keeps `/iroh-bytes/4` and v0.103 request, range, hash, ticket, and store representations;
- gossip keeps `/iroh-gossip/1` and v0.101 HyParView, Plumtree, topic, and envelope encodings; and
- docs keeps `/iroh-sync/1`, v0.101 tickets and signed entries, reconciliation messages, redb table
  names, and existing migrations.

`DocTicket` no longer exposes the external `iroh_tickets::ParseError`. Parsing returns
`krikos_docs::ParseError`, and `DocTicket::try_new` is the fallible constructor for untrusted peer
lists. `DocTicket::new` remains as a trusted-state convenience and panics when its invariant is
violated. Ticket and start-sync inputs now reject oversized peer lists or endpoint addresses.

Persistent docs stores are opened and migrated as before. When an older redb file requires a
format rewrite, keep the automatically created `.backup-redb-v1` or
`.backup-redb-v2-tuples` sibling until the application has reopened the migrated store and
validated its documents. Migration failure leaves that backup available for rollback; do not
delete or rename either file while a docs process is running.
