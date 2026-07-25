# Migrating from Iroh 1.x to 2.0

Iroh 2.0 makes construction at external and resource-admission boundaries
fallible. Most applications only need to propagate the new errors with `?`.
No wire-format migration is required by the changes below.

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

`dns::Builder::build` now returns `Result<DnsResolver, dns::BuildError>`.

```rust
let resolver = dns_builder.build()?;
```

The error reports resolver initialization failures that were previously hidden
inside an infallible constructor.

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

## `iroh-runtime`

`iroh-runtime` is a new published implementation dependency. Cargo resolves it
transitively for normal `iroh` and `iroh-relay` users. Direct dependencies are
only needed for custom runtime, tracing, or deterministic simulation
integrations.
