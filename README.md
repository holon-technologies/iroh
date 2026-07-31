<h1 align="center">Krikos</h1>

<h3 align="center">
Peer-to-peer QUIC, dialed by public key.
</h3>

[![CI](https://img.shields.io/github/actions/workflow/status/holon-technologies/iroh/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/holon-technologies/iroh/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE)

Krikos gives you an API for dialing by public key. You say "connect to that
endpoint" and Krikos finds and maintains the fastest route for you — direct
where hole-punching succeeds, relayed through an open ecosystem of public
relay servers where it does not.

## Quickstart

Krikos is not yet published to crates.io — a release is pending crate-name
reservation (see [ADR-0002](docs/adr/0002-krikos-rebrand.md)). Until then,
depend on it directly from this repository:

```toml
[dependencies]
krikos = { git = "https://github.com/holon-technologies/iroh", branch = "main" }
```

The full working example below is
[`krikos/examples/echo.rs`](krikos/examples/echo.rs); run it with
`cargo run -p krikos --example echo`:

```rust
use krikos::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_error::{Result, StdResultExt};

/// Each protocol is identified by its ALPN string.
///
/// The ALPN, or application-layer protocol negotiation, is exchanged in the connection handshake,
/// and the connection is aborted unless both endpoints pass the same bytestring.
const ALPN: &[u8] = b"krikos-example/echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let router = start_accept_side().await?;

    // wait for the endpoint to be online
    router.endpoint().online().await;

    connect_side(router.endpoint().addr()).await?;

    // This makes sure the endpoint in the router is closed properly and connections close gracefully
    router.shutdown().await.anyerr()?;

    Ok(())
}

async fn connect_side(addr: EndpointAddr) -> Result<()> {
    let endpoint = Endpoint::bind(presets::N0).await?;

    // Open a connection to the accepting endpoint
    let conn = endpoint.connect(addr, ALPN).await?;

    // Open a bidirectional QUIC stream
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;

    // Send some data to be echoed
    send.write_all(b"Hello, world!").await.anyerr()?;

    // Signal the end of data for this particular stream
    send.finish().anyerr()?;

    // Receive the echo, but limit reading up to maximum 1000 bytes
    let response = recv.read_to_end(1000).await.anyerr()?;
    assert_eq!(&response, b"Hello, world!");

    // Explicitly close the whole connection.
    conn.close(0u32.into(), b"bye!");

    // The above call only queues a close message to be sent (see how it's not async!).
    // We need to actually call this to make sure this message is sent out.
    endpoint.close().await;
    // If we don't call this, but continue using the endpoint, we then the queued
    // close call will eventually be picked up and sent.
    // But always try to wait for endpoint.close().await to go through before dropping
    // the endpoint to ensure any queued messages are sent through and connections are
    // closed gracefully.
    Ok(())
}

async fn start_accept_side() -> Result<Router> {
    let endpoint = Endpoint::bind(presets::N0).await?;

    // Build our protocol handler and add our protocol, identified by its ALPN, and spawn the endpoint.
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();

    Ok(router)
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    /// The `accept` method is called for each incoming connection for our ALPN.
    ///
    /// The returned future runs on a newly spawned tokio task, so it can run as long as
    /// the connection lasts.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // We can get the remote's endpoint id from the connection.
        let endpoint_id = connection.remote_id();
        println!("accepted connection from {endpoint_id}");

        // Our protocol is a simple request-response protocol, so we expect the
        // connecting peer to open a single bi-directional stream.
        let (mut send, mut recv) = connection.accept_bi().await?;

        // Echo any bytes received back directly.
        // This will keep copying until the sender signals the end of data on the stream.
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        println!("Copied over {bytes_sent} byte(s)");

        // By calling `finish` on the send stream we signal that we will not send anything
        // further, which makes the receive stream on the other end terminate.
        send.finish()?;

        // Wait until the remote closes the connection, which it does once it
        // received the response.
        connection.closed().await;

        Ok(())
    }
}
```

## What you get

- **Dial by public key.** Each endpoint has a [`SecretKey`](krikos/src/lib.rs)
  used to authenticate and encrypt the connection; you connect to an
  [`EndpointId`](krikos/src/lib.rs), not an IP address and port.
- **Hole-punching with relay fallback.** Krikos tries to establish a direct
  connection by hole-punching first, and falls back to a relay server when
  that fails.
- **QUIC streams, datagrams, and stream priorities.** Bidirectional and
  unidirectional streams, an unreliable datagram transport, and per-stream
  send priorities are all exposed directly.
- **No head-of-line blocking.** Streams are multiplexed over one encrypted
  QUIC connection, so a lost packet on one stream does not stall the others.

## How it is verified

Krikos is verified by deterministic simulation: production endpoint, QUIC,
and relay code runs against a synthetic network with controlled latency,
loss, NAT and relay behaviour, driven by seed-reproducible scenarios that can
be replayed and minimised on failure. See
[`docs/testing/simulation.md`](docs/testing/simulation.md) for the testing
strategy and [`docs/testing/deterministic-simulation-architecture.md`](docs/testing/deterministic-simulation-architecture.md)
for how the simulator achieves seed-reproducible runs.

## Relationship to upstream

Krikos is a hard fork of [`n0-computer/iroh`](https://github.com/n0-computer/iroh).
Every package, library name, and Rust import path was renamed
(`use iroh::Endpoint` became `use krikos::Endpoint`), but relay wire
compatibility with upstream `v1.0.3` was deliberately preserved and is
machine-guarded by [`krikos-relay/tests/wire_compat.rs`](krikos-relay/tests/wire_compat.rs)
and [`scripts/tests/check-relay-compatibility.sh`](scripts/tests/check-relay-compatibility.sh).
Upstream's copyright stands — see [License](#license) below.

For the full package mapping and what did and did not change, see the
[Krikos migration guide](docs/release/krikos-migration.md) and
[ADR-0002: the Krikos rebrand](docs/adr/0002-krikos-rebrand.md).

## Repository structure

The published crates and their `cargo metadata` descriptions:

- [`krikos`](krikos) — p2p QUIC connections dialed by public key.
- [`krikos-base`](krikos-base) — base type and utilities for Krikos.
- [`krikos-runtime`](krikos-runtime) — internal runtime capabilities for Krikos.
- [`krikos-resolver`](krikos-resolver) — provider-neutral DNS resolution for Krikos.
- [`krikos-dns`](krikos-dns) — DNS-based endpoint discovery for Krikos.
- [`krikos-relay`](krikos-relay) — Krikos's relay server and client.
- [`krikos-dns-server`](krikos-dns-server) — a pkarr relay and DNS server.

Plus the isolated deterministic simulation workspace, which production crates
never depend on:

- [`krikos-sim`](krikos-sim) — deterministic simulation and replay infrastructure for Krikos.

## Documentation

Start at [`docs/README.md`](docs/README.md) for architecture, testing, and
release documentation.

## License

Copyright 2025 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
