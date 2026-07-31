<h1 align="center">Krikos</h1>

<h3 align="center">
Peer-to-peer QUIC, dialed by public key.
</h3>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](../LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](../LICENSE-APACHE)

`krikos` is the main library and the crate most applications depend on
directly: it gives you an API for dialing another endpoint by its public
key. You say "connect to that endpoint", and krikos finds and maintains the
fastest route for you — direct where hole-punching succeeds, relayed
through [`krikos-relay`](../krikos-relay) where it does not.

Under the hood, krikos establishes peer-to-peer [QUIC] connections. Because
it is built on QUIC, all connections are end-to-end encrypted and may carry
any number of concurrent streams; dialing by public key also makes them
mutually authenticated, since each endpoint's public key is its TLS
identity.

`krikos` builds on [`krikos-base`](../krikos-base) for shared types,
[`krikos-runtime`](../krikos-runtime) for its runtime, and
[`krikos-dns`](../krikos-dns) for public-key-based address lookup.

## Overview

A krikos endpoint is created and controlled by `Endpoint`. Each endpoint has
a unique `SecretKey`, whose public key is the endpoint's identity, the
`EndpointId`. Connections are authenticated against this key, so an
`EndpointId` cannot be impersonated.

A connection is usually established with the help of a relay server. When an
endpoint is created it connects to the closest relay and designates it as
its home relay. Other endpoints reach it first through this relay, then both
sides use QUIC NAT traversal to try to establish a direct connection; if
that is not possible, traffic keeps flowing over the relay. Relay servers
only forward encrypted packets addressed to endpoint IDs and cannot read
traffic between endpoints.

To discover addressing information for an endpoint, krikos uses an address
lookup service. The `N0` preset used in the example below installs
DNS/pkarr-based lookup via [`krikos-dns`](../krikos-dns), so you can connect
to another endpoint knowing only its `EndpointId`.

## Example

The full, worked echo example — the accepting side copies back whatever it
receives — lives in this crate as
[`examples/echo.rs`](examples/echo.rs) and is reproduced in the
[Quickstart in the root README](../README.md#quickstart). Run it with
`cargo run --example echo`. More examples are in [`examples/`](examples),
each documented in the file itself.

## Development

For notes on krikos's structured tracing events and how to build the
documentation, see [DEVELOPMENT.md](DEVELOPMENT.md).

## Documentation

See the [root README](../README.md) for what Krikos is and how it is
verified, and [`docs/`](../docs/README.md) for architecture and testing
documentation.

## License

Copyright 2025 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](../LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](../LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[QUIC]: https://en.wikipedia.org/wiki/QUIC
