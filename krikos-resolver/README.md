# krikos-resolver

Peer-to-peer QUIC, dialed by public key.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](../LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](../LICENSE-APACHE)

`krikos-resolver` provides the generic DNS resolver used by Krikos. It resolves host addresses and
TXT records, supports explicit Ring or AWS-LC TLS providers for encrypted DNS, and exposes runtime
capabilities for deterministic timeout and retry testing. [`krikos-dns`](../krikos-dns) depends on
this crate for its DNS resolution.

The crate intentionally does not understand Krikos endpoint identifiers, endpoint records, pkarr,
or DNS publication. Applications normally depend on [`krikos`](../krikos); direct dependencies are
useful for relay integrations, custom resolvers, and runtime adapters.

## Support boundary

- `krikos-resolver` is versioned and released in lockstep with the public Krikos crates.
- Select at most one of `tls-ring` and `tls-aws-lc-rs` in production builds.
- Resolver resets atomically replace the implementation before waking in-flight operations.
- Address results are bounded to 64 records per IP family and lookup.

## Documentation

See the [root README](../README.md) for what Krikos is, and
[`docs/`](../docs/README.md) for architecture and testing documentation.

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
