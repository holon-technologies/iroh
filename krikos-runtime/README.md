# krikos-runtime

Peer-to-peer QUIC, dialed by public key.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](../LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](../LICENSE-APACHE)

`krikos-runtime` contains the bounded runtime capabilities shared by production
Krikos and its deterministic simulator: clocks, task ownership, decision streams,
stable identifiers, and causal tracing. [`krikos`](../krikos) depends on this
crate for its runtime.

Most applications should depend on [`krikos`](../krikos), not on this crate
directly. Krikos selects the production runtime automatically. A direct
dependency is intended for runtime adapters, deterministic test harnesses, and
tooling that consumes the trace schema.

## Support boundary

- `krikos-runtime` is versioned and released in lockstep with the public Krikos
  crates.
- Public types are supported for the matching Krikos major version, but this
  crate is not an independent compatibility layer between different Krikos
  releases.
- Implementations must preserve finite task admission, owned cancellation,
  clock-domain consistency, deterministic decision paths, and monotonic trace
  identifiers.
- Production code should use the defaults exposed by `krikos` unless it has a
  concrete need to provide these capabilities.

See the crate-level API documentation for the capability contracts and
[`docs/release/v2-migration.md`](../docs/release/v2-migration.md) for the Krikos
architecture migration notes.

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
