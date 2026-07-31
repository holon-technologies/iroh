# krikos-dns

Peer-to-peer QUIC, dialed by public key.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](../LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](../LICENSE-APACHE)

`krikos-dns` publishes and resolves Krikos endpoint information over DNS,
using the [pkarr](https://pkarr.org) signed packet format. It is the
address lookup mechanism the `N0` preset installs for
[`krikos`](../krikos), and it depends on [`krikos-resolver`](../krikos-resolver)
for the underlying DNS resolution.

Most applications should depend on [`krikos`](../krikos), not on this crate
directly.

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
