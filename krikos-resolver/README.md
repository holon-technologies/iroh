# krikos-resolver

`krikos-resolver` provides the generic DNS resolver used by Krikos. It resolves host addresses and
TXT records, supports explicit Ring or AWS-LC TLS providers for encrypted DNS, and exposes runtime
capabilities for deterministic timeout and retry testing.

The crate intentionally does not understand Krikos endpoint identifiers, endpoint records, pkarr,
or DNS publication. Applications normally depend on `krikos`; direct dependencies are useful for
relay integrations, custom resolvers, and runtime adapters.

## Support boundary

- `krikos-resolver` is versioned and released in lockstep with the public Krikos crates.
- Select at most one of `tls-ring` and `tls-aws-lc-rs` in production builds.
- Resolver resets atomically replace the implementation before waking in-flight operations.
- Address results are bounded to 64 records per IP family and lookup.

## License

Licensed under either the Apache License, Version 2.0, or the MIT license, at your option.
