# iroh-resolver

`iroh-resolver` provides the generic DNS resolver used by Iroh. It resolves host addresses and
TXT records, supports explicit Ring or AWS-LC TLS providers for encrypted DNS, and exposes runtime
capabilities for deterministic timeout and retry testing.

The crate intentionally does not understand Iroh endpoint identifiers, endpoint records, pkarr,
or DNS publication. Applications normally depend on `iroh`; direct dependencies are useful for
relay integrations, custom resolvers, and runtime adapters.

## Support boundary

- `iroh-resolver` is versioned and released in lockstep with the public Iroh crates.
- Select at most one of `tls-ring` and `tls-aws-lc-rs` in production builds.
- Resolver resets atomically replace the implementation before waking in-flight operations.
- Address results are bounded to 64 records per IP family and lookup.

## License

Licensed under either the Apache License, Version 2.0, or the MIT license, at your option.
