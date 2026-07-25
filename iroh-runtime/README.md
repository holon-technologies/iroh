# iroh-runtime

`iroh-runtime` contains the bounded runtime capabilities shared by production
Iroh and its deterministic simulator: clocks, task ownership, decision streams,
stable identifiers, and causal tracing.

Most applications should depend on `iroh`, not on this crate directly. Iroh
selects the production runtime automatically. A direct dependency is intended
for runtime adapters, deterministic test harnesses, and tooling that consumes
the trace schema.

## Support boundary

- `iroh-runtime` is versioned and released in lockstep with the public Iroh
  crates.
- Public types are supported for the matching Iroh major version, but this
  crate is not an independent compatibility layer between different Iroh
  releases.
- Implementations must preserve finite task admission, owned cancellation,
  clock-domain consistency, deterministic decision paths, and monotonic trace
  identifiers.
- Production code should use the defaults exposed by `iroh` unless it has a
  concrete need to provide these capabilities.

See the crate-level API documentation for the capability contracts and
[`docs/release/v2-migration.md`](../docs/release/v2-migration.md) for the Iroh
2.0 migration notes.

## License

Licensed under either the Apache License, Version 2.0, or the MIT license, at
your option.
