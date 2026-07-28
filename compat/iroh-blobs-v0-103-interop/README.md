# iroh-blobs v0.103 interoperability driver

This excluded compatibility crate depends on the crates.io `iroh-blobs` v0.103.0 stack and the
local v2 port at the same time. It transfers a fixed payload in both directions over direct QUIC
connections and fails on connection, protocol, hash, or byte mismatches.

Run it from the repository root:

```console
cargo run --manifest-path compat/iroh-blobs-v0-103-interop/Cargo.toml --locked
```

The crate is deliberately excluded from the production workspace so its Iroh 1.x dependency graph
cannot be unified into release builds.
