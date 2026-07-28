# iroh-gossip v0.101 interoperability driver

This excluded compatibility crate runs the crates.io `iroh-gossip` v0.101.0 stack and the local v2
port in one process. The nodes form a direct HyParView link over the unchanged `/iroh-gossip/1`
ALPN and exchange a fixed Plumtree payload in both directions.

Run it from the repository root:

```console
cargo run --manifest-path compat/iroh-gossip-v0-101-interop/Cargo.toml --locked
```

The crate is deliberately excluded from the production workspace so its exact Iroh 1.0.3 graph
cannot enter v2 release builds.
