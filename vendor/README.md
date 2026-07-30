# Vendored dependencies

Three upstream crates are vendored because each carries a patch this project
requires and upstream has not accepted. Each directory is its crates.io package
plus the sibling `*.patch` file, and nothing else.

| Directory | Upstream | Patch | Scope |
|---|---|---|---|
| `noq-1.1.0/` | noq 1.1.0 | `noq-1.1.0.patch` | Production. Bounded event queues, per-poll budgets, connection-lifetime ownership. |
| `hickory-server-0.26.1/` | hickory-server 0.26.1 | `hickory-server-0.26.1.patch` | Production. Pre-spawn UDP-request and TCP-connection admission limits. |
| `rustls-0.23.41/` | rustls 0.23.41 | `rustls-0.23.41.patch` | Simulator only. Run-scoped entropy and key-exchange visibility for deterministic replay. Patched in by `iroh-sim/Cargo.toml`; no production crate resolves it. |

Each directory's `IROH-VENDOR.md` documents the exact delta, the update
procedure, and why the patch cannot be dropped.

`scripts/tests/check-vendor-provenance.sh` asserts in CI that every directory
still equals upstream plus its patch, so the claim above cannot silently rot.

The rustls tree is normalized with `rustfmt --edition 2021` at default settings
before the patch is applied; the other two are byte-identical to their packages.
