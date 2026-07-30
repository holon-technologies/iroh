# Migrating from upstream iroh to Krikos

This guide is for anyone whose code currently depends on an upstream
`n0-computer/iroh*` crate (`iroh`, `iroh-blobs`, `iroh-gossip`, ...) and wants
to move to this fork, Krikos. [ADR-0002](../adr/0002-krikos-rebrand.md) is the
decision record; this document is the practical companion it calls for.

It is a **naming and import-path migration**, not an API migration: package
names, library names, directory names, and every Rust import path changed
(`use iroh::Endpoint` becomes `use krikos::Endpoint`), but the public API
shape, the wire protocols, and the relay compatibility guarantees did not.
See ["What did not change"](#what-did-not-change) below for the specifics,
and why they were kept.

If you are instead migrating between this fork's *own* `1.x` and `2.0`
architecture-generation Rust APIs (an independent, unrelated set of breaking
changes to endpoint construction, DNS types, and simulator module paths),
see [`v2-migration.md`](v2-migration.md). The two migrations are orthogonal:
a project could need one, the other, or both, depending on which upstream
version and which fork revision it starts from.

## Why this isn't a one-line manifest change

Renaming only the *package* (`iroh` → `krikos` in `Cargo.toml`) while leaving
`[lib] name = "iroh"` unchanged would have made migration a one-line
dependency-alias change (`krikos = { package = "iroh", ... }`). ADR-0002
rejected that: a crate whose package and library names disagree is a
permanent source of confusion, and a fresh brand that still compiles as
`iroh` is not a fresh brand. So the *import path* changed too, across roughly
430 `use` statements in this fork's own source, and downstream code that
imports these crates has the same rewrite to do.

## Package mapping

Every package below is renamed at the identity level: package name, Rust
library name (the identifier used after `use`/`::`), and — except for the two
vendored forks and the two packages whose directory never contained the
string `iroh` — its directory. This table is generated from
[`scripts/rename-map.toml`](../../scripts/rename-map.toml), the single
source of truth the rebrand's completeness gate
(`scripts/tests/check-rebrand-complete.sh`) checks against; if this table and
that file ever disagree, the file is correct.

ADR-0002's own summary names 15 of these as "the" target list and mentions
`krikos-local-first-app-tests` separately ("plus...") because it is a test
harness rather than a library consumers depend on. All 16 renamed packages
are listed here for completeness.

| Old package | New package | Old import (`use ...`) | New import (`use ...`) | Directory | Publishable |
| --- | --- | --- | --- | --- | --- |
| `iroh` | `krikos` | `iroh::` | `krikos::` | `iroh/` → `krikos/` | yes |
| `iroh-base` | `krikos-base` | `iroh_base::` | `krikos_base::` | `iroh-base/` → `krikos-base/` | yes |
| `iroh-relay` | `krikos-relay` | `iroh_relay::` | `krikos_relay::` | `iroh-relay/` → `krikos-relay/` | yes |
| `iroh-dns` | `krikos-dns` | `iroh_dns::` | `krikos_dns::` | `iroh-dns/` → `krikos-dns/` | yes |
| `iroh-dns-server` | `krikos-dns-server` | `iroh_dns_server::` | `krikos_dns_server::` | `iroh-dns-server/` → `krikos-dns-server/` | yes |
| `iroh-resolver` | `krikos-resolver` | `iroh_resolver::` | `krikos_resolver::` | `iroh-resolver/` → `krikos-resolver/` | yes |
| `iroh-runtime` | `krikos-runtime` | `iroh_runtime::` | `krikos_runtime::` | `iroh-runtime/` → `krikos-runtime/` | yes |
| `iroh-blobs` | `krikos-blobs` | `iroh_blobs::` | `krikos_blobs::` | `protocols/iroh-blobs/` → `protocols/krikos-blobs/` | no (`publish = false`) |
| `iroh-gossip` | `krikos-gossip` | `iroh_gossip::` | `krikos_gossip::` | `protocols/iroh-gossip/` → `protocols/krikos-gossip/` | no (`publish = false`) |
| `iroh-docs` | `krikos-docs` | `iroh_docs::` | `krikos_docs::` | `protocols/iroh-docs/` → `protocols/krikos-docs/` | no (`publish = false`) |
| `iroh-app` | `krikos-app` | `iroh_app::` | `krikos_app::` | `framework/app/` (unchanged — path never contained `iroh`) | no (`publish = false`) |
| `iroh-sim` | `krikos-sim` | `iroh_sim::` | `krikos_sim::` | `iroh-sim/` → `krikos-sim/` | no (`publish = false`; its own nested workspace) |
| `iroh-bench` | `krikos-bench` | `iroh_bench::` | `krikos_bench::` | `iroh/bench/` → `krikos/bench/` | no (`publish = false`) |
| `iroh-local-first-app-tests` | `krikos-local-first-app-tests` | `iroh_local_first_app_tests::` | `krikos_local_first_app_tests::` | `integration-tests/local-first-app/` (unchanged) | no (`publish = false`) |
| `iroh-noq` | `krikos-noq` | `noq::` (unchanged — see note) | `noq::` (unchanged) | `vendor/noq-1.1.0/` (unchanged — vendored, byte-verified against upstream) | fork-published (`1.1.0-holon.1`) |
| `iroh-hickory-server` | `krikos-hickory-server` | `hickory_server::` (unchanged — see note) | `hickory_server::` (unchanged) | `vendor/hickory-server-0.26.1/` (unchanged — vendored, byte-verified against upstream) | fork-published (`0.26.1-holon.1`) |

Two rows above keep their Rust *library* identifier unchanged even though the
*package* name changes: `krikos-noq`'s library is still `noq`, and
`krikos-hickory-server`'s is still `hickory_server`, both matching the
identifier of the upstream crate they resource-hardened-fork. Cargo package
aliasing keeps `use noq::...` / `use hickory_server::...` working at their
call sites regardless of which package supplies them, so nothing downstream
that uses these two through the normal `noq`/`hickory-server` crates.io names
needs to change at all — only code that depended on them by their old
Holon-published package name (`iroh-noq`, `iroh-hickory-server`) does.

Two packages exist in this repository that are **not** part of the rename,
by construction: `local-first-notes` (the example under `examples/`) and
`determinism-checker` (an internal tooling crate), because neither package
name ever contained the string `iroh`.

## Rewriting `Cargo.toml`

Replace the dependency line for each crate you use, keeping the version
requirement in the same position:

```diff
 [dependencies]
-iroh = "0.3"
-iroh-base = "0.3"
+krikos = "1.0"
+krikos-base = "1.0"
```

Publication to crates.io has not happened yet as of this writing (name
reservation is a separate, owner-gated action per ADR-0002's open items), so
until then a real dependency on this fork is a `git` or `path` dependency,
not a version requirement:

```toml
[dependencies]
krikos = { git = "https://github.com/holon-technologies/iroh", package = "krikos" }
```

## Rewriting imports

The mechanical rule is: wherever the old crate's identifier appeared as a
Rust path root, replace it with the new one. This covers `use` statements,
fully-qualified paths, `extern crate`, and intra-doc links:

```diff
-use iroh::Endpoint;
-use iroh_base::{EndpointAddr, SecretKey};
-use iroh_blobs::BlobsProtocol;
+use krikos::Endpoint;
+use krikos_base::{EndpointAddr, SecretKey};
+use krikos_blobs::BlobsProtocol;
```

```diff
-let secret = iroh_base::SecretKey::generate(rand::rngs::OsRng);
+let secret = krikos_base::SecretKey::generate(rand::rngs::OsRng);
```

Nothing about *how* these paths are used changes — only the crate-root
segment. Types, methods, and their signatures are the same objects under a
new name (again excluding this fork's separate, independent `v2` Rust API
changes documented in [`v2-migration.md`](v2-migration.md), which are not
part of this rename).

## Worked example

Below is a real, complete program, not pseudocode. The "after" side is
[`krikos/examples/echo.rs`](../../krikos/examples/echo.rs) verbatim, unmodified,
as it exists in this repository today; it is a workspace example target and
is compiled by CI on every change (verified directly for this guide with
`cargo check -p krikos --example echo --all-features`, which succeeds). The
"before" side is the same program under upstream's names, produced by
mechanically reversing the package/import-path mapping above — this repo
does not vendor upstream `iroh` source to compile the reversed side against,
so it is not independently build-verified the way the "after" side is, but
the substitution is exact and 1:1 with the table above, and every API used
(`Endpoint::bind`, `Router::builder`, `ProtocolHandler`, `Connection`) is
unchanged in shape by the rename.

**Before (upstream iroh):**

```rust
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_error::{Result, StdResultExt};

const ALPN: &[u8] = b"krikos-example/echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let router = start_accept_side().await?;
    router.endpoint().online().await;
    connect_side(router.endpoint().addr()).await?;
    router.shutdown().await.anyerr()?;
    Ok(())
}

async fn connect_side(addr: EndpointAddr) -> Result<()> {
    let endpoint = Endpoint::bind(presets::N0).await?;
    let conn = endpoint.connect(addr, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"Hello, world!").await.anyerr()?;
    send.finish().anyerr()?;
    let response = recv.read_to_end(1000).await.anyerr()?;
    assert_eq!(&response, b"Hello, world!");
    conn.close(0u32.into(), b"bye!");
    endpoint.close().await;
    Ok(())
}

async fn start_accept_side() -> Result<Router> {
    let endpoint = Endpoint::bind(presets::N0).await?;
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();
    Ok(router)
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}
```

**After (Krikos — this is `krikos/examples/echo.rs`, unmodified):**

```rust
use krikos::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_error::{Result, StdResultExt};

const ALPN: &[u8] = b"krikos-example/echo/0";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let router = start_accept_side().await?;
    router.endpoint().online().await;
    connect_side(router.endpoint().addr()).await?;
    router.shutdown().await.anyerr()?;
    Ok(())
}

async fn connect_side(addr: EndpointAddr) -> Result<()> {
    let endpoint = Endpoint::bind(presets::N0).await?;
    let conn = endpoint.connect(addr, ALPN).await?;
    let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
    send.write_all(b"Hello, world!").await.anyerr()?;
    send.finish().anyerr()?;
    let response = recv.read_to_end(1000).await.anyerr()?;
    assert_eq!(&response, b"Hello, world!");
    conn.close(0u32.into(), b"bye!");
    endpoint.close().await;
    Ok(())
}

async fn start_accept_side() -> Result<Router> {
    let endpoint = Endpoint::bind(presets::N0).await?;
    let router = Router::builder(endpoint).accept(ALPN, Echo).spawn();
    Ok(router)
}

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}
```

Note the `ALPN` constant, `b"krikos-example/echo/0"`, is unchanged by this
rename either way: it is application-defined wire data this specific example
picked for its own protocol, not part of the rename's scope, and picking a
different string does not affect interoperability with anything except two
copies of this same example.

## Environment variables

Every `IROH_*`-prefixed environment variable this fork reads was renamed to
`KRIKOS_*`, alongside the package/import rename, so a deployment's
environment needs the same substitution as its `Cargo.toml`:

| Old | New | Purpose |
| --- | --- | --- |
| `IROH_SECRET` | `KRIKOS_SECRET` | endpoint secret key, read by several examples |
| `IROH_DNS_DATA_DIR` | `KRIKOS_DNS_DATA_DIR` | `krikos-dns-server` data directory override |
| `IROH_TEST_QLOG` | `KRIKOS_TEST_QLOG` | enables qlog test output |
| `IROH_FORCE_STAGING_RELAYS` | `KRIKOS_FORCE_STAGING_RELAYS` | forces staging relay/DNS mode |
| `IROH_FUZZ_TOOLCHAIN` | `KRIKOS_FUZZ_TOOLCHAIN` | pinned fuzzing toolchain |
| `IROH_FUZZ_RUSTFLAGS` | `KRIKOS_FUZZ_RUSTFLAGS` | fuzzing `RUSTFLAGS` override |
| `IROH_RELAY_ACCESS_TOKEN` | `KRIKOS_RELAY_ACCESS_TOKEN` | relay bearer-token allowlist |
| `IROH_RELAY_ACME_CA` | `KRIKOS_RELAY_ACME_CA` | relay ACME CA trust override |
| `IROH_RELAY_ACME_URL` | `KRIKOS_RELAY_ACME_URL` | relay ACME directory URL override |
| `IROH_RELAY_HTTP_BEARER_TOKEN` | `KRIKOS_RELAY_HTTP_BEARER_TOKEN` | relay HTTP auth bearer token |
| `IROH_REPO_ROOT` | `KRIKOS_REPO_ROOT` | `scripts/krikos-test-env`'s repo-root override |
| `IROH_TEST_DOCKERFILE` | `KRIKOS_TEST_DOCKERFILE` | test-env Dockerfile override |
| `IROH_TEST_ENTRYPOINT` | `KRIKOS_TEST_ENTRYPOINT` | test-env entrypoint override |
| `IROH_TEST_IMAGE` | `KRIKOS_TEST_IMAGE` | pre-built test-env image override |
| `IROH_TEST_BUILD_JOBS` | `KRIKOS_TEST_BUILD_JOBS` | test-env build parallelism |
| `IROH_PATCHBAY_PARITY_RECEIPT` | `KRIKOS_PATCHBAY_PARITY_RECEIPT` | patchbay parity receipt output path |
| `IROH_BENCH_BUILD_PROFILE` | `KRIKOS_BENCH_BUILD_PROFILE` | build-time var (`cargo:rustc-env`, read via `env!()`) |
| `IROH_BENCH_OPT_LEVEL` | `KRIKOS_BENCH_OPT_LEVEL` | build-time var (same mechanism) |

A GitHub Actions workflow input/env name, `IROH_REF` (the netsim runner's
pinned ref), was renamed to `KRIKOS_REF` alongside these; it is CI-internal,
not something an application deployment sets.

Two more `KRIKOS_`-shaped identifiers exist in the source but are **not**
environment variables — do not set them in a deployment's environment.
`KRIKOS_BLOCK_SIZE` and `KRIKOS_TXT_NAME` are Rust `const` names (a BAO block
size and the DNS TXT record label constant, respectively) that happen to use
the same `SCREAMING_SNAKE_CASE` convention as an env var. Renaming
`KRIKOS_TXT_NAME` the *identifier* did not rename what it points to: its
*value* is still the literal `"_iroh"`, on purpose — see the next section.

## What did not change

Everything in this section was **deliberately** left exactly as upstream
defines it. These are not oversights the rename missed; each one is a
contract that some other party — an upstream-speaking relay, an
operator-supplied access-control service, a DNS resolver — matches against
literally, by value, and none of those parties know or care what this fork
calls its own Rust crates. Renaming any of them would be a wire-protocol or
API break wearing a naming change's clothes, which
[ADR-0002](../adr/0002-krikos-rebrand.md) explicitly rules out of scope.

### Relay wire compatibility with upstream `v1.0.3`

This fork's relay client and server remain bidirectionally compatible with
upstream iroh `v1.0.3` (pinned exactly, commit `f2eb930dda3779c6d852b72f3712aacd6e573ab1`
— see [`relay-compatibility.md`](../relay-compatibility.md) for the full
normative contract and its test matrix). The specific values that keep their
upstream spelling:

| Contract | Value | Kept because |
| --- | --- | --- |
| Client authentication header | `x-iroh-relay-client-auth-v1` | HTTP header a real upstream-speaking relay client/server reads by exact name |
| Relay V1 WebSocket subprotocol | `iroh-relay-v1` | negotiated over the wire during relay handshake |
| Relay V2 WebSocket subprotocol | `iroh-relay-v2` | same |
| Captive-portal probe header (challenge) | `X-Iroh-Challenge` | emitted and read back across process/build boundaries, including against n0's production relays |
| Captive-portal probe header (response) | `X-Iroh-Response` | same |
| HTTP access-control request header | `X-Iroh-NodeId` | sent to an operator-configured, third-party access-control service that matches on this exact header name |
| TLS challenge-signature domain | `iroh-relay handshake v1 challenge signature` | fed into the relay handshake's cryptographic signature; changing it is a wire break, not a rename |
| TLS exporter label | `iroh-relay handshake v1` | fed into TLS `export_keying_material`; same reasoning |

### Protocol ALPNs and the DNS discovery label

| Contract | Value | Kept because |
| --- | --- | --- |
| Blobs ALPN | `/iroh-bytes/4` | QUIC ALPN `krikos-blobs` negotiates with; must byte-match an upstream `iroh-blobs` v0.103 peer to connect at all |
| Gossip ALPN | `/iroh-gossip/1` | same, for `krikos-gossip` against upstream `iroh-gossip` v0.101 |
| Docs ALPN | `/iroh-sync/1` | same, for `krikos-docs` against upstream `iroh-docs` |
| Relay QUIC address-discovery ALPN | `/iroh-qad/0` | negotiated between this fork's relay and endpoint over QUIC |
| DNS TXT record label | `_iroh` | endpoint-discovery wire format; every resolver and every node — including n0's own production `dns.iroh.link` service this fork's defaults still point at — must agree on this exact label to find each other |

### Public API shape

Aside from the rename itself (crate/type/module *names*) and this fork's
separately-documented `v1`→`v2` architecture-cut breaks (see
[`v2-migration.md`](v2-migration.md), which is unrelated to upstream
migration), method signatures, builder patterns, and behavior are unchanged.
If a type existed on upstream `iroh::Endpoint`, the equivalent method exists
on `krikos::Endpoint` with the same signature; only the path to reach it is
different.

### Everything else this fork depends on or points at

Real external crates this fork depends on (`iroh-metrics`, `iroh-io`,
`iroh-test`) keep their real, upstream-owned crates.io names, because they
are not part of this rename's package set — this fork depends on them, it
does not publish them. Likewise, n0's production infrastructure hostnames
this fork's defaults still resolve against (`iroh.link`, `iroh.network`) are
real DNS names, not identifiers, and pointing them somewhere else would be a
functional break, not a rename.

## Checklist

1. Update `Cargo.toml`: rename each dependency per the [package
   mapping](#package-mapping) table, keeping the version requirement (or
   switching to a `git`/`path` dependency until the crate names are
   published — see [above](#rewriting-cargotoml)).
2. Update every `use`/fully-qualified-path reference per [Rewriting
   imports](#rewriting-imports). A repository-wide search for `iroh` after
   this step should only turn up the values listed in [What did not
   change](#what-did-not-change) — anything else is either a stray import
   this step missed or a genuine external reference (an `iroh-metrics`
   dependency, a real `iroh.link`/`iroh.computer` URL) that is correct to
   leave alone.
3. Update deployment environment variables per the [environment
   variables](#environment-variables) table.
4. Rebuild and run your test suite. Nothing about wire behavior or public
   API shape should have moved; if something else broke, it is either a
   dependency version mismatch (this fork's `1.0.0` is not upstream's
   version numbering) or one of the independent `v2` architecture-cut
   changes in [`v2-migration.md`](v2-migration.md), not this rename.
