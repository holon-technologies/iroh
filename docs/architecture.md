# Krikos Fork Architecture

**Status:** implemented in the working tree; immutable candidate and hosted validation pending.

This document explains crate ownership, dependency direction, workspace isolation, and
compatibility boundaries in this fork. The machine-readable policy in
[`scripts/workspace-architecture.toml`](../scripts/workspace-architecture.toml) is the source of
truth for first-party package layers and allowed normal/dev edges. The source contract in
`scripts/tests/check-workspace-architecture.sh` combines that policy with Cargo metadata and the
structural checks described below. Release readiness still requires an immutable candidate and the
local/hosted evidence listed in the v2 release checklist.

## Compatibility policy

The v2 cut may break Rust source APIs, crate names, module paths, Cargo features, builders, and
simulator-internal interfaces. It must preserve the relay V1/V2 wire protocol in both directions
against upstream `v1.0.3`. The exact wire contract and baseline are defined in
[`relay-compatibility.md`](relay-compatibility.md).

Rust API breaks must be listed in [`release/v2-migration.md`](release/v2-migration.md). Relay wire
breaks are not migration-guide items: they are regressions unless introduced as a new, additive,
negotiated protocol version.

## Workspace boundaries

The root workspace contains publishable production crates and non-published production tooling.
`krikos-sim` is a nested, non-published workspace because it applies a deterministic Rustls patch
that must never enter the production dependency graph. Fuzzing is also isolated from the root
workspace.

| Package | Responsibility | May depend on first-party packages |
| --- | --- | --- |
| `krikos-base` | Stable identity, address, relay-map, and key value types | none |
| `krikos-runtime` | Runtime, clock, task, decision, and trace capabilities | none |
| `krikos-resolver` | Generic bounded A, AAAA, TXT, and host resolution | none |
| `krikos-dns` | Krikos endpoint DNS records, endpoint lookup, pkarr integration | `krikos-base`, `krikos-resolver` |
| `krikos-relay` | Relay client, server, shared wire protocol, and sessions | `krikos-base`, `krikos-resolver`, `krikos-runtime` |
| `krikos` | Public endpoint and connection orchestration | `krikos-base`, `krikos-dns`, `krikos-resolver`, `krikos-relay`, `krikos-runtime` |
| `krikos-dns-server` | Deployable endpoint DNS and pkarr service | `krikos-base`, `krikos-dns`, `krikos-resolver`; `krikos` only for dev/tests |
| `krikos-identity` | Deterministic account identity, authorization, recovery, and transparency protocol; optional storage/network adapters | `krikos-base`, optionally `krikos` |
| `krikos-blobs` | Content-addressed storage and transfer protocol | `krikos` |
| `krikos-gossip` | Topic-based broadcast protocol | `krikos-base`, optionally `krikos` |
| `krikos-docs` | Local-first documents, capabilities, persistence, and synchronization | `krikos`, `krikos-base`, `krikos-blobs`, `krikos-gossip` |
| `krikos-app` | Experimental application lifecycle, standard local-first bundle, and opt-in account-identity protocol composition | `krikos`, `krikos-base`, `krikos-blobs`, `krikos-gossip`, `krikos-docs`, optionally `krikos-identity` |
| `krikos-bench` | Non-published benchmarks and resource canaries | public packages it exercises |
| `determinism-checker` | Non-published source-boundary checker | no production package may depend on it |
| `krikos-sim` | Deterministic model, execution, evidence, and operations | production packages; never the reverse |

`krikos-resolver` is the implemented generic-resolution boundary. `krikos-dns` composes it through
`EndpointDnsResolver`, while relay code depends on the generic crate directly.

The layer order is `foundation` → `platform` → `protocol`/`service` → `documents` → `framework`.
Dependencies may remain within a layer or point left, never right. Tooling sits outside the
production layering and may consume the lower layers it validates, while production packages may
not depend on tooling. Protocol packages are added to the policy when their sources are imported;
the policy records whether each package is still excluded or admitted to a workspace. A
`protocols/*/Cargo.toml` without a policy owner is rejected.

## Dependency rules

- The production graph is acyclic and points from orchestration toward stable capability/value
  crates.
- Production packages never depend on simulator, fuzz, benchmark, or deterministic-patch code.
- `krikos-base`, `krikos-runtime`, and `krikos-resolver` remain first-party leaves.
- Relay code never depends on endpoint-record parsing, pkarr, DNS publication, or the DNS server.
- Dev dependencies are checked separately from normal dependencies; a test edge never justifies a
  production edge.
- Feature unification must not install an unselected TLS provider or simulator-only implementation.

These rules are enforced by `scripts/tests/check-workspace-architecture.sh`. Cargo metadata remains
the authoritative graph input; documentation diagrams are not accepted as proof. Negative fixtures
prove that upward edges and unmanaged protocol manifests are rejected.

## Imported protocol provenance

[`protocols/upstream-baselines.toml`](../protocols/upstream-baselines.toml) pins each imported
component to an HTTPS repository, exact release tag, resolved commit, final import prefix, import
state, SPDX license, and required license files. Pull-request CI validates those committed facts
without network access. The weekly and manually dispatched `Upstream Protocol Provenance Audit`
resolves each tag remotely and reports remote unavailability separately from a tag mismatch.

## TLS provider boundary

Generic client and server capability is provider-neutral. Production bundles select exactly one of
Ring or AWS-LC. An exact AWS-LC build may not contain Ring, and an exact Ring build may not contain
AWS-LC. Both providers may be enabled only for all-features/documentation jobs, where Ring has
documented precedence for process-global Rustls provider installation.

The relay target feature shape is:

- `server`: provider-neutral relay server library;
- `relay-bin`: internal target marker included by provider bundles so feature unification cannot
  select the binary from a provider-neutral library consumer;
- `server-ring`: server plus Ring;
- `server-aws-lc-rs`: server plus AWS-LC;
- `tls-ring` / `tls-aws-lc-rs`: provider selection for client/resolver TLS.

## Construction boundary

Normal endpoint construction installs production runtime, networking, monitoring, mapping, relay,
and cryptographic capabilities. Deterministic tests install those capabilities atomically through
one validated `SimulationEnvironment` and one explicit unsafe-test capability. Individual public
simulation setters and global mutable simulation environments are forbidden.

## Module ownership

Large modules are split by responsibility, not by line-count quota:

- endpoint: construction/binding, public handle, lifecycle, and relay status;
- socket: immutable configuration, shared inner state, actor/messages, and direct-address state;
- relay transport: session state, connection/reconnect, and message handling;
- relay server: configuration/limits/certificates, supervision, routes, HTTP listener/upgrade,
  connection handling, and relay service;
- simulator: `engine`, `model`, `execution`, `evidence`, `operations`, and a thin `cli`.

`krikos-sim` exposes public types only through those domain facades. Its scenario implementation is
split into schema, migration, validation, builder, and generator owners; its runner is split into
reference model, backend, orchestration, reporting, and errors; and CLI command implementations
remain private behind the stable `cargo sim` command surface.

The DNS-server crate root owns declarations and curated reexports only. Service smoke,
publish/resolve, and mainline fallback are package-boundary tests; private storage eviction remains
a unit test next to the store.

Facades own public exports. Sibling implementation modules exchange explicit handles/messages and
do not reach into each other's mutable state. Every task, queue, retry loop, payload, and shutdown
path retains a named bound and an observable owner.

## Persistent and deterministic artifacts

Scenario, trace, manifest, corpus, and failure artifacts remain replayable across module moves.
Moving a Rust type does not authorize changing its serialized name or representation. Any actual
format change requires a schema version, explicit migration, old-fixture replay, and migration
documentation.

## Release boundary

First-party publishable crates move in lockstep on the v2 line. Package order places leaf packages
before consumers. A release is blocked by an undocumented Rust API break, a forbidden dependency
edge, provider leakage, a failed deterministic replay, or a relay compatibility failure. This
architecture work does not itself authorize tagging or publication.

The imported protocol and framework packages form a separate, experimental release set. Their
dependency order is `krikos-blobs` → `krikos-gossip` → `krikos-docs` → `krikos-app`; the first two are
independent siblings in the graph, while this order gives packaging a stable sequence. They remain
`publish = false` and outside the platform package verifier until
[`framework/release-gate.toml`](../framework/release-gate.toml) records separate approval for
package naming, registry ownership, a public API baseline, and the supported persistent-data
schema. A platform v2 release cannot open this gate as a side effect.

`krikos-identity` is also unpublished, but it is not one of those four imported framework-release
packages. Its repository-owned acceptance evidence must be green on the stable candidate: the
feature/dependency boundary, checked wire/vector inventory, deterministic model, bounded
fuzz/simulation corpus, persistent-provider recovery, network integration, and documentation/API
gates. That evidence is necessary but does not satisfy the six independent release approvals:
third-party security audit, independently maintained interoperability, production provider
diversity, protocol governance, public API/SemVer baseline, and persistent-schema support. The
optional `krikos-app` component registers its six account-identity ALPNs on the existing endpoint;
it does not move endpoint-secret persistence into the account store.

`krikos-base` keeps its existing feature-weight contract for this cut: `default` enables `relay`.
The deterministic `key-types` feature exposes key, signature, endpoint-identifier, and address
types, including their relay/URL value types, without enabling `rand` or `getrandom`. `os-rng` adds
those entropy dependencies and `SecretKey::generate`; the legacy `key` feature remains a
compatibility alias for `os-rng`. `krikos-identity` disables `krikos-base` defaults and requests only
`key-types`; its own default feature set is empty, and only its explicit `os-rng` feature enables its
direct optional `getrandom` dependency. The `fs-store`, `net`, and `provider-store` integrations do
not imply `os-rng`.

The repository gate [`scripts/check-identity-feature-matrix.sh`](../scripts/check-identity-feature-matrix.sh)
compiles the reviewed identity feature combinations and rejects forbidden dependencies in the
no-default normal dependency tree. It invokes
[`scripts/tests/check-identity-os-rng-boundary.sh`](../scripts/tests/check-identity-os-rng-boundary.sh)
to keep the manifest, source gates, explicit-RNG APIs, and ambient-entropy boundary aligned.

## Vendored dependency boundary

Three upstream crates are vendored under [`vendor/`](../vendor/README.md) because each carries a
patch this project requires and upstream has not accepted. `scripts/tests/check-vendor-provenance.sh`
asserts in CI that every vendored directory still equals upstream plus its patch.

`noq` and `hickory-server` are published as differently named forks — `krikos-noq` and
`krikos-hickory-server` — because their patches are resource-hardening deltas that only this
project's endpoint and DNS-server code needs: bounded event queues, per-poll budgets, and
connection-lifetime ownership in Noq; pre-spawn UDP-request and TCP-connection admission limits in
Hickory. Cargo dependency package aliases keep the Rust library names (`noq`, `hickory_server`)
unchanged at import sites, so the fork is source-compatible and downstream provenance stays
explicit through the exact `-holon.N` prerelease version.

`rustls` cannot be forked and published under a different name. Noq, Tokio-Rustls, and other
transitive dependencies resolve the crate literally named `rustls`; a differently named fork would
coexist as a distinct crate in the dependency graph, making its public Rustls types incompatible
with the `rustls` types those other dependencies expect at integration boundaries. The patch that
`krikos-sim` needs — threading `provider.secure_random` through session-ID and `Random` construction,
and keeping the negotiated `KxState`'s `SupportedKxGroup` alive past the handshake so simulation
runs can replay deterministically from a seed — therefore cannot ship as a publishable production
crate. It instead lives only in `krikos-sim`'s nested, non-published workspace via a
`[patch.crates-io]` entry scoped to that workspace's own lockfile; every publishable production
crate resolves the public `rustls` crate unmodified. See [`vendor/README.md`](../vendor/README.md)
and `vendor/rustls-0.23.41/KRIKOS-VENDOR.md` for the exact patch contents and update procedure.

## Production resource admission

Production endpoints and relay servers enforce a finite ceiling on every connection, task, actor,
and event-queue family that a remote peer or a DNS response can cause to grow, so that a hostile
stream of connection attempts, distinct endpoint identities, distinct relay URLs, or QUIC datagrams
cannot exhaust process memory.

Three designs were considered. Adding a single live-task ceiling to the production task executor
and rejecting the next spawn was rejected: the vendored Noq runtime's spawn hook returns `()`, so a
rejected spawn cannot be reported back to Noq without stranding connection state Noq had already
begun to construct, and one catch-all ceiling risks rejecting unrelated critical tasks along with
the offending one. Bounding only first-party subsystems — endpoint connections, remote-state
actors, active-relay actors, relay QUIC-address-discovery connections — while leaving Noq's
internal event channels unbounded was also rejected: it leaves the underlying event-queue memory
growth path open, and gives no defense-in-depth if a subsystem admission check regresses.

The chosen design layers all three: explicit admission ceilings on connections and actors, acquired
*before* the corresponding Noq connection driver, actor, or task is created; bounded Noq-internal
event queues, reached through the same narrow vendored Noq patch described above; and a larger
task-executor ceiling that acts as a fail-closed backstop for any task family the layered admission
missed. Subsystem admission handles ordinary overload with domain-specific, recoverable errors; the
executor ceiling firing at all means an admission invariant has regressed, which is treated as an
internal capacity violation that closes the endpoint rather than silently reverting to unbounded
growth.

The two public types that carry this contract are `EndpointLimits` (`krikos/src/endpoint/limits.rs`,
set through `Builder::limits` in `krikos/src/endpoint/builder.rs`) — the validated, nonzero
connection/actor/task ceilings for one endpoint — and `TaskGroupLimits`
(`krikos-runtime/src/task.rs`) — the validated, nonzero live-task ceiling for one production task
group. The endpoint derives its requested task-group ceiling from its declared subsystem ceilings
plus a fixed supervisor headroom, so admitted subsystem capacity always fits inside the executor
backstop it depends on.
