# Iroh Fork Architecture

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
`iroh-sim` is a nested, non-published workspace because it applies a deterministic Rustls patch
that must never enter the production dependency graph. Fuzzing is also isolated from the root
workspace.

| Package | Responsibility | May depend on first-party packages |
| --- | --- | --- |
| `iroh-base` | Stable identity, address, relay-map, and key value types | none |
| `iroh-runtime` | Runtime, clock, task, decision, and trace capabilities | none |
| `iroh-resolver` | Generic bounded A, AAAA, TXT, and host resolution | none |
| `iroh-dns` | Iroh endpoint DNS records, endpoint lookup, pkarr integration | `iroh-base`, `iroh-resolver` |
| `iroh-relay` | Relay client, server, shared wire protocol, and sessions | `iroh-base`, `iroh-resolver`, `iroh-runtime` |
| `iroh` | Public endpoint and connection orchestration | `iroh-base`, `iroh-dns`, `iroh-resolver`, `iroh-relay`, `iroh-runtime` |
| `iroh-dns-server` | Deployable endpoint DNS and pkarr service | `iroh-base`, `iroh-dns`, `iroh-resolver`; `iroh` only for dev/tests |
| `iroh-blobs` | Content-addressed storage and transfer protocol | `iroh` |
| `iroh-gossip` | Topic-based broadcast protocol | `iroh-base`, optionally `iroh` |
| `iroh-docs` | Local-first documents, capabilities, persistence, and synchronization | `iroh`, `iroh-base`, `iroh-blobs`, `iroh-gossip` |
| `iroh-app` | Experimental application lifecycle and standard local-first bundle | `iroh`, `iroh-base`, `iroh-blobs`, `iroh-gossip`, `iroh-docs` |
| `iroh-bench` | Non-published benchmarks and resource canaries | public packages it exercises |
| `determinism-checker` | Non-published source-boundary checker | no production package may depend on it |
| `iroh-sim` | Deterministic model, execution, evidence, and operations | production packages; never the reverse |

`iroh-resolver` is the implemented generic-resolution boundary. `iroh-dns` composes it through
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
- `iroh-base`, `iroh-runtime`, and `iroh-resolver` remain first-party leaves.
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

`iroh-sim` exposes public types only through those domain facades. Its scenario implementation is
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
dependency order is `iroh-blobs` → `iroh-gossip` → `iroh-docs` → `iroh-app`; the first two are
independent siblings in the graph, while this order gives packaging a stable sequence. They remain
`publish = false` and outside the platform package verifier until
[`framework/release-gate.toml`](../framework/release-gate.toml) records separate approval for
package naming, registry ownership, a public API baseline, and the supported persistent-data
schema. A platform v2 release cannot open this gate as a side effect.

`iroh-base` keeps its existing feature-weight contract for this cut: `default` enables `relay`, and
`key` also enables `relay` because key-facing endpoint/address types require relay URL support.
Consumers seeking the smallest value-type build must use `default-features = false` and then select
only the required features.
