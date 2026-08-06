# Documentation

## Architecture and contracts

- [Architecture contract](architecture.md) — crate ownership boundaries, the v2 hard cut, and the vendored dependency boundary.
- [Relay compatibility contract](relay-compatibility.md) — V1/V2 wire protocol guarantees.
- [Transports](../TRANSPORTS.md) — the transport registry.
- [Architecture decision records](adr/) — accepted product/architecture decisions: [ADR-0001](adr/0001-local-first-application-framework-monorepo.md), the local-first application framework monorepo; [ADR-0002](adr/0002-krikos-rebrand.md), the Krikos rebrand; and [ADR-0003](adr/0003-n0-operated-default-endpoints.md), keeping n0-operated relay and discovery endpoints as the shipped defaults.
- [Architecture baselines](architecture-baselines/) — dated, immutable evidence records (commits, CI runs, toolchain) frozen ahead of major architecture cuts.

## Local-first application framework

- [Getting started](framework/getting-started.md) — using `krikos-app`, the experimental application layer over the v2 endpoint, blobs, gossip, and docs crates.
- [Upstream protocol sync runbook](framework/upstream-sync.md) — how imported protocol packages (`krikos-blobs`, `krikos-gossip`, `krikos-docs`) are synced from their upstream release tags.
- [Framework release gate](framework/release-gate.md) — the four approvals blocking `krikos-blobs`, `krikos-gossip`, `krikos-docs` and `krikos-app` from publication: what each requires, and how the gate is opened.

## Account identity and authorization

- [Identity protocol profile](../protocols/krikos-identity/README.md) — the normative v1
  foundational, account-control, synchronization, and network-envelope profile currently documented
  by the crate, including its codepoints, common bounds, and feature boundary.
- [Security and deployment](../protocols/krikos-identity/docs/security-and-deployment.md) — threat
  model, invariants, deployment profiles, migration rules, and external release gates.
- [Provider operations](../protocols/krikos-identity/docs/provider-operations.md) — persistence,
  recovery, compaction, auditing, incident procedure, and the normative bounded provider-portability
  wire appendix.
- [Design-to-evidence map](../protocols/krikos-identity/docs/design-evidence.md) — implementation,
  test, model, simulation, fuzz, and interoperability evidence.
- [Identity stable-release gate](../protocols/krikos-identity/docs/release-gate.md) — the six
  independently evidenced approvals that keep `krikos-identity` unpublished.

## Upstream protocol provenance

- [Commit maps](upstream/commit-maps/) — old-to-new commit ID mappings recorded when each imported protocol package's history was rewritten into this monorepo.

## Testing

- [Testing strategy](testing/simulation.md) — how deterministic gates and exploratory campaigns divide the work.
- [Deterministic simulation architecture](testing/deterministic-simulation-architecture.md) — how the simulator achieves seed-reproducible runs.
- [Determinism audit](testing/determinism-audit.md) — the boundary inventory.
- [Fuzzing](testing/fuzzing.md) — the bounded fuzz campaign.
- [Production resource canary](testing/production-resource-canary.md).

## Simulation operations

- [Operations](simulation/operations.md) — running, replaying, and minimizing.
- [Relay parity](simulation/relay-parity.md) and [Patchbay parity](simulation/patchbay-parity.md).

## Release

- [Krikos migration guide](release/krikos-migration.md) — migrating from upstream
  [n0-computer/iroh](https://github.com/n0-computer/iroh): the package mapping, the import-path
  rewrite, and what the rename deliberately did not change.
- [v2 migration guide](release/v2-migration.md) — this fork's own independent `1.x` → `2.0`
  architecture-cut Rust API changes.
- [v2 release checklist](release/v2-release-checklist.md).

## History

- [Inherited upstream changelogs](history/) — releases prior to this fork.

Project goals and current testing status live in [`GOAL.md`](../GOAL.md) at the
repository root.
