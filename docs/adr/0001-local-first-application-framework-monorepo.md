# ADR-0001: Build the local-first application framework as a crate-structured monorepo

## Status

Accepted on 2026-07-28. The project owner approved the product direction: an opinionated
local-first application framework with custom ALPN protocols as the extension boundary.

This ADR defines a target architecture. It does not claim that the protocol imports or framework
runtime are implemented, and it does not add scope to the v2 architecture hard-cut pull request.

## Scope

This decision covers:

- the source-repository boundary for transport, protocols, framework orchestration, services, and
  their shared verification;
- the default application model and its relationship to lower-level crates;
- dependency direction, runtime ownership, persistence, compatibility, upstream provenance, and
  release policy; and
- the criteria for splitting a component into another repository later.

It does not define a graphical application toolkit, a general-purpose database, a hosted control
plane, a plugin marketplace, language bindings, or a final public product/crate name.

## Context

### Confirmed current state

The fork already uses a multi-crate production workspace with enforced dependency direction.
`iroh-base`, `iroh-runtime`, and `iroh-resolver` are leaves; `iroh` owns endpoint orchestration;
relay and DNS services retain independent responsibilities. Production code cannot depend on the
simulator, and the relay wire contract remains compatible with exact upstream `v1.0.3`. These are
normative constraints in [`docs/architecture.md`](../architecture.md) and
[`docs/relay-compatibility.md`](../relay-compatibility.md).

The current README describes blobs, gossip, and documents as separately composed protocols. In the
upstream organization they are separate repositories, but their current manifests form one product
stack:

- `iroh-blobs` depends on `iroh` and supplies content-addressed transfer and storage;
- `iroh-gossip` optionally depends on `iroh` for its network implementation; and
- `iroh-docs` depends directly on `iroh`, `iroh-blobs`, and `iroh-gossip` and describes itself as a
  meta-protocol over blobs and gossip.

The pinned `iroh-blobs` README explicitly does not classify its current line as production quality.
The import is therefore a source/protocol baseline, not a production-readiness endorsement. This
framework owns the additional resource, persistence, failure, compatibility, and system evidence
required before describing the integrated bundle as supported.

The upstream sources are:

| Component | Approved import baseline | Source |
| --- | --- | --- |
| blobs | tag `v0.103.0`, commit `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc` | <https://github.com/n0-computer/iroh-blobs> |
| gossip | tag `v0.101.0`, commit `2ce78afe09d89d41d123f28eac19bdc831609cc8` | <https://github.com/n0-computer/iroh-gossip> |
| docs | tag `v0.101.0`, commit `091e8cac47bbc49cdb84b0bfed227cc163b61dfe` | <https://github.com/n0-computer/iroh-docs> |

These exact release tags, rather than floating `main` branches, are the provenance baselines for
the first imports. A later decision may select a newer exact commit after reviewing the delta; it
may not silently reinterpret these baselines.

### Decision drivers

- The product is intended to be an integrated application framework, not only a transport library.
- Framework features cross transport, content, synchronization, persistence, lifecycle, testing,
  and developer tooling; those changes need atomic review and verification.
- AI-assisted implementation reduces the cost of producing cross-component changes but increases
  the need for machine-enforced dependency, compatibility, resource, and state-ownership rules.
- Repository boundaries are coordination boundaries, not substitutes for crate or protocol
  architecture.
- The fork is intentionally free to diverge at Rust source and product levels while retaining the
  relay interoperability needed to share infrastructure.

## Goals

- Provide one production-quality API for starting and operating a local-first application node.
- Include identity, connectivity, blobs, documents, gossip, persistence, synchronization,
  lifecycle, configuration, and telemetry in the standard framework bundle.
- Keep transport and protocol crates usable independently by callers that do not want the standard
  framework bundle.
- Make cross-component changes atomic while retaining a directed, enforced crate graph.
- Preserve imported source history, licenses, attribution, wire/data fixtures, and exact provenance.
- Keep peer-controlled work, queues, payloads, retries, task sets, and shutdown bounded and
  observable.
- Preserve relay V1/V2 interoperability with upstream `v1.0.3` independently from application
  protocol evolution.

## Non-goals

- Combining all behavior into one Rust crate or one module tree.
- Making every framework subsystem configurable through Cargo feature combinations.
- Importing every crate or repository owned by n0-computer.
- Automatically mirroring upstream branches or accepting upstream changes without review.
- Preserving Rust source compatibility with the imported protocol releases during the port to the
  fork's v2 APIs.
- Changing an imported wire protocol or persistent representation as an incidental consequence of
  moving source.
- Publishing imported or new framework crates before package naming, registry ownership, and
  release authority are resolved.

## Decision

### One product repository, many architectural crates

The application framework SHALL live in this repository. The repository SHALL contain the
transport platform, application protocols, opinionated framework runtime, deployable services,
simulation, integration tests, and release gates needed to validate them together.

The monorepo SHALL remain a crate-structured system. A source monorepo does not authorize reverse
dependencies, private-state reach-through, unbounded feature unification, or a public “god crate.”

The target logical layers and dependency direction are:

```text
examples and end-to-end applications
                  |
                  v
framework runtime and standard application bundle
                  |
                  v
docs --------> blobs + gossip
  \                |       /
   \---------------+------/
                   v
          iroh endpoint transport
                   |
                   v
base + runtime + resolver + relay protocol/client

deployable relay/DNS services depend only on their platform capabilities
simulation and test tooling may depend upward; production never depends on them
```

The initial physical layout SHALL add new sources without moving the freshly stabilized platform
crates solely for visual symmetry:

```text
protocols/
  iroh-blobs/
  iroh-gossip/
  iroh-docs/

framework/
  app/

examples/
integration-tests/
```

Existing root crates remain in place during protocol import. A later physical-directory cleanup is
allowed only as an independently justified, behavior-preserving change after the first vertical
framework milestone.

### Opinionated standard bundle with a lower-level escape hatch

The framework's standard application bundle SHALL start one endpoint and one router and register
the reviewed blobs, gossip, and docs protocols. It SHALL own their coordinated startup, health,
cancellation, and shutdown. Applications MAY register additional ALPN handlers through an explicit
extension API.

The standard bundle SHALL not offer arbitrary compile-time combinations of its required protocols.
Callers needing a smaller or different composition use the lower-level crates and `Router`
directly. This avoids a combinatorial feature matrix while keeping the platform extensible.

Protocol registration SHALL reject duplicate ALPN values before any network task starts. ALPN
length, protocol count, handler concurrency, inbound request size, pending work, and shutdown time
SHALL have named, testable bounds.

### Runtime and state ownership

The framework runtime SHALL model an application node with explicit lifecycle states:

```text
Configured -> Starting -> Running -> Draining -> Stopped
                  |           |
                  +-> Failed <-+
```

Construction SHALL validate configuration before producing effects. Startup SHALL either return a
fully running handle or cancel and join every component it started; callers SHALL never receive a
partially initialized application. One supervisor SHALL own all framework tasks, bounded queues,
cancellation, health propagation, and the absolute shutdown deadline.

The running handle SHALL provide capability-scoped access to documents, blobs, gossip, endpoint
connectivity, health, and shutdown. It SHALL not expose mutable component internals or boolean
permission flags. Secrets and write capabilities SHALL use dedicated types and SHALL never appear
in `Debug`, ordinary logs, metrics labels, or unredacted error messages.

### Persistence and deterministic behavior

The first production bundle SHALL use the imported, reviewed persistent stores rather than inventing
a universal storage abstraction. In-memory stores are for tests, examples, and explicitly
ephemeral applications.

An application data directory SHALL contain a versioned manifest and component-owned subdirectories.
Opening unknown, newer, corrupt, or partially migrated state SHALL return typed errors. A schema or
encoding change requires an explicit version, migration, old-fixture replay, crash/restart tests,
and rollback or backup instructions. Component moves alone SHALL preserve serialized names and
representations.

Protocol state transitions SHALL remain separable from clocks, randomness, networking, storage,
and task scheduling so the existing simulator can drive deterministic replay, partitions,
duplicates, reordering, bounded resource exhaustion, and cancellation races.

### Security and privacy

All network messages, tickets, capabilities, imported persistent state, and application paths SHALL
be treated as untrusted input. Transport authentication proves an endpoint key; it does not by
itself grant document write authority or application-level permissions. Docs namespace/author
capabilities and framework identity capabilities remain distinct types with explicit transfer and
storage rules.

The first bundle SHALL protect identity and secret capability files against accidental disclosure,
use atomic replacement, redact secrets from diagnostics, and avoid peer/application identifiers or
content in metric labels. Blob and document stores are not implicitly encrypted at rest. User
documentation must state that limitation; transparent at-rest encryption requires a separate key
management, migration, recovery, and threat-model decision.

### Compatibility boundaries

Compatibility is classified independently:

| Boundary | Policy |
| --- | --- |
| relay wire | Existing V1/V2 contract against exact upstream `v1.0.3`; regressions block merge and release |
| imported protocol wire | Characterize the pinned import before porting; preserve it unless a new versioned ALPN is deliberately introduced |
| imported persistent state | Replay pinned fixtures before and after import; changes require explicit migration |
| Rust source API | May change during the framework port; every intentional change is documented |
| framework API | Establish a semver baseline after the first supported release; no stability claim during initial unpublished integration |

Application protocol evolution SHALL be additive and negotiated. Existing ALPN meanings and wire
tags SHALL not be repurposed. The relay compatibility matrix remains independent and cannot be
weakened because all application protocols now share a repository.

### Upstream provenance and import policy

Each protocol repository SHALL be imported from its exact approved tag and commit with rewritten
history under its final `protocols/` prefix. The import SHALL retain upstream license and copyright
files and add an `UPSTREAM.md` containing repository URL, tag, commit, import date, history-rewrite
method, and owned divergence.

Imports SHALL be performed from disposable mirror clones with `git filter-repo`; the active worktree
SHALL never be history-rewritten. Each rewritten history is merged as an unrelated history in its
own reviewable import commit. Imported GitHub workflows, repository-global configuration, and
release automation SHALL not become active in the monorepo; only source, tests, fixtures, relevant
design documents, licenses, and attribution remain in the current tree.

After import, upstream is a reviewed source of changes, not an automatically synchronized parent.
Every later upstream sync SHALL name exact old/new commits, review the complete delta, preserve
Holon invariants, and pass local compatibility and system gates. Git submodules and floating Git
dependencies are forbidden.

Imported packages SHALL remain `publish = false` until public package names and registry ownership
are approved. Their upstream names may be retained internally during porting, but that does not
claim permission to publish under those names.

The initial framework manifest SHALL use the provisional internal package name `iroh-app` with
`publish = false`. That name exists only to build and test the vertical slice; it creates no public
branding or stability commitment. The project owner must approve the final product and Cargo
namespace before the framework API baseline or any publication candidate is created.

### Release and CI policy

One repository does not require every crate to keep the same version forever. During initial
framework integration, owned framework-facing crates SHALL use one reviewed release train so a
tested set can be identified atomically. After the first supported framework release, a leaf crate
may adopt an independent release cadence only when its compatibility contract and consumers can be
verified independently.

Path-aware CI MAY avoid irrelevant expensive jobs, but changes to platform leaves, protocol wire or
storage, the framework supervisor, workspace manifests, dependency policy, or shared test tooling
SHALL run the complete integration matrix. Required gates include:

- crate graph and feature graph policy;
- strict formatting, Clippy, documentation, dependency, and package checks;
- imported wire and persistent-fixture compatibility;
- two-node framework end-to-end synchronization;
- deterministic simulation and fault injection;
- crash/restart and migration tests;
- relay golden and live v1.0.3 interoperability; and
- platform/target jobs required by the release checklist.

### Repository split criteria

A component MAY move to another repository only when all of the following are true:

1. it has a genuinely independent product and release lifecycle;
2. it has consumers outside this framework that benefit from independent governance;
3. its public compatibility and integration contracts are executable without this repository;
4. atomic cross-repository changes are rare rather than routine; and
5. the split has an owner, migration plan, rollback, and CI replacement for lost monorepo gates.

Repository size, line count, or the availability of AI coding assistance is not sufficient reason
to split.

## Consequences

### Positive

- Framework-wide changes can update transport, protocols, persistence, tests, and documentation in
  one review and one candidate revision.
- Agents and humans operate from one dependency graph and one set of compatibility contracts.
- The first local-first experience can be designed as a product rather than as instructions for
  manually coordinating four repositories.
- Lower-level crates remain independently testable and reusable.
- Relay interoperability remains a narrow, explicit infrastructure contract.

### Negative

- Repository history and checkout size increase after three history-preserving imports.
- CI needs path classification, caching, and tiered gates to avoid running every expensive job for
  documentation-only changes.
- Ownership must be enforced in manifests and tests because a monorepo makes illicit internal
  coupling mechanically easy.
- Coordinated releases and vulnerability response affect a larger source tree.
- Upstream synchronization becomes selective integration work rather than a simple dependency
  update.

### Neutral

- Crate boundaries, protocol versions, deployable services, and registry packages remain distinct
  even though their sources share a repository.
- This decision does not require the public framework name to remain “Iroh.”

## Alternatives considered

### Keep the upstream polyrepo topology

Rejected for the framework product. It preserves upstream coordination boundaries but makes
ordinary framework features span multiple repositories, release trains, compatibility windows,
and CI systems.

### Use Git submodules or a manifest-only umbrella repository

Rejected. Submodules preserve repository separation but do not provide atomic source changes,
simple Cargo path resolution, unified code review, or a single immutable system candidate.

### Use crates.io/Git dependencies without importing sources

Rejected as the long-term ownership model. It is useful for experimentation, but the intended
framework divergence would remain coupled to external source APIs and release timing. Floating Git
dependencies are also incompatible with reproducible release evidence.

### Combine everything into the `iroh` crate

Rejected. A single crate would produce feature and ownership coupling, slower incremental checks,
larger public API blast radius, and no enforceable inward dependency graph.

## Acceptance criteria

This ADR is realized when:

- the three pinned protocol histories and their provenance are present under `protocols/`;
- blobs and gossip depend inward on the fork's v2 platform, and docs depends on blobs and gossip;
- no platform, relay, resolver, or DNS crate depends on framework or application protocols;
- one standard framework API starts a complete node or returns a typed startup error after cleaning
  up all partial work;
- two independently persisted nodes can exchange and converge one document and its referenced blob
  through the standard bundle;
- restart preserves identity, document state, and content availability;
- a custom bounded ALPN handler can be added without modifying framework internals;
- protocol, persistent-state, deterministic, resource-bound, and relay compatibility gates pass;
  and
- all publishable names, registry ownership, licensing, and package contents are approved before
  publication.

## Evidence

- Confirmed: current workspace members and v2 metadata are defined in `Cargo.toml:1-37`.
- Confirmed: current crate responsibilities and dependency rules are defined in
  `docs/architecture.md:21-56`.
- Confirmed: task, queue, retry, payload, shutdown, and deterministic artifact ownership rules are
  defined in `docs/architecture.md:74-110`.
- Confirmed: the relay compatibility baseline and required matrix are defined in
  `docs/relay-compatibility.md:9-16` and `docs/relay-compatibility.md:98-126`.
- Confirmed: the current public README composes blobs, gossip, and docs above the endpoint/router in
  `README.md:45-50` and `README.md:85-115`.
- Confirmed: upstream docs is a meta-protocol over blobs and gossip, and the three manifests depend
  on Iroh and each other as described above:
  <https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/README.md>,
  <https://github.com/n0-computer/iroh-docs/blob/091e8cac47bbc49cdb84b0bfed227cc163b61dfe/Cargo.toml>,
  <https://github.com/n0-computer/iroh-blobs/blob/e82cbdcbdac9a78033174aad55e3199b2cf4c0dc/Cargo.toml>,
  and
  <https://github.com/n0-computer/iroh-gossip/blob/2ce78afe09d89d41d123f28eac19bdc831609cc8/Cargo.toml>.
- Proposed and approved: the product is an opinionated local-first framework with custom ALPN
  protocols as its escape hatch.

## Open questions

1. **Public product and crate namespace:** before any new or imported package is published, the
   project owner must choose the public product name, approve Cargo package names, and establish
   registry ownership. This does not block source import or unpublished integration.

There are no unresolved architecture questions blocking the first three protocol ports or the
two-node vertical slice.

## Follow-up

Execute the phased plan in
[`docs/superpowers/plans/2026-07-28-local-first-application-framework.md`](../superpowers/plans/2026-07-28-local-first-application-framework.md)
after the v2 architecture hard-cut branch is merged and green.
