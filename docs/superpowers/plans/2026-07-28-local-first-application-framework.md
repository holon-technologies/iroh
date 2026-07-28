# Local-First Application Framework Monorepo Implementation Plan

**Status:** In progress from merge commit
`caa3e5632ce2ce46a6bd0cf8d608c4ee63db7999` on branch
`codex/local-first-framework-monorepo`

**Governing decision:**
[`ADR-0001`](../../adr/0001-local-first-application-framework-monorepo.md)

**User-visible goal:** provide one production-quality, opinionated API that starts an Iroh
application node with identity, connectivity, content-addressed blobs, replicated documents,
gossip, persistence, synchronization, lifecycle, telemetry, and custom ALPN extension points.

**Success criteria:** one repository owns the platform and imported protocol sources; the enforced
crate graph remains acyclic; imported history and compatibility artifacts are traceable to exact
upstream releases; one validated framework startup either returns a fully running node or cleans up
all partial work; two persisted nodes synchronize a document and referenced blob; restart preserves
identity and state; custom protocols remain possible; and relay v1.0.3 compatibility, protocol/data
compatibility, deterministic simulation, resource, package, and hosted platform gates are green.

## Scope

- Import `iroh-blobs`, `iroh-gossip`, and `iroh-docs` with preserved, rewritten history.
- Port those crates from upstream Iroh 1.x APIs to this fork's v2 platform and workspace rules.
- Preserve or deliberately version imported wire protocols and persistent representations.
- Add the opinionated framework lifecycle, supervisor, configuration, identity, persistence, and
  standard protocol bundle.
- Add a two-node vertical slice, deterministic/fault coverage, architecture enforcement, release
  policy, and operational documentation.

## Non-goals

- Modifying or extending PR #7 while it is under review.
- Moving existing platform crates into new directories for visual symmetry.
- Importing every n0-computer repository or auxiliary crate.
- Building a graphical UI toolkit, hosted control plane, plugin marketplace, or language bindings.
- Preserving the imported crates' Rust source APIs where they conflict with the v2 platform.
- Changing imported wire/data formats merely because source moves into this repository.
- Publishing, tagging, reserving package names, or deploying infrastructure during implementation.
- Supporting arbitrary Cargo-feature combinations of the standard framework bundle.

## Chosen approach

Extend the existing root workspace upward instead of restructuring the platform again. Import each
protocol from one exact release into its final `protocols/` prefix, initially excluded from the root
workspace so the import commit remains faithful and independently buildable. Characterize its wire,
persistence, resource, and shutdown behavior before porting it to the local v2 APIs. Only then add
it to the production workspace and architecture graph.

Port blobs and gossip before docs because docs composes both. After all three protocol crates are
green, add a separate framework crate at `framework/app`. The standard bundle owns one endpoint,
one router, the three standard protocols, identity and storage roots, supervised tasks, and an
absolute shutdown deadline. Lower-level crates remain public and independently usable.

## Approved upstream baselines

| Component | Tag | Commit | Import prefix |
| --- | --- | --- | --- |
| `iroh-blobs` | `v0.103.0` | `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc` | `protocols/iroh-blobs` |
| `iroh-gossip` | `v0.101.0` | `2ce78afe09d89d41d123f28eac19bdc831609cc8` | `protocols/iroh-gossip` |
| `iroh-docs` | `v0.101.0` | `091e8cac47bbc49cdb84b0bfed227cc163b61dfe` | `protocols/iroh-docs` |

The history-rewrite tool is `git-filter-repo` v2.47.0. It runs only in disposable mirror clones.
Execution must verify the tool version, exact source ref, clean active worktree, and target-prefix
absence before any merge. The active repository is never rewritten or force-pushed.

## Global architectural invariants

- Dependencies point inward: framework → docs → blobs/gossip → iroh → base/runtime/resolver/relay.
- Platform, relay, resolver, DNS, and deployable service crates never depend on application
  protocols or framework crates.
- Imported crates remain `publish = false` until public naming and registry ownership are approved.
- Existing ALPN bytes, message tags, field encodings, tickets, hashes, and persistent schemas are
  immutable until characterized. A deliberate change uses a new version/schema and migration.
- Relay V1/V2 interoperability against upstream `v1.0.3` remains an independent release blocker.
- Construction validates before effects. Startup is atomic from the caller's perspective.
- Every task has one supervisor, cancellation path, observable failure, and bounded shutdown.
- Every peer-controlled size, batch, range, queue, retry, concurrent task set, and decoded output has
  a named bound checked before allocation or scheduling.
- Secrets and write capabilities use dedicated types and never appear in debug output, ordinary
  logs, metric labels, or unredacted errors.
- State-machine decisions remain separable from clocks, randomness, storage, networking, and task
  scheduling so they can be replayed deterministically.
- Arithmetic over sizes, offsets, ranges, epochs, counters, and durations uses checked operations
  and fallible conversions unless a local proof documents why another operation is correct.
- Unsafe code remains denied. An imported unsafe block must be removed or receive a separately
  reviewed safety contract and boundary tests before workspace admission.

## Resolved implementation decisions

- The physical import prefixes are final; existing platform crate paths remain unchanged for this
  initiative.
- Imported repository-global workflows and configuration are removed from the current tree after
  import. Component source, tests, fixtures, design documents, licenses, and attribution remain.
- Imported standalone lockfiles are retained in the provenance import commit and removed when a
  crate joins the root workspace and root lockfile.
- The first framework release has one standard protocol bundle. Minimal/custom users compose the
  lower crates directly instead of disabling required framework components through features.
- Existing component stores are used behind capability-scoped framework handles. No universal
  storage trait is introduced.
- The production persistent implementation uses the imported filesystem/redb stores; in-memory
  stores are explicitly ephemeral and primarily test-oriented.
- The framework accepts a validated identity source and supplies memory and protected-file identity
  stores. Identity creation/persistence is never implicit after a partial startup.
- The first supported application lifecycle is `Configured → Starting → Running → Draining →
  Stopped`, with `Failed` reachable from startup or runtime component failure.
- A new application protocol version uses a new ALPN. Existing ALPN meanings are never repurposed.
- `framework/app` initially uses the provisional package name `iroh-app` with `publish = false`.
  Public product/Cargo naming remains a project-owner decision before API freeze or publication;
  it does not block the unpublished lifecycle work or vertical slice.

## Entry gate

Do not execute source imports from the stacked design branch. First merge PR #7, wait for required
hosted checks, update local `main`, and create a new implementation branch from that immutable
revision. If PR #7 changes architecture or compatibility contracts during review, update this ADR
and plan before Task 1.

## Phase 1: Establish governance and reproducible imports

### Task 1: Land the target decision and capture the green platform baseline

**Resources:** `docs/adr/0001-local-first-application-framework-monorepo.md`, this plan,
`docs/architecture.md`, `Cargo.toml`, `Cargo.lock`,
`scripts/tests/check-workspace-architecture.sh`, PR #7 merge revision and hosted check results.

**Depends on:** PR #7 merged to `main`; clean implementation branch created from that merge.

**Interfaces and state:** the current architecture document continues to describe implemented
source; ADR-0001 describes the accepted target. The implementation branch records its exact base
SHA and Rust/Cargo versions before changing the graph.

**Implementation:** land only the ADR and plan first. Reconcile statements changed by PR review.
Capture root and simulator Cargo metadata, dependency trees, release package order, relay
compatibility evidence, and the full green local command set as the behavior-preserving baseline.
Do not create `protocols/` members or framework APIs in this task.

**Failure and operations:** stop if the hard-cut hosted checks are red, the local tree is dirty, the
relay compatibility baseline differs, or the post-cut semver reference does not identify the merged
architecture cut. Documentation must not silently override an implemented contract.

**Validation:** run `cargo make format-check`, `git diff --check`,
`scripts/tests/check-workspace-architecture.sh`,
`scripts/tests/check-relay-compatibility.sh --live`, and
`scripts/run-v2-semver-checks.sh`. Record the immutable base SHA in the implementation PR.

### Task 2: Add machine-readable layer and upstream-provenance policy

**Resources:** new `scripts/workspace-architecture.toml`,
`scripts/tests/check-workspace-architecture.sh`, new
`scripts/tests/check-workspace-architecture-fixtures.sh`, new
`protocols/upstream-baselines.toml`, new `scripts/tests/check-protocol-provenance.sh`, CI workflow
registration, `docs/architecture.md`.

**Depends on:** Task 1.

**Interfaces and state:** `workspace-architecture.toml` owns each first-party package's layer and
allowed normal/dev edges. `upstream-baselines.toml` owns component name, source URL, exact tag,
source commit, import prefix, import state (`pending`, `imported`, `ported`), and expected license.
Scripts read these files; duplicated hard-coded allowlists are forbidden.

**Implementation:** first add fixture-driven failing cases for an upward platform dependency, an
unmanaged `protocols/*/Cargo.toml`, a floating source ref, duplicate import prefix, missing license,
and a baseline SHA that does not resolve to its tag. Extract the existing graph allowlist from the
embedded Python into TOML without changing the allowed current graph. Add the three pinned protocol
records in `pending` state. Make provenance validation network-free for ordinary CI by checking
committed facts; a scheduled/manual audit may resolve tags remotely.

**Failure and operations:** report the exact package/edge or provenance field. Network
unavailability cannot make a pull-request check silently pass or fail if committed provenance is
internally consistent; remote drift audits report infrastructure and mismatch separately.

**Validation:** prove every negative fixture fails for the intended reason, then run the current
workspace graph and source-contract gates green. Run `cargo metadata --no-deps --format-version 1`
and confirm the production graph is unchanged.

### Task 3: Import the blobs history without changing the production graph

**Resources:** disposable mirror of `https://github.com/n0-computer/iroh-blobs`, exact tag
`v0.103.0`, `git-filter-repo` v2.47.0, new `protocols/iroh-blobs/`, new
`docs/upstream/commit-maps/iroh-blobs-v0.103.0.tsv`, `protocols/upstream-baselines.toml`.

**Depends on:** Task 2.

**Interfaces and state:** rewritten commits place every retained upstream path under
`protocols/iroh-blobs/`. `UPSTREAM.md` records source/tag/commit, import date, tool version, rewritten
baseline commit, license files, tree fingerprint, and owned cleanup commits. The root workspace
explicitly excludes the unported standalone crate for this task.

**Implementation:** clone a disposable mirror at the exact commit; verify the tag and clean object
database; run `git filter-repo --to-subdirectory-filter protocols/iroh-blobs`; retain the generated
old→new commit map; merge the rewritten history with `--allow-unrelated-histories`. In a separate
cleanup commit, remove imported repository-level CI/config that must not be active, add
`UPSTREAM.md`, set `publish = false`, and mark the baseline `imported`. Do not adapt Rust source or
rewrite upstream authorship in the import commit.

**Failure and operations:** abort before merge if the target prefix exists, a tag resolves
differently, the tool version differs, or licenses are missing. Never run filter-repo in the active
repository. If cleanup accidentally removes source/test/design material, reset only the disposable
import branch and repeat; do not patch the provenance record to excuse a mismatched tree.

**Validation:** verify the source baseline maps to one rewritten commit, `git log --follow` reaches
upstream history, retained files match the source tree except the reviewed cleanup list, licenses
are present, no nested workflow is active, and root metadata/tests remain unchanged. Run the
standalone upstream suite using `--manifest-path protocols/iroh-blobs/Cargo.toml --locked` before
any v2 port and record incompatibilities rather than editing around them.

## Phase 2: Port content and messaging protocols

### Task 4: Characterize and port `iroh-blobs` to the v2 platform

**Resources:** `protocols/iroh-blobs/Cargo.toml`, `src/{lib,net_protocol,protocol,provider,ticket}.rs`,
`src/get/`, `src/store/`, `src/api/`, existing `tests/{blobs,tags}.rs`, new
`tests/compat/v0_103_0.rs`, root `Cargo.toml`/`Cargo.lock`, architecture/provenance policy, v2
migration documentation.

**Depends on:** Task 3.

**Interfaces and state:** preserve the imported ALPN, request/response encoding, BLAKE3 hash and
hash-sequence semantics, range behavior, ticket encoding, store metadata, partial-download state,
and garbage-collection reachability. The port may change constructors and Rust module paths. Blobs
may depend on `iroh`, `iroh-base`, and approved external leaves; it may not depend on docs, gossip,
framework, DNS server, relay server, or simulator.

**Implementation:** first freeze golden wire/ticket vectors and persistent-store fixtures from the
imported baseline. Add bounds for decoded requests, range count, blob/collection count, pending
provider requests, downloader concurrency, RPC queues, import concurrency, and shutdown. Replace
Iroh 1.x endpoint/router calls with v2 APIs without changing protocol bytes. Adopt workspace
edition/MSRV/lints/repository metadata, use root dependencies, remove the standalone lockfile, add
the crate as a root member, mark its provenance `ported`, and keep `publish = false`.

**Failure and operations:** invalid peer input returns typed protocol errors before allocation;
store corruption returns a typed persistent-state error; provider/downloader task failure reaches
the owner; cancellation drains or aborts bounded work by the deadline. Do not regenerate fixtures
to match port output until the difference is classified and approved.

**Validation:** RED-GREEN the compatibility fixtures against deliberate copied codec changes. Run
all imported unit/integration/examples, filesystem crash/reopen tests, malformed/range/property
tests, strict Clippy/docs, root architecture gates, no-default/default/all-feature graphs, package
contents, and a current-to-baseline blob transfer driver where the imported protocol permits it.

### Task 5: Import the gossip history without changing the production graph

**Resources:** disposable mirror of `https://github.com/n0-computer/iroh-gossip`, exact tag
`v0.101.0`, `git-filter-repo` v2.47.0, new `protocols/iroh-gossip/`, new
`docs/upstream/commit-maps/iroh-gossip-v0.101.0.tsv`, provenance metadata.

**Depends on:** Task 2. Execute after Task 4 in the shared branch so import reviews and graph
changes remain isolated.

**Interfaces and state:** use the same import contract as Task 3 with prefix
`protocols/iroh-gossip`. The standalone crate remains excluded until ported.

**Implementation:** repeat the verified disposable-mirror, subdirectory rewrite, commit-map,
unrelated-history merge, repository-config cleanup, attribution, `publish = false`, and provenance
transition. Do not mix the history import with network/protocol changes.

**Failure and operations:** identical to Task 3. A component-specific exception must be documented
in `UPSTREAM.md` and reviewed; it cannot weaken the global import checks.

**Validation:** verify history reachability, tree equivalence, licenses, and unchanged root graph.
Run the standalone imported suite, including `tests/sim.rs`, against its original dependency graph
before porting.

### Task 6: Characterize and port `iroh-gossip` to the v2 platform

**Resources:** `protocols/iroh-gossip/Cargo.toml`, `src/{lib,api,net,proto}.rs`,
`src/net/{address_lookup,util}.rs`, `src/proto/{hyparview,plumtree,state,topic,sim}.rs`, existing
`tests/sim.rs`, new `tests/compat/v0_101_0.rs`, root workspace/architecture/provenance files.

**Depends on:** Tasks 4 and 5.

**Interfaces and state:** preserve ALPN, topic identifiers, message/neighbor encoding, HyParView
membership transitions, Plumtree eager/lazy behavior, duplicate suppression, and observable API
semantics. Gossip may depend on `iroh`, `iroh-base`, and `iroh-runtime`; it may not depend on blobs,
docs, framework, services, or simulator production code.

**Implementation:** freeze codec and deterministic protocol-transition fixtures before the port.
Separate pure membership/broadcast transitions from endpoint I/O and clocks. Adapt the optional
network implementation to v2 Endpoint/Router and runtime capabilities. Name and enforce maximum
message size, peers per view, pending messages, duplicate-cache entries, fanout work, retries,
concurrent handlers, and shutdown. Join the root workspace under shared lint/metadata rules,
remove its standalone lockfile, mark provenance `ported`, and retain `publish = false`.

**Failure and operations:** malformed messages, impossible transitions, stale peers, full queues,
partitions, duplicate storms, task failure, and shutdown races have explicit results. Peer input
never panics or grows a collection without a configured bound. Internal impossible state uses
release assertions with invariant-naming messages.

**Validation:** run golden codec tests, model/property tests for membership and convergence,
deterministic partition/reorder/duplicate scenarios, fuzz parsers, concurrency/shutdown tests,
strict workspace checks, feature graphs, and an interop driver against the pinned import if the
wire protocol supports independent baseline/current nodes.

## Phase 3: Port replicated documents and persistent state

### Task 7: Import the docs history without changing the production graph

**Resources:** disposable mirror of `https://github.com/n0-computer/iroh-docs`, exact tag
`v0.101.0`, `git-filter-repo` v2.47.0, new `protocols/iroh-docs/`, new
`docs/upstream/commit-maps/iroh-docs-v0.101.0.tsv`, provenance metadata.

**Depends on:** Task 2. Execute after Task 6 so the docs port can immediately target local blobs
and gossip.

**Interfaces and state:** use the same import contract as Tasks 3 and 5 with prefix
`protocols/iroh-docs`. Retain store migrations, fixtures, licenses, and design documentation. The
standalone crate remains excluded until ported.

**Implementation:** perform the verified history rewrite and merge, remove only repository-global
automation/configuration, add provenance, set `publish = false`, and mark `imported`. Keep imported
redb migration code and old schema support intact.

**Failure and operations:** do not normalize or delete old store migrations during import. A source
tree mismatch, missing migration, or missing license aborts the task.

**Validation:** verify history/tree/license provenance and the unchanged root graph. Run the
standalone imported client, GC, and sync suites against its original locked dependency graph.

### Task 8: Characterize and port `iroh-docs` onto local blobs and gossip

**Resources:** `protocols/iroh-docs/Cargo.toml`, `src/{actor,api,engine,heads,keys,net,protocol,ranger,store,sync,ticket}.rs`,
`src/engine/`, `src/net/`, `src/store/`, existing `tests/{client,gc,sync}.rs`, new
`tests/compat/v0_101_0.rs`, root workspace/architecture/provenance files, migration docs.

**Depends on:** Tasks 6 and 7.

**Interfaces and state:** preserve namespace and author key semantics, entry ordering, signed data,
ticket encoding, range-based set reconciliation, sync messages, content-hash references, garbage
collection reachability, redb schemas, and v1→v2/redb migrations. Docs depends on local blobs,
gossip, `iroh`, and approved platform leaves; it cannot reach framework or services.

**Implementation:** generate immutable wire/ticket/store fixtures with the imported baseline and
prove old store open/migrate/reopen behavior. Replace crates.io blobs/gossip/Iroh with workspace
dependencies. Adapt endpoint/router/runtime calls and source APIs without changing encoded meaning.
Separate deterministic reconciliation/merge decisions from live engine effects. Bound entries per
sync batch, range recursion/work, messages, pending peers, live sync sessions, actor queues,
database transactions, and shutdown. Join the root workspace, remove the standalone lockfile, mark
provenance `ported`, and retain `publish = false`.

**Failure and operations:** signature/capability violations, corrupt/newer store schemas, migration
failure, missing referenced blobs, queue saturation, peer disappearance, and component failure use
typed errors with no partial authority escalation. Migrations are idempotent or explicitly
single-use with backup/rollback instructions; cancellation cannot report success before durable
state reaches its documented point.

**Validation:** run golden wire/ticket fixtures, old-store replay, migration/crash/restart tests,
range-reconciliation model/property tests, corrupt-state and malicious-peer tests, blobs/gossip/docs
end-to-end sync, strict workspace checks, package inspection, and deterministic convergence under
partition, reordering, duplication, and restart.

## Phase 4: Build the opinionated application framework

### Task 9: Implement the unpublished framework lifecycle core

**Resources:** new `framework/app/Cargo.toml`, new
`framework/app/src/{lib,config,error,identity,lifecycle,protocol_registry,supervisor}.rs`, new
`framework/app/tests/lifecycle.rs`, root workspace/architecture policy.

**Depends on:** Task 8. Use the provisional package name `iroh-app` with `publish = false`; do not
establish a public semver or branding commitment in this task.

**Interfaces and state:** use validated configuration and capability types. The public shape is a
builder/configured value that asynchronously produces a running handle. Internally model
`Configured`, `Starting`, `Running`, `Draining`, `Stopped`, and `Failed`; do not model lifecycle or
permissions as independent booleans. The registry owns unique bounded ALPN keys and handlers. The
supervisor owns every task and one cancellation/deadline tree.

**Implementation:** write failing tests first for invalid configuration without side effects,
duplicate/oversized ALPN rejection, protocol-count limits, identity-store failure, component startup
failure at every position, runtime child failure, queue saturation, concurrent shutdown, shutdown
deadline, and drop behavior. Add `IdentityStore` capabilities with memory and protected-file
implementations, explicit create/load policy, atomic file replacement, secret-redacted errors, and
platform-specific permission tests. Implement structured supervision and typed startup/runtime/
shutdown errors. Add the crate to the framework layer only after tests prove partial cleanup.

**Failure and operations:** startup failure cancels and joins all previously started children before
returning. Runtime component failure changes health, triggers the configured fail-fast policy, and
is observable. Shutdown is idempotent, bounded by one absolute deadline, and reports components
that failed or timed out. Dropping the handle cannot silently detach owned tasks.

**Validation:** RED-GREEN-REFACTOR lifecycle tests with injected component fakes, property tests for
legal state transitions, Loom/model tests where synchronization warrants them, strict Clippy/docs,
secret-redaction tests, platform permission tests, architecture graph checks, and task-leak/resource
canaries.

### Task 10: Compose the standard local-first protocol and persistence bundle

**Resources:** new `framework/app/src/{application,data_root,standard_bundle}.rs`, local blobs,
gossip, docs, and `iroh` public APIs; new `framework/app/tests/{startup,persistence,protocol_registry}.rs`;
application data-manifest schema and fixtures.

**Depends on:** Task 9.

**Interfaces and state:** the standard bundle owns one identity, endpoint, router, blobs store,
gossip instance, docs store/engine, metrics namespace, and supervisor. `DataRoot` validates and owns
a versioned manifest plus component subdirectories. The running handle returns read-only or
capability-scoped blobs/docs/gossip/endpoint handles and accepts custom bounded protocol handlers.

**Implementation:** define the startup dependency order and reverse cleanup order. Validate identity
and data-root schema, open stores, build endpoint, instantiate standard protocols, register unique
ALPNs, start the router, and only then publish the running handle. Provide an explicitly ephemeral
constructor for tests. Add health aggregation and component-specific metrics without secret or
peer-controlled cardinality. Do not add Cargo features that remove a standard protocol.

**Failure and operations:** incompatible/corrupt data roots fail before network exposure. If any
later component fails, close the router/endpoint, cancel protocols, flush or close stores according
to their durability contracts, and join tasks. Disk-full, read-only storage, corrupt manifest,
duplicate ALPN, bind failure, and shutdown timeout are testable typed outcomes.

**Validation:** inject failure after every startup stage and assert no port, lock, task, or temporary
file remains. Run clean/crash restart, data-root version, store corruption, disk failure, health,
metrics-cardinality, custom protocol, and concurrent shutdown tests. Run full protocol and relay
compatibility suites after composition.

### Task 11: Deliver the two-node local-first vertical slice

**Resources:** new `integration-tests/local-first-app/` package, new
`examples/local-first-notes/`, framework APIs, deterministic fixtures, user-facing getting-started
documentation.

**Depends on:** Task 10.

**Interfaces and state:** two nodes with separate persisted identities/data roots create and share a
document capability. Node A adds content as a blob and references its hash from the document; Node B
connects, synchronizes metadata/content, validates signatures/hashes, and reads identical bytes.
Both restart and retain identity and state. A custom ALPN echo handler demonstrates the extension
boundary without modifying framework internals.

**Implementation:** build the scenario first as an executable end-to-end test using local addresses
and deterministic temporary roots. Expose the smallest API needed to make the example readable;
do not bypass framework ownership through test-only internals. Add bounded invitation/ticket parsing,
explicit read/write capability handling, progress/health observation, graceful shutdown, and
restart. Then turn the same flow into a documented example/CLI walkthrough.

**Failure and operations:** cover offline peer, relay-only path, duplicate update, conflicting
authors, missing blob, corrupt content, revoked/missing write capability, interrupted sync, full
disk, restart during sync, and retry exhaustion. Failures preserve prior durable state and are
recoverable where the protocol permits.

**Validation:** the end-to-end test proves convergence of document entries and blob bytes, stable
identities across restart, no unauthorized writes, idempotent resync, bounded retry/work, custom
ALPN routing, and clean shutdown. Run once direct, once through a local relay, and under the
supported platform matrix.

## Phase 5: Prove system behavior and prepare controlled rollout

### Task 12: Extend deterministic simulation, fuzzing, and fault injection

**Resources:** `iroh-sim/Cargo.toml` and domain facades, new application/protocol scenario models,
`fuzz/Cargo.toml`, parser/codec targets, persistent fixtures, failure corpus and minimization tools.

**Depends on:** Task 11.

**Interfaces and state:** simulation controls time, randomness, network delivery, partitions,
storage faults, and task scheduling through explicit capabilities. Production crates never depend
on simulator code. Every randomized failure records seed, scenario, trace, artifact versions, and
candidate SHA.

**Implementation:** add model operations for node start/stop/restart, document create/write/share,
blob add/fetch/GC, gossip partition/heal, message duplicate/reorder/drop, disk error, migration, and
shutdown. Define invariants: authorized histories converge, hashes match bytes, deleted/unreachable
content follows documented GC semantics, identities do not change unexpectedly, capabilities do not
escalate, queue/task/resource bounds hold, and relay compatibility is unaffected. Fuzz all imported
decoders, tickets, manifests, migrations, and custom protocol registration. Add targeted crash and
fault injection at durable boundaries.

**Failure and operations:** corpus growth and simulation work are bounded; nightly/soak jobs have
explicit budgets. Any failure is minimized and replayable locally. Infrastructure timeout is not
reported as behavioral success.

**Validation:** focused deterministic tests on every pull request, bounded fuzz smoke, scheduled
seeded swarms/soaks, old-artifact replay, fault-injection tests, resource canaries, and trace/corpus
schema compatibility checks.

### Task 13: Close CI, packaging, documentation, and release gates

**Resources:** `.github/workflows/ci.yml` and release workflows, `Makefile.toml`, root and simulator
manifests, package verifier/order, external-type allowlists, semver baselines, architecture and
release docs, upstream-sync runbook, README/framework guide.

**Depends on:** Task 12.

**Interfaces and state:** CI classifies changed paths but escalates platform/protocol/framework and
policy changes to full integration. Release metadata identifies one exact compatible set. Imported
and framework crates remain unpublished until naming/ownership gates are satisfied.

**Implementation:** register root and simulator format/Clippy/test/docs jobs, protocol compatibility,
old-store migration, two-node direct/relay E2E, deterministic/fuzz/resource, dependency/license,
package extraction, target/platform, and relay live lanes. Extend package-order verification but
fail intentionally with a clear naming/ownership gate for unpublished crates. Establish the first
framework semver baseline only when its supported public API is approved. Document standard-bundle
setup, lower-level composition, storage backup/migration, health/shutdown, custom protocols,
security expectations, upstream provenance, and exact sync procedure.

**Failure and operations:** no workflow may silently skip a required imported protocol, migration,
relay, platform, or privileged lane. Publication remains a separately authorized action. An
upstream sync uses exact commits, a reviewed delta, compatibility fixtures, and a new provenance
entry; automation never follows `main`.

**Validation:** run the full clean-candidate matrix and package archives from one immutable SHA.
Inspect dependency trees, features, licenses/attribution, archive contents, checksums, SBOM and
provenance artifacts. Run release workflow with publication disabled. Obtain project-owner approval
for package names and registry ownership before removing `publish = false` or tagging.

## Rollout and rollback

1. **Imported but excluded:** each upstream history exists under its final prefix, remains
   standalone/unpublished, and does not change production behavior. Rollback reverts the import and
   cleanup merge commits.
2. **Ported protocol crates:** each crate joins the workspace only after compatibility and system
   tests pass. Rollback removes the workspace edge and restores the prior crates.io dependency only
   on development branches; no release may contain a mixed, unverified graph.
3. **Experimental framework:** the standard bundle remains unpublished and is exercised by examples
   and integration/simulation tests. Its data-root schema is explicitly experimental and cannot be
   used to claim production migration support.
4. **Supported framework candidate:** freeze public names/APIs, schema versions, migration and
   compatibility baselines; run the complete immutable-candidate matrix.
5. **Release:** requires separate authority for registry ownership, publication, tags, artifacts,
   containers, and infrastructure. After publication, rollback means a new corrective version and
   supported state migration, never rewriting an existing release.

## Final acceptance checklist

- [x] PR #7 is merged and its hosted architecture/compatibility evidence is green.
- [ ] Exact upstream tags, commits, licenses, rewritten histories, and commit maps are verified.
- [ ] Blobs, gossip, and docs are root workspace members with enforced inward-only dependencies.
- [ ] Imported wire, ticket, and persistent-state fixtures pass after the v2 ports.
- [ ] All peer-controlled work and all framework task/shutdown paths have named bounds and owners.
- [ ] Framework startup is atomic and lifecycle transitions are exhaustively tested.
- [ ] Two persisted nodes synchronize and recover the vertical slice directly and through relay.
- [ ] Custom ALPN registration works without weakening standard-bundle ownership or bounds.
- [ ] Deterministic, fuzz, fault, crash/restart, migration, and resource gates pass.
- [ ] Relay golden/live interoperability remains green against upstream v1.0.3.
- [ ] Public product/package names and registry ownership are approved before publication.
- [ ] Full platform, package, security/license, SBOM/provenance, and dry-run release evidence is tied
      to one clean immutable candidate.

## Required execution workflow

Use `superpowers:test-driven-development` and `tigerstyle:tigerstyle-rust` for every port and runtime
task. Because Tasks 3–8 have independent import/review boundaries but share Git history and the root
workspace, execute them sequentially in one integration branch or use isolated worktrees with
`superpowers:subagent-driven-development`; never run concurrent history merges in one worktree. Use
`superpowers:verification-before-completion` before every task handoff and the final candidate.

## Evidence and remaining decision

- Current workspace and compatibility evidence is mapped in ADR-0001.
- The immutable pre-import platform evidence is recorded in
  [`docs/architecture-baselines/2026-07-28-v2-platform.md`](../../architecture-baselines/2026-07-28-v2-platform.md).
- Upstream repository/tag/commit evidence was captured on 2026-07-28 from the three official
  n0-computer repositories.
- `git-filter-repo` is not installed in the current environment; Task 3 must provision exact
  v2.47.0 in an isolated tool environment and record its checksum/version before import.
- The only blocking product decision is the public product and Cargo package namespace. It does not
  block the provisional unpublished framework or vertical slice, but it must be resolved before
  Task 13 freezes the public API/package identity or any package is published.
