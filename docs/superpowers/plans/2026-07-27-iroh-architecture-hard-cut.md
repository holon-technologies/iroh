# Iroh Architecture Hard-Cut Implementation Plan

**Status:** Implemented and locally verified; immutable candidate and hosted evidence pending

**User-visible goal:** make the fork's crate graph and internal module boundaries coherent and
maintainable, accepting one explicit Rust source-API hard cut while preserving bidirectional relay
wire interoperability so the fork and upstream-compatible deployments can share relay
infrastructure.

**Success criteria:** the production workspace has an enforced acyclic dependency policy; generic
DNS resolution no longer pulls endpoint-record concerns into the relay; TLS provider selection is
explicit and exact-provider builds are proven; simulation-only capabilities cannot be assembled
incoherently; oversized modules are split by responsibility; `iroh-sim` has a navigable domain API;
black-box tests live at package boundaries; current architecture and migration documents agree
with the code; and fork/upstream relay clients and servers pass the pinned compatibility matrix in
both directions.

**Scope:** workspace manifests, crate dependencies, relay protocol compatibility, TLS features,
DNS resolver extraction, endpoint and socket internals, relay server internals, simulator public
organization, simulator/runtime injection, DNS-server test placement, architecture enforcement,
release sequencing, migration documentation, and CI verification.

**Non-goals:** preserving Rust source compatibility with upstream or the fork's pre-cut API;
splitting every large file solely to meet a line-count target; creating separate relay client,
server, or protocol crates; merging `iroh-sim` into the production workspace; redesigning the relay
protocol; changing persistent data formats without an explicit migration; publishing crates,
creating a release, or mutating deployed infrastructure.

## Chosen approach

Make one documented major-version source cut instead of carrying compatibility shims through the
new architecture. Establish relay compatibility as an independent, executable wire contract
before moving relay code. Normalize workspace metadata, extract a provider-neutral generic DNS
resolver crate, and make TLS/provider and simulation-environment boundaries explicit. Then split
large modules behind stable facades, reorganize the simulator by domain, relocate tests, and close
with architecture contracts, migration documentation, and full verification.

This deliberately keeps closely coupled code together where the boundary would create more
coordination than value: relay client/server/protocol remain one crate, `iroh-base` and
`iroh-runtime` remain small production leaves, `iroh-dns-server` remains a deployable package, and
the deterministic simulator remains an isolated workspace because of its simulator-only Rustls
patch.

## Compatibility boundary

The hard cut permits changes to public Rust names, module paths, crate dependencies, feature names,
builder methods, test-only APIs, and simulator CLI internals. It does not permit an existing relay
V1 or V2 meaning to change.

The sole pinned compatibility baseline for this cut is upstream tag `v1.0.3`, resolved to commit
`f2eb930dda3779c6d852b72f3712aacd6e573ab1`. No additional deployed revision is required for the
initial compatibility SLA. If infrastructure requirements expand later, each additional revision
becomes an additive pinned target and does not replace `v1.0.3` or use a floating `main` reference.

The following remain wire-compatible for every preserved protocol version:

- relay path `/relay`, probe path `/ping`, authentication header/query conventions, WebSocket
  version/subprotocol strings, version preference/negotiation, and supported upgrade mechanisms;
- challenge and signature bytes, TLS exporter label, domain-separation strings, and token
  verification semantics;
- frame discriminants, field order, integer widths, length encodings, stream framing, malformed
  input behavior, and unknown-frame behavior;
- packet/frame/restart bounds, including the 64 KiB packet and 1 MiB frame limits;
- ping/pong, status, endpoint-gone, restart, single-datagram, and batched-datagram behavior.

Compatibility means current fork client to baseline server and baseline client to current fork
server. It does not imply compatible Rust APIs, build features, server configuration files, CLI
flags, metrics names, or deployment manifests. A future wire change must add a new negotiated
`ProtocolVersion`; it must never repurpose a V1/V2 tag or serialization.

## Architectural invariants

- Production dependencies point inward and remain acyclic. No production crate may depend on
  `iroh-sim`, simulator fixtures, or deterministic patched Rustls.
- `iroh-runtime` and `iroh-base` remain low-level leaves. The relay depends on generic resolution,
  never endpoint-record encoding, pkarr, DNS publication, or the DNS server.
- A selected TLS provider is explicit. An AWS-LC-only relay server build must not compile or install
  Ring through the server feature; the inverse applies to a Ring-only build.
- Production endpoint construction cannot gain simulation state accidentally. Test construction
  supplies one validated environment and one explicit unsafe-test capability.
- Every externally supplied count, length, duration, queue, task set, retry, and network payload
  remains bounded. Refactors must preserve existing shutdown ownership and error propagation.
- Deterministic scenario, trace, manifest, corpus, and failure artifacts remain replayable. A format
  change requires a version bump, migration, and old-fixture replay test.
- Relay compatibility failures are release blockers even though ordinary Rust API compatibility is
  intentionally broken at the cut.

## Assumptions and resolved decisions

- The architecture cut targets the v2 major line. Until the cut is released, package versions may
  remain `Unreleased`; all publishable first-party crates move in lockstep when release work begins.
- `iroh-resolver` is the chosen generic DNS crate name. Registry availability and ownership are a
  publication gate, not a reason to retain the current dependency inversion.
- `iroh-dns` will expose endpoint-aware lookup through an `EndpointDnsResolver` service/wrapper
  composed with `iroh_resolver::DnsResolver`; endpoint-specific inherent methods will not remain on
  the generic resolver.
- `iroh-base` keeps its current feature-weight behavior for this cut, including `key` implying the
  required relay types. The relationship will be documented rather than changed incidentally.
- Both-provider relay builds are allowed only for documentation/all-features jobs and use documented
  Ring precedence. Supported production configurations select exactly one provider.
- Golden protocol fixtures are the mandatory pull-request gate. Live cross-version client/server
  processes run in release and scheduled CI because compiling a historical dependency graph can be
  slower and more externally brittle; that lane may not silently skip.
- Source moves are behavior-preserving unless a task explicitly names an approved hard-cut API.
  Characterization tests precede each move.

**Resolved baseline decision:** `v1.0.3` is the sole upstream relay compatibility target for this
cut. There is no remaining baseline-selection question.

## Phase 1: Freeze the cut and relay contract

### Task 1: Record the hard-cut architecture and relay compatibility contract

**Resources:** new `docs/architecture.md`, new `docs/relay-compatibility.md`, new
`docs/release/v2-migration.md`, `iroh-relay/src/http.rs`,
`iroh-relay/src/protos/{common,streams,handshake,relay}.rs`, deployment inventory supplied by the
operator.

**Depends on:** none.

**Interfaces and state:** the architecture document owns the crate graph and dependency rules; the
relay document owns the pinned baseline set and immutable V1/V2 values; the migration document
owns all intentional source breaks. Baselines are exact commit hashes with tag and provenance,
never branches.

**Implementation:** write the compatibility boundary and invariants above into authoritative docs.
Extract the current path/header/query/subprotocol strings, protocol-version ordering,
domain-separation values, frame tags, wire widths, and limits into a reviewed compatibility table.
Record upstream `v1.0.3` at `f2eb930dda3779c6d852b72f3712aacd6e573ab1` as the sole baseline for
this cut. Define adding a future infrastructure revision as an additive compatibility-target
change that cannot remove or weaken the v1.0.3 gate. Start the v2 migration guide with a checklist
whose entries are completed by later tasks.

**Failure and operations:** do not infer compatibility from shared source or successful current-to-
current tests. If a deployed revision cannot be built, preserve its captured wire fixtures and a
minimal provenance-marked compatibility driver; do not replace it with a nearby revision.

**Validation:** peer-review the frozen constants against source at both current HEAD and every
baseline. A script introduced in Task 2 must fail if the document omits a preserved constant or
uses a moving ref.

### Task 2: Add relay golden fixtures and bidirectional interoperability gates

**Resources:** new `iroh-relay/tests/wire_compat.rs`, new
`iroh-relay/tests/relay_interop.rs`, new `iroh-relay/tests/fixtures/compat/v1.0.3/`, new
`scripts/tests/check-relay-compatibility.sh`, new scheduled/release compatibility workflow, normal
CI registration.

**Depends on:** Task 1.

**Interfaces and state:** fixtures contain provenance, protocol version, direction, expected bytes,
and semantic value. Test drivers can force V1 or V2 rather than accepting only the default
negotiation. Temporary certificates, ports, keys, and process state are per-test and cleaned up on
success and failure.

**Implementation:** first create failing assertions for every frozen constant and representative
frame. Generate and review golden bytes from the pinned baseline, including minimum, typical,
maximum, and one-over-limit cases. Cover handshake challenge/signature and TLS exporter transcripts
where supported, header and query bearer authentication, version negotiation, single and batched
datagrams, ping/pong, status, endpoint-gone, restart, malformed/truncated/oversized frames, and
unknown discriminants. Add a process-level matrix for current client to baseline server, baseline
client to current server, and current/current with forced V1 and V2. Exercise each transport shared
by the baseline; capability-gate extensions that did not exist there rather than claiming
compatibility.

**Failure and operations:** a byte difference, negotiation downgrade, asymmetric data path, timeout,
or authentication mismatch fails closed. The live lane distinguishes build/infrastructure failure
from incompatibility but both remain red. Pin historical source, Cargo lockfile, toolchain/container,
and test timeouts; never fetch a floating branch or silently regenerate fixtures.

**Validation:** prove tests RED by altering a copied discriminant or domain separator in the test
driver, then restore and prove GREEN. Run golden tests on every pull request and the complete live
matrix in scheduled/release CI. Retain logs and baseline/current revision identifiers.

## Phase 2: Establish workspace and crate boundaries

### Task 3: Normalize workspace metadata and enforce the dependency graph

**Resources:** root `Cargo.toml`, all production member manifests, `iroh-sim/Cargo.toml`,
`iroh/bench/Cargo.toml`, `iroh-dns-server/Cargo.toml`, release manifests/scripts, new
`scripts/tests/check-workspace-architecture.sh`, CI.

**Depends on:** Task 1.

**Interfaces and state:** root `[workspace.package]` owns lockstep version, edition 2024, MSRV 1.91,
license, repository, and shared metadata. Root `[workspace.dependencies]` owns internal path/version
pairs and agreed common dependency floors; crate-specific feature choices remain local. The nested
simulator workspace duplicates the source-of-truth metadata intentionally because it cannot
inherit through the workspace boundary.

**Implementation:** add workspace inheritance to every applicable package, including missing
`rust-version` declarations in DNS server and bench tooling. Centralize first-party dependency
versions without broadening features. Encode an allowed-edge list for first-party crates and checks
that the graph is acyclic, production never reaches the simulator, `iroh-runtime`/`iroh-base` remain
leaves, `iroh-sim` stays excluded, and only the simulator workspace patches deterministic Rustls.
The target normal-edge allowlist is: resolver/base/runtime have no first-party dependencies; DNS
depends on base+resolver; relay depends on base+resolver+runtime; Iroh depends on
base+DNS+resolver+relay+runtime; DNS server depends on base+DNS+resolver, with Iroh allowed only as
a dev dependency; and bench/tool packages may depend on the public packages they exercise but may
not be depended on by production packages. Update package/release ordering so the new resolver can
be inserted before consumers in Task 4.

**Failure and operations:** metadata drift, an undeclared first-party edge, a cycle, a simulator
patch leaking into production, or a missing member fails with the exact crate/edge/value. Avoid
centralizing feature arrays that differ by consumer because Cargo feature unification can increase
the production graph silently.

**Validation:** run `cargo metadata` for root and simulator workspaces, the new architecture script,
`cargo tree` policy assertions, and existing package-order/source-contract tests. Capture the graph
before and after and review every new edge.

### Task 4: Extract provider-neutral generic DNS into `iroh-resolver`

**Resources:** new `iroh-resolver/Cargo.toml`, new `iroh-resolver/src/{lib,dns,runtime,error}.rs`,
`iroh-dns/src/dns.rs`, endpoint-record/pkarr modules in `iroh-dns`,
`iroh-relay/src/{client,client/tls}.rs`, `iroh/src/endpoint.rs`, affected examples/tests,
workspace/release manifests, migration guide.

**Depends on:** Task 3.

**Interfaces and state:** `iroh-resolver` exports the generic `Resolver` and `DnsRuntime` contracts,
`DnsResolver`, `DnsError`, `BuildError`, `StaggeredError`, `DnsProtocol`, `BoxIter`, and generic
A/AAAA/TXT/host resolution. It has no dependency on `iroh-base`, endpoint records, pkarr,
`simple-dns`, or the DNS server. It owns provider features `tls-ring` and `tls-aws-lc-rs` for its
Hickory/Rustls implementation. `iroh-dns::EndpointDnsResolver` composes a generic resolver with
endpoint-record parsing/lookup and owns endpoint-specific methods; any identically named DNS
features forward to `iroh-resolver` rather than reimplementing generic TLS selection.

**Implementation:** write characterization tests around family staggering, per-attempt timeout,
reset, caching/lookup behavior, error typing, and the 64-address-per-family bound. Move generic
implementation and tests without semantic changes. Introduce the endpoint-aware wrapper in
`iroh-dns`, migrate Iroh endpoint construction to compose it explicitly, and migrate relay client
TLS lookup to depend only on `iroh-resolver`. Remove the old endpoint-specific inherent methods and
update all imports/examples as an intentional source break. Add the exact before/after mapping to
the migration guide and place `iroh-resolver` before `iroh-dns`, `iroh-relay`, and `iroh` in package
order. Update external-type allowlists and feature forwarding in every consumer.

**Failure and operations:** preserve swap-before-notify reset semantics, deterministic
`DnsRuntime`, bounded stagger, cancellation safety, and typed errors. A reset must not expose a
partially replaced resolver. A relay dependency tree containing endpoint DNS record or pkarr
dependencies fails the architecture contract.

**Validation:** new resolver unit/integration tests; endpoint DNS tests; relay TLS/DNS tests; exact
root/simulator builds; `cargo tree -p iroh-relay` proving the unwanted DNS dependencies are absent;
package extraction/build for `iroh-resolver`; docs and public API review.

### Task 5: Make relay TLS provider selection explicit

**Resources:** `iroh-relay/Cargo.toml`, `iroh-relay/src/main.rs`, TLS installation/config modules,
`iroh/Cargo.toml`, CI feature matrices, architecture script, migration guide.

**Depends on:** Task 3. It may run after Task 4 or independently once manifests are stable.

**Interfaces and state:** `server` contains provider-neutral library server capability;
`server-ring = ["server", "tls-ring"]`; `server-aws-lc-rs = ["server", "tls-aws-lc-rs"]`.
Consumer bundles such as `iroh` test utilities select one provider explicitly. Exact-provider
binary builds install that provider; an embedding library may install its own provider while
checking `--lib --features server`. Both-provider all-features/docs builds use documented Ring
precedence.

**Implementation:** add a source-contract test that initially exposes `server` implying Ring.
Separate provider-neutral server dependencies from provider bundles. Replace the binary's
unconditional Ring installation with feature-gated provider selection and a binary-target compile
error when neither provider is selected. Preserve `cargo check --lib --features server` as a valid
provider-neutral embedding build. Audit dev/test features so AWS-LC-only validation does not unify
Ring transitively. Document renamed feature bundles in the migration guide.

**Failure and operations:** unsupported zero-provider server builds fail at compile time with an
actionable message. Provider installation failure remains startup failure. Do not let an
all-features success substitute for exact AWS-LC-only and exact Ring-only evidence.

**Validation:** run `cargo check/test` for relay client Ring, client AWS-LC, server Ring, server
AWS-LC, and documented both-provider configuration; repeat relevant `iroh` test-utils builds for
each provider. Inspect `cargo tree -e features` to prove AWS-LC-only has no Ring and Ring-only has no
AWS-LC. Include explicit no-default invocations for `tls-ring`, `tls-aws-lc-rs`, `server-ring`, and
`server-aws-lc-rs`, plus the provider-neutral `--lib --features server` check. Register exact
matrices in CI.

## Phase 3: Harden construction and split production modules

### Task 6: Replace independent simulation setters with one validated environment

**Resources:** `iroh/src/endpoint.rs`, `iroh-sim` endpoint construction call sites, endpoint unit
tests, architecture script, migration guide.

**Depends on:** Task 3.

**Interfaces and state:** production `Endpoint::builder` remains free of simulation defaults.
Test-only construction accepts one `SimulationEnvironment` with private fields and a validating
constructor/builder, plus one explicit `UnsafeTestOnly` capability. Runtime, socket factory,
monitor, mapper, relay transport, and crypto provider are installed atomically from that value.

**Implementation:** characterize current coherent simulation construction. Make environment fields
private, validate completeness and compatible runtime/socket ownership, and retain the existing
single bundle call in simulator code. Remove the individual hidden setters for runtime, socket,
monitor, mapper, relay, and crypto rather than deprecating them. Migrate endpoint unit tests to
fixtures that construct complete environments. Add an architecture check that rejects reintroduced
individual public simulation setters.

**Failure and operations:** incomplete or internally mismatched environments return a typed
construction error before spawning tasks or binding sockets. Capability naming and docs must make
clear that production safety guarantees do not apply. No global environment, process mutable
state, or broad simulation feature enters normal builds.

**Validation:** endpoint production tests, simulator construction/replay tests, invalid-environment
tests, no-default-feature build, API/doc review, and source-contract check for the single entry
point.

### Task 7: Split `iroh::endpoint` behind a narrow facade

**Resources:** `iroh/src/endpoint.rs`, new
`iroh/src/endpoint/{builder,handle,lifecycle,relay_status,tests}.rs`, imports and public reexports.

**Depends on:** Task 6.

**Interfaces and state:** `iroh::Endpoint`, its builder, public status types, and documented call
flow remain discoverable from the endpoint facade. Construction/binding, handle methods,
close/lifecycle ownership, and relay mode/status logic become separate internal responsibility
modules.

**Implementation:** add characterization tests for bind, connect, accept, close, relay-mode
selection, status watching, and drop/shutdown. Move one responsibility at a time without changing
signatures beyond Task 6's approved break. Keep shared state ownership in one module and pass
explicit handles rather than exposing fields across siblings. Move tests next to the behavior they
exercise; reserve facade tests for public integration behavior.

**Failure and operations:** preserve task ownership, cancellation order, idempotent close, and error
context. Avoid dependency cycles between builder and lifecycle by depending on private state/types
through a single internal module. Do not optimize or redesign connection behavior during the move.

**Validation:** focused endpoint tests after every move, full `iroh` tests, rustdoc links, import
surface comparison excluding the approved simulation cut, clippy, and formatting.

### Task 8: Split socket orchestration and relay transport actor by ownership

**Resources:** `iroh/src/socket.rs`, `iroh/src/socket/transports/relay/actor.rs`, new
`iroh/src/socket/{config,inner,actor,direct_addr}.rs`, conversion to
`iroh/src/socket/transports/relay/actor/{mod,session,connect,messages,tests}.rs`, affected tests.

**Depends on:** Task 7.

**Interfaces and state:** socket config/static config/bind errors, endpoint inner state,
actor/messages/network changes, direct-address state, and relay transport actor/session concerns
have explicit module owners. Message enums remain the only mutation interface to actor-owned state.

**Implementation:** characterize address publication, network-change handling, relay reconnect,
direct-path updates, shutdown, and backpressure. Extract immutable configuration first, then state
holders, then actor messages/loop, then direct-address logic. Split relay transport actor into
session state, connection/reconnect, message handling, and tests while keeping its facade private.
Pass bounded channels and immutable config explicitly.

**Failure and operations:** preserve queue capacities, retry/backoff ceilings, timer semantics,
network monitor ownership, and shutdown drainage. No extracted helper may spawn an unowned task or
introduce an unbounded collection/channel. Actor failures propagate to the existing supervisor.

**Validation:** socket and relay transport unit tests after each extraction, deterministic network
transition/reconnect scenarios, leak/shutdown tests, relevant integration tests, clippy, and
formatting.

### Task 9: Split relay server and HTTP service without changing the wire

**Resources:** `iroh-relay/src/server.rs`, `iroh-relay/src/server/http_server.rs`, new
`iroh-relay/src/server/{config,certs,limits,supervisor,routes}.rs`, conversion to
`iroh-relay/src/server/http_server/{mod,listener,upgrade,connection,service,tests}.rs`, Task 2
compatibility tests.

**Depends on:** Tasks 2 and 5.

**Interfaces and state:** config/limits/certificates, listener lifecycle, supervisor ownership,
route assembly, HTTP upgrade/connection handling, and relay service/session handling have separate
owners. Protocol constants and codecs stay in `protos`/`http`, not server orchestration.

**Implementation:** create characterization tests for startup, graceful shutdown, certificate
loading/reload behavior, route selection, upgrade negotiation, authentication, connection
accounting, and limits. Extract pure config/limit types, then lifecycle/supervisor, then routes,
then listener/accept and HTTP connection handling. Run golden compatibility tests after every move
and the live bidirectional matrix after each meaningful upgrade/session change.

**Failure and operations:** preserve readiness semantics, accept-loop error policy, connection/task
bounds, graceful shutdown deadline, authentication failure status, and metrics emission. Never
copy wire constants into server modules or change parse/encode behavior as part of the split.

**Validation:** relay unit/integration tests, exact TLS matrices, Task 2 golden gate after every
commit, current/current forced V1/V2 tests, scheduled live baseline/current matrix, clippy,
formatting, and docs.

## Phase 4: Reorganize simulator and package-level tests

### Task 10: Establish the `iroh-sim` domain API

**Resources:** `iroh-sim/src/lib.rs`, simulator modules and all simulator imports/tests, migration
guide.

**Depends on:** Task 3.

**Interfaces and state:** the public hierarchy is:

- `engine`: kernel, ledger, network, NAT, relay, and discovery;
- `model`: scenario schema, observations, and invariants;
- `execution`: backends, runner, campaign, and minimization;
- `evidence`: manifest, trace, artifact, corpus, failure, coverage, and parity;
- `operations`: gate, soak, swarm, and policies;
- `cli`: a thin argument/dispatch shell.

**Implementation:** create domain facade modules first and migrate internal callers/tests to them.
Resolve ambiguous root names, including the simulator's `EndpointId`, through domain-qualified
paths. Remove the existing flat root `pub use` surface in the hard cut; do not add deprecated
compatibility aliases. Limit public exports to types needed by scenarios, tooling, or external
test harnesses and keep implementation helpers `pub(crate)`.

**Failure and operations:** public-domain moves must not alter deterministic ordering,
serialization names, CLI output schemas, or stable failure classes. If a serialized Rust type path
is embedded anywhere, add explicit serde names/migration before moving it.

**Validation:** compile all simulator bins/tests/examples against domain paths, rustdoc the public
surface, run scenario/corpus replay, compare representative manifests/traces byte-for-byte or via
approved version migration, and ensure no unintended root reexports remain.

### Task 11: Split simulator CLI, runner, and scenario model by responsibility

**Resources:** `iroh-sim/src/cli.rs`, `iroh-sim/src/runner.rs`,
`iroh-sim/src/scenario_model.rs`, conversion to
`iroh-sim/src/cli/{mod,run,replay,campaign,soak,parity,corpus,gate,shared}.rs`,
`iroh-sim/src/runner/{mod,reference,backend,orchestration,report,error}.rs`, and
`iroh-sim/src/scenario_model/{mod,schema,migration,validation,builder,generator}.rs`, simulator
tests and contracts.

**Depends on:** Task 10.

**Interfaces and state:** CLI has one module per run, replay, campaign, soak, parity, corpus, and
gate command plus shared source-identity/artifact/error helpers. Runner separates pure
`ReferenceModel`, deterministic backend, orchestration/reporting, and errors. Scenario model
separates schema, version migration, validation, builder, and generator.

**Implementation:** snapshot CLI help and machine-readable output. Extract command argument types
and execution one command at a time. Move pure reference-model transitions away from I/O, then
separate backend driving from report assembly. Make scenario parsing run schema identification,
migration, structural validation, semantic validation, then construction in a visible pipeline.
Keep generators bounded and seed-explicit.

**Failure and operations:** preserve exit codes, artifact-root preparation before execution,
source revision/seed identity, stable failure taxonomy, and deterministic event ordering. Unknown
schema versions fail with a typed error; migration never silently drops a field; command modules do
not own global mutable state.

**Validation:** CLI snapshot/contract tests, runner unit tests for pure transitions, backend
integration tests, old/current schema fixture tests, corpus replay, parity/gate tests, determinism
semantic/source contracts, clippy, formatting, and simulator docs.

### Task 12: Move DNS-server tests to the correct boundaries

**Resources:** `iroh-dns-server/src/lib.rs`, `iroh-dns-server/src/store.rs`, new
`iroh-dns-server/tests/{publish_resolve,smoke,mainline}.rs`, shared test support if required,
manifest dev features.

**Depends on:** Task 4 so tests use final resolver imports.

**Interfaces and state:** crate root contains declarations and curated reexports only. Store
eviction is a private unit test beside store implementation. Publish/resolve and service smoke are
black-box integration tests using only the supported package API. Mainline-network coverage
remains explicitly ignored/manual with a documented reason and invocation.

**Implementation:** move the four current root tests without weakening assertions. Extract only
genuinely shared integration setup. Declare exact test-only features/provider rather than relying
on default feature unification. Update imports for `iroh-resolver`/`EndpointDnsResolver`.

**Failure and operations:** black-box tests own temporary storage, listeners, tasks, and shutdown;
they must not use private modules. Ignored network tests state required external resources and
timeout bounds.

**Validation:** package unit tests, integration tests with default and intended no-default feature
sets, ignored-test compile, leak/cleanup checks where available, clippy, and formatting.

## Phase 5: Documentation, governance, and closure

### Task 13: Make architecture and migration documentation authoritative

**Resources:** root `README.md`, new/current architecture and compatibility docs, deterministic
architecture/audit documents, `docs/release/v2-migration.md`, crate READMEs and feature docs.

**Depends on:** Tasks 4–12.

**Interfaces and state:** `docs/architecture.md` is the current source of truth for crate ownership,
allowed dependencies, normal/simulator workspace boundaries, TLS selection, resolver layering, and
relay compatibility. Historical audits are labeled historical and link to current status.

**Implementation:** update the README repository map to include DNS, resolver, runtime, simulator,
bench/tooling, and their intended audiences. Remove or archive stale “Proposed/awaiting approval”
language from implemented deterministic work. Separate closed historical findings from active
risks. Complete the migration guide with old/new imports, feature mappings, simulation builder
changes, simulator module paths, semantic changes (if any), and an explicit statement that Rust
source compatibility was intentionally cut while relay wire compatibility was retained. Document
`iroh-base` feature implications.

**Failure and operations:** no document may claim a compatibility lane or architecture gate that CI
does not execute. Historical evidence keeps dates and revisions. Avoid duplicate sources of truth;
secondary docs link to the authoritative contract.

**Validation:** docs build, link check, architecture source contract, migration examples compiled
as doctests or fixtures, and a manual review from the perspective of a pre-cut library consumer and
a relay operator.

### Task 14: Replace the pre-cut semver gate and enforce post-cut stability

**Resources:** `scripts/run-v2-semver-checks.sh`, release scripts/workflows, new architecture-cut
baseline metadata, migration guide, CI.

**Depends on:** Tasks 2 and 13; final cut API must be settled.

**Interfaces and state:** the old v1.0.3 Rust API is an inventory/migration input, not a zero-break
gate. The accepted v2 architecture-cut revision becomes the new API baseline for accidental future
break detection. Relay wire compatibility continues to use the independent upstream baseline from
Tasks 1–2.

**Implementation:** run the existing semver report once and map every intentional break into the
migration guide. Change the release-readiness gate so known hard-cut API differences do not block
v2, but undocumented differences do. After the cut revision is approved, pin its package API data
or tag/commit as the baseline for subsequent v2 changes. Keep wire compatibility scripts separate
and mandatory so replacing the Rust baseline cannot weaken relay guarantees.

**Failure and operations:** do not globally disable semver analysis or classify every change as
allowed. A break absent from the migration inventory fails. The new baseline cannot be a dirty tree
or moving branch and is not created/published without explicit release authority.

**Validation:** prove the old gate reports the expected intentional breaks, prove an undocumented
fixture break fails the migration audit, prove a post-cut accidental break fails the new semver
gate, and rerun the relay compatibility matrix unchanged.

### Task 15: Run complete verification and produce the cut-readiness record

**Resources:** all changed packages, root/simulator workflows, architecture and compatibility
scripts, package/release checks, new dated cut-readiness audit.

**Depends on:** Tasks 1–14.

**Interfaces and state:** one immutable candidate revision owns all local and hosted evidence. The
audit maps every success criterion and intentional break to current code, a passing command/run,
and migration guidance.

**Implementation:** start with focused tests for each changed boundary, then run formatting,
workspace and simulator clippy with warnings denied, default/all/no-default feature checks,
workspace and simulator tests, docs, dependency policy, `cargo deny`, external-type checks,
determinism boundary/semantic contracts, package extraction/builds, package-order checks, and relay
golden/live interoperability. Review a clean final diff for accidental public exports, feature
unification, wire changes, and user work overlap. Run hosted platform matrices on the same
revision.

**Failure and operations:** no retry-only waivers. Classify infrastructure failures separately but
rerun them successfully before closure. A missing external compatibility revision, unexplained
golden change, flaky deterministic seed, undocumented source break, package graph drift, or dirty
candidate keeps the cut blocked. This task does not tag or publish anything.

**Validation:** at minimum execute and retain results for:

```bash
cargo make format-check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
cargo deny check
cargo test --manifest-path iroh-sim/Cargo.toml --all-targets
cargo clippy --manifest-path iroh-sim/Cargo.toml --all-targets --all-features -- -D warnings
cargo doc --manifest-path iroh-sim/Cargo.toml --all-features --no-deps
scripts/tests/check-workspace-architecture.sh
scripts/tests/check-relay-compatibility.sh
```

Also run the repository's existing default/no-default feature, MSRV, external-type,
determinism-boundary, semantic-contract, package, and release dry-run commands discovered in the
current CI/make definitions. Record exact commands, revision, platform, result, and artifact links
in the cut-readiness audit.

## Delivery sequence and review checkpoints

Implement as a series of reviewable changes, keeping all completed gates green:

1. contract/docs plus relay fixtures and cross-version harness;
2. workspace metadata/dependency enforcement;
3. `iroh-resolver` extraction and consumer migration;
4. TLS feature correction and exact-provider CI;
5. simulation-environment hard cut;
6. endpoint and socket/transport responsibility splits;
7. relay server/HTTP split under the already-green compatibility harness;
8. simulator API/module reorganization and DNS-server test moves;
9. authoritative docs, semver-baseline transition, and full closure audit.

Do not combine the relay wire harness and relay structural refactor in one review. Do not combine
the resolver extraction with unrelated behavior changes. At each checkpoint, update the migration
guide and architecture graph so reviewers can distinguish intentional breaks from regressions.

## Rollback and recovery

Before the architecture cut is released, each checkpoint can be reverted independently because
behavior-preserving moves follow characterization tests and the source breaks are isolated in
explicit commits. If a structural move breaks relay compatibility, revert that move; never update
goldens to bless unexplained output. If resolver extraction exposes a semantic mismatch, keep the
new crate boundary but restore the characterized behavior before proceeding. If exact TLS provider
support cannot be made independent, keep the provider-neutral feature design blocked rather than
shipping an AWS-LC feature that silently installs Ring.

After release, do not restore the old Rust API piecemeal. Fix defects forward on the v2 architecture
and use the migration guide for consumers. Relay V1/V2 regressions remain eligible for immediate
forward fixes or release rollback because shared infrastructure compatibility is a hard contract.

## Acceptance checklist

- [x] Upstream `v1.0.3` is pinned and tested in both client/server directions.
- [x] Golden V1/V2 fixtures cover constants, handshake/auth, frames, limits, and invalid inputs.
- [x] `iroh-relay` no longer depends on endpoint-specific DNS/pkarr code.
- [x] AWS-LC-only server builds contain no Ring; Ring-only builds contain no AWS-LC.
- [x] Production and simulator dependency graphs satisfy the enforced allowed-edge policy.
- [x] Simulation construction exposes only one validated test environment entry point.
- [x] Endpoint, socket, relay actor, relay server, and HTTP modules have clear responsibility
  owners with preserved shutdown/resource behavior.
- [x] `iroh-sim` exposes the documented domain hierarchy without flat compatibility reexports.
- [x] DNS-server crate root contains no black-box implementation tests.
- [x] README, architecture, deterministic status, feature, compatibility, and v2 migration docs
  agree with the code.
- [x] Every intentional Rust API break appears in the migration inventory.
- [x] The old API compatibility gate has a deliberate cut transition; relay wire gates remain
  independent and mandatory.
- [ ] Full local and hosted evidence is green on one immutable, clean candidate revision.

## Execution brief

Execute this plan sequentially with `superpowers:executing-plans`. Use
`superpowers:test-driven-development` for each contract, extraction, and refactor; apply
`tigerstyle:tigerstyle-rust` to every Rust/API/Cargo change. If a characterized behavior or
compatibility test fails unexpectedly, switch to `superpowers:systematic-debugging` before editing
production behavior. Before any completion, handoff, commit, or release-readiness claim, use
`superpowers:verification-before-completion` and attach current evidence. External publication,
tagging, and deployed-infrastructure changes require a separate explicit instruction.
