# Design-to-evidence map

This document maps the source identity architecture to the repository artifacts that implement or
verify it. It is an audit index, not a normative wire specification. The foundational,
account-control, synchronization, and network-envelope profile currently documented in
[`../README.md`](../README.md) is normative for that scope; the provider-portability appendix and
operational procedures are normative in [`provider-operations.md`](provider-operations.md), and
deployment rules remain in
[`security-and-deployment.md`](security-and-deployment.md).

Evidence labels have precise meanings:

- **Implemented** means the named repository source and focused tests exist.
- **Repository gate** means acceptance depends on the named command remaining green.
- **External gate** means the design calls for evidence that this repository cannot honestly
  manufacture. It remains a release prerequisite.
- **Non-goal** means the design intentionally excludes the behavior.

No entry here turns availability evidence into authority, a unit test into a security audit, or a
single Rust implementation into independent interoperability evidence.

## Design sections

| Design section | Authoritative implementation and verification evidence |
| --- | --- |
| 1. Executive Summary | Crate boundary and authority model in [`../src/lib.rs`](../src/lib.rs); deterministic projection in [`../src/state.rs`](../src/state.rs); deployment summary in [`security-and-deployment.md`](security-and-deployment.md). |
| 2. Problem Statement | Stable account/device/controller separation in [`../src/genesis.rs`](../src/genesis.rs), [`../src/keys.rs`](../src/keys.rs), and [`../src/device.rs`](../src/device.rs); rotation/revocation histories in `tests/state_machine.rs`. |
| 3. Goals and non-goals | Scope, goals, and explicit exclusions in [`security-and-deployment.md`](security-and-deployment.md); crate-level release gates in [`../src/lib.rs`](../src/lib.rs). Mandatory chains/tokens, civil identity, universal reputation, global application ordering, retroactive plaintext erasure, and automatic fork merging remain non-goals. |
| 4. Design Principles | Previous-policy authorization and append-only projection in [`../src/state.rs`](../src/state.rs); availability/authority separation in [`../src/checkpoint.rs`](../src/checkpoint.rs), [`../src/provider.rs`](../src/provider.rs), and `tests/checkpoint_projection.rs`; privacy and migration in [`../src/privacy.rs`](../src/privacy.rs) and [`../src/crypto_migration.rs`](../src/crypto_migration.rs). |
| 5. High-Level Architecture | Runtime-independent core in [`../src/lib.rs`](../src/lib.rs); pure transition in [`../src/state.rs`](../src/state.rs); effect boundary in [`../src/store.rs`](../src/store.rs) and [`../src/operations.rs`](../src/operations.rs); optional redb/provider/network features in `Cargo.toml`. |
| 6. Identity Hierarchy | `AccountId`, `ControllerId`, `DeviceId`, and application identifiers in [`../src/schema.rs`](../src/schema.rs); derivation-bearing descriptors in [`../src/genesis.rs`](../src/genesis.rs), [`../src/keys.rs`](../src/keys.rs), and [`../src/application.rs`](../src/application.rs); frozen derivation tests in `tests/genesis_schema.rs`, `tests/policy_schema.rs`, and `tests/device_application_schema.rs`. |
| 7. Cryptographic Key Hierarchy | Tagged algorithm/key/signature types in [`../src/types.rs`](../src/types.rs), [`../src/keys.rs`](../src/keys.rs), and [`../src/key_wrap.rs`](../src/key_wrap.rs); controller migration in [`../src/crypto_migration.rs`](../src/crypto_migration.rs); contributory-key and wrapping tests in `tests/vectors.rs` and `tests/key_rotation.rs`. |
| 8. Account-Control Event Log | Canonical event, intent, admission, and final-approval schemas in [`../src/event.rs`](../src/event.rs); 22 operations in [`../src/operations.rs`](../src/operations.rs) and [`../src/types.rs`](../src/types.rs); deterministic application/fork retention in [`../src/state.rs`](../src/state.rs); `tests/account_event_schema.rs`, `tests/event_evidence.rs`, `tests/state_machine.rs`, and `tests/task2_golden_vectors.rs`. |
| 9. Control Policies and Threshold Authorization | Weighted scoped rules in [`../src/policy.rs`](../src/policy.rs); exact pre-state evaluation in [`../src/verifier.rs`](../src/verifier.rs) and [`../src/state.rs`](../src/state.rs); `tests/policy_schema.rs` and `tests/policy_authorization.rs`. |
| 10. Device Authorization and Capabilities | Device records/lifecycle operations in [`../src/device.rs`](../src/device.rs); structural capability and narrowing rules in [`../src/capability.rs`](../src/capability.rs) and [`../src/capability_verifier.rs`](../src/capability_verifier.rs); `tests/device_application_schema.rs`, `tests/capability_schema.rs`, and `tests/capabilities.rs`. |
| 11. Device Pairing Protocol | Typed ceremony, transcript, possession proof, two-party confirmation, SAS, expiry, and nonce-store contract in [`../src/pairing.rs`](../src/pairing.rs); endpoint-owned connection binding in [`../src/net/mod.rs`](../src/net/mod.rs); `src/pairing/tests.rs`, `tests/net_contracts.rs`, and the pairing fuzz target. Direct and local-relay integration are implemented and remain covered by the final current-tree test gate. |
| 12. Revocation Model | Suspend/reinstate/revoke/rotate types in [`../src/device.rs`](../src/device.rs); terminal tombstones, epoch effects, and fork behavior in [`../src/state.rs`](../src/state.rs); application-key write gate in [`../src/store.rs`](../src/store.rs); `tests/state_machine.rs`, `tests/key_rotation.rs`, and `tests/operational_recovery.rs`. |
| 13. Transparency and Availability | Checkpoints, provider heads/receipts/equivocation evidence in [`../src/checkpoint.rs`](../src/checkpoint.rs); Merkle structures in [`../src/merkle.rs`](../src/merkle.rs); provider log and recovery aggregates in [`../src/transparency.rs`](../src/transparency.rs), [`../src/provider.rs`](../src/provider.rs), and [`../src/audit.rs`](../src/audit.rs); bounded interchange in [`../src/provider/interchange.rs`](../src/provider/interchange.rs); publication in [`../src/publication.rs`](../src/publication.rs); transparency, checkpoint, publication, wire-format, audit, and persistence tests. Optional public anchoring is the opaque non-authoritative interface in [`../src/provider/anchor.rs`](../src/provider/anchor.rs). |
| 14. Freshness and Online Status | Presence challenge/proof in [`../src/presence.rs`](../src/presence.rs); monotonic account/caller freshness evaluation with explicit time in [`../src/freshness.rs`](../src/freshness.rs); `tests/presence.rs` and `tests/freshness_decision.rs`. |
| 15. Forks, Concurrency, and Conflict Resolution | Complete predecessor sets, retained branches, deterministic `ForkId`, and explicit resolution in [`../src/state.rs`](../src/state.rs) and [`../src/recovery.rs`](../src/recovery.rs); exact-CAS source store in [`../src/store.rs`](../src/store.rs); fork/order tests in `tests/state_machine.rs`, `tests/store_conformance.rs`, and `tests/checkpoint_projection.rs`. |
| 16. Recovery | Typed begin/veto/cancel/finalize operations and private guardian evidence in [`../src/recovery.rs`](../src/recovery.rs); recovery projection in [`../src/state.rs`](../src/state.rs); encrypted authority/data backup split in [`../src/privacy.rs`](../src/privacy.rs); `tests/recovery_schema.rs`, `tests/recovery_guardians.rs`, `tests/private_backup.rs`, and `tests/operational_recovery.rs`. |
| 17. Social Graph and Attestations | Bounded signed hints, exact authority time, common validity interval, and opt-in transitivity in [`../src/social.rs`](../src/social.rs); encrypted/local relationship policy in [`../src/privacy.rs`](../src/privacy.rs) and the deployment guide; `tests/social.rs`. No attestation implicitly grants control authority. |
| 18. Human-Readable Names and Discovery | Normalized aliases, bounded resolver candidates, signed claims, and explicit TOFU decisions in [`../src/names.rs`](../src/names.rs); `tests/names.rs`. Names remain aliases rather than account identity. |
| 19. Application Data and Group-Key Rotation | Signed application envelope and counter/context verification in [`../src/application.rs`](../src/application.rs); KEM/DEM wrapping and revision-bound rotation in [`../src/key_wrap.rs`](../src/key_wrap.rs); structural authorization in capability modules; `tests/application_verification.rs`, `tests/device_application_schema.rs`, and `tests/key_rotation.rs`. |
| 20. Transport Integration | Frozen six-ALPN registry, authenticated endpoint dispatch, one shared bounded supervisor, direct/local-relay handlers, endpoint-owned pairing binding, and resumable sync in [`../src/transport.rs`](../src/transport.rs), [`../src/net/mod.rs`](../src/net/mod.rs), [`../src/net/protocol.rs`](../src/net/protocol.rs), and [`../src/sync.rs`](../src/sync.rs); `tests/net_contracts.rs`, `tests/sync_contracts.rs`, `tests/store_conformance.rs`, and the opt-in `krikos-app` identity component test provide integration evidence. |
| 21. Protocol Interfaces | Concrete mapping is recorded in the next table. |
| 22. State Machines | Device, account, checkpoint-publication, and operational-effect lifecycle mapping is recorded below. |
| 23. Threat Model | Implemented threat/mitigation and residual-risk statement in [`security-and-deployment.md`](security-and-deployment.md); adversarial tests span signatures, substitutions, rollback/equivocation, replay/forks, bounds, recovery, and persistence. Third-party security review remains an external gate. |
| 24. Privacy Model | Secret/private wrappers and encrypted artifacts in [`../src/privacy.rs`](../src/privacy.rs), [`../src/recovery.rs`](../src/recovery.rs), and [`../src/key_wrap.rs`](../src/key_wrap.rs); redacted/no-public-wire tests in `tests/privacy_boundaries.rs`, `tests/private_artifacts.rs`, and compile-fail rustdoc. |
| 25. Comparison of Ledger Options | The implemented choice is a provider-replicated append-only Merkle log with optional opaque external anchoring, not a mandatory blockchain: [`../src/provider.rs`](../src/provider.rs), [`../src/merkle.rs`](../src/merkle.rs), and [`provider-operations.md`](provider-operations.md). |
| 26. Lessons from Peergos | Reflected in per-device keys, append-only authority, explicit capabilities, provider availability separation, encrypted metadata, and key rotation across the modules named for sections 6, 8, 10, 13, 19, and 24. This is architectural provenance rather than a separate wire object. |
| 27. Serialization and Compatibility | Pinned canonical Postcard v1 profile, codepoints, extension rules, and documented foundational, account-control, synchronization, and network-envelope schemas in [`../README.md`](../README.md); exact provider manifests, chunks, registries, commitment preimages, and bounds in [`provider-operations.md`](provider-operations.md) backed by [`../src/provider/interchange.rs`](../src/provider/interchange.rs), [`../src/provider/compaction.rs`](../src/provider/compaction.rs), and `tests/provider_wire_formats.rs`; bounded canonical re-encode check in [`../src/codec.rs`](../src/codec.rs); migration/upgrade types in [`../src/crypto_migration.rs`](../src/crypto_migration.rs); schema/vector tests and interoperability asset validator are repository gates. |
| 28. Storage and Garbage Collection | Canonical source, journal, fork, checkpoint, and effect retention in [`../src/store.rs`](../src/store.rs); provider generation export/retention/compaction in [`../src/provider.rs`](../src/provider.rs), [`../src/provider/compaction.rs`](../src/provider/compaction.rs), and [`provider-operations.md`](provider-operations.md); provider redb store v7 and audit redb v2 with explicit legacy rejection in [`../src/provider/redb.rs`](../src/provider/redb.rs) and [`../src/audit/redb.rs`](../src/audit/redb.rs); `tests/store_conformance.rs`, `tests/provider_persistence.rs`, provider redb unit tests, and provider fuzzing. |
| 29. Error Model | Typed stable distinctions in [`../src/error.rs`](../src/error.rs), propagated across decoding, verification, projection, storage, networking, and operations. Error taxonomy and no-panic searches are final audit repository gates. |
| 30. API Ergonomics | Validated constructors and explicit state/decision types are re-exported from [`../src/lib.rs`](../src/lib.rs); raw cryptography and wire helpers remain internal. `framework/app/src/identity_protocol.rs`, `framework/app/tests/identity_component.rs`, and `framework/app/examples/identity.rs` implement and exercise the opt-in application component without taking ownership of endpoint-key persistence. |
| 31. Testing Strategy | Complete category-to-command mapping appears below. Deterministic simulation, formal bounded checking, aggregate fuzz smoke, and language-independent vector validation are final repository gates. |
| 32. Transparency Provider Operations | Admission control, rate limits, immutable generations, streaming export/assembly, exact portable preflight, recovery/mirror/compaction, anchoring, constant-size audit CAS, metrics, and incident procedure in [`../src/provider.rs`](../src/provider.rs), [`../src/provider/interchange.rs`](../src/provider/interchange.rs), [`../src/provider/redb.rs`](../src/provider/redb.rs), [`../src/audit.rs`](../src/audit.rs), [`../src/audit/redb.rs`](../src/audit/redb.rs), [`../src/operations.rs`](../src/operations.rs), [`provider-operations.md`](provider-operations.md), and `examples/provider_auditor.rs`. |
| 33. Deployment Profiles | Local-only, consumer, high-security, and enterprise profiles in [`security-and-deployment.md`](security-and-deployment.md). Profiles cannot weaken the account-committed minimum. |
| 34. Implementation Roadmap | Phase mapping appears below. Repository artifacts can complete engineering phases; third-party audit and independent implementation remain external gates. |
| 35. Initial Product Decisions | Frozen v1 choices are recorded in [`../README.md`](../README.md), crate feature boundaries, policy constructors, provider defaults, pairing, capability, freshness, privacy, and key-rotation modules. |
| 36. Security-Critical Invariants | Direct invariant-to-enforcement mapping appears below; deterministic simulation must also check them after every step. |
| 37. Open Design Questions | Resolved v1 choices and genuinely external/open items are recorded in [`security-and-deployment.md`](security-and-deployment.md). Future choices require new protocol versions or explicit authorized migrations, not reinterpretation of v1 bytes. |
| 38. Final Recommendation | Delivered as the managed `krikos-identity` core plus optional storage/provider/network adapters and integration component. Production release remains conditioned on the external gates. |
| 39. References | The design document remains the source bibliography. Transport integration uses the workspace `krikos` API; no reference is treated as executable evidence by itself. |

## Named interface mapping

The design's illustrative traits are realized with narrower pure functions and state-view traits
where dynamic dispatch is unnecessary. This preserves the intended boundary without freezing the
pseudocode as an accidental wire or ABI contract.

| Design interface | v1 repository interface | Evidence |
| --- | --- | --- |
| `AccountStore` | [`AccountStore`](../src/store.rs), `MemoryAccountStore`, and feature-gated `RedbAccountStore`; exact revision CAS commits source event plus outbox atomically and pages checkpoint/source history. | `tests/store_conformance.rs`, `tests/operational_recovery.rs`. |
| `AccountVerifier` | `AccountGenesis::account_id`, `AccountState::from_genesis`, `AccountState::validate_and_apply`, and `verify_checkpoint`; effects are returned rather than executed. | `tests/genesis_schema.rs`, `tests/state_machine.rs`, `tests/checkpoint_projection.rs`. |
| `TransparencyClient` | [`TransparencyClient`](../src/publication.rs), `publish_checkpoint_concurrently`, provider log/store/auditor interfaces. | `tests/publication.rs`, `tests/transparency_crypto.rs`, `tests/provider_persistence.rs`. |
| `FreshnessVerifier` | Pure `evaluate_freshness` over `VerifiedCheckpoint`, signed provider receipts, account requirement, stricter caller requirement, and explicit verifier time. | `tests/freshness_decision.rs`. |
| `CapabilityVerifier` | Pure `evaluate_capability`, `CapabilityStateView`, and `DelegationSignatureVerifier`. | `tests/capabilities.rs`, `tests/application_verification.rs`. |
| Transport/distribution | Discovery, gossip, blob, authenticated endpoint facts, ALPN, bounded framing, shared supervisor, and frozen-revision sync contracts in `transport`, `net`, and `sync`. | `tests/net_contracts.rs`, `tests/sync_contracts.rs`, `tests/store_conformance.rs`, and `framework/app/tests/identity_component.rs`, including direct/local-relay, cancellation, shutdown, backpressure, and cursor-reopen cases. |
| Recovery signer boundaries | `OfflineSigner`, `HardwareController`, `CanonicalSigningRequest`, guardian authority verification, and encrypted backup restoration. | `tests/privacy_boundaries.rs`, `tests/recovery_guardians.rs`, `tests/private_backup.rs`. |
| Name resolver | [`NameResolver`](../src/names.rs) plus bounded cryptographic filtering and explicit TOFU output. | `tests/names.rs`. |
| Provider operations | `ProviderAdmissionControl`, `ProviderStore`, `ProviderAuditStore`, generation/audit/recovery manifest and chunk assemblers, anchoring/compaction interfaces, and durable operational effect traits. | `tests/provider_wire_formats.rs`, `tests/provider_persistence.rs`, provider/audit redb unit suites, operational tests, and provider auditor example. |

## Lifecycle mapping

| Design lifecycle | Representation and transition evidence |
| --- | --- |
| Device `Proposed -> Active` | A `DeviceAuthorizationProposal` is non-authoritative until code 1 creates a validated `DeviceAuthorization`; pairing produces ceremony evidence but does not directly mutate authority. |
| Device `Active <-> Suspended` | Codes 4 and 5; `ProjectedDeviceLifecycle::{Active,Suspended}`; state-machine lifecycle tests. |
| Device rotation | Code 7 atomically terminally revokes the old `DeviceId` and authorizes the independently derived replacement ID. There is no externally visible half-rotated projection. |
| Device `Revoked` | Code 6 and `ProjectedDeviceLifecycle::Revoked`; old IDs/key roles are permanent tombstones. |
| Account `Genesis -> Active` | `AccountGenesis` deterministically constructs the initial `AccountState`; first event uses the genesis-anchor predecessor. |
| Account recovery | `ProjectionLifecycle::RecoveryPending`; begin/veto/cancel/finalize are codes 13--16 and bind the exact prior state, admission, delay, and replacement plan. |
| Account fork | `ProjectionLifecycle::Forked`; all valid branches are retained; code 17 selects one existing branch under common pre-fork authority and late branches reopen a fork. |
| Crypto migration | `ProjectionLifecycle::{MigrationPending,MigrationDual}`; codes 18--20 stage, activate, retire, or abort without suite downgrade/reuse. |
| Protocol upgrade | `ProjectionLifecycle::UpgradePending`; code 21 makes this v1 implementation fail closed/read-only for an authorized future major. |
| Account retirement | `ProjectionLifecycle::Retired`; code 22 is terminal except for identical replay. |
| Checkpoint publication | `PublicationStage::{Draft,Authorized,Published,Replicated,Observed}`; failures remain explicit outcomes and never advance authority. |
| Durable effects | `OperationalEffectPhase` records claim, rotation, checkpoint authorization, publication/observation, notification, retry, terminal failure, and completion across crashes. |

## Authoritative operation registry

All operation codepoints are closed in `OperationKind`, encoded by `AccountOperation`, projected in
`AccountState`, documented in the crate README, and frozen by
`tests/task2_golden_vectors.rs::account_operation_vectors_cover_every_v1_code` plus
`tests/state_machine.rs::frozen_epoch_table_covers_every_v1_operation_kind`.

| Code | Operation | Primary schema/transition module |
| ---: | --- | --- |
| 1 | `AuthorizeDevice` | `device.rs`, `state.rs` |
| 2 | `UpdateDeviceAuthorization` | `device.rs`, `state.rs` |
| 3 | `UpdateDeviceMetadata` | `device.rs`, `state.rs` |
| 4 | `SuspendDevice` | `device.rs`, `state.rs` |
| 5 | `ReinstateDevice` | `device.rs`, `state.rs` |
| 6 | `RevokeDevice` | `device.rs`, `state.rs` |
| 7 | `RotateDeviceKeys` | `device.rs`, `state.rs` |
| 8 | `AddController` | `keys.rs`, `state.rs` |
| 9 | `RemoveController` | `keys.rs`, `state.rs` |
| 10 | `ChangeControlPolicy` | `policy.rs`, `state.rs` |
| 11 | `ChangeRecoveryPolicy` | `policy.rs`, `recovery.rs`, `state.rs` |
| 12 | `ChangeProviderPolicy` | `policy.rs`, `provider.rs`, `state.rs` |
| 13 | `BeginRecovery` | `recovery.rs`, `state.rs` |
| 14 | `VetoRecovery` | `recovery.rs`, `state.rs` |
| 15 | `CancelRecovery` | `recovery.rs`, `state.rs` |
| 16 | `FinalizeRecovery` | `recovery.rs`, `state.rs` |
| 17 | `ResolveFork` | `recovery.rs`, `state.rs` |
| 18 | `BeginCryptoMigration` | `crypto_migration.rs`, `state.rs` |
| 19 | `ActivateCryptoMigration` | `crypto_migration.rs`, `state.rs` |
| 20 | `RetireCryptoSuite` | `crypto_migration.rs`, `state.rs` |
| 21 | `UpgradeProtocol` | `crypto_migration.rs`, `state.rs` |
| 22 | `RetireAccount` | `crypto_migration.rs`, `state.rs` |
| 23 | Reserved `PublishCheckpoint` | Rejected as an authority operation; checkpoint publication is the availability-plane journal in `publication.rs`/`operations.rs`. |

## Roadmap artifacts

| Roadmap phase | Repository evidence | Acceptance boundary |
| --- | --- | --- |
| Phase 0: specification foundation | README wire profile/codepoints, canonical codec and types, deterministic state projection, traits, limits, vectors, threat/deployment docs. | Binary-plus-JSON interoperability validator and reference/formal model commands must be green. |
| Phase 1: core multi-device identity | Account/device/controller hierarchy, 22-operation log, policies, pairing core, capabilities, revocation, sync schema, group-key wrapping, six direct/local-relay handlers, and the opt-in app component/example. | Current-tree network, store, and app integration tests must remain green. |
| Phase 2: transparency availability | Checkpoints, Merkle proofs, provider admission/log/store/auditor, publication/freshness, provider example and operations guide. | Full persistent fault/crash and provider fuzz gates must remain green. |
| Phase 3: recovery and advanced control | Weighted policy, recovery lifecycle, guardians, hardware/offline exact signing requests, fork resolution, encrypted authority/application backup. | Recovery durable operational matrix and private-artifact boundaries must remain green. |
| Phase 4: privacy and interoperability | Blinded/private lookup, pairwise IDs, social/name/TOFU, opaque anchoring, portable credentials. | Independent cross-language implementation is an **external gate**; checked-in language-independent assets are the repository prerequisite. |
| Phase 5: hardening | Deterministic simulation/corpus, formal bounded model, aggregate fuzzing, docs, incident/migration playbooks, final audits. | Third-party security audit and independent provider interoperability are **external gates**; stable release must not be claimed before them. |

## Test-category and command map

Rust commands use 1.91.0 except bounded fuzzing, which uses the explicitly pinned reviewed nightly
named by the runner and workflows. Exact fuzz duration/execution evidence belongs in the final
verification report so this durable map does not overstate an old run.

| Design test category | Focused artifacts and command |
| --- | --- |
| Unit/schema/crypto | `cargo +1.91.0 test --locked -p krikos-identity --no-default-features --all-targets`; schema, vectors, policy, Merkle, capability, freshness, presence, recovery, privacy, and application test files. |
| Feature/dependency boundary | `scripts/check-identity-feature-matrix.sh` compiles the reviewed core, singleton integration, integration-combination, and all-feature sets, then checks the no-default normal dependency tree. It invokes `scripts/tests/check-identity-os-rng-boundary.sh` to enforce `krikos-base/key-types`, legacy `key`/`os-rng`, identity `os-rng`, and explicit caller-owned RNG boundaries. |
| Property-based | Proptest histories/narrowing/Merkle cases in `tests/state_machine.rs`, `tests/capabilities.rs`, and `tests/merkle.rs`; also evaluator fuzz selectors. |
| State-machine/reference | `tests/state_machine.rs` plus the independent reference model and simulator replay command. The reference model must not call `AccountState` transition logic. |
| Deterministic distributed simulation | `krikos-sim` recorded scenarios/corpus and replay command covering time, reorder/loss/duplication, partitions, provider faults, crashes/storage loss, recovery, migrations, revocation, and key rotation. |
| Fuzzing | `scripts/run-bounded-fuzz.sh` identity target aggregation; corpus/selector inventory in `scripts/tests/check-fuzz-tooling.sh`; both fuzz CI workflows. Every public canonical decoder and stateful verifier/evaluator must have a selector or a documented non-wire reason. |
| Interoperability vectors | Manifest-v2 JSON metadata and 141 canonical binaries under `tests/vectors/`; the independent read-only validator owns a closed typed/semantic inventory, recursively extracts exact dependencies, derives hash/Merkle outputs, verifies repeatable signature/MAC bindings, and exercises omission/substitution/coordinated-replacement attacks. Two private guardian witnesses and one transient pairing message have explicit dispositions. `scripts/check-identity-interop-vectors.sh` proves deterministic regeneration and corpus reproduction. Independent implementation remains external. |
| Formal methods | Repository-owned bounded command for the model under `docs/identity/`, covering all six section 31.7 properties. A missing external checker is not a pass unless the repository supplies and runs a hermetic equivalent. |
| Provider portability | `cargo +1.91.0 test --locked -p krikos-identity --test provider_wire_formats`; commitment mirror tests in `audit::tests` and `provider::compaction::tests`; exact manifest/chunk schemas, registries, domains, and bounds are indexed in [`provider-operations.md`](provider-operations.md). |
| Persistent operations | `cargo +1.91.0 test --locked -p krikos-identity --features fs-store,provider-store --test store_conformance --test provider_persistence --test operational_recovery`. |
| Provider persistent schemas | `cargo +1.91.0 test --locked -p krikos-identity --features provider-store --lib provider::redb::tests -- --test-threads=1` and the corresponding `audit::redb::tests` command; covers provider store v7, audit store v2, explicit legacy rejection, prepared reopen/preflight, atomic CAS, and bounded hot-path canaries. |
| Network integration | Feature-gated two-node direct/local-relay pairing, proposal, and resumable sync tests plus bounded-frame/backpressure/cancel/shutdown cases. |
| Documentation/API | `RUSTDOCFLAGS='-Dwarnings' cargo +1.91.0 doc --locked -p krikos-identity --all-features --no-deps` and locked no-default/all-feature doctests. |
| Workspace/release | Workspace tests/Clippy/format, architecture/hermetic/package/release/reservation scripts, `git diff --check`, unsafe/panic/allocation audit, and final evidence report. |

## Security-critical invariant map

| Invariant | Enforcement and direct regression evidence |
| --- | --- |
| The account is not a device. | Separate self-certifying types/descriptors and endpoint dispatch; `tests/policy_schema.rs`, `tests/state_machine.rs`, `tests/net_contracts.rs`. |
| No ordinary account private key is copied to every device. | Public account state contains controller/device public descriptors only; per-device signing/agreement/endpoint roles and redacted secrets; key-role separation tests. Human custody is outside the crate and documented. |
| Every device is independently identifiable, authorizable, and revocable. | `DeviceId` commits all device public keys; codes 1--7; device tombstones; device/application schema and lifecycle tests. |
| Every account-control transition is signed under the previous policy. | `EventBody` predecessor set, intent/admission/final approval binding, pre-state policy evaluator; policy authorization and state-machine mutation-on-error tests. |
| Account identity survives complete device/controller rotation. | `AccountId` hashes immutable genesis; replacement IDs and controller/migration transitions do not rewrite genesis; genesis/state/migration tests. |
| Providers distribute state but cannot create it. | Provider admission requires exact pre-state-approved intent; checkpoints are independently account-authorized; provider log/persistence/projection tests. |
| Social relationships grant no implicit account authority. | Social module returns bounded hints only; no social type enters the control evaluator except the explicit private guardian recovery policy path; social/recovery tests. |
| Revocation becomes externally discoverable only after durable publication. | Projection emits durable effect; operational phases distinguish local authorization, provider publication, replication, and observation; publication/operational crash tests. |
| Offline validity is relative to known state, not globally current. | `AuthorizationContext`, checkpoint/epoch basis, explicit `FreshnessDecision`, and provider evidence/time requirements; capability/application/freshness tests. |
| Sensitive actions fail closed without required freshness or consistency. | Monotonic caller/account requirements, exact provider quorum/time, fork lifecycle gates, and `FreshnessUnavailable`; freshness/policy/application tests. |
| A removed device receives no future group keys. | Rotation snapshot derives exact active membership at revision; store blocks protected writes until required rotation commits; key-rotation and operational-recovery tests. |
| Conflicting security histories are detected and explicitly resolved. | Complete predecessor/head sets, distinct admitted `EventId`s, retained fork evidence, code 17 exact branch selection, and late-fork reopening tests. |

## External release gates

The machine-readable [`../release-gate.toml`](../release-gate.toml) and its
[`release-gate.md`](release-gate.md) checklist block stable publication. The following are
intentionally **not** claimed complete by repository tests:

1. `third_party_security_audit`: a named independent cryptographic and protocol audit of the stable
   candidate, with critical/high findings resolved or explicitly release-blocked.
2. `independently_maintained_interoperability`: a separately maintained implementation that
   validates the public v1 fixtures and negative cases and completes the required ceremonies in both
   directions.
3. `production_provider_diversity`: production evidence of the stable provider quorum across
   independently administered infrastructure and failure domains, including a provider-loss drill.
4. `protocol_governance`: a published process for wire changes, codepoint allocation, compatibility
   windows, vulnerability handling, and protocol-upgrade decisions.
5. `public_api_semver_baseline`: an immutable reviewed public API/rustdoc baseline, SemVer policy,
   compatibility result, and stable-crate release ownership.
6. `persistent_schema_support`: documented account/provider schema support windows,
   forward/rollback rules, migration fixtures, backup/restore drills, and operational ownership.

Platform-specific secure-hardware UX, attestation, backup, and signing-display normalization also
remain external deployment work, but they are not one of the six machine-readable release
approvals.

The checked-in vectors, bounded model, fuzz/simulation corpus, operational playbooks, and final
verification matrix are prerequisites for those gates, not replacements for them. Until every
approval has qualifying evidence, `python3 scripts/check-identity-release-gate.py --expect-closed`
must pass and `--require-open` must fail.
