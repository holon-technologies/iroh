# krikos-identity

`krikos-identity` is a distributed account-control and authorization protocol. It
keeps a stable account identity separate from every replaceable Krikos endpoint and
application device.

The crate is under active implementation and is not yet a stable protocol release.
Its core is deterministic and effect-free; transport, persistence, transparency,
and recovery adapters are layered on that core.

Stable publication is blocked by the separate machine-readable
[`release-gate.toml`](release-gate.toml). Its six approval criteria, evidence requirements, and
opening procedure are documented in [`docs/release-gate.md`](docs/release-gate.md).

Provider database configuration, crash recovery, compaction, auditor usage, durable effect
reconciliation, and private-safe metrics are documented in
[`docs/provider-operations.md`](docs/provider-operations.md). The broader deployment, threat,
privacy, and recovery boundary is documented in
[`docs/security-and-deployment.md`](docs/security-and-deployment.md). The implementation and
verification index is [`docs/design-evidence.md`](docs/design-evidence.md).

## Optional runtime integrations

The default feature set remains runtime-, storage-, and ambient-entropy-independent. APIs that
accept a caller-owned cryptographic RNG remain in the default core. `os-rng` enables only the
fallible convenience methods that obtain fresh secrets from the operating system; it does not
change protocol behavior or wire formats. `net` enables the six bounded Krikos v1 ALPN handlers and
the completed-handshake pairing exporter adapter; `fs-store` enables redb account and durable
pairing-nonce storage; and `provider-store` enables redb-backed provider persistence. These features
are independent and none implicitly enables `os-rng`.

The network handlers accept one length-delimited canonical request per authenticated connection,
enforce the 4 MiB frame and 16 MiB session ceilings, and route decoded requests through a
caller-owned `IdentityProtocolService`. Sync pages always come from the configured `AccountStore`
at a cursor-authenticated frozen source revision.

The negotiated ALPN bytes and maximum canonical request payloads, excluding the four-byte transport
length prefix, are fixed as follows:

| Protocol | Exact v1 ALPN bytes | Maximum request payload |
| --- | --- | ---: |
| Pairing | `krikos-identity/pairing/1` | 16 KiB |
| Synchronization | `krikos-identity/sync/1` | 4 MiB |
| Authorization proposal | `krikos-identity/proposal/1` | 256 KiB |
| Account checkpoint | `krikos-identity/checkpoint/1` | 1 MiB |
| Transparency gossip | `krikos-identity/transparency-gossip/1` | 1 MiB |
| Recovery | `krikos-identity/recovery/1` | 256 KiB |

Each handler applies its request-specific payload ceiling before canonical decoding. The 4 MiB
per-frame and 16 MiB per-connection session ceilings remain independent transport limits.

`krikos-app` exposes a separate opt-in `identity` feature and `IdentityProtocolComponent`. The
component registers all six handlers on the endpoint already created by the standard bundle and
uses a caller-supplied account store. It never reads, replaces, or writes the framework's
`IdentityStore`, which continues to own only endpoint-key persistence. A runnable default-deny
composition is available with:

```console
cargo run -p krikos-app --features identity --example identity
```

## Canonical wire profile v1

Signed v1 structures documented in this profile use exactly Postcard 1.1.3. The dependency is
pinned, and the rules below—not future Serde or Postcard behavior—are normative for the structures
explicitly listed here. Checked-in vectors provide byte-level release evidence only when their
repository gate is green. The complete provider-portability manifest/chunk schemas, provider-only
registries, commitment preimages, resource bounds, and persistent-store compatibility rules are
normative in [`docs/provider-operations.md`](docs/provider-operations.md).

### Language-independent interoperability catalog

[`tests/vectors/manifest.json`](tests/vectors/manifest.json) is descriptive JSON metadata for the
canonical binary files beside it; JSON is never hashed, signed, MACed, or decoded as protocol
wire. Manifest format v2 uses binding-schema v1 and derivation-schema v1. Each vector records its
exact canonical file, hex bytes, BLAKE3 file digest, byte length, wire type, version scope,
algorithm codes, expected identifiers, repeatable signature/MAC bindings, recursive derivations,
exact object dependencies, and a bounded tamper expectation.

The non-generating validator in
[`tests/interop_vectors.rs`](tests/interop_vectors.rs) owns a closed typed inventory independently
of the generator. It binds every name to its exact wire type and, where one wire type has several
semantic roles, to the operation, response, or migration/checkpoint phase. It recursively derives
authenticated subobjects from decoded binary bytes, recomputes identifiers and Merkle
relationships, verifies every signature and MAC, compares exact dependencies, and rejects
omission, substitution, coordinated replacement, extra-file, or missing-file mutations. The
current v2 catalog contains 141 required vectors, including all 22 account operations, the complete
account/recovery/migration/pairing ceremonies, network envelopes, Merkle structures, and provider
export/recovery/compaction/anchor boundaries.

`GuardianGrant` and `GuardianGrantOpening` are deliberately private nested witnesses and have no
standalone public wire form; both are covered inside `SignedGuardianApproval`. The public
`PairingConfirmation` is a transient state-machine input consumed before retained proposal
construction; its manifest disposition points to `PairingConfirmationContext` and
`DeviceAuthorizationProposal` vectors. These are the only declared catalog dispositions.

[`../../scripts/check-identity-interop-vectors.sh`](../../scripts/check-identity-interop-vectors.sh)
regenerates the catalog in a temporary directory, requires byte-for-byte equality, reproduces the
provider and sync fuzz corpora, and runs the read-only validator. An independently maintained
implementation consuming these assets remains an external stable-release gate, not repository
self-certification.

Postcard encodes unsigned integers as minimal unsigned LEB128 varints, `false` and
`true` as `0x00` and `0x01`, fixed arrays/tuples as their concatenated elements with
no length, and sequences/byte strings as a minimal-varint item count followed by
their elements. Struct fields appear in the documented declaration order with no
field tags or enclosing length. Closed protocol enums are explicit unsigned `u16`
codepoints; Serde variant ordinals are not used.

The foundational schemas, in field order, are:

```text
Digest             = (hash_algorithm: u16, bytes: [u8; 32])
SigningPublicKey   = (signature_algorithm: u16, bytes: [u8; 32])
AgreementPublicKey = (agreement_algorithm: u16, bytes: [u8; 32])
ProtocolSignature  = (signature_algorithm: u16, bytes: [u8; 64])
Extension          = (code: u32, critical: bool, value: bytes)
Extensions         = sequence<Extension>
```

An extension code must be nonzero. Extension sequences are strictly increasing by
code, contain at most 32 fields, contain at most 16 KiB per value and 64 KiB across
all values, and preserve unknown non-critical values byte-for-byte. An unknown
critical code fails closed.

Additional canonical requirements are:

- every independently signed or authoritative top-level structure carries an
  explicit protocol version; nested primitives do not;
- algorithm registries use unsigned 16-bit codepoints (`1` is the initial suite);
- schemas contain no maps, floats, `usize`, or unordered collections;
- set-like vectors are sorted and duplicate-free before encoding;
- integers use Postcard's minimal varint representation;
- decoders reject trailing bytes, non-minimal encodings, unsupported codepoints,
  and inputs larger than the type's named bound;
- every protocol-owned hash input is
  `ASCII("KRIKOS-ID/<object>/v1") || 0x00 || canonical_object_bytes`;
- JSON and other human-readable formats are never signing formats.

Initial codepoints are BLAKE3-256 (`hash = 1`), Ed25519 (`signature = 1`),
X25519 (`agreement = 1`), BLAKE3 derive-key (`KDF = 1`), and
XChaCha20-Poly1305 (`AEAD = 1`). Golden bytes in `tests/vectors.rs` freeze the
foundational profile.

### Synchronization and network-envelope schema

The four-byte big-endian stream length is transport framing and is not part of the canonical
payload. The canonical synchronization and optional `net` feature structures use these exact field
orders:

| Structure | Exact v1 fields |
|---|---|
| `SyncCursor` | `(protocol_version, account_id, source_heads: sequence<EventId, 16>, next_item: u64, delivered_bytes: u64, authenticator: [u8; 32])` |
| `SyncRequest` | `(protocol_version, account_id, known_heads: sequence<EventId, 16>, continuation: option<SyncCursor>, max_events: u16, max_frame_bytes: u32)` |
| `SyncFrame` | `(protocol_version, account_id, source_heads: sequence<EventId, 16>, events: sequence<AuthorizedEvent, 256>, continuation: option<SyncCursor>)` |
| `SyncResponse` | `(protocol_version, response_code: u16, frame: option<SyncFrame>, complete_account_id: option<AccountId>, complete_heads: option<sequence<EventId, 16>>)` |
| `EndpointAuthorizationRequest` | `(protocol_version, account_id, checkpoint_id, device_id)` |
| `AuthorizedSyncRequest` | `(authorization: EndpointAuthorizationRequest, request: SyncRequest)` |
| `AuthorizedProposalRequest` | `(authorization: EndpointAuthorizationRequest, proposal: DeviceAuthorizationProposal)` |
| `AuthorizedCheckpointRequest` | `(authorization: EndpointAuthorizationRequest, checkpoint: SignedCheckpoint)` |
| `IdentityProtocolAck` | `(protocol_version, protocol_code: u16, request_commitment, decision_code: u16)` |
| `IdentityProtocolReply` | `(protocol_version, reply_code: u16, ack: option<IdentityProtocolAck>, sync: option<SyncResponse>)` |

`SyncResponse` uses closed response code `1` for exactly one `frame` and code `2` for exactly one
`(complete_account_id, complete_heads)` pair. `IdentityProtocolReply` uses code `1` for exactly one
acknowledgement and code `2` for exactly one sync response. The acknowledgement protocol registry is
pairing `1`, sync `2`, proposal `3`, checkpoint `4`, transparency gossip `5`, and recovery `6`;
decision code `0` means accepted and nonzero values are caller-owned rejection codes. Old Serde enum
ordinals and every unknown response, reply, or protocol codepoint fail closed.

Every authorized envelope requires its outer authorization account to equal the nested request,
proposal, or checkpoint account during construction and canonical decoding. Endpoint authorization
is an authoritative top-level coordinate and therefore carries and validates `protocol_version = 1`.

Ed25519 public keys must decompress under ed25519-dalek's RFC 8032 encoding rules
and must not be a weak/small-order point. X25519 public keys are canonical
little-endian field elements strictly below `2^255 - 19`; inputs that produce an
all-zero result under a clamped contributory probe are rejected. Actual key agreement
also rejects an all-zero shared secret.

## Authoritative account operation registry

| Code | Operation |
|---:|---|
| 1 | `AuthorizeDevice` |
| 2 | `UpdateDeviceAuthorization` |
| 3 | `UpdateDeviceMetadata` |
| 4 | `SuspendDevice` |
| 5 | `ReinstateDevice` |
| 6 | `RevokeDevice` |
| 7 | `RotateDeviceKeys` |
| 8 | `AddController` |
| 9 | `RemoveController` |
| 10 | `ChangeControlPolicy` |
| 11 | `ChangeRecoveryPolicy` |
| 12 | `ChangeProviderPolicy` |
| 13 | `BeginRecovery` |
| 14 | `VetoRecovery` |
| 15 | `CancelRecovery` |
| 16 | `FinalizeRecovery` |
| 17 | `ResolveFork` |
| 18 | `BeginCryptoMigration` |
| 19 | `ActivateCryptoMigration` |
| 20 | `RetireCryptoSuite` |
| 21 | `UpgradeProtocol` |
| 22 | `RetireAccount` |
| 23 | reserved; checkpoint publication is non-authoritative |

All other v1 operation codes are rejected. Account-level field schemas and their
golden vectors are frozen with the complete typed account schema below.

## Canonical account schema reference

The notation below is wire notation, not Rust layout. `sequence<T, N>` is a
Postcard sequence whose decoded item count must not exceed `N`; `option<T>` is
Postcard's closed option encoding. Every field list is in exact canonical order.
All `Extensions` fields are final so an extension cannot change the meaning of a
preceding field. The decoder reconstructs validated domain types and rejects a
wire value whose order, uniqueness, relationship, version, or closed codepoint is
invalid.

### Genesis, descriptors, and policies

| Structure | Exact v1 fields |
|---|---|
| `AccountGenesis` | `(protocol_version, account_nonce: [u8; 32], created_at, hash_algorithm, initial_policy, initial_controllers: sequence<ControllerDescriptor, 64>, initial_recovery_policy, initial_provider_policy, extensions)` |
| `ControllerDescriptor` | `(protocol_version, signing_key, class, weight, scope, extensions)` |
| `ProviderDescriptor` | `(protocol_version, signing_key, extensions)` |
| `DeviceDescriptor` | `(protocol_version, application_signing_key, agreement_key, endpoint_key, extensions)` |
| `PolicyRule` | `(operation, required_weight, eligible_controllers, freshness, delay: option<DurationMillis>, extensions)` |
| `ControlPolicy` | `(protocol_version, rules: sequence<PolicyRule, 64>, default_deny: bool, extensions)` |
| `ProviderFreshness` | `(required: ProviderQuorum, maximum_age: DurationMillis)` |
| `ReplicatedProviderPolicy` | `(providers: sequence<ProviderDescriptor, 16>, sufficient_threshold, preferred_replication, maximum_evidence_age, rotation_rule)` |
| `ProviderPolicy` | `(protocol_version, policy_version, mode, extensions)` |
| `ControllerThreshold` | `(selector, required_weight)` |
| `GuardianThreshold` | `(guardian_set_root, guardian_count: u16, total_weight: u64, required_weight)` |
| `RecoveryPolicy` | `(protocol_version, policy_version, authority, delay, lifetime, extensions)` |

`account_nonce` is nonzero. Genesis contains one to 64 controllers, sorted by
`ControllerId`, with no repeated identifier or signing key; both policy revisions
must be their genesis revision. The control and controller-recovery thresholds
must be satisfiable by the initial controller set. `DeviceDescriptor` uses three
independent public-key roles: application Ed25519 signing, X25519 agreement, and
Krikos endpoint Ed25519 signing; the three byte strings must be pairwise different.

The closed policy encodings are:

| Registry | Code | Payload |
|---|---:|---|
| `ControllerClass` | 1 | `PersonalDevice` |
|  | 2 | `HardwareSecurityKey` |
|  | 3 | `OfflineRecovery` |
|  | 4 | `GuardianAccount` |
|  | 5 | `Institutional` |
| `ControllerScope` | 1 | empty operation sequence (`AllV1Operations`) |
|  | 2 | nonempty sorted unique operation sequence |
| `ControllerSelector` | 1 | `(none, none)` (`AnyActive`) |
|  | 2 | `(some ControllerIdSet, none)` |
|  | 3 | `(none, some ControllerClassSet)` |
| `FreshnessRequirement` | 1 | `none` (`LatestKnown`) |
|  | 2 | `some ProviderFreshness` |
| `ProviderRotationRule` | 1 | `AccountEventOnly` |
| `ProviderMode` | 1 | `none` (`LocalOnly`) |
|  | 2 | `some ReplicatedProviderPolicy` |
| `RecoveryAuthority` | 1 | `(some ControllerThreshold, none)` |
|  | 2 | `(none, some GuardianThreshold)` |

Control-policy rules are nonempty, sorted uniquely by operation code, and always
default-deny. Explicit controller sets and class sets are nonempty, bounded to 64,
sorted, and duplicate-free. A replicated provider policy has one to 16 provider
descriptors sorted uniquely by self-certifying `ProviderId`; its nonzero quorum
satisfies `sufficient_threshold <= preferred_replication <= provider_count`.
Recovery exposes either a controller threshold or only the blinded guardian-set
root and aggregate count/weights. Guardian identities and individual weights are
not public policy fields. Recovery delay and lifetime are nonzero and
`lifetime > delay`.

### Capabilities and delegation

| Structure | Exact v1 fields |
|---|---|
| `CapabilityNamespace` / `CapabilityAction` | nonempty UTF-8 bytes |
| `ResourceSegment` | nonempty opaque bytes |
| `ResourcePath` | nonempty semantic-order sequence of `ResourceSegment` |
| `ResourceSelector` | `(code: u16, path: ResourcePath)` |
| `CapabilityConstraint` | `(code: u16, value: u64)` |
| `DelegationPermission` | `(code: u16, remaining_depth: u8)` |
| `CapabilityGrant` | `(protocol_version, namespace, action, resource, constraints, delegation, expires_at, extensions)` |
| `AuthorizationContext` | `(account_id, epoch, checkpoint_id)` |
| `CapabilityRoot` | `(authorization_context, holder, grant, extensions)` |
| `DelegationBody` | `(protocol_version, parent_grant_id, child_grant, issuer, subject, authorization_context, issued_at, nonce: [u8; 16], extensions)` |
| `SignedDelegation` | `(body, signature)` |
| `DelegationChain` | `(root, links)` |

| Registry | Code | Meaning |
|---|---:|---|
| `ResourceSelector` | 1 | exact complete path |
|  | 2 | complete-segment prefix |
| `CapabilityConstraint` | 1 | account epoch at least `value` |
|  | 2 | account epoch at most `value` |
|  | 3 | valid from Unix millisecond `value` |
| `DelegationPermission` | 1 | not delegable; depth must be zero |
|  | 2 | delegable; depth is 1 through 8 |

Namespace and action are each at most 128 UTF-8 bytes. A resource selector is at
most 1,024 canonical bytes and contains at most 64 nonempty segments. Constraints
are sorted uniquely by code, conjunctive, and limited to 32. A delegation chain
contains one to eight links in parent-to-child semantic order, stays within one
account context, contains no device/grant/delegation cycle, and every child must
strictly narrow its parent in resource, constraints, expiration, or remaining
delegation depth without changing namespace or action.

### Devices, application events, and group-key wraps

| Structure | Exact v1 fields |
|---|---|
| `BlindedMetadataCommitment` | `[u8; 32]` |
| `DeviceAuthorization` | `(protocol_version, device_id, descriptor, device_class, metadata_commitment, capabilities, authorization_epoch, extensions)` |
| `DeviceAuthorizationUpdate` | `(protocol_version, device_id, device_class, capabilities, authorization_epoch, extensions)` |
| `DeviceMetadataUpdate` | `(protocol_version, device_id, metadata_commitment, extensions)` |
| `DeviceUpdate` | `(code: u16, authorization-or-metadata payload)` |
| `SuspendDevice` / `ReinstateDevice` | `(protocol_version, device_id, extensions)` |
| `RevokeDevice` | `(protocol_version, device_id, reason_code, extensions)` |
| `RotateDeviceKeys` | `(protocol_version, old_device_id, new_authorization, extensions)` |
| `ApplicationEventCounter` | `u64` |
| `ApplicationEventBody` | `(protocol_version, account_id, application_id, device_id, account_epoch, checkpoint_id, local_counter, payload, extensions)` |
| `SignedApplicationEvent` | `(body, signature)` |
| `AgreementKeyId` | `Digest` of `(recipient_device_id, recipient_agreement_key)` under `KRIKOS-ID/agreement-key/v1` |
| `KeyWrapNonce` | `[u8; 24]` |
| `GroupKeyWrapHeader` | `(protocol_version, crypto_suite_id, account_id, application_id, group_id, authorizing_account_epoch, group_key_epoch, recipient_device_id, recipient_agreement_key_id, ephemeral_public_key, nonce, extensions)` |
| `WrappedGroupKey` | `(header, ciphertext, extensions)` |
| `RecipientKeyWraps` | nonempty recipient-ordered sequence of `WrappedGroupKey` |

| Registry | Code | Meaning |
|---|---:|---|
| `DeviceClass` | 1 | `GeneralPurpose` |
|  | 2 | `HardwareBacked` |
|  | 3 | `ApplicationOnly` |
|  | 4 | `Service` |
| `DeviceUpdate` | 1 | authorization-changing replacement |
|  | 2 | metadata-commitment-only replacement |

A device authorization binds `device_id` to the exact `DeviceDescriptor` and
contains at most 128 capability grants sorted uniquely by `CapabilityGrantId`.
An authorization update replaces the complete class/capability set and advances
security authority; a metadata update only changes or clears the blinded private
metadata commitment. The public 32-byte commitment must contain at least eight
distinct byte values, but that structural check is not proof of entropy: producers
must blind private metadata with fresh randomness. Rotation atomically revokes an
old `DeviceId` and installs a different complete authorization.

`ApplicationEventCounter` orders one device's events for one application only; it
does not claim a cross-device total order. An application event signs the exact
account epoch and checkpoint used for authorization. Its opaque payload is at most
1 MiB minus 4 KiB, while the complete signed envelope is at most 1 MiB.
`ApplicationEventId` derives from the complete signed envelope, including the
device signature. The application signature message is exactly
`b"KRIKOS-ID/application-event-signature/v1\0" || canonical(ApplicationEventBody)`.

The fixed v1 key-wrap suite is X25519, BLAKE3 derive-key, and
XChaCha20-Poly1305. Its 32-byte AEAD key is exactly
`BLAKE3 derive_key("KRIKOS-ID/group-key-wrap-key/v1", shared_secret ||
ephemeral_public_key || recipient_public_key)`, where all three inputs are their
raw 32-byte X25519 values in that order. AEAD associated data is the canonical
encoding of `(GroupKeyWrapHeader, WrappedGroupKey.extensions)`, binding both the
header and preserved noncritical outer extensions. The nonce is exactly 24 bytes,
the plaintext group key is exactly 32 bytes, and the ciphertext plus tag is
therefore exactly 48 bytes. Both the ephemeral X25519 secret and nonce must be
generated freshly and independently for every recipient; all-zero/non-contributory
DH output is rejected. A recipient set contains at most 1,024 wraps and at most
1 MiB total, is sorted uniquely by `DeviceId`, shares one distribution context,
and does not reuse an ephemeral public key or nonce. Rotation starts from a
validated post-state snapshot binding the exact account revision and complete
application-group membership; output recipients must match that snapshot exactly.
Snapshot construction accepts `Active`, `MigrationPending`, and `MigrationDual`
account projections. The two migration phases are intentionally eligible because
v1 controller-signature migration does not change the fixed X25519 key-wrap suite.
Recovery-pending, forked, upgraded/read-only, and retired projections are rejected
with their typed lifecycle errors before recipient processing.

`rotate_group_key_with_rng` in the default core, and the `os-rng` convenience function
`rotate_group_key`, return a local, non-wire `GroupKeyRotation` artifact containing the fixed
suite, exact `AccountRevision` (including the complete sorted head set),
account/application/group identifiers, account and group-key epochs, exact expected recipient IDs,
and `RecipientKeyWraps`. Persistence must accept this complete artifact, call
`validate_current_revision` immediately before writing, and atomically compare-and-swap against
the artifact revision. Persisting bare recipient wraps is outside the safety boundary: a stale or
forked rotation must never be committed.

### Provider evidence, admission, and checkpoints

| Structure | Exact v1 fields |
|---|---|
| `EventPredecessors` | `(code: u16, genesis_anchor-or-event-heads)` |
| `AccountOperation` | `(operation_code: u16, typed operation payload)` |
| `EventBody` | `(protocol_version, account_id, sequence, resulting_epoch, predecessors, operation, created_at, nonce: [u8; 16], extensions)` |
| `AuthorizedEvent` | `(body, admission_evidence, approvals)` |
| `KeyedSignature` | `(crypto_suite_id, controller_key_id, signature)` |
| `EventIntentApprovalBody` | `(protocol_version, controller_id, proposal_id, extensions)` |
| `SignedEventIntentApproval` | `(body, signatures: sequence<KeyedSignature, 2>)` |
| `EventIntentApprovals` | sorted nonempty sequence of at most 64 signed intent approvals |
| `ProviderLogEntryBody` | `(protocol_version, provider_id, log_id, account_id, subject, observed_at, extensions)` |
| `ProviderHeadBody` | `(protocol_version, provider_id, log_id, key_version, tree_size, tree_root, observed_at, extensions)` |
| `SignedProviderHead` | `(body, signature)` |
| `InclusionReceipt` | `(entry, leaf_index, audit_path, signed_head)` |
| `ProviderReceipts` | sequence of at most 16 inclusion receipts |
| `FreshnessEvidence` | `(code: u16, local-or-provider payload)` |
| `DelayEvidence` | `(code: u16, none-or-provider payload)` |
| `AdmissionEvidence` | `(protocol_version, proposal_id, preceding_checkpoint, provider_policy_id, freshness, delay, extensions)` |
| `ControllerApprovalBody` | `(protocol_version, controller_id, subject, extensions)` |
| `SignedControllerApproval` | `(body, signatures: sequence<KeyedSignature, 2>)` |
| `ControllerApprovals` | sorted nonempty sequence of at most 64 signed controller approvals |
| `CheckpointBody` | `(protocol_version, account_id, account_epoch, sequence, event_head, state_root, authorized_set_root, revoked_set_root, control_policy_id, recovery_policy_id, provider_policy_id, crypto_state_id, lifecycle, issued_at, extensions)` |
| `CheckpointAuthorization` | `(code: u16, controller-approvals-or-transition payload)` |
| `TransitionCheckpointWitness` | `(protocol_version, transition_kind, event_id, event_authorization_id)` |
| `SignedCheckpoint` | `(body, authorization)` |

| Registry | Code | Payload |
|---|---:|---|
| `EventPredecessors` | 1 | `GenesisAnchor` |
|  | 2 | nonempty sorted unique `EventId` sequence (at most 16) |
| `ProviderLogSubject` | 1 | `CheckpointId` |
|  | 2 | `ProposalId` event intent |
| `FreshnessEvidence` | 1 | `CheckpointId` known locally |
|  | 2 | `(checkpoint_id, provider_policy_id, receipts)` |
| `DelayEvidence` | 0 | unit / no-delay policy |
|  | 1 | `(provider_policy_id, required_quorum, observed_at, intent_approvals, receipts)` |
| controller approval subject | 1 | `(event_id, admission_evidence_id)` |
|  | 2 | `CheckpointId` |
| `CheckpointAuthorization` | 1 | `ControllerApprovals` over the exact `CheckpointId` |
|  | 2 | typed `TransitionCheckpointWitness` derived from `FinalizeRecovery` or `RetireAccount` |
| checkpoint transition kind | 1 | `FinalizeRecovery` |
|  | 2 | `RetireAccount` |
| `AccountLifecycle` | 1 | `Active` |
|  | 2 | `RecoveryPending` |
|  | 3 | `MigrationPending` |
|  | 4 | `MigrationDual` |
|  | 5 | `UpgradePending` |
|  | 6 | `Retired` |

`AccountOperation` uses the authoritative codes 1 through 22 in the table above
and decodes each code directly into its named typed payload; it never embeds an
opaque payload byte string. Code 23 and every unknown code fail closed. `EventBody`
is at most 256 KiB, has a nonzero nonce and a sequence greater than zero, and uses
the genesis anchor only at sequence 1. Ordinary later events name exactly one
existing event head. `ResolveFork` is the only v1 operation that names multiple
predecessor heads, and that set must exactly match its complete fork descriptor.
An `AuthorizedEvent` requires its admission evidence to name the body's exact
`ProposalId`. Its final `EventId` commits both that body and the exact
`AdmissionEvidenceId`, and every final approval names the pair
`(EventId, AdmissionEvidenceId)`. The complete authorized envelope is at most 256 KiB.

A provider receipt's entry and signed head must name the same provider and log,
and `leaf_index < tree_size`; its bottom-up Merkle audit path has at most 64
hashes. A receipt set is sorted uniquely by provider and every receipt names the
same account and subject. Freshness receipts log the exact preceding
`CheckpointId`; delay receipts log the exact `ProposalId` whose threshold intent
approvals they accompany. The delay anchor is the q-th earliest signed
`observed_at` among the required distinct configured providers, never a caller's
local clock or the latest/most favorable provider.

### Intent and admission-bound identifiers

All protocol-derived identifiers use
`BLAKE3-256(domain_ascii || 0x00 || canonical_body_bytes)`. In particular:

```text
ProposalId   = H("KRIKOS-ID/account-proposal/v1",   canonical(EventBody))
AdmissionEvidenceId = H("KRIKOS-ID/admission-evidence/v1", canonical(AdmissionEvidence))
EventId      = H("KRIKOS-ID/account-event/v1",      canonical((EventBody, AdmissionEvidenceId)))
EventAuthorizationId = H("KRIKOS-ID/event-authorization/v1", canonical(AuthorizedEvent))
CheckpointId = H("KRIKOS-ID/account-checkpoint/v1", canonical(CheckpointBody))
```

`ProposalId` is the circularity-free body intent named by proposal approvals and
provider delay receipts. Admission evidence therefore names `ProposalId` but does not
contain the final `EventId`. Once that evidence is fixed, its identifier and the body
derive `EventId`, and final controller approvals bind both `EventId` and
`AdmissionEvidenceId`. Different valid admissions for one body are thus detectable
same-predecessor histories, while additional approvals for the same admission merge
without changing `EventId`. `CheckpointId` excludes
`CheckpointAuthorization`, so direct controller approvals can merge and a
transition-derived witness can be attached without changing the checkpoint's
identity. A transition witness names the exact retained authorized-event envelope,
must reference the checkpoint event head, and is limited to recovery finalization or
terminal account retirement. This dependency order is acyclic:
`EventBody -> ProposalId -> AdmissionEvidence -> AdmissionEvidenceId -> EventId -> final approvals`.

Checkpoint publication is an availability-plane action, so v1 does not accept reserved account
operation code 23. Direct checkpoint authorization instead reuses the current
`ChangeProviderPolicy` rule's selector, controller scopes, and weighted threshold. This binds
publication authority to the policy that selects the transparency providers and prevents a
multi-controller account from silently becoming a one-signer checkpoint policy. A default-deny
account that omits that rule cannot create a directly authorized checkpoint; destructive recovery
and retirement checkpoints use their retained transition witness instead.

### Recovery and fork resolution

| Structure | Exact v1 fields |
|---|---|
| `RecoveryAuthorityPlan` | `(protocol_version, account_id, prior_checkpoint_id, prior_event_head, recovery_policy_id, recovery_policy_version, nonce: [u8; 32], replacement_controllers, replacement_control_policy, replacement_recovery_policy, retained_devices, expires_at, extensions)` |
| `RecoveryProposal` | `(protocol_version, plan, extensions)` |
| `GuardianGrant` | `(protocol_version, protected_account_id, recovery_policy_id, guardian_account_id, guardian_signing_key, weight, valid_from_epoch, expires_at, extensions)` |
| `GuardianGrantOpening` | `(protocol_version, guardian_grant_id, grant, blinding: [u8; 32], guardian_set_root, leaf_index, audit_path, extensions)` |
| `GuardianApprovalBody` | `(protocol_version, protected_account_id, recovery_id, decision, guardian_grant_id, account_epoch, approved_at, extensions)` |
| `SignedGuardianApproval` | `(body, opening, signature)` |
| `GuardianApprovalSet` | sorted nonempty sequence of at most 16 signed guardian approvals |
| `RecoveryThresholdEvidence` | `(code: u16, recovery-policy payload)` |
| code 13 `BeginRecovery` | `(protocol_version, expected_pending_recovery, recovery_id, proposal, threshold_evidence, extensions)` |
| code 14 `VetoRecovery` | `(protocol_version, expected_pending_recovery, pre_recovery_control_policy_id, freshness, extensions)` |
| code 15 `CancelRecovery` | `(protocol_version, expected_pending_recovery, threshold_evidence, freshness, extensions)` |
| `RecoveryDelayAnchor` | `(protocol_version, account_id, recovery_id, begin_proposal_id, provider_policy_id, required_quorum, observed_at, receipts, extensions)` |
| code 16 `FinalizeRecovery` | `(protocol_version, expected_pending_recovery, delay_anchor, finalized_at, extensions)` |
| `ForkDescriptor` | `(protocol_version, account_id, common_ancestor: ForkCommonAncestor, heads, extensions)` |
| code 17 `ResolveFork` | `(protocol_version, fork_id, fork, selected_head, revoked_controllers, revoked_devices, extensions)` |

The `GuardianGrant` and `GuardianGrantOpening` rows describe their private nested witness
encoding inside `SignedGuardianApproval`. The raw grant and opening types deliberately do not
implement `CanonicalWire` or `Clone` and cannot be exported as standalone public wire objects.

| Registry | Code | Payload or meaning |
|---|---:|---|
| `GuardianApprovalDecision` | 1 | begin the exact recovery proposal |
|  | 2 | cancel the exact pending recovery |
| `RecoveryThresholdEvidence` | 1 | `(recovery_policy_id, recovery_policy_version)`; the containing event's controller approvals complete the threshold evidence |
|  | 2 | `(recovery_policy_id, recovery_policy_version, guardian_approvals)` |
| `ForkCommonAncestor` | 1 | genesis anchor for a fork between first events |
|  | 2 | ordinary event ID shared by all branches |

```text
RecoveryId      = H("KRIKOS-ID/recovery/v1",       canonical(RecoveryProposal))
GuardianGrantId = H("KRIKOS-ID/guardian-grant/v1", canonical((protocol_version, GuardianGrant, blinding)))
ForkId          = H("KRIKOS-ID/fork/v1",           canonical((common_ancestor, sorted_heads)))
```

`RecoveryId` is body-only: later guardian signatures, threshold evidence, delay
receipts, and finalization do not change it. A guardian grant stays private until
its approval carries an opening. The public recovery policy commits only to the
aggregate guardian-set root, count, and threshold. An opening has a nonzero
32-byte blinding value, a leaf index below 16, and a Merkle path of at most 64
hashes; the projection layer verifies membership cryptographically. Guardian
approval sets contain 1 through 16 entries sorted uniquely by `GuardianGrantId`.
All entries bind the same account, recovery, decision, guardian-set root, and
policy, and must use distinct guardian accounts, signing keys, and leaf indexes.
Their checked aggregate weight must satisfy the committed policy threshold.

There is exactly one durable pending-recovery slot. `BeginRecovery` encodes an
explicit `expected_pending_recovery` option that must be `None`, so concurrent
begins fail unless the authoritative slot is vacant. The operational limit of
eight recovery attempts applies only to local, pre-admission work. A begin names
the exact body-derived recovery and the pre-recovery policy version. A veto is
authorized under the pre-recovery control policy; cancellation must meet the same
recovery-policy threshold as begin, with guardian decisions changed to `Cancel`.

Finalization uses provider receipts for the exact begin `ProposalId`. Its
`observed_at` is deterministically the q-th earliest signed observation from the
required distinct providers. The projection layer enforces the committed delay,
lifetime, and plan expiry before atomically installing the replacement
controllers and policies. The plan explicitly retains at most 1,024 sorted
devices; every other active device is revoked. Replacement controllers are a
nonempty, sorted set of at most 64 with unique identifiers and signing keys, and
the replacement recovery-policy version cannot roll back.

A fork descriptor contains the complete sorted set of 2 through 16 known heads,
and its common ancestor cannot also be a head. V1 resolution selects one existing
declared branch and adds only sorted, unique controller and device revocations;
it cannot synthesize new authority. The embedded `ForkId` is recomputed from the
common ancestor and complete head set. Every recovery and fork object in this
section is bounded to 256 KiB.

### Cryptographic migration, upgrade, and retirement

| Structure | Exact v1 fields |
|---|---|
| `CryptoSuiteDescriptor` | `(version, suite_code, hash_algorithm_code, signature_algorithm_code, agreement_algorithm_code, kdf_algorithm_code, aead_algorithm_code, extensions)` |
| `ControllerKeyBinding` | `(controller_id, old_key_id, new_signing_key, extensions)` |
| `CryptoMigrationBody` | `(version, account_id, from_suite_id, to_suite, bindings, successor_account_id, nonce: [u8; 32], extensions)` |
| `ControllerKeyBindingProof` | `(migration_id, controller_id, old_key_signature, new_key_signature)` |
| `ControllerKeyBindingProofSet` | sorted nonempty sequence of at most 64 proofs |
| code 18 `BeginCryptoMigration` | `(version, migration, proofs, extensions)` |
| code 19 `ActivateCryptoMigration` | `(version, migration_id, begin_event_id, extensions)` |
| code 20 `RetireCryptoSuite` | `(version, migration_id, mode, phase_event_id, successor_account_id, extensions)` |
| code 21 `ProtocolUpgrade` | `(version, from_major, to_major, specification_digest, compatibility, successor_account_id, extensions)` |
| code 22 `RetireAccount` | `(version, successor_account_id, reason_code, extensions)` |

| Registry | Code | Meaning |
|---|---:|---|
| `RetireCryptoSuiteMode` | 1 | abort an unactivated candidate; successor must be absent |
|  | 2 | retire the previous suite after dual activation |
| `UpgradeCompatibility` | 1 | clients that cannot validate the new major are read-only |

At most two controller-signature suites are active during migration. Begin carries
a complete, sorted old/new key binding and cross-signature proof for every
controller; Activate enters the dual-signature phase. Code 20 is recoverable in
both directions: mode 1 aborts a failed candidate, while mode 2 retires the
previous suite after successful dual operation. A v1 in-place migration may
change only the controller signature suite; it retains BLAKE3-256, X25519,
BLAKE3 derive-key, and XChaCha20-Poly1305. A digest-breaking suite requires a
distinct successor `AccountId`. Protocol upgrade requires `to_major > from_major`;
account retirement is terminal.

## Protocol resource bounds

| Resource | v1 maximum |
|---|---:|
| Canonical protocol object | 1 MiB |
| Account-control event or migration payload | 256 KiB |
| Controllers / policy rules / authorization signatures | 64 each |
| Simultaneously accepted controller suites | 2 |
| Future-algorithm public key / signature | 4 KiB / 8 KiB |
| Devices retained including tombstones | 1,024 |
| Capabilities per device / constraints per capability | 128 / 32 |
| Delegation depth | 8 |
| Transparency providers / private recovery guardians | 16 / 16 |
| Merkle proof path / extension fields | 64 hashes / 32 fields |
| One extension value / aggregate extension values | 16 KiB / 64 KiB |
| Fork heads / encoded fork evidence | 16 / 4 MiB |
| Capability name / resource selector | 128 bytes / 1,024 bytes |
| Private metadata envelope | 256 KiB |
| Complete application event / application payload | 1 MiB / 1 MiB minus 4 KiB |
| Wrapped group key | 4 KiB |
| Pending proposals / live pairing tickets / recovery attempts | 128 / 64 / 8 |
| Sync frame / session | 4 MiB / 16 MiB |

`identity_schema` fuzzes the exported sealed composite and closed-enum account-schema
decoders listed in this reference. The first byte selects a schema, the remaining
input is rejected above 1 MiB, and every accepted value must re-encode
byte-for-byte identically. CI runs this target under the same explicit time,
memory, input, and artifact limits as the other reviewed fuzz targets.

`identity_capability` drives the pure capability evaluator with bounded direct and
one-to-eight-link delegated proofs. Its 64-byte control input varies lifecycle,
historical grant possession, authenticated context lineage and timestamps,
constraints, revocations, signatures, request scope, and stale authorization
contexts without constructing an unbounded protocol collection.

`identity_pairing` fuzzes the bounded canonical pairing ticket, complete transcript,
four-role possession proof, consumed authorization proposal, presence challenge, and
presence proof decoders. Its dispatch byte is followed by at most 256 KiB, and every
accepted value must reproduce the input byte-for-byte.
