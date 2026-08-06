# Iroh Identity: Long-Term Distributed Multi-Device Identity Design

**Status:** Proposed architecture<br>
**Version:** 0.1<br>
**Date:** 2026-08-05<br>
**Target ecosystem:** Rust and Iroh-based local-first, peer-to-peer applications

---

## 1. Executive Summary

Iroh Identity is a distributed identity and authorization layer designed to let one human or organization operate one stable account across multiple independently secured devices.

The account is not represented by a private key copied to every device. Instead:

- the account has a stable, self-certifying identifier;
- every device generates and retains its own private keys;
- devices receive explicit, signed account authorizations;
- account-control changes form a verifiable per-account event log;
- current account checkpoints and revocations are replicated to independent transparency providers;
- social relationships remain private and are used only for discovery, verification, and explicitly configured recovery;
- application permissions are expressed as scoped capabilities;
- Iroh provides authenticated connectivity, NAT traversal, relay fallback, and replication transport;
- no blockchain, token, proof of work, or proof of stake is required;
- optional public-ledger anchoring may be added without making the account dependent on a particular chain.

The central design rule is:

> The signed account state determines authorization. The social graph helps users decide whom to trust. Replicated transparency state makes revocations discoverable while personal devices are offline.

This design deliberately separates five concerns:

1. **Account identity** — the stable identity that survives device replacement.
2. **Device identity** — independently generated keys for each physical or logical device.
3. **Account control** — policies and signed operations that add, restrict, rotate, or revoke devices.
4. **Availability and freshness** — mechanisms by which online verifiers discover recent account state.
5. **Application authorization** — capabilities granted to devices and applications without exposing the account-control authority.

---

## 2. Problem Statement

A distributed application needs to support one account on several devices while satisfying conflicting requirements:

- Devices must work offline.
- A lost or compromised device must be revocable.
- Remaining devices must continue to work after a revocation.
- An account must survive replacement of every ordinary device key.
- A service operator must not be able to impersonate the user.
- A verifier must be able to determine which account state it relied upon.
- Social recovery must not turn ordinary friendship into implicit account authority.
- Revocation information must remain available even if all legitimate personal devices are offline.
- The system must not require a globally replicated public history of personal relationships or device metadata.
- Applications such as games, databases, messaging, and collaborative tools must be able to reuse the identity layer.

The core distributed-systems limitation is unavoidable:

> A verifier that is offline, or unable to reach any source of newer account state, cannot prove that no newer revocation exists.

The protocol must therefore expose explicit freshness semantics rather than claiming absolute current knowledge.

---

## 3. Goals

### 3.1 Functional goals

- One stable account across any number of devices.
- Independent, hardware-backed device keys where available.
- Device addition, restriction, rotation, suspension, and revocation.
- Offline-verifiable account state.
- Deterministic state derivation from signed operations.
- Threshold authorization for sensitive account changes.
- Secure device-to-device pairing over Iroh.
- Explicit recovery policies, including offline and social recovery.
- Scoped application capabilities.
- Cross-application reuse.
- Optional human-readable names without making names the cryptographic identity.
- Durable revocation publication while personal devices are offline.
- Privacy-preserving social relationships and recovery configuration.
- Protocol versioning and cryptographic agility.

### 3.2 Security goals

- Compromise of one ordinary device must not automatically compromise the whole account.
- An infrastructure provider must not be able to forge account events.
- A revoked device must be unable to obtain future application encryption keys.
- Forks and conflicting account-control histories must be detectable.
- Sensitive operations must be attributable to the authorizing keys.
- Recovery must be explicit, auditable, and policy constrained.
- A social contact must not gain authority through transitive trust.
- Rollback and stale-state attacks must be detectable when newer signed state is available.
- Log-provider equivocation must be detectable through signed checkpoints and gossip.

### 3.3 Non-goals

The initial protocol does not attempt to provide:

- proof that a person has a particular civil identity;
- a universal reputation score;
- global ordering of all application events;
- cryptocurrency, token economics, or decentralized finance;
- guaranteed real-time revocation for completely disconnected verifiers;
- deletion of data already copied by a device before revocation;
- automatic merging of conflicting security-policy changes;
- anonymity against a global network observer without additional privacy transports;
- a globally public social graph.

---

## 4. Design Principles

### 4.1 The account is not a device

An Iroh `EndpointId` is useful as a transport-level device identity, but it must not be the long-lived account identity. Devices are replaceable; accounts are durable.

### 4.2 Never copy one ordinary private key to every device

Each device generates independent signing and key-agreement keys. Exporting one shared account key creates catastrophic compromise and weak revocation semantics.

### 4.3 Authorization is explicit

A device controls only the capabilities granted by a signed authorization. No authority is inferred from proximity, friendship, possession of encrypted data, or previous activity.

### 4.4 Security state is append-only and auditable

Account-control changes are immutable events linked by hashes. Current state is a deterministic projection of verified history or a trusted checkpoint plus subsequent events.

### 4.5 Availability is not authority

Relays, mirrors, transparency logs, and storage providers may distribute signed state but cannot create valid account state.

### 4.6 Social trust is contextual and non-transitive by default

“Known person,” “verified in person,” “recovery guardian,” and “application moderator” are separate claims. Alice trusting Bob does not imply that Alice trusts Carol because Bob trusts Carol.

### 4.7 Freshness is policy dependent

An established offline board game may accept older known state. Adding an account controller should require current state and stronger authorization.

### 4.8 Privacy by minimization

Public or widely replicated records contain opaque identifiers, hashes, epochs, and proofs—not device names, friend lists, recovery relationships, or application activity.

### 4.9 Cryptographic agility from day one

Serialized keys, signatures, hashes, and key derivation functions include algorithm identifiers. Account identifiers do not depend on one algorithm being safe forever.

---

## 5. High-Level Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                        Stable Account                       │
│  AccountId, policy, epochs, account-control event history  │
└──────────────────────────────┬──────────────────────────────┘
                               │ authorizes
              ┌────────────────┼────────────────┐
              │                │                │
       ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
       │   Device A  │  │   Device B  │  │   Device C  │
       │ unique keys │  │ unique keys │  │   revoked   │
       └──────┬──────┘  └──────┬──────┘  └─────────────┘
              │                │
              └────────┬───────┘
                       │ uses
       ┌───────────────▼────────────────┐
       │ Application-scoped capabilities│
       │ games, DB, messaging, storage  │
       └───────────────┬────────────────┘
                       │ transports and replicates over
       ┌───────────────▼────────────────┐
       │ Iroh endpoints, QUIC, relays,  │
       │ gossip, blobs, optional stores │
       └───────────────┬────────────────┘
                       │ publishes opaque checkpoints to
       ┌───────────────▼────────────────┐
       │ Independent transparency logs │
       │ inclusion proofs + signed heads│
       └────────────────────────────────┘
```

The architecture has four logical planes:

1. **Control plane:** account events, policies, device status, recovery.
2. **Data plane:** application data and application-specific replication.
3. **Availability plane:** account checkpoints, revocations, mirrors, gossip.
4. **Social plane:** private contacts, attestations, introductions, guardians.

---

## 6. Identity Hierarchy

### 6.1 Account identity

An account begins with a canonical genesis record. The stable identifier is derived from that record:

```text
AccountId = multihash(canonical_encode(AccountGenesis))
```

The genesis record contains no secret material.

```rust
pub struct AccountGenesis {
    pub protocol_version: ProtocolVersion,
    pub account_nonce: [u8; 32],
    pub created_at: Timestamp,
    pub hash_algorithm: HashAlgorithm,
    pub initial_policy: ControlPolicy,
    pub initial_controllers: Vec<ControllerDescriptor>,
    pub initial_recovery_policy: RecoveryPolicy,
}
```

Properties:

- `AccountId` is stable across device and controller rotation.
- Two accounts cannot accidentally collide because genesis includes random entropy.
- The genesis record commits to initial governance and recovery policy.
- Human-readable names are aliases, not identities.

### 6.2 Controller identity

Controllers authorize account-control events. A controller may be:

- a trusted personal device;
- a hardware security key;
- an offline recovery key;
- a recovery guardian account;
- a future threshold or institutional controller.

A controller is distinct from an application device. A low-trust game console may be authorized to sign game moves but not control account membership.

### 6.3 Device identity

Each installation generates independent keys:

```rust
pub struct DeviceKeys {
    pub signing: SigningKeyRef,
    pub key_agreement: AgreementKeyRef,
    pub endpoint: IrohSecretKeyRef,
}
```

The associated identifier is derived from the canonical public descriptor:

```text
DeviceId = multihash(canonical_encode(DevicePublicKeys))
```

The Iroh endpoint key may be identical to one transport key in constrained implementations, but the preferred long-term model separates:

- account event signing;
- application event signing;
- encryption/key agreement;
- Iroh transport identity.

This separation reduces cross-protocol risk and permits independent rotation.

### 6.4 Application identity

Applications should derive or request scoped identities rather than expose the account-control key.

Examples:

- game signing key;
- database replica identity;
- messaging-device key;
- anonymous pairwise contact identifier;
- temporary browser-session key.

Pairwise or application-specific identifiers reduce correlation across services.

---

## 7. Cryptographic Key Hierarchy

```text
Account control keys
├── authorize and revoke controllers/devices
├── change policies
└── approve recovery

Device signing keys
├── sign application actions
├── prove possession
└── authenticate device-specific requests

Device agreement keys
└── receive encrypted group/data keys

Iroh endpoint keys
└── authenticate transport endpoints

Application group keys
├── encrypt current shared application state
└── rotate after membership changes

Data encryption keys
└── encrypt objects, records, files, or message epochs

Recovery wrapping keys
└── protect account recovery material and encrypted backups
```

Recommended initial algorithms, subject to security review:

- signatures: Ed25519 or another Iroh-compatible audited signature scheme;
- key agreement: X25519 or a hybrid scheme when post-quantum support matures;
- hashing: BLAKE3 or SHA-256, encoded behind a multihash-style identifier;
- symmetric authenticated encryption: XChaCha20-Poly1305 or AES-256-GCM where hardware support and nonce discipline are appropriate;
- password derivation: Argon2id with versioned parameters;
- canonical serialization: deterministic CBOR or another formally specified canonical encoding.

No algorithm should be assumed permanent. Algorithm changes occur through versioned account events and migration rules.

---

## 8. Account-Control Event Log

### 8.1 Purpose

The per-account event log is the authoritative history for account control. It is not a blockchain and does not require global consensus. It provides ordering only inside one account.

### 8.2 Event envelope

```rust
pub struct AccountEvent {
    pub account_id: AccountId,
    pub protocol_version: ProtocolVersion,
    pub sequence: u64,
    pub epoch: u64,
    pub previous: EventHash,
    pub operation: AccountOperation,
    pub authorization: AuthorizationEvidence,
    pub created_at: Timestamp,
    pub nonce: [u8; 16],
}
```

The event hash is computed over the canonical unsigned envelope and authorization evidence according to the protocol specification.

### 8.3 Event operations

```rust
pub enum AccountOperation {
    AuthorizeDevice(DeviceAuthorization),
    UpdateDevice(DeviceUpdate),
    SuspendDevice { device_id: DeviceId },
    ReinstateDevice { device_id: DeviceId },
    RevokeDevice { device_id: DeviceId, reason_code: Option<u16> },
    RotateDeviceKeys(DeviceKeyRotation),
    AddController(ControllerAuthorization),
    RemoveController { controller_id: ControllerId },
    ChangeControlPolicy(ControlPolicy),
    ChangeRecoveryPolicy(RecoveryPolicy),
    PublishCheckpoint(CheckpointCommitment),
    ResolveFork(ForkResolution),
    UpgradeProtocol(ProtocolUpgrade),
    RetireAccount(AccountRetirement),
}
```

### 8.4 Invariants

A conforming implementation must enforce:

- sequence numbers increase by exactly one on a linear branch;
- `previous` matches the prior event hash;
- the operation satisfies the policy active before the operation;
- epoch changes follow defined operation rules;
- revoked controllers cannot authorize later events;
- an operation cannot silently weaken its own required authorization;
- unknown critical fields cause rejection;
- canonical encoding produces one byte representation;
- duplicate event hashes are idempotent;
- timestamps do not determine authority or ordering.

### 8.5 Epochs

An epoch marks security-relevant membership or key changes. Events such as device revocation, controller changes, recovery, and group-key rotation increment the epoch.

Application events reference the account epoch and checkpoint used during authorization.

```rust
pub struct AuthorizationContext {
    pub account_id: AccountId,
    pub epoch: u64,
    pub checkpoint_hash: CheckpointHash,
}
```

---

## 9. Control Policies and Threshold Authorization

### 9.1 Policy model

```rust
pub struct ControlPolicy {
    pub rules: Vec<PolicyRule>,
    pub default_deny: bool,
}

pub struct PolicyRule {
    pub operation_class: OperationClass,
    pub required_weight: u32,
    pub eligible_controllers: ControllerSelector,
    pub freshness: FreshnessRequirement,
    pub delay: Option<Duration>,
}
```

Controllers may carry weights, classes, and restrictions.

### 9.2 Recommended default policy

| Operation | Suggested authorization |
|---|---|
| Add low-risk application device | 1 trusted controller |
| Add full-control device | 2 controllers or 1 controller + recovery key |
| Revoke application-only device | 1 trusted controller |
| Revoke controller device | 2 controllers, except emergency policy |
| Change recovery policy | 2-of-N controllers plus fresh checkpoint |
| Change control threshold | Existing threshold; cannot self-authorize with weaker proposed rule |
| Recover account | Configured guardian/recovery threshold plus delay |
| Retire account | Highest configured threshold plus delay |

The first release may support a one-controller policy, but the wire format and validator should support multiple signatures from the beginning.

### 9.3 Signature collection

For sensitive operations, a proposal is content-addressed and circulated among controllers. Each controller signs the exact proposal hash. Once the threshold is satisfied, any participant can assemble and publish the final event.

This avoids requiring controllers to be online simultaneously.

---

## 10. Device Authorization and Capabilities

### 10.1 Device authorization record

```rust
pub struct DeviceAuthorization {
    pub device_id: DeviceId,
    pub public_keys: DevicePublicKeys,
    pub label_commitment: Option<Hash>,
    pub device_class: DeviceClass,
    pub capabilities: Vec<CapabilityGrant>,
    pub valid_from_epoch: u64,
    pub expires_at: Option<Timestamp>,
    pub metadata_commitment: Option<Hash>,
}
```

Human-readable device names should remain encrypted local metadata. Public records use opaque identifiers or commitments.

### 10.2 Capability grants

```rust
pub struct CapabilityGrant {
    pub namespace: CapabilityNamespace,
    pub action: String,
    pub resource: ResourceSelector,
    pub constraints: Vec<Constraint>,
    pub delegable: bool,
    pub expires_at: Option<Timestamp>,
}
```

Examples:

```text
iroh.identity/account/read

iroh.identity/device/propose

iroh.identity/device/authorize

iroh.identity/device/revoke

iroh.game/match/sign-move

iroh.database/collection/read

iroh.database/collection/write
```

Capability validation must be deterministic and default-deny.

### 10.3 Delegation

Delegation is opt-in, bounded, and cannot increase authority. A delegated capability must:

- be a strict subset of the parent capability;
- carry a shorter or equal expiration;
- include the complete delegation chain or a compact proof;
- be revocable through the parent authority or account state;
- specify whether further delegation is allowed.

---

## 11. Device Pairing Protocol

### 11.1 Security properties

Pairing must provide:

- mutual authentication;
- proof of possession of the new device keys;
- resistance to QR-ticket replay;
- explicit user confirmation;
- binding to the intended account;
- transcript binding to the Iroh connection;
- expiration and one-time use;
- no transfer of an ordinary account root private key.

### 11.2 Recommended flow

```text
New device                              Existing controller
----------                              -------------------
Generate device keys
Generate ephemeral pairing key
Create short-lived pairing ticket
Display QR / local code       ───────►  Scan ticket
                                        Connect via Iroh
                         ◄────────────  Send authenticated challenge
Sign challenge + transcript   ───────►  Verify key possession
Compare short auth string     ◄──────►  User confirms both devices
                                        Create authorization proposal
Approve/sign if policy allows ◄──────►  Collect required signatures
Receive published event       ◄───────  Publish account event/checkpoint
Sync encrypted app keys       ◄───────  Wrap keys for new device
```

### 11.3 Pairing ticket

```rust
pub struct PairingTicket {
    pub version: u16,
    pub ephemeral_public_key: PublicKey,
    pub proposed_device_id: DeviceId,
    pub iroh_endpoint_hint: EndpointAddr,
    pub random_secret_commitment: Hash,
    pub expires_at: Timestamp,
    pub nonce: [u8; 32],
}
```

A ticket must be invalidated after successful use or expiration.

### 11.4 Out-of-band confirmation

QR scanning is preferred. For remote pairing, show a short authentication string derived from the complete handshake transcript on both devices. The user must compare it through an independent channel.

---

## 12. Revocation Model

### 12.1 Meaning of revocation

Revocation means that, beginning at a defined account event and epoch, the device is no longer authorized for specified capabilities.

Revocation does not:

- erase data previously copied by the device;
- invalidate actions that were validly performed before revocation unless an application defines different rules;
- become globally observable before its signed proof is distributed;
- prove that the physical device is destroyed or offline.

### 12.2 Revocation process

1. Create a `RevokeDevice` proposal.
2. Obtain authorization required by the current control policy.
3. Commit the event to the per-account log.
4. Increment the account epoch.
5. Rotate affected application/group keys.
6. Publish a checkpoint to the configured transparency providers.
7. Obtain the required publication acknowledgements and inclusion proofs.
8. Notify active devices and application peers.
9. Mark the revocation as locally created, published, and sufficiently replicated.

### 12.3 Publication states

The user interface and API must distinguish:

```text
Draft        — not yet authorized
Authorized   — valid account event exists locally
Published    — accepted by at least one transparency provider
Replicated   — configured provider threshold acknowledged it
Observed     — known peers have received the updated state
```

“Revoked” should not be displayed as globally effective when the event exists only on one potentially offline device.

### 12.4 Stale verifier behavior

A verifier validates a device relative to a checkpoint:

```text
Valid at checkpoint C, epoch E, observed at time T
```

It must not claim universally current validity unless freshness policy is satisfied.

---

## 13. Transparency and Availability Layer

### 13.1 Why it is required

If all legitimate personal devices are offline, a revocation remains discoverable only if its signed proof exists on an independently reachable system.

A public cryptocurrency ledger is one way to obtain durable publication, but it introduces fees, public metadata, external governance, and unnecessary global consensus. The preferred design is a purpose-built transparency layer with optional public-chain anchoring.

### 13.2 Transparency provider role

A provider:

- accepts valid account-signed checkpoint submissions;
- stores append-only account checkpoint history;
- returns signed receipts and inclusion proofs;
- publishes signed tree heads;
- serves current and historical proofs;
- participates in gossip or permits auditors to detect equivocation.

A provider cannot:

- add or revoke devices;
- weaken account policy;
- recover an account;
- decrypt private account state;
- forge an account checkpoint.

### 13.3 Checkpoint format

```rust
pub struct AccountCheckpoint {
    pub account_id: AccountId,
    pub epoch: u64,
    pub sequence: u64,
    pub event_head: EventHash,
    pub state_root: Hash,
    pub authorized_set_root: Hash,
    pub revoked_set_root: Hash,
    pub policy_hash: Hash,
    pub issued_at: Timestamp,
    pub authorization: AuthorizationEvidence,
}
```

The checkpoint commits to current state without exposing private labels or relationships.

### 13.4 Provider receipt

```rust
pub struct InclusionReceipt {
    pub provider_id: ProviderId,
    pub account_id: AccountId,
    pub checkpoint_hash: CheckpointHash,
    pub log_index: u64,
    pub tree_size: u64,
    pub tree_root: Hash,
    pub inclusion_proof: Vec<Hash>,
    pub signed_tree_head: SignedTreeHead,
}
```

### 13.5 Replication policy

An account configures multiple providers and a publication threshold, for example:

```text
Providers: 4
Minimum successful publication: 2
Preferred full replication: 3
```

Provider selection may include:

- public community providers;
- application-operated providers;
- a home server;
- a paid private provider;
- a recovery guardian’s server;
- enterprise-operated providers.

### 13.6 Equivocation detection

Providers sign tree heads. Clients and auditors gossip observed heads over Iroh. Two inconsistent signed heads for the same tree size or a missing consistency proof constitute cryptographic evidence of provider misbehavior.

Provider trust is therefore limited to availability and timely inclusion, not correctness of account authorization.

### 13.7 Optional public-chain anchoring

A set of providers may periodically anchor a combined transparency-tree root to Bitcoin, Ethereum, or another durable public ledger.

This is optional and must not be required for normal account operation.

Only an opaque commitment is anchored:

```text
hash(log_set_id || period || aggregate_tree_root)
```

No device list, social relationship, username, or raw account event is published.

---

## 14. Freshness and Online Status

### 14.1 Authorization versus liveness

The protocol distinguishes:

- **Authorized:** valid under a known account checkpoint.
- **Freshly authorized:** valid under state satisfying an operation’s freshness policy.
- **Reachable:** a network path can currently be established.
- **Live:** the device recently proved possession of its private key in a challenge-response exchange.

None implies all the others.

### 14.2 Presence proof

```rust
pub struct PresenceProof {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub challenge: [u8; 32],
    pub session_id: SessionId,
    pub checkpoint_hash: CheckpointHash,
    pub expires_at: Timestamp,
    pub signature: Signature,
}
```

Presence proofs are:

- verifier-generated;
- single-session;
- short-lived;
- bound to a challenge and transcript;
- not reusable as long-term authorization.

### 14.3 Freshness classes

| Class | Example operations | Suggested requirement |
|---|---|---|
| Offline-safe | Continue local game, read cached data | Latest locally known valid state |
| Normal network | Messaging, casual match, sync | Recent provider checkpoint when available |
| Sensitive | Add device, change privileges | Fresh checkpoint plus controller approval |
| Critical | Recovery, lower threshold, retire account | Fresh multi-provider state, threshold, optional delay |

### 14.4 Expiring leases

Short-lived credentials may bound stale authorization risk:

- browser session: hours;
- guest device: hours or days;
- sensitive service credential: minutes or hours;
- personal device membership: long-lived, but checked against fresh checkpoints for sensitive operations.

Long-lived device membership should not require continuous internet access. Short-lived derived credentials can provide stronger online guarantees without disabling the underlying account offline.

---

## 15. Forks, Concurrency, and Conflict Resolution

### 15.1 Fork scenario

Two disconnected controllers may create different events with the same predecessor:

```text
                  ┌─ Authorize tablet
Checkpoint N ─────┤
                  └─ Revoke phone
```

Identity-control forks are not normal CRDT data conflicts. Automatically merging them can grant authority that no valid policy approved.

### 15.2 Prevention

Preferred prevention mechanisms:

- threshold authorization for sensitive operations;
- proposal identifiers and duplicate suppression;
- optional serialized control leases;
- providers rejecting a second successor unless it is an explicit fork-resolution event;
- controller software synchronizing fresh state before signing sensitive changes.

### 15.3 Detection

A fork exists when two validly signed events share the same account, sequence, and predecessor but have different hashes.

Both branches and all signatures are retained as evidence.

### 15.4 Resolution

Fork resolution must itself satisfy a policy defined before the fork. It identifies:

- accepted branch or synthesized state;
- rejected events;
- new epoch;
- required key rotations;
- potentially compromised controllers;
- recovery actions.

No longest-chain, earliest-timestamp, or most-replicated rule determines authority.

### 15.5 Application behavior during unresolved forks

- low-risk applications may continue using the last common checkpoint;
- sensitive operations fail closed;
- affected devices receive an explicit `AccountForked` state;
- providers serve evidence for all observed branches;
- the system does not silently select one branch.

---

## 16. Recovery

### 16.1 Recovery objectives

Recovery must handle:

- lost password or local unlock secret;
- loss of one device;
- loss of all personal devices;
- compromise of one controller;
- inaccessible storage provider;
- migration to replacement devices;
- recovery without granting infrastructure unilateral account control.

### 16.2 Recovery modes

#### Existing-device recovery

An authorized controller approves a new device through the ordinary pairing process.

#### Offline recovery key

A separately stored key or mnemonic-derived key participates in account recovery. It should not normally be available on daily-use devices.

#### Hardware recovery key

One or more hardware authenticators act as controllers with recovery-only capabilities.

#### Social recovery

Explicitly selected guardians authorize a recovery operation according to an account policy, such as 2-of-3 guardians.

Ordinary friendship does not create recovery authority.

### 16.3 Recovery guardian grant

```rust
pub struct GuardianGrant {
    pub guardian_account: AccountId,
    pub guardian_key: PublicKey,
    pub scope: RecoveryScope,
    pub weight: u32,
    pub valid_from_epoch: u64,
    pub expires_at: Option<Timestamp>,
}
```

The private guardian list should be encrypted. Public account state may commit to the recovery policy and guardian set without revealing identities until a recovery proof is used.

### 16.4 Recovery ceremony

1. The replacement device creates a recovery proposal.
2. Guardians verify the claimant using their chosen channels.
3. Each guardian signs the exact proposal.
4. The threshold is reached.
5. A configured security delay begins.
6. Existing devices and providers publish notifications.
7. Any authorized veto path may cancel a fraudulent recovery.
8. A recovery event creates a new control epoch.
9. Old controllers are revoked or explicitly retained.
10. Application and group keys are rotated.
11. The new checkpoint is replicated to transparency providers.

### 16.5 Identity recovery versus data recovery

Recovering account control does not guarantee recovery of encrypted historical data. Data recovery requires at least one of:

- retained encrypted backup plus recovery wrapping key;
- surviving device-wrapped data keys;
- guardian-assisted backup policy;
- application-specific recovery mechanism.

The user interface must clearly distinguish account recovery from data restoration.

---

## 17. Social Graph and Attestations

### 17.1 Private social graph

Contacts, friendships, endorsements, and recovery relationships are stored encrypted in user-controlled application data. They are not part of the public account-control ledger.

### 17.2 Social attestations

```rust
pub struct SocialAttestation {
    pub issuer: AccountId,
    pub subject: AccountId,
    pub claim: SocialClaim,
    pub scope: Option<String>,
    pub issued_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub nonce: [u8; 16],
    pub signature: Signature,
}
```

Example claims:

```rust
pub enum SocialClaim {
    KnowsPerson,
    VerifiedInPerson,
    VerifiedOrganization,
    TrustedForIntroductions,
    RecoveryGuardian,
    ApplicationRole(String),
}
```

### 17.3 Trust rules

- Claims are contextual.
- Claims are non-transitive unless an application explicitly defines bounded transitivity.
- A claim is not account-control authorization.
- Endorsements may expire or be revoked.
- No universal trust score is defined by the identity layer.
- Applications decide how to present and interpret attestations.

### 17.4 Contact verification

Recommended methods:

- QR code exchange;
- safety-number comparison;
- verification over an existing authenticated channel;
- mutual-contact introduction;
- organization-issued credential;
- optional transparency lookup for current account checkpoint.

Trust-on-first-use may be supported, but key or account changes must be surfaced rather than silently accepted.

---

## 18. Human-Readable Names and Discovery

### 18.1 Names are aliases

A username or domain-like name maps to an `AccountId`; it does not replace it.

### 18.2 Naming options

The protocol should permit several resolvers:

- local address book;
- DNS-based records;
- application-specific naming service;
- federated append-only registry;
- Peergos-like global append-only name PKI;
- public blockchain name system;
- direct invitation links.

### 18.3 Resolver interface

```rust
pub trait NameResolver {
    async fn resolve(&self, name: &str) -> Result<Vec<NameClaim>, ResolveError>;
    async fn reverse(&self, account: &AccountId) -> Result<Vec<NameClaim>, ResolveError>;
}
```

Resolvers are untrusted hints unless claims are cryptographically verified.

### 18.4 Name squatting and uniqueness

Global uniqueness requires consensus or a designated authority. The core identity protocol should remain functional without globally unique names.

---

## 19. Application Data and Group-Key Rotation

### 19.1 Separation from identity

Identity state authorizes access but should not store arbitrary application state.

```text
Identity checkpoint
        ↓ validates
Application capability
        ↓ authorizes
Application event or encrypted object
```

### 19.2 Data-key wrapping

An application group key is independently wrapped to each authorized device agreement key.

```rust
pub struct WrappedGroupKey {
    pub group_id: GroupId,
    pub key_epoch: u64,
    pub recipient_device: DeviceId,
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
```

### 19.3 Revocation and forward security

After revocation:

1. create a new application key epoch;
2. generate a fresh group key;
3. wrap it only for remaining authorized devices;
4. use it for future data;
5. optionally re-encrypt sensitive mutable state;
6. retain historical key access according to application policy.

Revocation cannot retract plaintext already learned by the removed device.

### 19.4 Application event envelope

```rust
pub struct SignedApplicationEvent<T> {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub authorization_context: AuthorizationContext,
    pub application: ApplicationId,
    pub event_id: EventId,
    pub payload: T,
    pub signature: Signature,
}
```

Applications define whether later-discovered stale authorization invalidates, quarantines, or merely annotates an event.

---

## 20. Iroh Integration

### 20.1 Endpoint use

Iroh provides secure device-to-device connectivity through cryptographic endpoint identities, QUIC, direct connectivity attempts, and relay fallback. Iroh Identity uses this transport but maintains a separate account identity.

### 20.2 Protocol identifiers

Suggested ALPN/protocol namespaces:

```text
iroh-identity/pairing/1

iroh-identity/sync/1

iroh-identity/proposal/1

iroh-identity/checkpoint/1

iroh-identity/transparency-gossip/1

iroh-identity/recovery/1
```

### 20.3 Data distribution

Potential mapping:

- immutable account events and checkpoint objects: content-addressed blobs;
- event-head announcements and provider-head gossip: gossip protocol;
- direct pairing and proposal signing: dedicated Iroh streams;
- encrypted application state: application-selected replication layer;
- provider discovery: tickets, DNS, configured endpoints, or application bootstrap.

The design must not depend on unstable higher-level crate APIs. Define internal traits around storage, gossip, transport, and discovery.

### 20.4 Transport authentication

A valid Iroh connection proves control of an endpoint key. Account authorization still requires binding that endpoint to a valid device authorization under a sufficiently fresh checkpoint.

```text
Authenticated Iroh endpoint
    + signed device binding
    + valid account state
    = authorized account device connection
```

---

## 21. Protocol Interfaces

### 21.1 Account store

```rust
#[async_trait]
pub trait AccountStore {
    async fn put_event(&self, event: &AccountEvent) -> Result<EventHash, StoreError>;
    async fn get_event(&self, hash: &EventHash) -> Result<Option<AccountEvent>, StoreError>;
    async fn get_head(&self, account: &AccountId) -> Result<Option<EventHash>, StoreError>;
    async fn put_checkpoint(&self, checkpoint: &AccountCheckpoint) -> Result<(), StoreError>;
}
```

### 21.2 Account verifier

```rust
pub trait AccountVerifier {
    fn verify_genesis(&self, genesis: &AccountGenesis) -> Result<AccountId, VerifyError>;
    fn apply_event(&self, state: &AccountState, event: &AccountEvent)
        -> Result<AccountState, VerifyError>;
    fn verify_checkpoint(&self, checkpoint: &AccountCheckpoint)
        -> Result<VerifiedCheckpoint, VerifyError>;
}
```

### 21.3 Transparency client

```rust
#[async_trait]
pub trait TransparencyClient {
    async fn publish(&self, checkpoint: &AccountCheckpoint)
        -> Result<InclusionReceipt, TransparencyError>;
    async fn latest(&self, account: &AccountId)
        -> Result<Option<PublishedCheckpoint>, TransparencyError>;
    async fn consistency_proof(&self, from: u64, to: u64)
        -> Result<ConsistencyProof, TransparencyError>;
}
```

### 21.4 Freshness verifier

```rust
pub trait FreshnessVerifier {
    fn evaluate(
        &self,
        checkpoint: &VerifiedCheckpoint,
        evidence: &[ProviderEvidence],
        requirement: &FreshnessRequirement,
        now: Timestamp,
    ) -> FreshnessDecision;
}
```

### 21.5 Capability verifier

```rust
pub trait CapabilityVerifier {
    fn authorize(
        &self,
        state: &AccountState,
        device: &DeviceId,
        request: &RequestedAction,
        context: &AuthorizationContext,
    ) -> Result<AuthorizationDecision, AuthorizationError>;
}
```

---

## 22. State Machines

### 22.1 Device lifecycle

```text
Proposed
   ↓ authorized
Active
   ├──→ Suspended ───→ Active
   ├──→ Rotating ────→ Active(new keys)
   └──→ Revoked

Revoked is terminal for the old DeviceId.
A replacement device receives a new DeviceId.
```

### 22.2 Account lifecycle

```text
Genesis
  ↓
Active
  ├──→ RecoveryPending ───→ Active(new epoch)
  ├──→ Forked ────────────→ Active(resolved epoch)
  ├──→ UpgradePending ────→ Active(new version)
  └──→ Retired
```

### 22.3 Checkpoint publication lifecycle

```text
Created → Authorized → Submitted → Included → Replicated
                         └────────→ Rejected/Retry
```

---

## 23. Threat Model

### 23.1 Adversaries

- thief holding a lost but still authorized device;
- malware controlling one device;
- malicious or compromised transparency provider;
- colluding minority of recovery guardians;
- malicious application with a limited capability;
- network attacker capable of delay, replay, partition, or selective blocking;
- social attacker attempting fraudulent recovery;
- compromised relay or storage provider;
- malicious controller attempting to fork account state;
- offline verifier with stale but valid state.

### 23.2 Key threats and mitigations

| Threat | Mitigation |
|---|---|
| One device compromised | Independent keys, limited capabilities, threshold control |
| Shared-key exfiltration | Never copy account root key to ordinary devices |
| Lost-device impersonation | Signed revocation, provider publication, key-epoch rotation |
| Stale-state acceptance | Explicit freshness policy, provider proofs, expiring credentials |
| Provider forges revocation | Account signatures required |
| Provider hides revocation | Multiple providers, publication threshold, gossip, leases |
| Provider equivocates | Signed tree heads, consistency proofs, gossip/auditors |
| Pairing MITM | QR secret, transcript binding, short auth string |
| Replay of pairing ticket | Nonce, expiration, one-time consumption |
| Guardian collusion | Threshold, delays, notifications, guardian diversity |
| Social graph leakage | Encrypt contacts and guardian metadata; publish commitments only |
| Forked account control | Threshold authorization, fork detection, explicit resolution |
| Rollback | Monotonic epoch/sequence, stored heads, provider evidence |
| App escalates privilege | Capability default-deny, no upward delegation |
| Old device reads future data | Rotate group keys and stop wrapping to revoked device |

### 23.3 Residual risks

- A compromised device can expose data already accessible to it.
- A verifier unable to obtain fresh state may accept stale authorization according to policy.
- A sufficiently large guardian or controller threshold can seize the account because that is what the configured policy authorizes.
- Metadata leakage remains possible through timing, provider access, and network observation.
- Recovery remains a usability-security tradeoff.

---

## 24. Privacy Model

### 24.1 Public or widely replicated

- `AccountId` or privacy-preserving lookup handle;
- protocol version;
- opaque checkpoint hash;
- epoch and sequence, if not hidden by a more advanced accumulator design;
- signed account-state commitment;
- transparency inclusion and consistency proofs;
- optional name claim.

### 24.2 Private and encrypted

- device labels and physical descriptions;
- friend and contact graph;
- recovery guardian names;
- application memberships;
- device location and network history;
- application data;
- detailed revocation reasons;
- key-wrapping material;
- user profile data.

### 24.3 Correlation reduction

Future versions should support:

- pairwise account pseudonyms;
- private information retrieval for checkpoint lookup;
- oblivious provider queries;
- batched checkpoint publication;
- rotating lookup handles derived from account secrets;
- zero-knowledge proofs of authorization where justified.

These features should not block a secure, auditable initial version.

---

## 25. Comparison of Ledger Options

| Option | Advantages | Disadvantages | Recommendation |
|---|---|---|---|
| Device-only event log | Simple, private, offline capable | Revocations unavailable when devices offline | Insufficient alone |
| Central account server | Easy freshness and ordering | Central control, outage and impersonation risks | Optional compatibility mode only |
| Federated transparency logs | Durable, cheap, auditable, no token | Provider governance and anti-equivocation needed | Primary recommendation |
| Ethereum contract | Global availability and ordering | Fees, public metadata, chain dependency | Optional anchor or specialized integration |
| Bitcoin transactions | Strong durable timestamping | Limited semantics, fees, latency, public metadata | Periodic anchoring only |
| New identity blockchain | Custom semantics | Consensus, validator incentives, governance burden | Do not build initially |
| Social graph only | Human-centered, private when local | No deterministic authorization or revocation | Advisory/recovery layer only |

---

## 26. Lessons from Peergos

Peergos demonstrates several relevant patterns:

- public identity keys and username claims can live in a globally mirrored append-only PKI;
- the PKI can be a source of truth without cryptocurrency;
- friend keys can be remembered locally using trust-on-first-use;
- the social graph can remain encrypted and private;
- capabilities can separate mirror, read, and write access;
- identity can remain portable across storage servers;
- multi-device login can be independent of phone numbers and email addresses.

Iroh Identity should reuse the principles, not copy the complete account model.

The key extension for this design is a first-class per-device authorization registry:

```text
Peergos-inspired global identity transparency
        +
independent device identities and revocation
        +
threshold account-control policy
        +
private social recovery
        +
Iroh-native transport and replication
```

Unlike password-derived multi-device access, each Iroh Identity device is separately identifiable and revocable.

---

## 27. Serialization and Compatibility

### 27.1 Canonical encoding

Every signed structure must have a formally specified canonical byte encoding. JSON must not be used for cryptographic signing.

Recommended requirements:

- deterministic CBOR profile;
- sorted map keys under the selected canonical profile;
- duplicate keys rejected;
- integer width normalization;
- unknown critical extension rejection;
- test vectors for every signed structure;
- domain-separation prefixes for all hashes and signatures.

Example:

```text
IROH-ID/account-event/v1 || canonical_cbor(event_body)
```

### 27.2 Version negotiation

- every structure includes a version;
- Iroh ALPN identifiers include major protocol version;
- minor compatible additions use optional non-critical fields;
- unsupported critical fields fail closed;
- account protocol upgrades require an authorized event;
- old clients can remain read-only when unable to validate new policy.

### 27.3 Cryptographic migration

A migration event binds old and new controller keys and specifies an overlap period. During transition, checkpoints may require signatures under both suites.

---

## 28. Storage and Garbage Collection

### 28.1 Event retention

Security-critical account events should remain retrievable for audit and fork resolution. Checkpoints allow ordinary clients to avoid replaying the complete history.

### 28.2 Checkpoint trust

A client may bootstrap from a checkpoint when it has:

- valid account authorization on the checkpoint;
- provider inclusion evidence if freshness is required;
- a policy-compatible proof linking it to trusted genesis or an earlier trusted checkpoint;
- no known conflicting branch.

### 28.3 Compaction

Compaction may archive old events but must not destroy evidence needed to verify:

- current controller authority;
- device authorization lineage;
- unresolved forks;
- protocol migrations;
- recovery transitions;
- provider equivocation.

---

## 29. Error Model

Suggested stable error classes:

```rust
pub enum IdentityError {
    InvalidEncoding,
    UnsupportedVersion,
    InvalidSignature,
    UnknownAccount,
    InvalidSequence,
    InvalidPreviousHash,
    StaleCheckpoint,
    FreshnessUnavailable,
    InsufficientAuthorization,
    DeviceNotAuthorized,
    DeviceSuspended,
    DeviceRevoked,
    CapabilityDenied,
    AccountForked,
    RecoveryPending,
    ProviderEquivocation,
    ProtocolUpgradeRequired,
}
```

Errors exposed to applications should distinguish:

- invalid proof;
- valid but stale proof;
- current state unavailable;
- explicit revocation;
- policy denial;
- unresolved fork.

This prevents applications from treating network failure as cryptographic invalidity or stale state as current authorization.

---

## 30. API Ergonomics

The library should provide safe high-level APIs and keep raw cryptographic operations internal.

```rust
let account = Identity::create(CreateAccountOptions::secure_default()).await?;

let proposal = account.propose_device(pairing_request).await?;
let approval = account.approve(proposal).await?;
let publication = account.publish(approval).await?;

let decision = verifier
    .verify_device_action(&signed_action, FreshnessClass::Sensitive)
    .await?;
```

Dangerous operations should require explicit types rather than booleans:

```rust
pub enum PublicationRequirement {
    LocalOnly,
    AtLeastOneProvider,
    ProviderThreshold { required: usize },
}
```

Default constructors should select conservative settings.

---

## 31. Testing Strategy

### 31.1 Unit tests

- canonical encoding and decoding;
- signature validation;
- policy evaluation;
- event application;
- capability subset checks;
- epoch transitions;
- expiry and freshness calculations;
- Merkle inclusion and consistency proofs.

### 31.2 Property-based tests

- encode/decode stability;
- arbitrary invalid events never mutate state;
- authority cannot increase through delegation;
- revoked keys never become valid without explicit new authorization under a new identity;
- event replay is idempotent;
- operation ordering obeys invariants.

### 31.3 State-machine tests

Generate long random histories involving:

- device additions and revocations;
- network partitions;
- concurrent proposals;
- controller compromise;
- provider outages;
- recovery attempts;
- protocol upgrades;
- key rotations.

Compare implementation state with a small executable reference model.

### 31.4 Deterministic simulation

Use a deterministic simulation harness for:

- virtual time;
- message delay, duplication, loss, and reordering;
- partitions and healing;
- provider equivocation;
- device crashes and storage loss;
- random but reproducible fault schedules.

### 31.5 Fuzzing

Fuzz:

- all decoders;
- event validators;
- policy and capability evaluators;
- proof parsers;
- pairing transcripts;
- recovery proof assembly;
- checkpoint synchronization.

### 31.6 Interoperability vectors

Publish language-independent test vectors for:

- genesis and account identifiers;
- event hashes;
- signatures;
- checkpoints;
- Merkle proofs;
- pairing transcript derivation;
- capability chains;
- recovery threshold examples.

### 31.7 Formal methods

Model the account-control state machine in TLA+, Alloy, or an equivalent system. Verify at minimum:

- revoked controllers cannot authorize future state;
- policy changes cannot bypass the previous policy;
- forks are detectable;
- threshold requirements are preserved;
- recovery cannot silently retain unauthorized old controllers;
- accepted events have a unique predecessor in non-forked state.

---

## 32. Operational Model for Transparency Providers

### 32.1 Service requirements

- append-only durable storage;
- signed tree-head generation;
- inclusion and consistency proof APIs;
- account lookup with abuse controls;
- monitoring and independent auditing;
- export and mirror support;
- no requirement to access plaintext private state.

### 32.2 Abuse and denial-of-service controls

Because account creation and checkpoint publication can be abused, providers may use:

- rate limits;
- proof of resource or small payment, without protocol-level token dependence;
- application sponsorship;
- invitation quotas;
- anonymous credentials;
- bounded record sizes;
- duplicate suppression.

An anti-abuse mechanism must not become account authority.

### 32.3 Provider discovery and trust

Clients may ship with an initial diverse provider list but users and applications can add or replace providers. Provider policies are committed in account state or local configuration.

---

## 33. Deployment Profiles

### 33.1 Local-only profile

- no transparency providers;
- account state replicated only among devices;
- strongest privacy;
- revocation propagates opportunistically;
- appropriate for isolated local networks and low-risk use.

### 33.2 Consumer profile

- three or more transparency providers;
- 2-provider publication threshold;
- QR pairing;
- one daily controller plus offline recovery key;
- optional social recovery;
- recent checkpoint required for sensitive actions.

### 33.3 High-security profile

- 2-of-3 or 3-of-5 controller policy;
- hardware-backed controllers;
- several independent providers;
- mandatory publication before sensitive changes become effective;
- delayed recovery with notifications;
- short-lived sensitive-operation credentials;
- public-ledger anchoring of provider roots.

### 33.4 Enterprise profile

- organization account with role-based controllers;
- hardware security modules;
- internal and external transparency providers;
- auditable policy templates;
- delegated department capabilities;
- compliance retention and incident-response hooks.

---

## 34. Implementation Roadmap

### Phase 0 — Specification foundation

- canonical data model;
- threat model;
- cryptographic algorithm registry;
- account state-machine reference implementation;
- protocol test vectors;
- storage and transport traits.

### Phase 1 — Core multi-device identity

- stable `AccountId`;
- independent device keys;
- single-controller policy expressed through threshold-capable types;
- event log and deterministic state projection;
- QR pairing over Iroh;
- device capabilities;
- revocation and epoch rotation;
- local synchronization;
- encrypted application-key wrapping.

### Phase 2 — Transparency availability

- checkpoint format;
- provider protocol;
- append-only Merkle log;
- inclusion and consistency proofs;
- multi-provider publication;
- signed-head gossip;
- freshness evaluation API;
- provider audit tooling.

### Phase 3 — Recovery and advanced control

- offline recovery keys;
- hardware-controller support;
- multi-signature/weighted threshold policies;
- social guardians;
- delayed recovery;
- fork resolution;
- secure encrypted backups.

### Phase 4 — Privacy and interoperability

- private lookup mechanisms;
- pairwise identifiers;
- external name resolvers;
- optional public-chain anchoring;
- standardized credential export;
- cross-language implementations.

### Phase 5 — Hardening

- deterministic distributed simulation;
- formal specification/model checking;
- third-party security audit;
- independent provider interoperability;
- incident-response and migration playbooks;
- stable protocol release.

---

## 35. Initial Recommended Product Decisions

For a practical first implementation:

1. Use one account with distinct per-device keys.
2. Make the account identifier the hash of a versioned genesis record.
3. Implement a linear signed event log with explicit fork detection.
4. Use single-controller approval initially, but represent authorization as a signature set and threshold policy.
5. Require QR-based local pairing for full-control devices.
6. Give application devices limited capabilities by default.
7. Implement revocation as an epoch-changing event followed by application-key rotation.
8. Publish checkpoints to at least three configurable transparency providers and consider revocation sufficiently replicated after two acknowledgements.
9. Keep social contacts and guardian identities encrypted.
10. Support an offline recovery key before implementing social recovery.
11. Treat human-readable usernames as optional aliases.
12. Keep public blockchains optional and limited to aggregate transparency-root anchoring.
13. Build strict freshness classes into the verifier API from the first release.
14. Never expose “valid” without identifying the checkpoint/freshness basis.
15. Make all protocol objects deterministic, versioned, bounded, and fuzzable.

---

## 36. Security-Critical Invariants

The implementation and specification must preserve these invariants:

```text
The account is not a device.

No ordinary account private key is copied to every device.

Every device is independently identifiable, authorizable, and revocable.

Every account-control transition is explicitly signed under the previous policy.

The account identity survives complete device and controller rotation.

A provider can distribute account state but cannot create it.

A social relationship grants no account authority unless an explicit policy says so.

Revocation is externally discoverable only after its proof is durably published.

Offline validation is always relative to known state, never claimed as globally current.

Sensitive actions fail closed when required freshness or account consistency is unavailable.

A device removed from an epoch receives no future group keys.

Conflicting security histories are detected and explicitly resolved, never silently merged.
```

---

## 37. Open Design Questions

These questions should be resolved before a stable protocol release:

1. Which canonical serialization profile will be normative?
2. Should provider lookup expose `AccountId`, a rotating handle, or both?
3. Should device authorization non-membership be represented with a sparse Merkle tree, sorted Merkle set, or another accumulator?
4. What provider acknowledgment threshold should consumer defaults use?
5. Which operations increment the account epoch?
6. How should emergency one-controller revocation interact with a normal multi-controller policy?
7. Should account-control proposals use a temporary serialization lease to reduce forks?
8. What maximum clock dependence is acceptable for expiry and recovery delay?
9. How should mobile secure hardware and platform backup behavior be normalized?
10. Which post-quantum migration strategy should be reserved in version 1?
11. How should pairwise identifiers coexist with public usernames?
12. What data-recovery guarantees should the core library provide versus applications?
13. Should transparency providers accept encrypted account-index records for private lookup?
14. Which parts should become an open standard independent of the Rust implementation?

---

## 38. Final Recommendation

Build Iroh Identity as a reusable account-control and authorization protocol with:

```text
Stable self-certifying account identity
+ independent per-device keys
+ signed per-account control log
+ threshold-capable authorization policy
+ explicit device capabilities
+ epoch-based revocation and key rotation
+ replicated transparency checkpoints
+ private social graph and explicit guardians
+ risk-based freshness semantics
+ Iroh-native pairing, synchronization, and gossip
+ optional public-ledger anchoring
```

Do not make Ethereum, Bitcoin, a custom blockchain, a central server, or a friends-of-friends graph the root of account authority.

A Peergos-inspired globally mirrored transparency mechanism is valuable, but Iroh Identity should add first-class device membership, threshold control, and explicit revocation availability. This yields a system that remains local-first and peer-to-peer while providing durable, independently verifiable identity state when personal devices are offline.

---

## 39. References

### Project basis

- `iroh-project-research.md`, project research supplied with this design.

### Iroh

- Iroh documentation: https://docs.iroh.com/

### Peergos

- Peergos overview and goals: https://book.peergos.org/
- Public Key Infrastructure: https://book.peergos.org/security/pki.html
- Usernames and global append-only key chains: https://book.peergos.org/architecture/pki.html
- Multi-device login: https://book.peergos.org/features/multi.html
- Signup and key generation: https://book.peergos.org/dev/signup.html
- Capabilities: https://book.peergos.org/security/capabilities.html
- Writing subspaces: https://book.peergos.org/architecture/writer.html
- Merkle-CHAMP: https://book.peergos.org/architecture/champ.html
- Migration and identity portability: https://book.peergos.org/features/migration.html

### Related architectural patterns

The design also draws on established ideas from capability security, key transparency, certificate-transparency-style append-only logs, threshold authorization, local-first software, authenticated data structures, and deterministic distributed-system testing. These are architectural influences rather than protocol dependencies.
