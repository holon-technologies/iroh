# Krikos Identity security and deployment guide

This document describes the implemented v1 security boundary and the operating choices that an
application or service must make around it. It is normative for deployment behavior, but it does
not declare the protocol production-ready. The foundational, account-control, synchronization, and
network-envelope profile currently documented in [`../README.md`](../README.md) is normative for
that scope. The normative provider-portability appendix and provider database procedures are in
[`provider-operations.md`](provider-operations.md).

## Scope

The guide covers account-control authority, device and endpoint authorization, transparency,
recovery, encrypted backups, privacy-sensitive artifacts, deployment profiles, migrations,
incident response, and release gates. It excludes civil identity, universal reputation,
application-wide ordering, mandatory public chains or tokens, retroactive erasure of plaintext
already learned by a revoked device, and anonymity against a global network observer.

## Goals

- Preserve a stable account identifier while every device, endpoint key, controller, and supported
  controller signature suite can be replaced under explicit prior authority.
- Make offline decisions state-relative and make online freshness claims identify their exact
  checkpoint and provider evidence.
- Detect conflicting account-control histories and require an authorized explicit resolution.
- Keep device labels, relationship labels, guardian membership, application data, and key material
  outside public account state.
- Bound all protocol-controlled decoding, storage pages, queues, proof paths, retries, and network
  sessions before they consume untrusted resources.

## Trust and authority boundaries

The following distinctions are mandatory:

| Component or fact | What it proves | What it never proves |
| --- | --- | --- |
| Krikos endpoint handshake | Control of the authenticated endpoint key on this connection | Account membership or current device authorization |
| Verified account event | A transition satisfied the previous account policy and its exact admission evidence | Global freshness when the verifier is offline |
| Verified checkpoint | A signed summary matches a reconstructed account state | That no newer checkpoint exists unless freshness evidence establishes it |
| Transparency provider | Inclusion, append-only history, and signed observation time for its configured generation | Account authority or permission to create a transition |
| Social attestation or name claim | A bounded, signed hint checked against caller-supplied authority facts | Controller, device, recovery, or capability authority |
| Application capability | Permission for one structural namespace/action/resource request at an exact account basis | Account-control authority or permission outside that request |
| Encrypted backup | Confidentiality and integrity of the enclosed authority bundle and optional application data | Freshness relative to histories learned after the backup checkpoint |

An authenticated application connection therefore requires both the transport endpoint proof and a
verified active device binding at the exact account/checkpoint basis. Pairing and recovery are
bootstrap protocols and use their ceremony-specific authority instead of pretending the proposed
or replacement device is already active.

The pure projection in [`../src/state.rs`](../src/state.rs) owns no clock, network, randomness, or
storage. Callers supply authenticated time/freshness evidence and persist source records and
idempotent effects through [`../src/store.rs`](../src/store.rs) and
[`../src/operations.rs`](../src/operations.rs). Availability mechanisms can delay or deny work but
cannot manufacture an authorization token.

### Network handler boundary

The `net` feature owns the only adapter that can turn a handshake-completed
`krikos::endpoint::Connection` into `AuthenticatedTransportBinding`. It checks the exact pairing
ALPN, obtains the authenticated remote endpoint from the connection, captures the local endpoint ID
from `Connection::local_id()` as recorded by the owning endpoint during handshake completion, and
derives exporter material under a fixed v1 label. The adapter accepts no caller-supplied endpoint ID.
The exporter context contains the exact ALPN and the two endpoint IDs in byte-sorted order, so both
connection directions derive the same binding without making the roles ambiguous. Raw exporter
bytes are zeroized after they enter the crate-private adapter.

Pairing, sync, proposal, checkpoint, transparency-gossip, and recovery each have a concrete exact-
ALPN handler. Sync, proposal, and checkpoint requests carry an account/checkpoint/device tuple and
are dispatched only after the authenticated remote endpoint is active in that exact verified
checkpoint. Pairing instead binds the proposed endpoint in the ticket to the completed handshake;
gossip and guardian recovery retain their own signature/authority checks at the service boundary.
Every request is canonical and length-delimited before decoding, every response is bounded, and
each connection owns one supervised stream task with cancellation and observable failure.

## Threat model

The implementation is designed to fail closed against:

- a compromised, revoked, suspended, unknown, or endpoint-mismatched device;
- a controller that is absent from the authoritative pre-state, outside the operation scope,
  retired, duplicated, below threshold, or using an invalid signature;
- reordered, replayed, concurrent, stale-predecessor, or conflicting account events;
- provider rollback, same-size equivocation, forged inclusion/consistency proofs, an unconfigured
  provider, or evidence from the wrong log/key generation;
- stale, future-dated, unrelated, or threshold-insufficient freshness and recovery observations;
- malformed, non-canonical, oversized, non-minimal, unsupported, or critically extended wire data;
- pairing transcript substitution, endpoint-role key reuse, expired/replayed tickets, one-sided
  confirmation, and transport-exporter substitution;
- capability broadening, delegation cycles, expired or revoked grants, and wrong checkpoint/epoch
  contexts;
- backup corruption, wrong passphrases, altered authenticated context, and authority bundles that
  do not replay to their signed checkpoint.

The model does not defeat a device or controller while it is still legitimately authorized, stop a
malicious provider from refusing service, make revocation instantly visible to a disconnected
verifier, recover plaintext already disclosed before revocation, or hide traffic patterns from a
global observer. Multi-provider policy reduces but does not remove correlated-provider risk.

## Privacy model

Public account state contains self-certifying identifiers, public keys, policy and algorithm
versions, epochs, hashes, blinded commitments, provider descriptors, proofs, and signed
checkpoints. Network peers additionally learn the endpoint keys, ALPN, timing, and address/relay
metadata needed for their connection.

Private or encrypted local storage must retain device labels, detailed revocation reasons, social
relationships, guardian identities and weights, recovery openings, application membership/data,
backup passphrases, blinding secrets, lookup secrets, pairwise-master secrets, agreement secrets,
and group keys. The secret-bearing wrappers in [`../src/privacy.rs`](../src/privacy.rs),
[`../src/recovery.rs`](../src/recovery.rs), and [`../src/key_wrap.rs`](../src/key_wrap.rs) are
redacted, non-`Copy`, and where appropriate non-`Clone`; raw private guardian grants/openings do not
implement the public canonical wire interface.

Blinded or pairwise identifiers limit direct disclosure but do not make low-entropy values safe by
themselves. Producers must use fresh high-entropy blindings. Rotating lookup handles and pairwise
identifiers reduce cross-context correlation; they do not conceal transport metadata or a
relying-party's own observations.

Operational metrics may use aggregate phases, stable error classes, queue saturation, retry counts,
and latency buckets. Account, event, checkpoint, device, controller, guardian, relationship,
lookup-handle, and peer identifiers must not be metric labels. Detailed identifiers belong only in
access-controlled audit records.

## Security-critical invariants

Every integration must preserve all twelve source-design invariants:

1. An account is not an endpoint or device.
2. No ordinary account private key is copied to every device.
3. Every device is independently identifiable, authorizable, and revocable.
4. Every account-control transition is authorized under the exact previous policy and advances
   from its declared predecessor set.
5. Account identity survives complete authorized device and controller rotation.
6. Providers distribute and timestamp authorized material but cannot create account authority.
7. Social relationships grant no account authority unless an explicit, independently verified
   policy consumes them.
8. Revocation is externally discoverable only after its proof is durably published; local
   authorization alone is not reported as observed publication.
9. Offline validation states its known checkpoint and epoch basis and is never presented as
   globally current.
10. Sensitive decisions fail closed when required freshness or account consistency is unavailable.
11. A removed device receives no future application group keys, and protected writes remain
   blocked until the current epoch's required group-key rotation is durably committed.
12. Conflicting security histories are retained as a fork and explicitly resolved, never silently
   merged or selected by arrival time.

Recovery must additionally install its complete declared replacement authority without silently
retaining an omitted old controller or active device. Network frames, history pages, sessions,
queues, proof paths, and retry loops enforce both item and byte/work bounds.

## Deployment profiles

These profiles are application choices layered on the same v1 schemas. They are not constructors
that silently weaken an account's committed policy.

### Local-only

- Use a `ProviderPolicy::local_only` account policy and the memory or `fs-store` account store.
- Replicate source events and checkpoints directly among authorized devices.
- Treat revocation as opportunistic: a disconnected verifier cannot learn a newer event.
- Complete operational checkpoint work at the policy-bound authorized stage without inventing
  provider receipts or observation.
- Suitable for isolated networks or lower-risk data where provider availability is deliberately
  traded for reduced public metadata.

### Consumer

- Commit at least three independently operated providers and require at least two receipts for the
  account's sufficient publication threshold.
- Use QR pairing with two-party SAS confirmation and durable pairing-nonce tombstones.
- Keep a daily controller plus a separately stored offline recovery controller.
- Require recent provider evidence for sensitive changes and rotate protected application keys
  after every authority-affecting revocation or recovery.

### High-security

- Use a weighted 2-of-3 or 3-of-5 controller policy with hardware/offline controller classes.
- Require several independently administered provider generations, threshold publication, later
  observation, and independent auditor comparison before treating sensitive changes as current.
- Use delayed recovery with explicit notifications, short-lived sensitive-operation credentials,
  encrypted offline backups, and tested recovery drills.
- An optional external anchor may commit the opaque hash of one complete verified provider
  compaction manifest. The anchor remains non-authoritative and chain/vendor semantics stay outside
  this crate.

### Enterprise

- Represent organization roles as scoped weighted controllers; keep department/application
  authority in structural capabilities rather than shared account secrets.
- Place controller keys in deployment-specific HSM boundaries and normalize their exact signing
  request display outside this portable crate.
- Operate internal and external providers, retain auditable policy templates and full recovery
  exports, and define incident-retention requirements before irreversible local sealing releases
  superseded provider material.
- Integrate aggregate metrics, access-controlled audit export, backup custody, recovery drills, and
  protocol/crypto migration into the organization's change-management process.

## Recovery and backup operations

Only one authoritative recovery may be pending for an account. A recovery proposal commits its
prior event head/checkpoint, nonce, replacement keys and policy, retained devices/controllers, and
the authority that must approve it. Begin admission derives its delay anchor from authenticated
provider observations; finalize cannot substitute a different admission anchor or guardian set.
Veto uses the pre-recovery control policy. Cancel uses the same pre-recovery recovery authority and,
for guardian recovery, exact provider observation of the cancel intent. Finalize installs the
declared authority atomically, revokes omitted active devices/controllers, and emits group-key
rotation, checkpoint, publication, and notification effects.

Store and operational-journal recovery is retry-based: reopen the account and effect stores,
reconstruct from canonical source records, reclaim an expired bounded lease, and rerun the same
stable effect. Never skip directly to a later phase or relabel a partial publication as observed.
Protected application writes remain blocked until the exact current-revision group-key rotation is
durable.

`BackupEnvelope` encrypts a fully replayable `BackupAuthorityBundle` and optional application bytes
with the fixed serialized Argon2id v1 profile, a fresh salt, independently fresh XChaCha20-Poly1305
wrapping/content nonces, and a fresh random content key. Restoration authenticates and decrypts the
envelope, replays every account event, and verifies the signed checkpoint. Account authority and
optional application-data restoration are reported separately. Wrong passphrases and ciphertext
corruption intentionally share one authentication-failure class.

Backups are checkpoint-relative, not globally current. After restoration, compare against the
configured providers and known peers before sensitive use. Keep at least one offline copy of the
authority material and passphrase under separate custody; the crate does not implement human
custody, cloud synchronization, secret sharing, or automatic rollback selection.

## Migration rules

### Controller cryptography

Cryptographic migration is an account-control state machine, not a configuration toggle. Begin
commits the candidate suite and cross-certified controller bindings; activation enters the dual
suite phase; retirement removes the old suite or aborts an unactivated candidate. During overlap,
account events and checkpoints require the exact active suite set. Retired suites, keys, and epochs
are tombstones and cannot be reused. A future digest break requires the successor-account path;
v1's original `AccountId` remains derived from its original genesis digest.

### Protocol version

Every independently signed or authoritative top-level wire structure names a version; nested
primitives inherit that enclosing version and do not invent a second version field. Every network
protocol names a major version in its ALPN. Unknown major versions and unknown critical extensions
fail closed. An authorized `UpgradeProtocol` transition is required before accepting a new account
protocol. Run old and new network handlers only for an explicitly documented compatibility window;
never reinterpret v1 bytes under a new schema.

### Provider generation

A provider signing-key change creates a new self-certifying provider descriptor, provider ID, log
ID, genesis key version, database path, and account-authorized provider policy. In-place generation
mutation is rejected. Retain and audit the old generation; select service data only from the exact
current account-authorized generation. See [`provider-operations.md`](provider-operations.md) for
export, compaction-manifest, mirror, and corruption procedures.

The current redb provider-generation layout is store version 7 and the normalized redb audit
journal is version 2. They are persistent implementation schemas, not portable interchange. Both
reject legacy versions explicitly and perform no automatic migration. Treat an upgrade as a
backup/restore boundary: preserve the old bytes, produce and verify a complete recovery export with
the old compatible binary, and restore into a new path only through an explicitly reviewed
migration procedure. Provider v7 reruns exact portable-size preflight for a prepared candidate on
reopen; audit v2 performs full contiguous replay on open, then uses a constant-size cursor and
single-record atomic CAS for observations. Active and complete-archive provider stores reconstruct
exact portable accounting on reopen. A locally sealed store instead uses a never-consulted
read-only sentinel because its complete export was deliberately released; every mutation rejects
the sealed state before consulting that sentinel. Never edit either database to bypass those
checks.

## Incident response

### Lost or compromised device

1. Obtain the freshest consistent account basis available under local policy.
2. Authorize `SuspendDevice` when compromise is uncertain, or `RevokeDevice`/`RotateDeviceKeys`
   when removal is required.
3. Commit the event and its mandatory outbox effects atomically.
4. Rotate every affected application group key and keep protected writes blocked until the exact
   current-epoch rotations commit.
5. Build/sign a checkpoint, publish to the committed provider threshold, journal receipts and later
   observation, notify peers, and preserve audit evidence.

### Controller compromise

Use the uncompromised pre-state threshold to remove or rotate the controller and change policy if
needed. If that threshold is unavailable, use the committed recovery policy; do not edit controller
storage out of band. Treat histories authorized by conflicting controller sets as forks and resolve
them only with `ResolveFork` under the common pre-fork policy.

### Provider rollback or equivocation

Stop accepting the suspect generation for freshness. Preserve both signed heads, consistency
proofs, receipts, database/export bytes, and the durable auditor record. Compare with independent
peers/providers. Change provider policy through an authorized account event and start a fresh
generation; never let a longer untrusted log override account authority.

### Store corruption or interrupted operation

Stop writes and preserve the original bytes. Reopen through the validating adapter; corruption must
not become an empty account or log. Restore from a fully verified export/backup into a new path,
compare signed heads/checkpoints, and replay the idempotent operational journal. Do not delete the
old path until incident retention and independent verification are complete.

### Suspected algorithm failure

Freeze sensitive operations if the current policy cannot establish a trustworthy basis. Use the
authorized crypto-migration state machine when the original signature/digest assumptions still
permit authorization. A break that invalidates the original account digest requires a successor
account and application-specific re-binding; v1 does not claim transparent identity continuity in
that case.

## Verification and audit checklist

Before a deployment is promoted, record evidence for:

- `scripts/check-identity-feature-matrix.sh`, including its
  `scripts/tests/check-identity-os-rng-boundary.sh` source/manifest check and no-default dependency
  isolation, plus Rust 1.91 all-target tests and strict Clippy;
- canonical-vector validation, decoder/verifier inventory, and bounded parser/state-machine tests;
- deterministic simulation replay and the repository-owned bounded formal-model command;
- memory and redb reopen/fault matrices for events, checkpoints, recovery, rotations, provider
  generations, receipts, notifications, retries, exports, compaction manifests, and auditors;
- the focused provider portability and persistence commands in
  [`provider-operations.md`](provider-operations.md), including manifest/chunk tampering, store-v6
  and audit-v1 rejection, prepared-candidate preflight/reopen, atomic CAS failure, and recovery
  archive immutability;
- real two-node direct and local-relay tests for the six v1 ALPN handlers, including endpoint,
  checkpoint, ALPN, framing, backpressure, cancellation, and shutdown failures;
- aggregate-only metrics, access control for detailed audit records, backup restoration drills, and
  provider diversity appropriate to the selected profile;
- dependency isolation, public API/rustdoc coverage, resource-bound review, `unsafe`/panic review,
  formatting, architecture, packaging, release, and compatibility checks.
- the stable-release policy remains fail-closed under
  `python3 scripts/check-identity-release-gate.py --expect-closed` until every approval in
  [`release-gate.md`](release-gate.md) has qualifying evidence.

The authoritative repository acceptance matrix is
[`design-evidence.md`](design-evidence.md); a skipped command or unavailable external system is a
residual gate, not a pass.

## Frozen v1 product decisions

The design document lists choices that had to be made before a stable wire profile could exist.
Version 1 resolves them as follows; changing a wire-significant answer requires an authorized
protocol upgrade rather than reinterpretation of existing bytes.

| Design question | Version 1 decision |
| --- | --- |
| Canonical serialization | Postcard 1.1.3 with the exact bounded, re-encode-checked profile and closed codepoints in the crate README and provider appendix. JSON is metadata only. |
| Provider lookup | Public account history may be keyed by `AccountId`; privacy-sensitive discovery uses a provider/account/generation-bound rotating `PrivateCheckpointLookupHandle`. Deployments choose which interface they expose. |
| Device non-membership | A sorted Merkle set with domain-separated typed leaves and adjacent-neighbor non-membership proofs. |
| Consumer provider threshold | The recommended profile configures three distinct providers, two as the sufficient threshold, and three as preferred replication. These are explicit policy fields, not hidden global defaults. |
| Epoch increments | The closed 22-operation table and mode-specific rules in `state.rs` are authoritative. Metadata-only update, migration begin, and migration abort are the deliberately non-incrementing cases. |
| Emergency controller loss | There is no out-of-band one-controller bypass. Use the applicable previous control threshold or the account's already committed recovery policy; conflicts remain forks. |
| Proposal serialization | V1 uses exact revision compare-and-swap, immutable admission evidence, and explicit fork retention rather than an authority-bearing lease. A local bounded lease may coordinate work but cannot suppress another valid branch. |
| Clock dependence | Pairing and presence accept at most two minutes of future skew; presence lasts at most five minutes and pairing at most ten. Account recovery delay/freshness uses signed provider observation time and explicit verifier time, never event metadata or an ambient clock. |
| Secure hardware | The portable boundary supplies exact typed bytes, key, purpose, account, epoch, and operation display facts. Platform attestation, UX, backup, and hardware normalization remain an external deployment gate. |
| Post-quantum migration | Algorithm-tagged bounded fields, cross-certified controller bindings, dual-suite overlap, retirement tombstones, and successor-account support are reserved. V1 does not select or claim support for a post-quantum suite. A digest break requires a successor account. |
| Pairwise identifiers and names | Pairwise IDs are relying-party scoped; public names are optional signed aliases. Neither replaces the stable `AccountId` or grants authority. |
| Data recovery boundary | The core backup can carry a replayable account-authority bundle and optional opaque application data, reports their restoration separately, and does not promise application-specific conflict resolution or cloud custody. |
| Encrypted provider indices | V1 supplies rotating private lookup handles and opaque anchor commitments but does not standardize an encrypted account-index record. Such a record requires a future protocol extension and leakage analysis. |
| Open standard boundary | The README's documented foundational, account-control, synchronization, and network-envelope profile, together with the provider procedures, checked fixtures, models, and protocol tests, are repository-owned v1 specification assets for their stated scopes. A separately maintained implementation and standards governance remain external release gates. |

## Evidence

Confirmed implementation evidence:

- account projection, fork and recovery invariants: [`../src/state.rs`](../src/state.rs),
  [`../tests/state_machine.rs`](../tests/state_machine.rs), and
  [`../tests/recovery_guardians.rs`](../tests/recovery_guardians.rs);
- atomic source/effect persistence and crash recovery: [`../src/store.rs`](../src/store.rs),
  [`../src/operations.rs`](../src/operations.rs),
  [`../tests/store_conformance.rs`](../tests/store_conformance.rs), and
  [`../tests/operational_recovery.rs`](../tests/operational_recovery.rs);
- provider proofs, publication, auditing, persistence, compaction, and anchoring:
  [`../src/provider.rs`](../src/provider.rs),
  [`../src/provider/interchange.rs`](../src/provider/interchange.rs),
  [`../src/provider/compaction.rs`](../src/provider/compaction.rs),
  [`../src/provider/redb.rs`](../src/provider/redb.rs), [`../src/audit.rs`](../src/audit.rs),
  [`../src/audit/redb.rs`](../src/audit/redb.rs), [`../src/publication.rs`](../src/publication.rs),
  [`../tests/provider_wire_formats.rs`](../tests/provider_wire_formats.rs), and
  [`../tests/provider_persistence.rs`](../tests/provider_persistence.rs);
- private artifacts, recovery openings, and backups: [`../src/privacy.rs`](../src/privacy.rs),
  [`../src/recovery.rs`](../src/recovery.rs),
  [`../tests/privacy_boundaries.rs`](../tests/privacy_boundaries.rs), and
  [`../tests/private_backup.rs`](../tests/private_backup.rs);
- resource bounds and canonical decoding: [`../src/limits.rs`](../src/limits.rs),
  [`../src/codec.rs`](../src/codec.rs), and
  [`../tests/schema_limits.rs`](../tests/schema_limits.rs).

## Open questions and external release gates

The stable publication criteria and decision authorities are normative in
[`release-gate.md`](release-gate.md) and machine-readable in
[`../release-gate.toml`](../release-gate.toml). These additional deployment questions are
deliberately not represented as completed repository work:

1. A third-party cryptographic and protocol security audit.
2. An independent implementation validating every interoperability vector and ceremony.
3. Production evidence that configured providers have genuinely independent operators,
   infrastructure, and failure domains.
4. Platform-specific secure-hardware/HSM request-display and attestation normalization.
5. Application policy for restored-but-not-yet-refreshed backups and later-discovered stale
   application events.
6. A chain/vendor choice, if an operator elects to anchor opaque provider commitments externally.
7. Operational validation of relay/provider capacity and abuse controls at the deployment's target
   scale.
