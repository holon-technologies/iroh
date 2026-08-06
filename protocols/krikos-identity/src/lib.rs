//! Distributed multi-device identity and authorization for Krikos.
//!
//! `krikos-identity` keeps a stable account identity separate from replaceable endpoint,
//! controller, and application-device keys. Its default-feature core verifies canonical v1 wire
//! objects, projects an append-only account-control history, detects forks, evaluates structural
//! capabilities, and returns explicit effects without reading a clock, network, database, or
//! random-number source.
//!
//! # Authority model
//!
//! An authenticated Krikos endpoint proves control of one transport key; it is an authorized
//! account device only after that key is matched to an active device at a verified checkpoint.
//! Likewise, transparency providers can retain, timestamp, and prove inclusion of authorized
//! records but cannot create account authority. [`AccountState`] applies each transition under the
//! exact previous policy and admission evidence, while [`AccountStore`] implementations retain the
//! canonical source history and idempotent operational effects.
//!
//! Offline decisions are always relative to a named checkpoint and epoch. Callers that require
//! current status must supply policy-sufficient provider evidence and explicit verifier time;
//! absence of that evidence is not converted into a global-validity claim. Conflicting histories
//! enter a forked lifecycle and require an explicitly authorized resolution.
//!
//! # Features
//!
//! - The default feature set is empty and contains the runtime-independent, deterministic protocol
//!   core. APIs that accept caller-owned randomness remain available here.
//! - `fs-store` enables the redb-backed account source, checkpoint, and effect store.
//! - `provider-store` enables redb-backed provider generations, auditing, and operational journals.
//! - `net` enables bounded Tokio/Krikos framing and protocol adapters.
//! - `os-rng` enables only convenience APIs that obtain fresh secrets from the operating system.
//!
//! Applications normally start with [`AccountGenesis`], reconstruct or load an [`AccountState`],
//! verify and commit [`AuthorizedEvent`] values through an [`AccountStore`], and make application
//! decisions only from a verified checkpoint/capability basis. All public wire decoding goes
//! through the bounded, canonical [`CanonicalWire`] contract.
//!
//! The exact v1 serialization profile and codepoints are documented in the crate README. Provider
//! recovery/compaction procedures and the security/deployment guide live in the crate's `docs/`
//! directory. This crate is not yet a stable protocol release; external audit, independent
//! interoperability, and production provider diversity remain explicit release gates.
#![forbid(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(krikos_docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

mod application;
mod audit;
mod capability;
mod capability_verifier;
mod checkpoint;
mod codec;
mod crypto_migration;
mod device;
mod error;
mod event;
mod extension;
mod freshness;
mod genesis;
mod key_wrap;
mod keys;
/// Protocol-wide resource limits.
pub mod limits;
pub mod merkle;
mod names;
#[cfg(feature = "net")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "net")))]
pub mod net;
mod operations;
mod pairing;
mod policy;
mod presence;
mod privacy;
mod proposal;
mod provider;
mod publication;
mod recovery;
#[cfg(any(feature = "fs-store", feature = "provider-store"))]
mod redb_guard;
mod schema;
mod social;
mod state;
mod store;
mod sync;
mod transparency;
/// Runtime-independent transport, discovery, gossip, and blob contracts.
pub mod transport;
mod types;
mod verifier;

pub use application::{
    ApplicationAuthorizationView, ApplicationDeviceStatus, ApplicationEventBody,
    ApplicationEventCounter, SignedApplicationEvent, verify_application_event,
};
#[cfg(feature = "provider-store")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "provider-store")))]
pub use audit::RedbProviderAuditStore;
pub use audit::{
    DurableProviderAuditor, MemoryProviderAuditStore, ProviderAuditAppend, ProviderAuditArtifact,
    ProviderAuditArtifactKind, ProviderAuditCursor, ProviderAuditRecord, ProviderAuditSnapshot,
    ProviderAuditStatus, ProviderAuditStore,
};
pub use capability::{
    AuthorizationContext, CapabilityAction, CapabilityConstraint, CapabilityGrant,
    CapabilityNamespace, CapabilityRoot, DelegationBody, DelegationChain, DelegationPermission,
    MAX_RESOURCE_PATH_SEGMENTS, ResourcePath, ResourceSegment, ResourceSelector, SignedDelegation,
};
pub use capability_verifier::{
    CapabilityDecision, CapabilityDenialReason, CapabilityDeviceStatus, CapabilityProof,
    CapabilityRequest, CapabilityStateView, DelegationSignatureStatus, DelegationSignatureVerifier,
    evaluate_capability,
};
pub use checkpoint::{
    AccountLifecycle, CHECKPOINT_AUTHORIZED_DEVICE_TYPE_TAG, CHECKPOINT_REVOKED_DEVICE_TYPE_TAG,
    CHECKPOINT_STATE_CONTROLLER_TYPE_TAG, CHECKPOINT_STATE_DEVICE_TYPE_TAG,
    CHECKPOINT_STATE_METADATA_TYPE_TAG, CheckpointAuthorization, CheckpointBody,
    CheckpointMerkleSets, CheckpointTransitionKind, InclusionReceipt, ProviderCheckpointBundle,
    ProviderCheckpointLineage, ProviderEquivocationEvidence, ProviderHeadBody,
    ProviderLogEntryBody, ProviderLogSubject, ProviderReceipts, SignedCheckpoint,
    SignedProviderHead, TransitionCheckpointWitness, TrustedCheckpointBootstrap,
    VerifiedCheckpoint, bootstrap_checkpoint_from_genesis, bootstrap_checkpoint_from_prior,
    build_checkpoint_body, build_checkpoint_merkle_sets,
    build_provider_checkpoint_bundle_from_genesis, build_provider_checkpoint_bundle_from_prior,
    verify_checkpoint, verify_provider_head_progression,
};
pub use codec::CanonicalWire;
pub use crypto_migration::{
    ActivateCryptoMigration, BeginCryptoMigration, ControllerKeyBinding, ControllerKeyBindingProof,
    ControllerKeyBindingProofSet, CryptoMigrationBody, CryptoSuiteDescriptor, ProtocolUpgrade,
    RetireAccount, RetireCryptoSuite, RetireCryptoSuiteMode, UpgradeCompatibility,
};
pub use device::{
    BlindedMetadataCommitment, DeviceAuthorization, DeviceAuthorizationUpdate, DeviceClass,
    DeviceMetadataUpdate, DeviceUpdate, ReinstateDevice, RevokeDevice, RotateDeviceKeys,
    SuspendDevice,
};
pub use error::{AlgorithmKind, IdentityError};
pub use event::{
    AccountOperation, AdmissionEvidence, AuthorizedEvent, ControllerApprovalBody,
    ControllerApprovals, DelayEvidence, EventBody, EventIntentApprovalBody, EventIntentApprovals,
    EventPredecessors, FreshnessEvidence, KeyedSignature, SignedControllerApproval,
    SignedEventIntentApproval,
};
pub use extension::{Extension, Extensions};
pub use freshness::{FreshnessDecision, evaluate_freshness};
pub use genesis::AccountGenesis;
#[cfg(feature = "os-rng")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
pub use key_wrap::rotate_group_key;
pub use key_wrap::{
    AgreementKeyId, AgreementSecretKey, GroupKey, GroupKeyDistributionSnapshot, GroupKeyRotation,
    GroupKeyWrapHeader, KeyWrapNonce, RecipientKeyWraps, WrappedGroupKey,
    rotate_group_key_with_rng, unwrap_group_key,
};
pub use keys::{
    ControllerClass, ControllerDescriptor, ControllerScope, DeviceDescriptor, EndpointPublicKey,
    ProviderDescriptor,
};
pub use names::{
    NameAuthorityContext, NameCandidateSet, NameClaimBody, NameResolver, NormalizedName,
    SignedNameClaim, TofuDecision, TofuObservation, VerifiedNameCandidates, VerifiedNameClaim,
    evaluate_name_tofu, resolve_name_candidates, verify_name_candidates, verify_name_claim,
};
#[cfg(feature = "provider-store")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "provider-store")))]
pub use operations::RedbOperationalEffectStore;
pub use operations::{
    MemoryOperationalEffectStore, OperationalAuditRecord, OperationalCheckpointAuthorizer,
    OperationalCheckpointBuild, OperationalCheckpointCommit, OperationalEffectJournal,
    OperationalEffectPhase, OperationalEffectRecord, OperationalEffectStore,
    OperationalGroupKeyRotator, OperationalMetricsSnapshot, OperationalPeerNotifier,
    OperationalProviderReceipt, build_authorize_and_commit_checkpoint, complete_ready_effect,
    notify_and_complete_effect, publish_and_journal_checkpoint, rotate_and_journal_group_keys,
};
#[cfg(feature = "fs-store")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "fs-store")))]
pub use pairing::RedbPairingNonceStore;
pub use pairing::{
    AuthenticatedTransportBinding, Cancelled, ConfirmationParticipant, Confirmed, Connected,
    ConnectionEphemeralSecret, Consumed, Expired, Issued, MAX_PAIRING_ENDPOINT_HINT_BYTES,
    MemoryPairingNonceStore, NonceConsumeResult, PairingAdmission, PairingCeremony,
    PairingChallenge, PairingConfirmation, PairingConfirmationContext, PairingConfirmationOutcome,
    PairingConsumeError, PairingConsumeOutcome, PairingNonce, PairingNonceKey, PairingNonceStore,
    PairingPossessionProof, PairingProofId, PairingSessionId, PairingTicket, PairingTicketId,
    PairingTicketRequest, PairingTicketSecrets, PairingTranscript, PairingTranscriptId, Proven,
    ShortAuthString,
};
pub use policy::{
    ControlPolicy, ControllerClassSet, ControllerIdSet, ControllerSelector, ControllerThreshold,
    FreshnessRequirement, GuardianSetRoot, GuardianThreshold, PolicyRule, ProviderFreshness,
    ProviderMode, ProviderPolicy, ProviderRotationRule, RecoveryAuthority, RecoveryPolicy,
    RecoveryPolicyVersion, ReplicatedProviderPolicy,
};
pub use presence::{
    DevicePresenceChallenge, PresenceProof, PresenceProofId, PresenceSessionId,
    PresenceVerifierChallenge, verify_presence_proof,
};
pub use privacy::{
    ApplicationBackupData, ApplicationDataRestoration, BackupAuthorityBundle, BackupEnvelope,
    BackupPassphrase, BackupRestoration, BlindedCommitment, BlindingSecret,
    CanonicalSigningRequest, CredentialClaim, CredentialVerificationContext,
    HardwareApprovalRequest, HardwareController, LookupHandleSecret, OfflineSigner,
    PairwiseIdentifier, PairwiseMasterSecret, PortableCredentialBody, PrivateArtifactContext,
    PrivateCheckpointLookupHandle, PrivateLabel, PrivateMetadata, PrivateMetadataEnvelope,
    PrivateMetadataKey, RelyingPartyContext, RestoredAccountAuthority, SignedPortableCredential,
    SigningPurpose, VerifiedPortableCredential, verify_portable_credential,
};
pub use proposal::{DeviceAuthorizationProposal, DeviceAuthorizationProposalId};
#[cfg(feature = "provider-store")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "provider-store")))]
pub use provider::RedbProviderStore;
pub use provider::{
    AddressedProviderGeneration, MAX_PROVIDER_EXPORT_CHUNK_BYTES, MAX_PROVIDER_EXPORT_CHUNK_ITEMS,
    MAX_PROVIDER_EXPORT_ITEM_BYTES, MAX_PROVIDER_PORTABLE_AUDIT_BYTES,
    MAX_PROVIDER_PORTABLE_GENERATION_BYTES, MemoryProviderStore, OpaqueProviderAnchorCommitment,
    ProviderAccountHistoryPage, ProviderAccountHistoryRecord, ProviderAdmissionControl,
    ProviderAdmissionRequest, ProviderAnchor, ProviderAnchorEvidence, ProviderAnchorStatus,
    ProviderAppendPermit, ProviderAuditExportAssembler, ProviderAuditExportChunk,
    ProviderAuditExportManifest, ProviderCompactionAuthorization, ProviderCompactionManifest,
    ProviderExportComponent, ProviderExportComponentDescriptor, ProviderGenerationExport,
    ProviderGenerationExportAssembler, ProviderGenerationExportChunk,
    ProviderGenerationExportManifest, ProviderGenerationRegistry, ProviderGenerationRoute,
    ProviderGenerationSnapshot, ProviderRecoveryExport, ProviderRecoveryExportManifest,
    ProviderRetainedCheckpointEvidence, ProviderRetainedRange, ProviderRetentionClass,
    ProviderRetentionInventory, ProviderRetentionItem, authorize_provider_append,
    derive_provider_retention_inventory, verify_provider_compaction,
};
pub use publication::{
    ProviderCheckpointLineagePage, ProviderPublicationOutcome, PublicationBatch, PublicationStage,
    PublicationTracker, PublishedCheckpoint, TransparencyClient, publish_checkpoint_concurrently,
};
pub use recovery::{
    BeginRecovery, CancelRecovery, FinalizeRecovery, ForkCommonAncestor, ForkDescriptor,
    GUARDIAN_GRANT_LEAF_TYPE_TAG, GuardianApprovalBody, GuardianApprovalDecision,
    GuardianApprovalSet, GuardianAuthorityContext, GuardianGrant, GuardianGrantOpening,
    RecoveryAuthorityPlan, RecoveryDelayAnchor, RecoveryProposal, RecoveryThresholdEvidence,
    ResolveFork, SignedGuardianApproval, VerifiedGuardianAuthority, VetoRecovery,
    verify_guardian_authority,
};
pub use schema::{
    AccountId, AdmissionEvidenceId, AlgorithmPublicKey, AlgorithmSignature, ApplicationEventId,
    ApplicationId, CapabilityGrantId, CheckpointId, ControlPolicyId, ControllerApprovalId,
    ControllerId, ControllerKeyId, ControllerWeight, CryptoMigrationId, CryptoStateId,
    CryptoSuiteId, DelegationDepth, DelegationId, DeviceId, EventAuthorizationId, EventId,
    EventIntentApprovalId, ForkId, GenesisAnchor, GroupId, GroupKeyEpoch, GroupKeyWrapId,
    GuardianGrantId, ProposalId, ProtocolMajor, ProviderId, ProviderKeyVersion, ProviderLogId,
    ProviderPolicyId, ProviderPolicyVersion, ProviderQuorum, RecoveryId, RecoveryPolicyId,
    RequiredWeight, RevocationReasonCode,
};
pub use social::{
    SignedSocialAttestation, SocialAttestationBody, SocialAttestationVerificationContext,
    SocialTransitivityPolicy, SocialTrustHint, VerifiedSocialAttestation, evaluate_social_trust,
    verify_social_attestation,
};
pub use state::{
    AccountRevision, AccountState, ApplyDisposition, ApplyOutcome, ProjectedController,
    ProjectedDevice, ProjectedDeviceLifecycle, ProjectionEffect, ProjectionLifecycle,
};
#[cfg(feature = "fs-store")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "fs-store")))]
pub use store::RedbAccountStore;
pub use store::{
    AccountSnapshot, AccountStore, BatchCommitReceipt, CheckpointCommitReceipt,
    CheckpointJournalPage, CheckpointJournalRecord, ClaimEffects, CommitReceipt, EffectFailure,
    EffectId, EffectRecord, EffectStatus, EventHistoryCursor, EventHistoryPage, EventHistoryRecord,
    ForkEvidenceRecord, LeaseId, MemoryAccountStore, StoreFuture, StoredGroupKeyRotation,
};
pub use sync::{
    CursorKey, SyncCursor, SyncFrame, SyncRequest, SyncResponse, SyncSessionBudget,
    reconcile_sync_frame, serve_sync_request,
};
pub use transparency::{
    MemoryTransparencyLog, ProviderHeadAuditDisposition, ProviderHeadAuditor, ProviderHeadSigner,
    ProviderHistoryPage, ProviderHistoryRecord, ProviderLogAdmission,
    verify_event_intent_admission, verify_guardian_recovery_intent_admission,
};
pub use types::{
    AeadAlgorithm, AgreementAlgorithm, AgreementPublicKey, Digest, DurationMillis, Epoch,
    HashAlgorithm, KdfAlgorithm, OperationKind, ProtocolSignature, ProtocolVersion,
    RESERVED_PUBLISH_CHECKPOINT_CODE, Sequence, SignatureAlgorithm, SigningPublicKey, Timestamp,
};
