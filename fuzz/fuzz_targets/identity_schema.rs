#![no_main]

use krikos_identity::{
    AccountGenesis, AccountOperation, ActivateCryptoMigration, AdmissionEvidence, AgreementKeyId,
    ApplicationEventBody, ApplicationEventCounter, AuthorizationContext, AuthorizedEvent,
    BackupAuthorityBundle, BackupEnvelope, BeginCryptoMigration, BeginRecovery, BlindedCommitment,
    BlindedMetadataCommitment, CancelRecovery, CanonicalWire, CapabilityAction,
    CapabilityConstraint, CapabilityGrant, CapabilityNamespace, CapabilityRoot,
    CheckpointAuthorization, CheckpointBody, CheckpointTransitionKind, ControlPolicy,
    ControllerApprovalBody, ControllerApprovals, ControllerClass, ControllerClassSet,
    ControllerDescriptor, ControllerIdSet, ControllerKeyBinding, ControllerKeyBindingProof,
    ControllerKeyBindingProofSet, ControllerScope, ControllerSelector, CredentialClaim,
    CryptoMigrationBody, CryptoSuiteDescriptor, DelayEvidence, DelegationBody, DelegationChain,
    DelegationPermission, DeviceAuthorization, DeviceAuthorizationUpdate, DeviceClass,
    DeviceDescriptor, DeviceMetadataUpdate, DeviceUpdate, EndpointPublicKey, EventBody,
    EventIntentApprovalBody, EventIntentApprovals, EventPredecessors, FinalizeRecovery,
    ForkDescriptor, FreshnessEvidence, GroupKeyWrapHeader, GuardianApprovalBody,
    GuardianApprovalDecision, GuardianApprovalSet, GuardianSetRoot, InclusionReceipt, KeyWrapNonce,
    KeyedSignature, NameClaimBody, NormalizedName, PairwiseIdentifier, PortableCredentialBody,
    PrivateArtifactContext, PrivateCheckpointLookupHandle, PrivateMetadataEnvelope,
    ProtocolUpgrade, ProviderDescriptor, ProviderHeadBody, ProviderLogEntryBody, ProviderPolicy,
    ProviderReceipts, RecipientKeyWraps, RecoveryAuthorityPlan, RecoveryDelayAnchor,
    RecoveryPolicy, RecoveryPolicyVersion, RecoveryProposal, RecoveryThresholdEvidence,
    ReinstateDevice, RelyingPartyContext, ResolveFork, ResourcePath, ResourceSegment,
    ResourceSelector, RetireAccount, RetireCryptoSuite, RetireCryptoSuiteMode, RevokeDevice,
    RotateDeviceKeys, SignedApplicationEvent, SignedCheckpoint, SignedControllerApproval,
    SignedDelegation, SignedEventIntentApproval, SignedGuardianApproval, SignedNameClaim,
    SignedPortableCredential, SignedProviderHead, SignedSocialAttestation, SocialAttestationBody,
    SuspendDevice, TransitionCheckpointWitness, UpgradeCompatibility, VetoRecovery,
    WrappedGroupKey, limits::MAX_ENCODED_OBJECT_BYTES,
};
use libfuzzer_sys::fuzz_target;

type SchemaDecoder = fn(&[u8]);

// Keep this registry explicit: adding a public canonical schema should be a reviewed fuzz-coverage
// decision. ResourceSegment deliberately remains at index 37 because the reviewed text corpus
// starts with ASCII `%` (37) followed by a canonical 33-byte segment.
const SCHEMA_DECODERS: [SchemaDecoder; 112] = [
    round_trip::<AccountGenesis>,
    round_trip::<ControllerClass>,
    round_trip::<ControllerScope>,
    round_trip::<ControllerDescriptor>,
    round_trip::<ProviderDescriptor>,
    round_trip::<EndpointPublicKey>,
    round_trip::<DeviceDescriptor>,
    round_trip::<ControllerIdSet>,
    round_trip::<ControllerClassSet>,
    round_trip::<ControllerSelector>,
    round_trip::<ControlPolicy>,
    round_trip::<ProviderPolicy>,
    round_trip::<RecoveryPolicyVersion>,
    round_trip::<GuardianSetRoot>,
    round_trip::<RecoveryPolicy>,
    round_trip::<CapabilityNamespace>,
    round_trip::<CapabilityAction>,
    round_trip::<ResourcePath>,
    round_trip::<ResourceSelector>,
    round_trip::<CapabilityConstraint>,
    round_trip::<DelegationPermission>,
    round_trip::<CapabilityGrant>,
    round_trip::<AuthorizationContext>,
    round_trip::<CapabilityRoot>,
    round_trip::<DelegationBody>,
    round_trip::<SignedDelegation>,
    round_trip::<DelegationChain>,
    round_trip::<ProviderLogEntryBody>,
    round_trip::<ProviderHeadBody>,
    round_trip::<SignedProviderHead>,
    round_trip::<InclusionReceipt>,
    round_trip::<ProviderReceipts>,
    round_trip::<CheckpointBody>,
    round_trip::<CheckpointAuthorization>,
    round_trip::<SignedCheckpoint>,
    round_trip::<EventPredecessors>,
    round_trip::<KeyedSignature>,
    round_trip::<ResourceSegment>,
    round_trip::<EventIntentApprovalBody>,
    round_trip::<SignedEventIntentApproval>,
    round_trip::<EventIntentApprovals>,
    round_trip::<FreshnessEvidence>,
    round_trip::<DelayEvidence>,
    // AdmissionEvidence remains at index 43 for the reviewed v1 corpus seed.
    round_trip::<AdmissionEvidence>,
    round_trip::<ControllerApprovalBody>,
    round_trip::<SignedControllerApproval>,
    round_trip::<ControllerApprovals>,
    round_trip::<CryptoSuiteDescriptor>,
    round_trip::<ControllerKeyBinding>,
    round_trip::<CryptoMigrationBody>,
    round_trip::<ControllerKeyBindingProof>,
    round_trip::<ControllerKeyBindingProofSet>,
    round_trip::<BeginCryptoMigration>,
    round_trip::<ActivateCryptoMigration>,
    round_trip::<RetireCryptoSuiteMode>,
    round_trip::<RetireCryptoSuite>,
    round_trip::<UpgradeCompatibility>,
    round_trip::<ProtocolUpgrade>,
    round_trip::<RetireAccount>,
    round_trip::<DeviceClass>,
    round_trip::<BlindedMetadataCommitment>,
    round_trip::<DeviceAuthorization>,
    round_trip::<DeviceAuthorizationUpdate>,
    round_trip::<DeviceMetadataUpdate>,
    round_trip::<DeviceUpdate>,
    round_trip::<SuspendDevice>,
    round_trip::<ReinstateDevice>,
    round_trip::<RevokeDevice>,
    round_trip::<RotateDeviceKeys>,
    round_trip::<ApplicationEventCounter>,
    round_trip::<ApplicationEventBody>,
    round_trip::<SignedApplicationEvent>,
    round_trip::<AgreementKeyId>,
    round_trip::<KeyWrapNonce>,
    round_trip::<GroupKeyWrapHeader>,
    round_trip::<WrappedGroupKey>,
    round_trip::<RecipientKeyWraps>,
    round_trip::<AccountOperation>,
    round_trip::<EventBody>,
    round_trip::<AuthorizedEvent>,
    round_trip::<RecoveryAuthorityPlan>,
    round_trip::<RecoveryProposal>,
    // Raw grants/openings have no public canonical decoder. SignedGuardianApproval at index 84
    // retains fuzz coverage for their private nested decoder and validation boundary.
    round_trip::<GuardianApprovalDecision>,
    round_trip::<GuardianApprovalBody>,
    round_trip::<SignedGuardianApproval>,
    round_trip::<GuardianApprovalSet>,
    round_trip::<RecoveryThresholdEvidence>,
    round_trip::<BeginRecovery>,
    round_trip::<VetoRecovery>,
    round_trip::<CancelRecovery>,
    round_trip::<RecoveryDelayAnchor>,
    round_trip::<FinalizeRecovery>,
    round_trip::<ForkDescriptor>,
    round_trip::<ResolveFork>,
    round_trip::<CheckpointTransitionKind>,
    round_trip::<TransitionCheckpointWitness>,
    // Task 8 social records: indices 96..98.
    round_trip::<SocialAttestationBody>,
    round_trip::<SignedSocialAttestation>,
    // Task 8 names: indices 98..101.
    round_trip::<NormalizedName>,
    round_trip::<NameClaimBody>,
    round_trip::<SignedNameClaim>,
    // Task 8 private/public envelopes and privacy-preserving identifiers: indices 101..112.
    round_trip::<PrivateArtifactContext>,
    round_trip::<PrivateMetadataEnvelope>,
    round_trip::<BlindedCommitment>,
    round_trip::<PrivateCheckpointLookupHandle>,
    round_trip::<RelyingPartyContext>,
    round_trip::<PairwiseIdentifier>,
    round_trip::<CredentialClaim>,
    round_trip::<PortableCredentialBody>,
    round_trip::<SignedPortableCredential>,
    round_trip::<BackupAuthorityBundle>,
    round_trip::<BackupEnvelope>,
];

fn round_trip<T: CanonicalWire>(payload: &[u8]) {
    let Ok(decoded) = T::from_canonical_bytes(payload) else {
        return;
    };
    let encoded = decoded.to_canonical_bytes();
    assert_eq!(
        encoded.as_deref(),
        Ok(payload),
        "an accepted identity schema failed to reproduce its canonical bytes"
    );
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, payload)) = input.split_first() else {
        return;
    };
    if payload.len() > MAX_ENCODED_OBJECT_BYTES {
        return;
    }

    // Selector values are append-only. Never reduce them modulo the table length: doing so would
    // silently retarget saved corpus inputs whenever a decoder is appended.
    let decoder_index = usize::from(selector);
    let Some(decoder) = SCHEMA_DECODERS.get(decoder_index) else {
        return;
    };
    decoder(payload);
});
