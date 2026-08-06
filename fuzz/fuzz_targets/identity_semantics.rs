#![no_main]

use std::convert::Infallible;

use futures_lite::future::block_on;
use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountId, AccountStore, AdmissionEvidenceId, AgreementPublicKey,
    AgreementSecretKey, AlgorithmPublicKey, AlgorithmSignature, ApplicationAuthorizationView,
    ApplicationDeviceStatus, ApplicationEventBody, ApplicationEventCounter, ApplicationEventId,
    ApplicationId, AuthorizationContext, AuthorizedEvent, CanonicalWire, CapabilityGrantId,
    CheckpointId, ClaimEffects, ControlPolicyId, ControllerApprovalId, ControllerId,
    ControllerKeyId, ControllerWeight, CredentialClaim, CredentialVerificationContext,
    CryptoMigrationId, CryptoStateId, CryptoSuiteId, DelegationDepth, DelegationId,
    DeviceAuthorization, DeviceAuthorizationProposalId, DeviceClass, DeviceDescriptor, DeviceId,
    DevicePresenceChallenge, Digest, DurableProviderAuditor, DurationMillis, EndpointPublicKey,
    Epoch, EventAuthorizationId, EventId, EventIntentApprovalId, Extensions, ForkCommonAncestor,
    ForkId, FreshnessEvidence, FreshnessRequirement, GenesisAnchor, GroupId, GroupKeyEpoch,
    GroupKeyWrapId, GuardianApprovalSet, GuardianAuthorityContext, GuardianGrantId,
    GuardianThreshold, HashAlgorithm, IdentityError, LeaseId, MemoryAccountStore,
    MemoryOperationalEffectStore, MemoryProviderAuditStore, MemoryProviderStore,
    NameAuthorityContext, NameCandidateSet, NameClaimBody, NormalizedName,
    OperationalEffectJournal, OperationalEffectPhase, PairingChallenge, PairingConfirmationContext,
    PairingNonce, PairingProofId, PairingSessionId, PairingTicketId, PairingTranscriptId,
    PortableCredentialBody, PresenceProof, PresenceProofId, PresenceSessionId,
    PresenceVerifierChallenge, PrivateArtifactContext, PrivateMetadata, PrivateMetadataEnvelope,
    PrivateMetadataKey, ProjectionEffect, ProposalId, ProtocolMajor, ProtocolSignature,
    ProviderAdmissionControl, ProviderAdmissionRequest, ProviderCheckpointBundle,
    ProviderDescriptor, ProviderGenerationExport, ProviderGenerationRegistry, ProviderHeadSigner,
    ProviderId, ProviderKeyVersion, ProviderLogAdmission, ProviderLogId, ProviderPolicy,
    ProviderPolicyId, ProviderPolicyVersion, ProviderQuorum, ProviderRecoveryExport,
    RecoveryAuthority, RecoveryId, RecoveryPolicy, RecoveryPolicyId, RecoveryPolicyVersion,
    RequiredWeight, RevocationReasonCode, ShortAuthString, SignedApplicationEvent,
    SignedCheckpoint, SignedNameClaim, SignedPortableCredential, SignedSocialAttestation,
    SigningPublicKey, SocialAttestationBody, SocialAttestationVerificationContext,
    SocialTransitivityPolicy, Timestamp, TofuDecision, authorize_provider_append,
    build_provider_checkpoint_bundle_from_genesis, derive_provider_retention_inventory,
    evaluate_freshness, evaluate_name_tofu, evaluate_social_trust,
    limits::MAX_ALGORITHM_SIGNATURE_BYTES, verify_application_event, verify_guardian_authority,
    verify_name_candidates, verify_name_claim, verify_portable_credential, verify_presence_proof,
    verify_provider_compaction, verify_social_attestation,
};
use libfuzzer_sys::fuzz_target;
use rand_core::{TryCryptoRng, TryRng};

type IdentitySemanticsDecoder = fn(&[u8]);

/// One selector byte plus the largest bounded leaf payload in this registry.
const MAX_SEMANTICS_PAYLOAD_BYTES: usize = MAX_ALGORITHM_SIGNATURE_BYTES.saturating_add(16);

// This named inventory is intentionally kept beside the decoder table. Tooling can compare these
// exact public type names with the crate's sealed CanonicalWire implementations without inferring
// names from generic function pointers.
const IDENTITY_SEMANTICS_TYPE_NAMES: [&str; 53] = [
    "AccountId",
    "AdmissionEvidenceId",
    "AlgorithmPublicKey",
    "AlgorithmSignature",
    "ApplicationEventId",
    "ApplicationId",
    "CapabilityGrantId",
    "CheckpointId",
    "ControlPolicyId",
    "ControllerApprovalId",
    "ControllerId",
    "ControllerKeyId",
    "ControllerWeight",
    "CryptoMigrationId",
    "CryptoStateId",
    "CryptoSuiteId",
    "DelegationDepth",
    "DelegationId",
    "DeviceAuthorizationProposalId",
    "DeviceId",
    "EventAuthorizationId",
    "EventId",
    "EventIntentApprovalId",
    "ForkCommonAncestor",
    "ForkId",
    "GenesisAnchor",
    "GroupId",
    "GroupKeyEpoch",
    "GroupKeyWrapId",
    "GuardianGrantId",
    "PairingChallenge",
    "PairingConfirmationContext",
    "PairingNonce",
    "PairingProofId",
    "PairingSessionId",
    "PairingTicketId",
    "PairingTranscriptId",
    "PresenceProofId",
    "PresenceSessionId",
    "PresenceVerifierChallenge",
    "ProposalId",
    "ProtocolMajor",
    "ProviderId",
    "ProviderKeyVersion",
    "ProviderLogId",
    "ProviderPolicyId",
    "ProviderPolicyVersion",
    "ProviderQuorum",
    "RecoveryId",
    "RecoveryPolicyId",
    "RequiredWeight",
    "RevocationReasonCode",
    "ShortAuthString",
];

const IDENTITY_SEMANTICS_DECODERS: [IdentitySemanticsDecoder; 53] = [
    round_trip::<AccountId>,
    round_trip::<AdmissionEvidenceId>,
    round_trip::<AlgorithmPublicKey>,
    round_trip::<AlgorithmSignature>,
    round_trip::<ApplicationEventId>,
    round_trip::<ApplicationId>,
    round_trip::<CapabilityGrantId>,
    round_trip::<CheckpointId>,
    round_trip::<ControlPolicyId>,
    round_trip::<ControllerApprovalId>,
    round_trip::<ControllerId>,
    round_trip::<ControllerKeyId>,
    round_trip::<ControllerWeight>,
    round_trip::<CryptoMigrationId>,
    round_trip::<CryptoStateId>,
    round_trip::<CryptoSuiteId>,
    round_trip::<DelegationDepth>,
    round_trip::<DelegationId>,
    round_trip::<DeviceAuthorizationProposalId>,
    round_trip::<DeviceId>,
    round_trip::<EventAuthorizationId>,
    round_trip::<EventId>,
    round_trip::<EventIntentApprovalId>,
    round_trip::<ForkCommonAncestor>,
    round_trip::<ForkId>,
    round_trip::<GenesisAnchor>,
    round_trip::<GroupId>,
    round_trip::<GroupKeyEpoch>,
    round_trip::<GroupKeyWrapId>,
    round_trip::<GuardianGrantId>,
    round_trip::<PairingChallenge>,
    round_trip::<PairingConfirmationContext>,
    round_trip::<PairingNonce>,
    round_trip::<PairingProofId>,
    round_trip::<PairingSessionId>,
    round_trip::<PairingTicketId>,
    round_trip::<PairingTranscriptId>,
    round_trip::<PresenceProofId>,
    round_trip::<PresenceSessionId>,
    round_trip::<PresenceVerifierChallenge>,
    round_trip::<ProposalId>,
    round_trip::<ProtocolMajor>,
    round_trip::<ProviderId>,
    round_trip::<ProviderKeyVersion>,
    round_trip::<ProviderLogId>,
    round_trip::<ProviderPolicyId>,
    round_trip::<ProviderPolicyVersion>,
    round_trip::<ProviderQuorum>,
    round_trip::<RecoveryId>,
    round_trip::<RecoveryPolicyId>,
    round_trip::<RequiredWeight>,
    round_trip::<RevocationReasonCode>,
    round_trip::<ShortAuthString>,
];

fn round_trip<T: CanonicalWire>(payload: &[u8]) {
    let Ok(decoded) = T::from_canonical_bytes(payload) else {
        return;
    };
    assert_eq!(
        decoded.to_canonical_bytes().as_deref(),
        Ok(payload),
        "an accepted identity semantics leaf failed canonical reproduction"
    );
}

const REJECT_RELATIONSHIP_CONTROL: u8 = b'!';

fn reject_relationship(payload: &[u8]) -> bool {
    payload.first() == Some(&REJECT_RELATIONSHIP_CONTROL)
}

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    let encoded = digest
        .to_canonical_bytes()
        .expect("a fixed BLAKE3 digest must have a canonical encoding");
    T::from_canonical_bytes(&encoded)
        .expect("a typed digest identifier must accept a canonical Digest encoding")
}

fn guardian_authority_semantics(reject: bool) {
    let approvals = GuardianApprovalSet::from_canonical_bytes(include_bytes!(
        "../../protocols/krikos-identity/tests/vectors/guardian-approval-set.bin"
    ))
    .expect("the reviewed guardian approval fixture must remain canonical");
    let policy_version = RecoveryPolicyVersion::new(7);
    let required_weight =
        RequiredWeight::new(2).expect("the fixed guardian threshold weight is nonzero");
    let threshold = GuardianThreshold::new(approvals.guardian_set_root(), 3, 3, required_weight)
        .expect("the fixed guardian threshold is internally satisfiable");
    let policy = RecoveryPolicy::new(
        policy_version,
        RecoveryAuthority::guardian_threshold(threshold),
        DurationMillis::new(1_000),
        DurationMillis::new(30_000),
        Extensions::default(),
    )
    .expect("the reviewed guardian policy must remain valid");
    let first = approvals
        .as_slice()
        .first()
        .expect("the canonical guardian approval set is nonempty");
    let body = first.body();
    let valid_context = GuardianAuthorityContext::try_new(
        body.protected_account_id(),
        body.recovery_id(),
        policy
            .id()
            .expect("the fixed recovery policy must derive an identifier"),
        policy_version,
        body.account_epoch(),
        body.decision(),
        Timestamp::from_unix_millis(50_100),
    )
    .expect("the fixed guardian authority context must be valid");
    let verified = verify_guardian_authority(&policy, &approvals, &valid_context)
        .expect("the reviewed guardian approvals must satisfy their exact policy");
    assert_eq!(
        verified.approval_count(),
        2,
        "the reviewed guardian fixture must retain two distinct approvals"
    );

    if reject {
        let substituted = GuardianAuthorityContext::try_new(
            body.protected_account_id(),
            typed_id::<RecoveryId>(0x99),
            valid_context.recovery_policy_id(),
            policy_version,
            body.account_epoch(),
            body.decision(),
            Timestamp::from_unix_millis(50_100),
        )
        .expect("the substituted guardian context is structurally valid");
        assert!(
            verify_guardian_authority(&policy, &approvals, &substituted).is_err(),
            "guardian authority must reject a substituted recovery identifier"
        );
    }
}

fn social_semantics(reject: bool) {
    let issuer = SecretKey::from_bytes(&[0x11; 32]);
    let subject = SecretKey::from_bytes(&[0x12; 32]);
    let issuer_key = SigningPublicKey::ed25519(*issuer.public().as_bytes())
        .expect("the fixed issuer key is valid Ed25519 material");
    let subject_key = SigningPublicKey::ed25519(*subject.public().as_bytes())
        .expect("the fixed subject key is valid Ed25519 material");
    let claim_digest = Digest::new(HashAlgorithm::Blake3_256, [0x17; 32]);
    let body = SocialAttestationBody::try_new(
        typed_id::<AccountId>(0x13),
        typed_id::<CheckpointId>(0x14),
        issuer_key,
        typed_id::<AccountId>(0x15),
        typed_id::<CheckpointId>(0x16),
        subject_key,
        claim_digest,
        Timestamp::from_unix_millis(10),
        Some(Timestamp::from_unix_millis(20)),
        Extensions::default(),
    )
    .expect("the fixed social attestation body must be valid");
    let signature = AlgorithmSignature::new(
        1,
        issuer
            .sign(
                &body
                    .signing_bytes()
                    .expect("the social body must produce signing bytes"),
            )
            .to_bytes()
            .to_vec(),
    )
    .expect("the fixed social signature must use the v1 algorithm shape");
    let attestation = SignedSocialAttestation::try_new(body.clone(), signature)
        .expect("the fixed social attestation signature must verify");
    let context = SocialAttestationVerificationContext::try_new(
        body.issuer_account_id(),
        body.issuer_checkpoint_id(),
        body.issuer_signing_key(),
        body.subject_account_id(),
        body.subject_checkpoint_id(),
        body.subject_signing_key(),
        body.claim_digest(),
        Timestamp::from_unix_millis(19),
    )
    .expect("the fixed social verification context must be valid");
    let verified = verify_social_attestation(&attestation, &context)
        .expect("the fixed social attestation must verify at its authority time");
    let hint = evaluate_social_trust(
        &[verified],
        SocialTransitivityPolicy::default(),
        Timestamp::from_unix_millis(19),
    )
    .expect("one verified social edge is valid with transitivity disabled");
    assert_eq!(
        hint.depth(),
        1,
        "one verified social edge must have depth one"
    );

    if reject {
        let expired = SocialAttestationVerificationContext::try_new(
            body.issuer_account_id(),
            body.issuer_checkpoint_id(),
            body.issuer_signing_key(),
            body.subject_account_id(),
            body.subject_checkpoint_id(),
            body.subject_signing_key(),
            body.claim_digest(),
            Timestamp::from_unix_millis(20),
        )
        .expect("the expired social context is structurally valid");
        assert!(
            verify_social_attestation(&attestation, &expired).is_err(),
            "social verification must reject its exclusive expiry boundary"
        );
    }
}

fn name_semantics(reject: bool) {
    let secret = SecretKey::from_bytes(&[0x41; 32]);
    let signing_key = SigningPublicKey::ed25519(*secret.public().as_bytes())
        .expect("the fixed name key is valid Ed25519 material");
    let body = NameClaimBody::try_new(
        NormalizedName::try_new("alice.example")
            .expect("the fixed lowercase DNS-style name is normalized"),
        typed_id::<AccountId>(0x42),
        typed_id::<CheckpointId>(0x43),
        signing_key,
        Timestamp::from_unix_millis(10),
        Some(Timestamp::from_unix_millis(20)),
        Extensions::default(),
    )
    .expect("the fixed name claim body must be valid");
    let signature = AlgorithmSignature::new(
        1,
        secret
            .sign(
                &body
                    .signing_bytes()
                    .expect("the name claim must produce signing bytes"),
            )
            .to_bytes()
            .to_vec(),
    )
    .expect("the fixed name signature must use the v1 algorithm shape");
    let claim = SignedNameClaim::try_new(body.clone(), signature)
        .expect("the fixed self-signed name claim must verify");
    let context = NameAuthorityContext::try_new(
        body.name().clone(),
        body.subject_account_id(),
        body.subject_checkpoint_id(),
        body.subject_signing_key(),
        Timestamp::from_unix_millis(19),
    )
    .expect("the fixed name authority context must be valid");
    let verified = verify_name_claim(&claim, &context)
        .expect("the fixed name claim must verify against its exact authority");
    assert!(
        matches!(
            evaluate_name_tofu(None, &verified)
                .expect("a verified name claim must produce a TOFU decision"),
            TofuDecision::FirstUse { .. }
        ),
        "a name without prior observation must remain first-use"
    );
    let candidates = NameCandidateSet::try_new(vec![claim.clone()])
        .expect("one fixed name candidate is bounded");
    assert_eq!(
        verify_name_candidates(&candidates, std::slice::from_ref(&context))
            .expect("the fixed candidate set must be evaluable")
            .as_slice()
            .len(),
        1,
        "the exact name authority must retain its one matching candidate"
    );

    if reject {
        let substituted = NameAuthorityContext::try_new(
            body.name().clone(),
            body.subject_account_id(),
            typed_id::<CheckpointId>(0x44),
            body.subject_signing_key(),
            Timestamp::from_unix_millis(19),
        )
        .expect("the substituted name context is structurally valid");
        assert!(
            verify_name_claim(&claim, &substituted).is_err(),
            "name verification must reject a substituted checkpoint"
        );
    }
}

struct RepeatingRng(u8);

impl TryRng for RepeatingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from(self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from(self.0))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        destination.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

fn private_metadata_semantics(reject: bool) {
    let context = PrivateArtifactContext::try_new(
        typed_id::<AccountId>(1),
        typed_id::<CheckpointId>(2),
        Epoch::new(3),
        Some(typed_id::<ApplicationId>(4)),
        5,
        Extensions::default(),
    )
    .expect("the fixed private-artifact context must be valid");
    let key =
        PrivateMetadataKey::try_new([0x31; 32]).expect("the fixed private-metadata key is nonzero");
    let plaintext = PrivateMetadata::try_new(b"private profile: alpine orchid".to_vec())
        .expect("the fixed private metadata is nonempty and bounded");
    let envelope =
        PrivateMetadataEnvelope::seal_with_rng(context, &key, &plaintext, &mut RepeatingRng(0x41))
            .expect("fixed entropy must seal private metadata");
    assert_eq!(
        envelope
            .open(&key)
            .expect("the exact private metadata key must authenticate")
            .as_bytes(),
        plaintext.as_bytes(),
        "authenticated private metadata must reproduce its exact plaintext"
    );

    if reject {
        let wrong_key = PrivateMetadataKey::try_new([0x32; 32])
            .expect("the substituted private-metadata key is nonzero");
        assert_eq!(
            envelope.open(&wrong_key),
            Err(IdentityError::PrivateArtifactAuthenticationFailed),
            "private metadata must reject a substituted key"
        );
    }
}

fn portable_credential_semantics(reject: bool) {
    let issuer = SecretKey::from_bytes(&[0x41; 32]);
    let subject = SecretKey::from_bytes(&[0x42; 32]);
    let issuer_key = SigningPublicKey::ed25519(*issuer.public().as_bytes())
        .expect("the fixed credential issuer key is valid Ed25519 material");
    let subject_key = SigningPublicKey::ed25519(*subject.public().as_bytes())
        .expect("the fixed credential subject key is valid Ed25519 material");
    let account_id = typed_id::<AccountId>(0x43);
    let checkpoint_id = typed_id::<CheckpointId>(0x44);
    let body = PortableCredentialBody::try_new(
        account_id,
        checkpoint_id,
        Epoch::GENESIS,
        vec![subject_key],
        account_id,
        issuer_key,
        Timestamp::from_unix_millis(10),
        Timestamp::from_unix_millis(20),
        vec![
            CredentialClaim::try_new("display-name", b"Ada".to_vec())
                .expect("the fixed credential claim is bounded"),
        ],
        Extensions::default(),
    )
    .expect("the fixed portable credential body must be valid");
    let signature = AlgorithmSignature::new(
        1,
        issuer
            .sign(
                &body
                    .signing_bytes()
                    .expect("the credential body must produce signing bytes"),
            )
            .to_bytes()
            .to_vec(),
    )
    .expect("the fixed credential signature must use the v1 algorithm shape");
    let credential = SignedPortableCredential::try_new(body.clone(), signature)
        .expect("the fixed portable credential signature must verify");
    let context = CredentialVerificationContext::try_new(
        body.account_id(),
        body.checkpoint_id(),
        body.account_epoch(),
        body.issuer_account_id(),
        body.issuer_signing_key(),
        Timestamp::from_unix_millis(19),
    )
    .expect("the fixed credential verification context must be valid");
    let verified = verify_portable_credential(&credential, &context)
        .expect("the fixed portable credential must verify");
    assert_eq!(
        verified.claims().len(),
        1,
        "the fixed portable credential must reveal one selected claim"
    );

    if reject {
        let substituted = CredentialVerificationContext::try_new(
            body.account_id(),
            typed_id::<CheckpointId>(0x45),
            body.account_epoch(),
            body.issuer_account_id(),
            body.issuer_signing_key(),
            Timestamp::from_unix_millis(19),
        )
        .expect("the substituted credential context is structurally valid");
        assert!(
            verify_portable_credential(&credential, &substituted).is_err(),
            "portable credential verification must reject a substituted checkpoint"
        );
    }
}

struct FixedAuthorizationView {
    context: AuthorizationContext,
    status: ApplicationDeviceStatus,
    authorization: DeviceAuthorization,
}

impl ApplicationAuthorizationView for FixedAuthorizationView {
    fn authorization_context(&self) -> AuthorizationContext {
        self.context
    }

    fn device_status(&self, device_id: DeviceId) -> ApplicationDeviceStatus {
        if device_id == self.authorization.device_id() {
            self.status
        } else {
            ApplicationDeviceStatus::Unknown
        }
    }

    fn device_authorization(&self, device_id: DeviceId) -> Option<&DeviceAuthorization> {
        (device_id == self.authorization.device_id()).then_some(&self.authorization)
    }
}

fn application_authorization(secret: &SecretKey) -> DeviceAuthorization {
    let endpoint_secret = SecretKey::from_bytes(&[0x32; 32]);
    let descriptor = DeviceDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes())
            .expect("the fixed application key is valid Ed25519 material"),
        AgreementPublicKey::x25519([
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .expect("the fixed X25519 public key is contributory"),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*endpoint_secret.public().as_bytes())
                .expect("the fixed endpoint key is valid Ed25519 material"),
        ),
        Extensions::default(),
    )
    .expect("the fixed application device descriptor must keep key roles distinct");
    DeviceAuthorization::new(
        descriptor
            .id()
            .expect("the fixed application device must derive an identifier"),
        descriptor,
        DeviceClass::ApplicationOnly,
        None,
        Vec::new(),
        Epoch::new(3),
        Extensions::default(),
    )
    .expect("the fixed application device authorization must be valid")
}

fn application_event_semantics(reject: bool) {
    let secret = SecretKey::from_bytes(&[0x31; 32]);
    let authorization = application_authorization(&secret);
    let context = AuthorizationContext::new(
        typed_id::<AccountId>(0x41),
        Epoch::new(7),
        typed_id::<CheckpointId>(0x42),
    );
    let body = ApplicationEventBody::new(
        context.account_id(),
        ApplicationId::new(Digest::new(HashAlgorithm::Blake3_256, [0x43; 32])),
        authorization.device_id(),
        context.epoch(),
        context.checkpoint_id(),
        ApplicationEventCounter::new(11),
        b"payload".to_vec(),
        Extensions::default(),
    )
    .expect("the fixed application event body must be valid");
    let signature = secret.sign(
        &body
            .signing_bytes()
            .expect("the application event must produce signing bytes"),
    );
    let event = SignedApplicationEvent::new(body, ProtocolSignature::ed25519(signature.to_bytes()))
        .expect("the fixed signed application event must be bounded");
    let view = FixedAuthorizationView {
        context,
        status: ApplicationDeviceStatus::Active,
        authorization,
    };
    assert_eq!(
        verify_application_event(&event, &view).expect("the fixed application event must verify"),
        event
            .application_event_id()
            .expect("the fixed application event must derive an identifier"),
        "application verification must return the complete envelope identifier"
    );

    if reject {
        let rejected_view = FixedAuthorizationView {
            context,
            status: ApplicationDeviceStatus::Revoked,
            authorization: view.authorization.clone(),
        };
        assert_eq!(
            verify_application_event(&event, &rejected_view),
            Err(IdentityError::DeviceRevoked),
            "application verification must reject a revoked device"
        );
    }
}

fn presence_semantics(reject: bool) {
    let application_secret = SecretKey::from_bytes(&[10; 32]);
    let agreement_secret = AgreementSecretKey::from_bytes([11; 32]);
    let endpoint_secret = SecretKey::from_bytes(&[12; 32]);
    let descriptor = DeviceDescriptor::new(
        SigningPublicKey::ed25519(*application_secret.public().as_bytes())
            .expect("the fixed presence application key is valid Ed25519 material"),
        agreement_secret
            .public_key()
            .expect("the fixed presence agreement secret must derive a public key"),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*endpoint_secret.public().as_bytes())
                .expect("the fixed presence endpoint key is valid Ed25519 material"),
        ),
        Extensions::default(),
    )
    .expect("the fixed presence device descriptor must keep key roles distinct");
    let device_id = descriptor
        .id()
        .expect("the fixed presence device must derive an identifier");
    let account_id = typed_id::<AccountId>(1);
    let checkpoint_id = typed_id::<CheckpointId>(2);
    let authorization = DeviceAuthorization::new(
        device_id,
        descriptor.clone(),
        DeviceClass::GeneralPurpose,
        None,
        Vec::new(),
        Epoch::new(7),
        Extensions::default(),
    )
    .expect("the fixed presence authorization must be valid");
    let view = FixedAuthorizationView {
        context: AuthorizationContext::new(account_id, Epoch::new(7), checkpoint_id),
        status: ApplicationDeviceStatus::Active,
        authorization,
    };
    let challenge = DevicePresenceChallenge::new(
        account_id,
        device_id,
        PresenceVerifierChallenge::new([0x31; 32])
            .expect("the fixed presence verifier challenge is nonzero"),
        PresenceSessionId::new([0x41; 32])
            .expect("the fixed presence session identifier is nonzero"),
        Digest::new(HashAlgorithm::Blake3_256, [0x51; 32]),
        checkpoint_id,
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(301_000),
        descriptor.application_signing_key(),
        Extensions::default(),
    )
    .expect("the fixed presence challenge must have a bounded lifetime");
    let signature = application_secret.sign(
        &challenge
            .signing_bytes()
            .expect("the presence challenge must produce signing bytes"),
    );
    let proof = PresenceProof::new(
        challenge.clone(),
        ProtocolSignature::ed25519(signature.to_bytes()),
    )
    .expect("the fixed presence proof must be bounded");
    assert_eq!(
        verify_presence_proof(
            &proof,
            &challenge,
            Timestamp::from_unix_millis(1_000),
            &view,
        )
        .expect("the fixed presence proof must verify"),
        proof
            .proof_id()
            .expect("the fixed presence proof must derive an identifier"),
        "presence verification must return the complete proof identifier"
    );

    if reject {
        let substituted = DevicePresenceChallenge::new(
            challenge.account_id(),
            challenge.device_id(),
            PresenceVerifierChallenge::new([0x32; 32])
                .expect("the substituted presence challenge is nonzero"),
            challenge.session_id(),
            challenge.transcript_binding(),
            challenge.checkpoint_id(),
            challenge.issued_at(),
            challenge.expires_at(),
            challenge.signing_key(),
            Extensions::default(),
        )
        .expect("the substituted presence challenge is structurally valid");
        assert!(
            matches!(
                verify_presence_proof(
                    &proof,
                    &substituted,
                    Timestamp::from_unix_millis(1_000),
                    &view,
                ),
                Err(IdentityError::InvalidRelationship { .. })
            ),
            "presence verification must reject a substituted verifier challenge"
        );
    }
}

fn freshness_semantics(reject: bool) {
    let checkpoint_id = typed_id::<CheckpointId>(0x21);
    let context =
        AuthorizationContext::new(typed_id::<AccountId>(0x20), Epoch::new(4), checkpoint_id);
    let policy = ProviderPolicy::local_only(ProviderPolicyVersion::GENESIS, Extensions::default())
        .expect("the fixed local-only provider policy must be valid");
    let evidence = FreshnessEvidence::local_known(checkpoint_id);
    let decision = evaluate_freshness(
        context,
        &policy,
        FreshnessRequirement::latest_known(),
        FreshnessRequirement::latest_known(),
        &evidence,
        Timestamp::from_unix_millis(1_000),
    )
    .expect("latest-known evidence must verify for its exact checkpoint");
    assert_eq!(
        decision.context(),
        context,
        "freshness evaluation must retain the exact authorization context"
    );

    if reject {
        let substituted = FreshnessEvidence::local_known(typed_id::<CheckpointId>(0x22));
        assert!(
            evaluate_freshness(
                context,
                &policy,
                FreshnessRequirement::latest_known(),
                FreshnessRequirement::latest_known(),
                &substituted,
                Timestamp::from_unix_millis(1_000),
            )
            .is_err(),
            "freshness evaluation must reject a substituted checkpoint"
        );
    }
}

fn operational_effect_semantics(reject: bool) {
    let genesis = AccountGenesis::from_canonical_bytes(include_bytes!(
        "../../protocols/krikos-identity/tests/vectors/account-genesis.bin"
    ))
    .expect("the reviewed account genesis fixture must remain canonical");
    let event = AuthorizedEvent::from_canonical_bytes(include_bytes!(
        "../../protocols/krikos-identity/tests/vectors/authorized-event.bin"
    ))
    .expect("the reviewed authorized event fixture must remain canonical");
    let account_id = genesis
        .account_id()
        .expect("the reviewed account genesis must derive an identifier");
    let account_store = MemoryAccountStore::new();
    let initial = block_on(account_store.create_account(genesis))
        .expect("the fixed account must be created once in its private store");
    let committed = block_on(account_store.commit_event(initial.revision().clone(), event))
        .expect("the reviewed event must commit against its matching genesis");
    let lease_id = LeaseId::new([0x51; 16]).expect("the fixed effect lease is nonzero");
    let claimed = block_on(
        account_store.claim_effects(
            account_id,
            ClaimEffects::new(
                Timestamp::from_unix_millis(200),
                Timestamp::from_unix_millis(250),
                lease_id,
                8,
            )
            .expect("the fixed effect claim is time-ordered and bounded"),
        ),
    )
    .expect("the fixed account effects must be claimable");
    let notification = claimed
        .into_iter()
        .find(|effect| {
            matches!(
                effect.effect(),
                ProjectionEffect::NotifyAccountChanged { .. }
            )
        })
        .expect("the committed account event must request one change notification");
    assert_eq!(
        committed.snapshot().state().account_id(),
        account_id,
        "the committed event must retain the genesis account identity"
    );

    let journal = OperationalEffectJournal::new(MemoryOperationalEffectStore::new());
    assert_eq!(
        journal
            .begin(&notification, Timestamp::from_unix_millis(201))
            .expect("the claimed notification effect must begin journaling")
            .phase(),
        OperationalEffectPhase::Claimed,
        "a new operational journal must begin in the claimed phase"
    );
    assert_eq!(
        journal
            .record_peers_notified(notification.id(), Timestamp::from_unix_millis(202))
            .expect("the notification effect must record peer completion")
            .phase(),
        OperationalEffectPhase::PeersNotified,
        "peer notification must advance the operational phase"
    );
    assert_eq!(
        journal
            .record_completed(notification.id(), Timestamp::from_unix_millis(203))
            .expect("a peer-notified effect must complete")
            .phase(),
        OperationalEffectPhase::Completed,
        "the valid notification journal must reach completion"
    );

    if reject {
        let rejected_journal = OperationalEffectJournal::new(MemoryOperationalEffectStore::new());
        rejected_journal
            .begin(&notification, Timestamp::from_unix_millis(201))
            .expect("the rejected-path journal must begin from the same valid claim");
        assert!(
            rejected_journal
                .record_completed(notification.id(), Timestamp::from_unix_millis(202))
                .is_err(),
            "a notification effect must reject completion before peers are notified"
        );
    }
}

struct AllowProviderAdmission;

impl ProviderAdmissionControl for AllowProviderAdmission {
    fn check(
        &self,
        _admission: ProviderLogAdmission,
        _request: ProviderAdmissionRequest,
    ) -> Result<(), IdentityError> {
        Ok(())
    }
}

struct SemanticProviderSigner(SecretKey);

impl ProviderHeadSigner for SemanticProviderSigner {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

fn semantic_checkpoint_bundle() -> ProviderCheckpointBundle {
    let genesis = AccountGenesis::from_canonical_bytes(include_bytes!(
        "../../protocols/krikos-identity/tests/vectors/account-genesis.bin"
    ))
    .expect("the reviewed account genesis fixture must remain canonical");
    let event = AuthorizedEvent::from_canonical_bytes(include_bytes!(
        "../../protocols/krikos-identity/tests/vectors/authorized-event.bin"
    ))
    .expect("the reviewed authorized event fixture must remain canonical");
    let checkpoint = SignedCheckpoint::from_canonical_bytes(include_bytes!(
        "../../protocols/krikos-identity/tests/vectors/checkpoint-direct.bin"
    ))
    .expect("the reviewed signed checkpoint fixture must remain canonical");
    build_provider_checkpoint_bundle_from_genesis(&genesis, &[event], &checkpoint, None)
        .expect("the reviewed genesis, event, and checkpoint must form one provider bundle")
}

fn semantic_recovery_export(generation: ProviderGenerationExport) -> ProviderRecoveryExport {
    let audit = MemoryProviderAuditStore::new(generation.provider().clone(), generation.log_id());
    let auditor = DurableProviderAuditor::new(audit.clone());
    if let Some(head) = generation.latest_head() {
        auditor
            .observe(head.clone(), None)
            .expect("the authenticated provider head must enter its audit journal");
    }
    ProviderRecoveryExport::new(
        generation,
        audit
            .snapshot()
            .expect("the semantic provider audit snapshot must be durable"),
    )
    .expect("the generation and audit snapshot must bind exactly")
}

fn provider_retention_semantics(reject: bool) {
    let signer = SemanticProviderSigner(SecretKey::from_bytes(&[0x71; 32]));
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*signer.0.public().as_bytes())
            .expect("the fixed provider signing key is valid"),
        Extensions::default(),
    )
    .expect("the fixed provider descriptor must be valid");
    let log_id = typed_id::<ProviderLogId>(0x72);
    let store = MemoryProviderStore::new(provider, log_id, ProviderKeyVersion::GENESIS)
        .expect("the fixed provider generation must open");
    let bundle = semantic_checkpoint_bundle();
    let admission = bundle.provider_log_admission();
    let request = ProviderAdmissionRequest::for_admission(&admission)
        .expect("the fixed provider admission must be bounded");
    let receipt = store
        .append(
            authorize_provider_append(admission, request, &AllowProviderAdmission)
                .expect("the verified provider admission must yield an opaque permit"),
            Timestamp::from_unix_millis(1_000),
            &signer,
        )
        .expect("the fixed provider checkpoint must append atomically");
    assert_eq!(receipt.leaf_index(), 0);
    let route = store
        .generation_route()
        .expect("the fixed provider route must be exact");
    let recovery = semantic_recovery_export(
        store
            .export_generation()
            .expect("the active generation must export"),
    );
    let inventory = derive_provider_retention_inventory(&recovery)
        .expect("the authenticated generation must derive mandatory retention");
    let authorization = verify_provider_compaction(&recovery, &recovery, &inventory)
        .expect("an exact full archive must authorize local sealing");
    store
        .seal_after_verified_mirror(&authorization, &recovery, &inventory)
        .expect("the exact archive must seal the active generation");

    let account_id = bundle
        .verified_checkpoint()
        .checkpoint()
        .body()
        .account_id();
    let retained = store
        .latest_retained_checkpoint_evidence(account_id)
        .expect("sealed current checkpoint evidence must remain queryable")
        .expect("the fixed account must retain its current checkpoint evidence");
    let reconstructed = build_provider_checkpoint_bundle_from_genesis(
        retained
            .genesis()
            .expect("the fixed retained checkpoint must retain its genesis anchor"),
        retained.events(),
        retained.checkpoint(),
        retained.transition_event(),
    )
    .expect("raw retained evidence must remain independently verifiable");
    assert_eq!(
        reconstructed.verified_checkpoint().checkpoint_id(),
        bundle.verified_checkpoint().checkpoint_id(),
        "retained evidence may reconstruct proof material but not mutate the sealed generation"
    );

    let archive = MemoryProviderStore::restore_recovery(recovery.clone())
        .expect("the full recovery archive must restore read-only");
    assert_eq!(
        archive
            .archived_recovery_export()
            .expect("the restored archive must reproduce its exact recovery export"),
        recovery
    );
    let mut registry = ProviderGenerationRegistry::new();
    assert_eq!(
        registry
            .insert(store.clone())
            .expect("the sealed generation must register under its exact route"),
        route
    );
    assert!(
        registry.insert(archive).is_err(),
        "an archive cannot replace or duplicate an existing generation route"
    );

    if reject {
        let replay_admission = bundle.provider_log_admission();
        let replay_request = ProviderAdmissionRequest::for_admission(&replay_admission)
            .expect("the replay admission remains structurally bounded");
        assert_eq!(
            store.append(
                authorize_provider_append(
                    replay_admission,
                    replay_request,
                    &AllowProviderAdmission,
                )
                .expect("the replay remains a verified opaque admission"),
                Timestamp::from_unix_millis(1_001),
                &signer,
            ),
            Err(IdentityError::ProviderArchiveRequired),
            "raw retained evidence must not authorize a write to a sealed generation"
        );
    }
}

fn run_semantic_selector(selector: u8, payload: &[u8]) {
    let reject = reject_relationship(payload);
    match selector {
        53 => guardian_authority_semantics(reject),
        54 => social_semantics(reject),
        55 => name_semantics(reject),
        56 => private_metadata_semantics(reject),
        57 => portable_credential_semantics(reject),
        58 => application_event_semantics(reject),
        59 => presence_semantics(reject),
        60 => freshness_semantics(reject),
        61 => operational_effect_semantics(reject),
        62 => provider_retention_semantics(reject),
        _ => {}
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&selector, payload)) = input.split_first() else {
        return;
    };
    if payload.len() > MAX_SEMANTICS_PAYLOAD_BYTES {
        return;
    }

    let decoder_count = IDENTITY_SEMANTICS_TYPE_NAMES.len();
    assert_eq!(
        decoder_count,
        IDENTITY_SEMANTICS_DECODERS.len(),
        "identity semantics names and decoder registry must remain aligned"
    );
    match usize::from(selector) {
        decoder_index @ 0..=52 => {
            let Some(decoder) = IDENTITY_SEMANTICS_DECODERS.get(decoder_index) else {
                return;
            };
            decoder(payload);
        }
        53..=62 => run_semantic_selector(selector, payload),
        _ => {}
    }
});
