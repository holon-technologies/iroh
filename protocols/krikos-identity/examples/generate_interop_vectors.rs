//! Regenerate the checked-in identity-protocol interoperability assets.
//!
//! This tool is intentionally separate from the validator. Run it explicitly with
//! `cargo run -p krikos-identity --example generate_interop_vectors` and review every changed
//! binary and metadata entry. Normal tests never write fixture files.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

use krikos_base::SecretKey;
use krikos_identity::{
    merkle::{
        MerkleConsistencyProof, MerkleInclusionProof, MerkleNonMembershipProof, MerkleSetLeaf,
    },
    net::{
        AuthorizedCheckpointRequest, AuthorizedProposalRequest, AuthorizedSyncRequest,
        EndpointAuthorizationRequest, IdentityProtocolAck, IdentityProtocolKind,
        IdentityProtocolReply, IdentityServiceOutcome,
    },
    *,
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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

struct InteropProviderSigner<'a>(&'a SecretKey);

impl ProviderHeadSigner for InteropProviderSigner<'_> {
    fn sign_provider_head(&self, message: &[u8]) -> Result<ProtocolSignature, IdentityError> {
        Ok(ProtocolSignature::ed25519(self.0.sign(message).to_bytes()))
    }
}

#[allow(dead_code, unused_imports)]
mod task2 {
    include!("../tests/task2_golden_vectors.rs");

    pub(super) fn operations() -> Vec<AccountOperation> {
        account_operations()
    }

    pub(super) fn recovery_values() -> (
        RecoveryProposal,
        BeginRecovery,
        VetoRecovery,
        CancelRecovery,
        FinalizeRecovery,
        GuardianApprovalBody,
        SignedGuardianApproval,
        GuardianApprovalSet,
        RecoveryThresholdEvidence,
    ) {
        let proposal = recovery_proposal();
        let (begin, veto, cancel, finalize) = recovery_operations();
        let (body, signed, approvals, evidence) = guardian_evidence();
        (
            proposal,
            proposal_to_begin(begin),
            veto,
            cancel,
            finalize,
            body,
            signed,
            approvals,
            evidence,
        )
    }

    fn proposal_to_begin(begin: BeginRecovery) -> BeginRecovery {
        begin
    }

    pub(super) fn migration_values() -> (BeginCryptoMigration, CryptoMigrationId) {
        migration_parts()
    }

    pub(super) fn recovery_plan_anchor_and_fork()
    -> (RecoveryAuthorityPlan, RecoveryDelayAnchor, ForkDescriptor) {
        let proposal = recovery_proposal();
        let (_, _, _, finalize) = recovery_operations();
        let fork = account_operations()
            .into_iter()
            .find_map(|operation| match operation {
                AccountOperation::ResolveFork(resolution) => Some(resolution.fork().clone()),
                _ => None,
            })
            .unwrap();
        (
            proposal.plan().clone(),
            finalize.delay_anchor().clone(),
            fork,
        )
    }

    fn transition_event(operation: AccountOperation, fill: u8) -> AuthorizedEvent {
        let requires_empty_approvals = matches!(operation, AccountOperation::FinalizeRecovery(_));
        let body = EventBody::new(
            typed_id::<AccountId>(1),
            Sequence::new(1),
            Epoch::new(1),
            EventPredecessors::genesis(typed_id::<GenesisAnchor>(fill)),
            operation,
            Timestamp::from_unix_millis(u64::from(fill)),
            [fill; 16],
            Extensions::default(),
        )
        .unwrap();
        let checkpoint_id = typed_id::<CheckpointId>(fill.wrapping_add(1));
        let evidence = AdmissionEvidence::new(
            body.proposal_id().unwrap(),
            checkpoint_id,
            typed_id::<ProviderPolicyId>(fill.wrapping_add(2)),
            FreshnessEvidence::local_known(checkpoint_id),
            DelayEvidence::none(),
            Extensions::default(),
        )
        .unwrap();
        let event_id = evidence.event_id_for_body(&body).unwrap();
        let approvals = if requires_empty_approvals {
            Vec::new()
        } else {
            vec![
                SignedControllerApproval::new(
                    ControllerApprovalBody::event(
                        typed_id::<ControllerId>(fill.wrapping_add(3)),
                        event_id,
                        evidence.admission_evidence_id().unwrap(),
                        Extensions::default(),
                    )
                    .unwrap(),
                    vec![keyed_signature(fill.wrapping_add(4))],
                )
                .unwrap(),
            ]
        };
        AuthorizedEvent::new(body, evidence, ControllerApprovals::new(approvals).unwrap()).unwrap()
    }

    fn transition_checkpoint(
        event: &AuthorizedEvent,
        lifecycle: AccountLifecycle,
    ) -> SignedCheckpoint {
        let body = CheckpointBody::new(
            event.body().account_id(),
            Epoch::new(2),
            Sequence::new(2),
            event.event_id().unwrap(),
            digest(0xa1),
            digest(0xa2),
            digest(0xa3),
            typed_id::<ControlPolicyId>(0xa4),
            typed_id::<RecoveryPolicyId>(0xa5),
            typed_id::<ProviderPolicyId>(0xa6),
            typed_id::<CryptoStateId>(0xa7),
            lifecycle,
            Timestamp::from_unix_millis(900),
            Extensions::default(),
        )
        .unwrap();
        SignedCheckpoint::new(
            body,
            CheckpointAuthorization::transition_derived(event).unwrap(),
        )
        .unwrap()
    }

    pub(super) fn transition_checkpoints() -> (SignedCheckpoint, SignedCheckpoint) {
        let (_, _, _, finalize) = recovery_operations();
        let finalize_event = transition_event(AccountOperation::FinalizeRecovery(finalize), 0xb0);
        let retire_event = transition_authorized_event();
        (
            transition_checkpoint(&finalize_event, AccountLifecycle::Active),
            transition_checkpoint(&retire_event, AccountLifecycle::Retired),
        )
    }
}

#[allow(dead_code, unused_imports)]
mod backup {
    include!("../tests/private_backup.rs");

    pub(super) struct Fixture {
        pub signer: SecretKey,
        pub genesis: AccountGenesis,
        pub event: krikos_identity::AuthorizedEvent,
        pub checkpoint: SignedCheckpoint,
        pub bundle: BackupAuthorityBundle,
        pub envelope: BackupEnvelope,
    }

    pub(super) fn fixture() -> Fixture {
        let signer = SecretKey::from_bytes(&[0x11; 32]);
        let genesis = genesis(&signer);
        let mut state = AccountState::from_genesis(&genesis).unwrap();
        let event = authorized_event(&state, &signer);
        state.validate_and_apply(&event).unwrap();
        let checkpoint = signed_checkpoint(
            &state,
            &signer,
            build_checkpoint_body(&state, Timestamp::from_unix_millis(99)).unwrap(),
        );
        let bundle = BackupAuthorityBundle::try_new(
            genesis.clone(),
            vec![event.clone()],
            checkpoint.clone(),
        )
        .unwrap();
        let passphrase =
            BackupPassphrase::try_new(b"correct horse battery staple".to_vec()).unwrap();
        let envelope = BackupEnvelope::seal_with_rng(
            context(&bundle),
            &passphrase,
            &bundle,
            None,
            &mut RepeatingRng(0x64),
        )
        .unwrap();
        Fixture {
            signer,
            genesis,
            event,
            checkpoint,
            bundle,
            envelope,
        }
    }

    pub(super) fn migration_checkpoints() -> (SignedCheckpoint, SignedCheckpoint) {
        let signer = SecretKey::from_bytes(&[0x11; 32]);
        let genesis = genesis(&signer);
        let mut state = AccountState::from_genesis(&genesis).unwrap();
        let event = authorized_event(&state, &signer);
        state.validate_and_apply(&event).unwrap();
        let make = |lifecycle| {
            let body = CheckpointBody::new(
                state.account_id(),
                state.epoch(),
                state.sequence(),
                event.event_id().unwrap(),
                Digest::new(HashAlgorithm::Blake3_256, [0xc1; 32]),
                Digest::new(HashAlgorithm::Blake3_256, [0xc2; 32]),
                Digest::new(HashAlgorithm::Blake3_256, [0xc3; 32]),
                state.control_policy_id(),
                state.recovery_policy_id(),
                state.provider_policy_id(),
                typed_id::<krikos_identity::CryptoStateId>(0xc4),
                lifecycle,
                Timestamp::from_unix_millis(101),
                Extensions::default(),
            )
            .unwrap();
            signed_checkpoint(&state, &signer, body)
        };
        (
            make(krikos_identity::AccountLifecycle::MigrationPending),
            make(krikos_identity::AccountLifecycle::MigrationDual),
        )
    }
}

#[allow(dead_code, unused_imports)]
mod application_fixture {
    include!("../tests/application_verification.rs");

    pub(super) fn fixture() -> (SecretKey, DeviceAuthorization, SignedApplicationEvent) {
        let secret = SecretKey::from_bytes(&[0x31; 32]);
        let authorization = fixture_authorization(&secret);
        let event = signed_event(&secret, &authorization, context(), b"payload".to_vec());
        (secret, authorization, event)
    }
}

#[allow(dead_code, unused_imports)]
mod capability_fixture {
    include!("../tests/capability_schema.rs");

    pub(super) struct Fixture {
        pub secret: krikos_base::SecretKey,
        pub grant: CapabilityGrant,
        pub root: CapabilityRoot,
        pub body: DelegationBody,
        pub signed: SignedDelegation,
        pub chain: DelegationChain,
    }

    pub(super) fn fixture() -> Fixture {
        let secret = krikos_base::SecretKey::from_bytes(&[0x35; 32]);
        let root_grant = grant(
            ResourceSelector::prefix(path(&[b"collection"])).unwrap(),
            vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(1))],
            DelegationPermission::delegable(DelegationDepth::new(2).unwrap()),
            Some(Timestamp::from_unix_millis(300)),
        );
        let root = CapabilityRoot::new(
            context(1, 1),
            device_id(10),
            root_grant.clone(),
            Extensions::default(),
        )
        .unwrap();
        let grant = grant(
            ResourceSelector::prefix(path(&[b"collection", b"blue"])).unwrap(),
            vec![CapabilityConstraint::AccountEpochAtLeast(Epoch::new(2))],
            DelegationPermission::delegable(DelegationDepth::new(1).unwrap()),
            Some(Timestamp::from_unix_millis(250)),
        );
        let body = DelegationBody::new(
            root_grant.capability_grant_id().unwrap(),
            grant.clone(),
            device_id(10),
            device_id(11),
            context(1, 2),
            Timestamp::from_unix_millis(20),
            [1; 16],
            Extensions::default(),
        )
        .unwrap();
        let signature = secret.sign(&body.to_canonical_bytes().unwrap());
        let signed = SignedDelegation::new(
            body.clone(),
            ProtocolSignature::ed25519(signature.to_bytes()),
        );
        let chain = DelegationChain::new(root.clone(), vec![signed.clone()]).unwrap();
        Fixture {
            secret,
            grant,
            root,
            body,
            signed,
            chain,
        }
    }
}

#[allow(dead_code, unused_imports)]
mod key_wrap_fixture {
    include!("../tests/key_rotation.rs");

    pub(super) fn fixture() -> (
        GroupKeyWrapHeader,
        WrappedGroupKey,
        krikos_identity::RecipientKeyWraps,
    ) {
        let recipient_secret = AgreementSecretKey::from_bytes([0x20; 32]);
        let recipient = authorization(&recipient_secret, 0, 1);
        let (state, _) = active_state(std::slice::from_ref(&recipient));
        let snapshot = snapshot(&state, vec![recipient.device_id()]);
        let mut random = ScriptedRng::new((0x40_u8..=0x77).collect());
        let rotation =
            rotate_group_key_with_rng(&snapshot, &GroupKey::new([0x90; 32]), &mut random).unwrap();
        let wraps = rotation.recipient_key_wraps().clone();
        let wrapped = wraps.as_slice()[0].clone();
        (wrapped.header().clone(), wrapped, wraps)
    }
}

#[allow(dead_code, unused_imports)]
mod private_metadata_fixture {
    include!("../tests/private_artifacts.rs");

    pub(super) fn fixture() -> (PrivateArtifactContext, PrivateMetadataEnvelope) {
        let context = context();
        let key = PrivateMetadataKey::try_new([0x31; 32]).unwrap();
        let plaintext =
            PrivateMetadata::try_new(b"private profile: alpine orchid".to_vec()).unwrap();
        let envelope = PrivateMetadataEnvelope::seal_with_rng(
            context.clone(),
            &key,
            &plaintext,
            &mut RepeatingRng(0x41),
        )
        .unwrap();
        (context, envelope)
    }
}

#[allow(dead_code, unused_imports)]
mod portable_fixture {
    include!("../tests/privacy_boundaries.rs");

    pub(super) fn fixture() -> (SecretKey, SignedPortableCredential) {
        let secret = SecretKey::from_bytes(&[0x41; 32]);
        let issuer_key = SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap();
        let subject_key =
            SigningPublicKey::ed25519(*SecretKey::from_bytes(&[0x42; 32]).public().as_bytes())
                .unwrap();
        let account = typed_id::<AccountId>(0x43);
        let body = PortableCredentialBody::try_new(
            account,
            typed_id::<CheckpointId>(0x44),
            Epoch::GENESIS,
            vec![subject_key],
            account,
            issuer_key,
            Timestamp::from_unix_millis(10),
            Timestamp::from_unix_millis(20),
            vec![CredentialClaim::try_new("display-name", b"Ada".to_vec()).unwrap()],
            Extensions::default(),
        )
        .unwrap();
        let signature = AlgorithmSignature::new(
            1,
            secret
                .sign(&body.signing_bytes().unwrap())
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        (
            secret,
            SignedPortableCredential::try_new(body, signature).unwrap(),
        )
    }
}

#[allow(dead_code, unused_imports)]
mod social_fixture {
    include!("../tests/social.rs");

    pub(super) fn fixture() -> (SecretKey, SignedSocialAttestation) {
        let issuer = SecretKey::from_bytes(&[0x11; 32]);
        let subject = SecretKey::from_bytes(&[0x12; 32]);
        let value = signed_attestation(
            &issuer,
            typed_id::<AccountId>(0x13),
            typed_id::<CheckpointId>(0x14),
            &subject,
            typed_id::<AccountId>(0x15),
            typed_id::<CheckpointId>(0x16),
            0x17,
        );
        (issuer, value)
    }
}

#[allow(dead_code, unused_imports)]
mod name_fixture {
    include!("../tests/names.rs");

    pub(super) fn fixture() -> (SecretKey, SignedNameClaim) {
        let secret = SecretKey::from_bytes(&[0x41; 32]);
        let value = signed_claim(
            "alice.example",
            &secret,
            typed_id::<AccountId>(0x42),
            typed_id::<CheckpointId>(0x43),
            10,
            Some(20),
        );
        (secret, value)
    }
}

#[allow(dead_code, unused_imports)]
mod guardian_fixture {
    include!("../tests/recovery_guardians.rs");

    pub(super) fn fixture() -> (
        SecretKey,
        GuardianApprovalBody,
        SignedGuardianApproval,
        GuardianApprovalSet,
        krikos_identity::RecoveryThresholdEvidence,
    ) {
        let universe = GuardianUniverse::new(2);
        let context = universe.context(GuardianApprovalDecision::Begin);
        let signed = universe.approval(0, 0, context, APPROVED_AT);
        let approvals = universe.approvals(&[0, 1]);
        let body = signed.body().clone();
        let evidence = krikos_identity::RecoveryThresholdEvidence::guardian_approvals(
            universe.policy.id().unwrap(),
            POLICY_VERSION,
            approvals.clone(),
        )
        .unwrap();
        (
            SecretKey::from_bytes(&[1; 32]),
            body,
            signed,
            approvals,
            evidence,
        )
    }
}

#[allow(dead_code, unused_imports)]
mod transparency_fixture {
    include!("../tests/transparency_crypto.rs");

    pub(super) struct Fixture {
        pub secret: SecretKey,
        pub provider: ProviderDescriptor,
        pub entry: ProviderLogEntryBody,
        pub head: SignedProviderHead,
        pub receipt: InclusionReceipt,
        pub receipts: krikos_identity::ProviderReceipts,
        pub evidence: ProviderEquivocationEvidence,
    }

    pub(super) fn fixture() -> Fixture {
        let secret = SecretKey::from_bytes(&[0x71; 32]);
        let provider = provider_descriptor(&secret);
        let entry = entry(&provider, 100);
        let root = entry.merkle_leaf_hash().unwrap();
        let head = signed_head(&secret, &provider, root, 1, 105);
        let receipt = InclusionReceipt::new(entry.clone(), 0, Vec::new(), head.clone()).unwrap();
        let receipts = krikos_identity::ProviderReceipts::new(vec![receipt.clone()]).unwrap();
        let conflicting = signed_head(
            &secret,
            &provider,
            Digest::new(HashAlgorithm::Blake3_256, [0x99; 32]),
            1,
            106,
        );
        let evidence =
            ProviderEquivocationEvidence::new(&provider, head.clone(), conflicting).unwrap();
        Fixture {
            secret,
            provider,
            entry,
            head,
            receipt,
            receipts,
            evidence,
        }
    }
}

#[derive(Serialize)]
struct Manifest {
    format: &'static str,
    format_version: u16,
    binding_schema_version: u16,
    derivation_schema_version: u16,
    canonical_profile: &'static str,
    algorithms: BTreeMap<&'static str, &'static str>,
    deterministic_keys: Vec<KeyMetadata>,
    private_wire_exclusions: Vec<Exclusion>,
    transient_wire_dispositions: Vec<Exclusion>,
    required_inventory: Vec<String>,
    vectors: Vec<VectorMetadata>,
}

#[derive(Serialize)]
struct KeyMetadata {
    name: &'static str,
    algorithm: &'static str,
    test_only_secret_seed_hex: String,
    public_key_hex: String,
}

#[derive(Serialize)]
struct Exclusion {
    wire_type: &'static str,
    reason: &'static str,
    covered_by: &'static str,
}

#[derive(Serialize)]
struct VectorMetadata {
    name: String,
    wire_type: &'static str,
    canonical_file: String,
    canonical_hex: String,
    canonical_blake3_hex: String,
    encoded_length: usize,
    protocol_version: Option<u16>,
    version_scope: &'static str,
    algorithms: Vec<&'static str>,
    expected_ids: BTreeMap<&'static str, String>,
    signature_bindings: Vec<SignatureBinding>,
    mac_bindings: Vec<MacBinding>,
    derivations: Vec<DerivationMetadata>,
    dependencies: Vec<String>,
    tamper_cases: Vec<TamperMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SignatureBinding {
    name: String,
    algorithm: &'static str,
    domain_ascii: &'static str,
    message_hex: String,
    signer_key: &'static str,
    public_key_hex: String,
    signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MacBinding {
    name: String,
    algorithm: &'static str,
    key_derivation_algorithm: &'static str,
    key_derivation_context_ascii: &'static str,
    key_derivation_input_hex: String,
    message_domain_ascii: &'static str,
    message_hex: String,
    expected_mac_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DerivationMetadata {
    output_name: &'static str,
    algorithm: &'static str,
    domain_or_context_ascii: &'static str,
    message_hex: String,
    expected_output_hex: String,
}

#[derive(Serialize)]
struct TamperMetadata {
    name: &'static str,
    offset: usize,
    replacement_hex: String,
    expectation: &'static str,
}

struct Catalog {
    directory: PathBuf,
    vectors: Vec<VectorMetadata>,
}

struct VectorDetails {
    protocol_version: Option<u16>,
    version_scope: &'static str,
    algorithms: Vec<&'static str>,
    signature_bindings: Vec<SignatureBinding>,
    mac_bindings: Vec<MacBinding>,
    derivations: Vec<DerivationMetadata>,
    expected_ids: BTreeMap<&'static str, String>,
    dependencies: Vec<String>,
    tamper_expectation: &'static str,
}

impl Default for VectorDetails {
    fn default() -> Self {
        Self {
            protocol_version: Some(1),
            version_scope: "authoritative-top-level-v1",
            algorithms: vec!["BLAKE3-256"],
            signature_bindings: Vec::new(),
            mac_bindings: Vec::new(),
            derivations: Vec::new(),
            expected_ids: BTreeMap::new(),
            dependencies: Vec::new(),
            tamper_expectation: "canonical_digest_mismatch",
        }
    }
}

impl Catalog {
    fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            vectors: Vec::new(),
        }
    }

    fn add<T: CanonicalWire>(
        &mut self,
        name: impl Into<String>,
        wire_type: &'static str,
        value: &T,
        details: VectorDetails,
    ) {
        let name = name.into();
        let bytes = value.to_canonical_bytes().unwrap();
        let filename = format!("{name}.bin");
        fs::write(self.directory.join(&filename), &bytes).unwrap();
        let tamper_offset = match details.tamper_expectation {
            "signature_invalid_or_decode_rejected" => {
                let signature = details
                    .signature_bindings
                    .first()
                    .map(|binding| hex::decode(&binding.signature_hex).unwrap())
                    .expect("signed vector signature");
                bytes
                    .windows(signature.len())
                    .position(|window| window == signature.as_slice())
                    .and_then(|offset| offset.checked_add(signature.len().saturating_sub(1)))
                    .expect("signature bytes must occur in the signed canonical envelope")
            }
            "authentication_or_decode_rejected"
            | "private_metadata_authentication_rejected"
            | "key_wrap_authentication_rejected"
            | "merkle_proof_rejected"
            | "cursor_authentication_rejected" => bytes.len().saturating_sub(2),
            "identifier_or_binding_rejected" if wire_type == "PairingConfirmationContext" => 33,
            "identifier_or_binding_rejected" => bytes.len() / 2,
            _ => 0,
        };
        let replacement = if bytes.get(tamper_offset).copied().unwrap_or(0) == 0 {
            0xff
        } else {
            0
        };
        let mut derivations = derivations_for_wire_type(wire_type, &bytes);
        derivations.extend(details.derivations);
        let mut expected_ids = details.expected_ids;
        for derivation in &derivations {
            expected_ids
                .entry(derivation.output_name)
                .or_insert_with(|| format!("b3:{}", derivation.expected_output_hex));
        }
        self.vectors.push(VectorMetadata {
            name,
            wire_type,
            canonical_file: filename,
            canonical_hex: hex::encode(&bytes),
            canonical_blake3_hex: blake3::hash(&bytes).to_hex().to_string(),
            encoded_length: bytes.len(),
            protocol_version: details.protocol_version,
            version_scope: details.version_scope,
            algorithms: details.algorithms,
            expected_ids,
            signature_bindings: details.signature_bindings,
            mac_bindings: details.mac_bindings,
            derivations,
            dependencies: details.dependencies,
            tamper_cases: vec![TamperMetadata {
                name: "replace-bound-byte",
                offset: tamper_offset,
                replacement_hex: hex::encode([replacement]),
                expectation: details.tamper_expectation,
            }],
        });
    }
}

fn digest_hex(digest: &Digest) -> String {
    hex::encode(digest.as_bytes())
}

fn domain_derivation(
    output_name: &'static str,
    domain: &'static str,
    message: Vec<u8>,
    digest: &Digest,
) -> DerivationMetadata {
    DerivationMetadata {
        output_name,
        algorithm: "BLAKE3-256(domain || 0x00 || message)",
        domain_or_context_ascii: domain,
        message_hex: hex::encode(message),
        expected_output_hex: digest_hex(digest),
    }
}

fn derive_key_derivation(
    output_name: &'static str,
    context: &'static str,
    message: Vec<u8>,
    digest: &Digest,
) -> DerivationMetadata {
    DerivationMetadata {
        output_name,
        algorithm: "BLAKE3 derive_key(context, message)",
        domain_or_context_ascii: context,
        message_hex: hex::encode(message),
        expected_output_hex: digest_hex(digest),
    }
}

fn network_request_commitment_derivation(
    ack: &IdentityProtocolAck,
    canonical_request: &[u8],
) -> DerivationMetadata {
    let mut message = Vec::with_capacity(canonical_request.len().saturating_add(2));
    message.extend_from_slice(&ack.protocol().unwrap().code().to_be_bytes());
    message.extend_from_slice(canonical_request);
    derive_key_derivation(
        "network_request_commitment",
        "KRIKOS-ID/network-request-commitment/v1",
        message,
        &ack.request_commitment(),
    )
}

#[derive(Serialize)]
struct ProviderAnchorCommitmentPreimageMirror<'a> {
    format_version: u16,
    manifest: &'a ProviderCompactionManifest,
}

fn provider_anchor_commitment_derivation(
    anchor: OpaqueProviderAnchorCommitment,
    manifest: &ProviderCompactionManifest,
) -> DerivationMetadata {
    let message = postcard::to_stdvec(&ProviderAnchorCommitmentPreimageMirror {
        format_version: 1,
        manifest,
    })
    .unwrap();
    domain_derivation(
        "provider_anchor_commitment",
        "KRIKOS-ID/provider-anchor-commitment/v1",
        message,
        &anchor.digest(),
    )
}

#[derive(Serialize)]
struct ProviderChunkListCommitmentMirror<'a> {
    format_version: u16,
    component_code: u16,
    chunk_count: u32,
    commitments: &'a [Digest],
}

fn provider_chunk_list_derivation(
    output_name: &'static str,
    domain: &'static str,
    component_code: u16,
    commitments: &[Digest],
) -> DerivationMetadata {
    let message = postcard::to_stdvec(&ProviderChunkListCommitmentMirror {
        format_version: 1,
        component_code,
        chunk_count: u32::try_from(commitments.len()).unwrap(),
        commitments,
    })
    .unwrap();
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(&message);
    let digest = Digest::new(HashAlgorithm::Blake3_256, *hasher.finalize().as_bytes());
    domain_derivation(output_name, domain, message, &digest)
}

const MERKLE_INTERMEDIATE_OUTPUT_NAMES: [&str; 8] = [
    "merkle_node_1",
    "merkle_node_2",
    "merkle_node_3",
    "merkle_node_4",
    "merkle_node_5",
    "merkle_node_6",
    "merkle_node_7",
    "merkle_node_8",
];

fn merkle_domain_digest(domain: &str, message: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher.update(message);
    Digest::new(HashAlgorithm::Blake3_256, *hasher.finalize().as_bytes())
}

fn merkle_leaf_derivation(output_name: &'static str, leaf: &MerkleSetLeaf) -> DerivationMetadata {
    let message =
        postcard::to_stdvec(&(leaf.key().type_tag(), leaf.key().id(), leaf.value_hash())).unwrap();
    let digest = merkle_domain_digest("KRIKOS-ID/merkle-leaf/v1", &message);
    domain_derivation(output_name, "KRIKOS-ID/merkle-leaf/v1", message, &digest)
}

fn merkle_node_step(left: Digest, right: Digest) -> (Vec<u8>, Digest) {
    let message = postcard::to_stdvec(&(left, right)).unwrap();
    let digest = merkle_domain_digest("KRIKOS-ID/merkle-node/v1", &message);
    (message, digest)
}

fn merkle_split(tree_size: u64) -> u64 {
    assert!(tree_size > 1);
    let mut split = 1_u64;
    while split.checked_mul(2).is_some_and(|next| next < tree_size) {
        split = split.checked_mul(2).unwrap();
    }
    split
}

fn merkle_inclusion_steps(
    leaf_hash: Digest,
    leaf_index: u64,
    tree_size: u64,
    audit_path: &[Digest],
    path_index: &mut usize,
    steps: &mut Vec<(Vec<u8>, Digest)>,
) -> Digest {
    if tree_size == 1 {
        assert_eq!(leaf_index, 0);
        return leaf_hash;
    }
    let split = merkle_split(tree_size);
    let (left, right) = if leaf_index < split {
        let left =
            merkle_inclusion_steps(leaf_hash, leaf_index, split, audit_path, path_index, steps);
        let right = audit_path[*path_index];
        *path_index = path_index.checked_add(1).unwrap();
        (left, right)
    } else {
        let right = merkle_inclusion_steps(
            leaf_hash,
            leaf_index - split,
            tree_size - split,
            audit_path,
            path_index,
            steps,
        );
        let left = audit_path[*path_index];
        *path_index = path_index.checked_add(1).unwrap();
        (left, right)
    };
    let step = merkle_node_step(left, right);
    let digest = step.1;
    steps.push(step);
    digest
}

fn merkle_inclusion_derivations(
    leaf: &MerkleSetLeaf,
    proof: &MerkleInclusionProof,
    leaf_output_name: &'static str,
    root_output_name: &'static str,
) -> Vec<DerivationMetadata> {
    let leaf_derivation = merkle_leaf_derivation(leaf_output_name, leaf);
    let leaf_hash = Digest::new(
        HashAlgorithm::Blake3_256,
        hex::decode(&leaf_derivation.expected_output_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let mut path_index = 0_usize;
    let mut steps = Vec::new();
    let _root = merkle_inclusion_steps(
        leaf_hash,
        proof.leaf_index(),
        proof.tree_size(),
        proof.audit_path(),
        &mut path_index,
        &mut steps,
    );
    assert_eq!(path_index, proof.audit_path().len());
    assert!(!steps.is_empty());
    assert!(steps.len().saturating_sub(1) <= MERKLE_INTERMEDIATE_OUTPUT_NAMES.len());
    let last = steps.len() - 1;
    let mut derivations = vec![leaf_derivation];
    derivations.extend(
        steps
            .into_iter()
            .enumerate()
            .map(|(index, (message, digest))| {
                let output_name = if index == last {
                    root_output_name
                } else {
                    MERKLE_INTERMEDIATE_OUTPUT_NAMES[index]
                };
                domain_derivation(output_name, "KRIKOS-ID/merkle-node/v1", message, &digest)
            }),
    );
    derivations
}

fn merkle_consistency_derivations(
    old_leaf: &MerkleSetLeaf,
    proof: &MerkleConsistencyProof,
) -> Vec<DerivationMetadata> {
    assert_eq!(proof.old_size(), 1);
    assert_eq!(proof.new_size(), 3);
    assert_eq!(proof.audit_path().len(), 2);
    let old_root = merkle_leaf_derivation("old_merkle_root", old_leaf);
    let mut current = Digest::new(
        HashAlgorithm::Blake3_256,
        hex::decode(&old_root.expected_output_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let mut derivations = vec![old_root];
    for (index, sibling) in proof.audit_path().iter().copied().enumerate() {
        let (message, digest) = merkle_node_step(current, sibling);
        derivations.push(domain_derivation(
            if index + 1 == proof.audit_path().len() {
                "new_merkle_root"
            } else {
                MERKLE_INTERMEDIATE_OUTPUT_NAMES[index]
            },
            "KRIKOS-ID/merkle-node/v1",
            message,
            &digest,
        ));
        current = digest;
    }
    derivations
}

fn merkle_non_membership_derivations(proof: &MerkleNonMembershipProof) -> Vec<DerivationMetadata> {
    assert!(proof.predecessor().is_none());
    let successor = proof.successor().unwrap();
    merkle_inclusion_derivations(
        successor.leaf(),
        successor.proof(),
        "merkle_neighbor_leaf_hash",
        "merkle_root",
    )
}

#[derive(Deserialize)]
struct GenerationChunkMirror {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    generation_commitment: Digest,
    component_code: u16,
    ordinal: u32,
    start_index: u64,
    end_index: u64,
    item_payload_bytes: u64,
    payload: Vec<u8>,
}

#[derive(Deserialize)]
struct ProviderCheckpointBundleMirror {
    genesis: Option<AccountGenesis>,
    prior_checkpoint_id: Option<CheckpointId>,
    events: Vec<AuthorizedEvent>,
    checkpoint: SignedCheckpoint,
    transition_event: Option<AuthorizedEvent>,
}

#[derive(Deserialize)]
struct ProviderCheckpointBundleItemMirror {
    format_version: u16,
    bundle: ProviderCheckpointBundleMirror,
}

fn chunk_items(payload: &[u8]) -> Vec<Vec<u8>> {
    postcard::from_bytes(payload).expect("validated provider chunk payload must decode")
}

fn derivations_for_account_operation(operation: &AccountOperation) -> Vec<DerivationMetadata> {
    match operation {
        AccountOperation::BeginRecovery(begin) => derivations_for_wire_type(
            "RecoveryProposal",
            &begin.proposal().to_canonical_bytes().unwrap(),
        ),
        AccountOperation::ResolveFork(resolve) => derivations_for_wire_type(
            "ForkDescriptor",
            &resolve.fork().to_canonical_bytes().unwrap(),
        ),
        AccountOperation::BeginCryptoMigration(begin) => {
            derivations_for_wire_type("BeginCryptoMigration", &begin.to_canonical_bytes().unwrap())
        }
        _ => Vec::new(),
    }
}

fn derivations_for_wire_type(wire_type: &str, bytes: &[u8]) -> Vec<DerivationMetadata> {
    match wire_type {
        "AccountGenesis" => {
            let value = AccountGenesis::from_canonical_bytes(bytes).unwrap();
            vec![
                domain_derivation(
                    "account_id",
                    "KRIKOS-ID/account-id/v1",
                    bytes.to_vec(),
                    value.account_id().unwrap().as_digest(),
                ),
                domain_derivation(
                    "genesis_anchor",
                    "KRIKOS-ID/genesis-anchor/v1",
                    bytes.to_vec(),
                    value.genesis_anchor().unwrap().as_digest(),
                ),
            ]
        }
        "EventBody" => {
            let value = EventBody::from_canonical_bytes(bytes).unwrap();
            let mut derivations = vec![domain_derivation(
                "proposal_id",
                "KRIKOS-ID/account-proposal/v1",
                bytes.to_vec(),
                value.proposal_id().unwrap().as_digest(),
            )];
            derivations.extend(derivations_for_account_operation(value.operation()));
            derivations
        }
        "AccountOperation" => {
            let value = AccountOperation::from_canonical_bytes(bytes).unwrap();
            derivations_for_account_operation(&value)
        }
        "AdmissionEvidence" => {
            let value = AdmissionEvidence::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "admission_evidence_id",
                "KRIKOS-ID/admission-evidence/v1",
                bytes.to_vec(),
                value.admission_evidence_id().unwrap().as_digest(),
            )]
        }
        "AuthorizedEvent" => {
            let value = AuthorizedEvent::from_canonical_bytes(bytes).unwrap();
            let body_bytes = value.body().to_canonical_bytes().unwrap();
            let evidence_bytes = value.admission_evidence().to_canonical_bytes().unwrap();
            let evidence_id = value.admission_evidence().admission_evidence_id().unwrap();
            let admitted_message = postcard::to_stdvec(&(value.body(), evidence_id)).unwrap();
            let mut derivations = derivations_for_wire_type("EventBody", &body_bytes);
            derivations.extend([
                domain_derivation(
                    "admission_evidence_id",
                    "KRIKOS-ID/admission-evidence/v1",
                    evidence_bytes,
                    evidence_id.as_digest(),
                ),
                domain_derivation(
                    "event_id",
                    "KRIKOS-ID/account-event/v1",
                    admitted_message,
                    value.event_id().unwrap().as_digest(),
                ),
                domain_derivation(
                    "event_authorization_id",
                    "KRIKOS-ID/event-authorization/v1",
                    bytes.to_vec(),
                    value.event_authorization_id().unwrap().as_digest(),
                ),
            ]);
            derivations
        }
        "SignedCheckpoint" => {
            let value = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "checkpoint_id",
                "KRIKOS-ID/account-checkpoint/v1",
                value.body().to_canonical_bytes().unwrap(),
                value.checkpoint_id().unwrap().as_digest(),
            )]
        }
        "BeginCryptoMigration" => {
            let value = BeginCryptoMigration::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "crypto_migration_id",
                "KRIKOS-ID/crypto-migration/v1",
                value.migration().to_canonical_bytes().unwrap(),
                value.migration().crypto_migration_id().unwrap().as_digest(),
            )]
        }
        "EventIntentApprovalBody" => {
            let value = EventIntentApprovalBody::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "event_intent_approval_id",
                "KRIKOS-ID/event-intent-approval/v1",
                bytes.to_vec(),
                value.event_intent_approval_id().unwrap().as_digest(),
            )]
        }
        "ControllerApprovalBody" => {
            let value = ControllerApprovalBody::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "controller_approval_id",
                "KRIKOS-ID/controller-approval/v1",
                bytes.to_vec(),
                value.controller_approval_id().unwrap().as_digest(),
            )]
        }
        "RecoveryAuthorityPlan" => {
            let plan = RecoveryAuthorityPlan::from_canonical_bytes(bytes).unwrap();
            let proposal =
                RecoveryProposal::try_new(ProtocolVersion::V1, plan, Extensions::default())
                    .unwrap();
            vec![domain_derivation(
                "recovery_id",
                "KRIKOS-ID/recovery/v1",
                proposal.to_canonical_bytes().unwrap(),
                proposal.recovery_id().unwrap().as_digest(),
            )]
        }
        "RecoveryProposal" => {
            let value = RecoveryProposal::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "recovery_id",
                "KRIKOS-ID/recovery/v1",
                bytes.to_vec(),
                value.recovery_id().unwrap().as_digest(),
            )]
        }
        "BeginRecovery" => {
            let value = BeginRecovery::from_canonical_bytes(bytes).unwrap();
            derivations_for_wire_type(
                "RecoveryProposal",
                &value.proposal().to_canonical_bytes().unwrap(),
            )
        }
        "ForkDescriptor" => {
            let value = ForkDescriptor::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "fork_id",
                "KRIKOS-ID/fork/v1",
                postcard::to_stdvec(&(value.common_ancestor(), value.heads())).unwrap(),
                value.fork_id().unwrap().as_digest(),
            )]
        }
        "CapabilityGrant" => {
            let value = CapabilityGrant::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "capability_grant_id",
                "KRIKOS-ID/capability-grant/v1",
                bytes.to_vec(),
                value.capability_grant_id().unwrap().as_digest(),
            )]
        }
        "DelegationBody" => {
            let value = DelegationBody::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "delegation_id",
                "KRIKOS-ID/capability-delegation/v1",
                bytes.to_vec(),
                value.delegation_id().unwrap().as_digest(),
            )]
        }
        "SignedApplicationEvent" => {
            let value = SignedApplicationEvent::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "application_event_id",
                "KRIKOS-ID/application-event/v1",
                bytes.to_vec(),
                value.application_event_id().unwrap().as_digest(),
            )]
        }
        "WrappedGroupKey" => {
            let value = WrappedGroupKey::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "group_key_wrap_id",
                "KRIKOS-ID/group-key-wrap/v1",
                bytes.to_vec(),
                value.group_key_wrap_id().unwrap().as_digest(),
            )]
        }
        "ProviderLogEntryBody" => {
            let value = ProviderLogEntryBody::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "merkle_leaf_hash",
                "KRIKOS-ID/provider-log-entry/v1",
                bytes.to_vec(),
                &value.merkle_leaf_hash().unwrap(),
            )]
        }
        "MerkleSetLeaf" => {
            let value = MerkleSetLeaf::from_canonical_bytes(bytes).unwrap();
            vec![merkle_leaf_derivation("merkle_leaf_hash", &value)]
        }
        "MerkleNonMembershipProof" => {
            let value = MerkleNonMembershipProof::from_canonical_bytes(bytes).unwrap();
            merkle_non_membership_derivations(&value)
        }
        "PairingTicket" => {
            let value = PairingTicket::from_canonical_bytes(bytes).unwrap();
            vec![derive_key_derivation(
                "pairing_ticket_id",
                "KRIKOS-ID/pairing-ticket-id/v1",
                bytes.to_vec(),
                value.ticket_id().unwrap().as_digest(),
            )]
        }
        "PairingTranscript" => {
            let value = PairingTranscript::from_canonical_bytes(bytes).unwrap();
            vec![derive_key_derivation(
                "pairing_transcript_id",
                "KRIKOS-ID/pairing-transcript-id/v1",
                bytes.to_vec(),
                value.transcript_id().unwrap().as_digest(),
            )]
        }
        "PairingPossessionProof" => {
            let value = PairingPossessionProof::from_canonical_bytes(bytes).unwrap();
            vec![derive_key_derivation(
                "pairing_proof_id",
                "KRIKOS-ID/pairing-possession-proof-id/v1",
                bytes.to_vec(),
                value.proof_id().unwrap().as_digest(),
            )]
        }
        "DeviceAuthorizationProposal" => {
            let value = DeviceAuthorizationProposal::from_canonical_bytes(bytes).unwrap();
            vec![derive_key_derivation(
                "device_authorization_proposal_id",
                "KRIKOS-ID/device-authorization-proposal-id/v1",
                bytes.to_vec(),
                value.proposal_id().unwrap().as_digest(),
            )]
        }
        "PresenceProof" => {
            let value = PresenceProof::from_canonical_bytes(bytes).unwrap();
            vec![derive_key_derivation(
                "presence_proof_id",
                "KRIKOS-ID/device-presence-proof-id/v1",
                bytes.to_vec(),
                value.proof_id().unwrap().as_digest(),
            )]
        }
        "BackupAuthorityBundle" => {
            let value = BackupAuthorityBundle::from_canonical_bytes(bytes).unwrap();
            let mut derivations = derivations_for_wire_type(
                "AccountGenesis",
                &value.genesis().to_canonical_bytes().unwrap(),
            );
            for event in value.events() {
                derivations.extend(derivations_for_wire_type(
                    "AuthorizedEvent",
                    &event.to_canonical_bytes().unwrap(),
                ));
            }
            derivations.extend(derivations_for_wire_type(
                "SignedCheckpoint",
                &value.checkpoint().to_canonical_bytes().unwrap(),
            ));
            derivations
        }
        "ProviderGenerationExportChunk" => {
            let value = ProviderGenerationExportChunk::from_canonical_bytes(bytes).unwrap();
            let chunk_commitment = value.commitment().unwrap();
            let mut derivations = vec![
                domain_derivation(
                    "provider_generation_chunk_commitment",
                    "KRIKOS-ID/provider-generation-chunk/v1",
                    bytes.to_vec(),
                    &chunk_commitment,
                ),
                provider_chunk_list_derivation(
                    "provider_generation_chunk_list_commitment",
                    "KRIKOS-ID/provider-generation-chunk-list/v1",
                    value.component().unwrap().code(),
                    &[chunk_commitment],
                ),
            ];
            let mirror: GenerationChunkMirror = postcard::from_bytes(bytes).unwrap();
            assert_eq!(mirror.format_version, 1);
            assert_eq!(mirror.provider_id, value.provider_id());
            assert_eq!(mirror.log_id, value.log_id());
            assert_eq!(mirror.key_version, value.key_version());
            assert_eq!(mirror.generation_commitment, value.generation_commitment());
            assert_eq!(mirror.component_code, value.component().unwrap().code());
            assert_eq!(mirror.ordinal, value.ordinal());
            assert_eq!(mirror.start_index, value.start_index());
            assert_eq!(mirror.end_index, value.end_index());
            assert_eq!(mirror.item_payload_bytes, value.item_payload_bytes());
            if value.component() == Ok(ProviderExportComponent::CheckpointBundles) {
                for item in chunk_items(&mirror.payload) {
                    let item: ProviderCheckpointBundleItemMirror =
                        postcard::from_bytes(&item).unwrap();
                    assert_eq!(item.format_version, 1);
                    if let Some(genesis) = &item.bundle.genesis {
                        derivations.extend(derivations_for_wire_type(
                            "AccountGenesis",
                            &genesis.to_canonical_bytes().unwrap(),
                        ));
                    }
                    let _prior_checkpoint_id = item.bundle.prior_checkpoint_id;
                    for event in &item.bundle.events {
                        derivations.extend(derivations_for_wire_type(
                            "AuthorizedEvent",
                            &event.to_canonical_bytes().unwrap(),
                        ));
                    }
                    derivations.extend(derivations_for_wire_type(
                        "SignedCheckpoint",
                        &item.bundle.checkpoint.to_canonical_bytes().unwrap(),
                    ));
                    if let Some(event) = &item.bundle.transition_event {
                        derivations.extend(derivations_for_wire_type(
                            "AuthorizedEvent",
                            &event.to_canonical_bytes().unwrap(),
                        ));
                    }
                }
            }
            derivations
        }
        "ProviderAuditExportChunk" => {
            let value = ProviderAuditExportChunk::from_canonical_bytes(bytes).unwrap();
            let chunk_commitment = value.commitment().unwrap();
            vec![
                domain_derivation(
                    "provider_audit_chunk_commitment",
                    "KRIKOS-ID/provider-audit-chunk/v1",
                    bytes.to_vec(),
                    &chunk_commitment,
                ),
                provider_chunk_list_derivation(
                    "provider_audit_chunk_list_commitment",
                    "KRIKOS-ID/provider-audit-chunk-list/v1",
                    0,
                    &[chunk_commitment],
                ),
            ]
        }
        "ProviderGenerationExportManifest" => {
            let value = ProviderGenerationExportManifest::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "provider_generation_manifest_commitment",
                "KRIKOS-ID/provider-generation-manifest/v1",
                bytes.to_vec(),
                &value.commitment().unwrap(),
            )]
        }
        "ProviderAuditExportManifest" => {
            let value = ProviderAuditExportManifest::from_canonical_bytes(bytes).unwrap();
            vec![domain_derivation(
                "provider_audit_manifest_commitment",
                "KRIKOS-ID/provider-audit-manifest/v1",
                bytes.to_vec(),
                &value.commitment().unwrap(),
            )]
        }
        "ProviderRecoveryExportManifest" => {
            let value = ProviderRecoveryExportManifest::from_canonical_bytes(bytes).unwrap();
            let mut derivations = vec![domain_derivation(
                "provider_recovery_manifest_commitment",
                "KRIKOS-ID/provider-recovery-manifest/v1",
                bytes.to_vec(),
                &value.commitment().unwrap(),
            )];
            derivations.extend(derivations_for_wire_type(
                "ProviderGenerationExportManifest",
                &value.generation().to_canonical_bytes().unwrap(),
            ));
            derivations.extend(derivations_for_wire_type(
                "ProviderAuditExportManifest",
                &value.audit().to_canonical_bytes().unwrap(),
            ));
            derivations
        }
        "SyncFrame" => {
            let value = SyncFrame::from_canonical_bytes(bytes).unwrap();
            value
                .events()
                .iter()
                .flat_map(|event| {
                    derivations_for_wire_type(
                        "AuthorizedEvent",
                        &event.to_canonical_bytes().unwrap(),
                    )
                })
                .collect()
        }
        "SyncResponse" => SyncResponse::from_canonical_bytes(bytes)
            .unwrap()
            .as_frame()
            .map_or_else(Vec::new, |frame| {
                derivations_for_wire_type("SyncFrame", &frame.to_canonical_bytes().unwrap())
            }),
        "AuthorizedProposalRequest" => {
            let value = AuthorizedProposalRequest::from_canonical_bytes(bytes).unwrap();
            derivations_for_wire_type(
                "DeviceAuthorizationProposal",
                &value.proposal().to_canonical_bytes().unwrap(),
            )
        }
        "AuthorizedCheckpointRequest" => {
            let value = AuthorizedCheckpointRequest::from_canonical_bytes(bytes).unwrap();
            derivations_for_wire_type(
                "SignedCheckpoint",
                &value.checkpoint().to_canonical_bytes().unwrap(),
            )
        }
        "IdentityProtocolReply" => IdentityProtocolReply::from_canonical_bytes(bytes)
            .unwrap()
            .as_sync()
            .map_or_else(Vec::new, |response| {
                derivations_for_wire_type("SyncResponse", &response.to_canonical_bytes().unwrap())
            }),
        _ => Vec::new(),
    }
}

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn add_digest_ids(catalog: &mut Catalog) {
    macro_rules! add_id {
        ($name:literal, $type:ty, $seed:expr) => {{
            let value = typed_id::<$type>($seed);
            catalog.add(
                $name,
                stringify!($type),
                &value,
                VectorDetails {
                    protocol_version: None,
                    version_scope:
                        "standalone-algorithm-tagged-digest; version inherited from enclosing v1 object",
                    ..VectorDetails::default()
                },
            );
        }};
    }

    add_id!("id-genesis-anchor", GenesisAnchor, 0x01);
    add_id!("id-account", AccountId, 0x02);
    add_id!("id-controller", ControllerId, 0x03);
    add_id!("id-controller-key", ControllerKeyId, 0x04);
    add_id!("id-control-policy", ControlPolicyId, 0x05);
    add_id!("id-recovery-policy", RecoveryPolicyId, 0x06);
    add_id!("id-provider", ProviderId, 0x07);
    add_id!("id-provider-log", ProviderLogId, 0x08);
    add_id!("id-provider-policy", ProviderPolicyId, 0x09);
    add_id!("id-device", DeviceId, 0x0a);
    add_id!("id-capability-grant", CapabilityGrantId, 0x0b);
    add_id!("id-delegation", DelegationId, 0x0c);
    add_id!("id-proposal", ProposalId, 0x0d);
    add_id!("id-event", EventId, 0x0e);
    add_id!("id-event-authorization", EventAuthorizationId, 0x0f);
    add_id!("id-admission-evidence", AdmissionEvidenceId, 0x10);
    add_id!("id-controller-approval", ControllerApprovalId, 0x11);
    add_id!("id-event-intent-approval", EventIntentApprovalId, 0x12);
    add_id!("id-checkpoint", CheckpointId, 0x13);
    add_id!("id-recovery", RecoveryId, 0x14);
    add_id!("id-guardian-grant", GuardianGrantId, 0x15);
    add_id!("id-fork", ForkId, 0x16);
    add_id!("id-crypto-suite", CryptoSuiteId, 0x17);
    add_id!("id-crypto-migration", CryptoMigrationId, 0x18);
    add_id!("id-crypto-state", CryptoStateId, 0x19);
    add_id!("id-application", ApplicationId, 0x1a);
    add_id!("id-application-event", ApplicationEventId, 0x1b);
    add_id!("id-group", GroupId, 0x1c);
    add_id!("id-group-key-wrap", GroupKeyWrapId, 0x1d);
}

fn signature_details(
    domain: &'static str,
    message: Vec<u8>,
    secret: &SecretKey,
    signature: [u8; 64],
) -> VectorDetails {
    let binding = signature_binding("signature-1", domain, message, secret, signature);
    VectorDetails {
        algorithms: vec!["BLAKE3-256", "Ed25519"],
        signature_bindings: vec![binding],
        tamper_expectation: "signature_invalid_or_decode_rejected",
        ..VectorDetails::default()
    }
}

fn signature_binding(
    name: &str,
    domain: &'static str,
    message: Vec<u8>,
    secret: &SecretKey,
    signature: [u8; 64],
) -> SignatureBinding {
    let signer_key = match secret.public().as_bytes() {
        bytes if bytes == SecretKey::from_bytes(&[0x01; 32]).public().as_bytes() => "guardian-1",
        bytes if bytes == SecretKey::from_bytes(&[0x02; 32]).public().as_bytes() => "guardian-2",
        bytes if bytes == SecretKey::from_bytes(&[0x0a; 32]).public().as_bytes() => {
            "pairing-presence-application"
        }
        bytes if bytes == SecretKey::from_bytes(&[0x0c; 32]).public().as_bytes() => {
            "pairing-endpoint"
        }
        bytes if bytes == SecretKey::from_bytes(&[0x11; 32]).public().as_bytes() => {
            "account-controller-and-social-issuer"
        }
        bytes if bytes == SecretKey::from_bytes(&[0x31; 32]).public().as_bytes() => {
            "application-device"
        }
        bytes if bytes == SecretKey::from_bytes(&[0x35; 32]).public().as_bytes() => {
            "capability-delegator"
        }
        bytes if bytes == SecretKey::from_bytes(&[0x41; 32]).public().as_bytes() => {
            "name-and-portable-credential-issuer"
        }
        bytes if bytes == SecretKey::from_bytes(&[0x71; 32]).public().as_bytes() => {
            "transparency-provider"
        }
        bytes if bytes == SecretKey::from_bytes(&[0x91; 32]).public().as_bytes() => {
            "migration-successor-controller"
        }
        _ => panic!("every deterministic signer must have a named manifest key"),
    };
    SignatureBinding {
        name: name.to_owned(),
        algorithm: "Ed25519",
        domain_ascii: domain,
        message_hex: hex::encode(message),
        signer_key,
        public_key_hex: hex::encode(secret.public().as_bytes()),
        signature_hex: hex::encode(signature),
    }
}

fn interop_crypto_migration() -> (BeginCryptoMigration, CryptoMigrationId) {
    let old_secret = SecretKey::from_bytes(&[0x11; 32]);
    let new_secret = SecretKey::from_bytes(&[0x91; 32]);
    let old_signing_key = SigningPublicKey::ed25519(*old_secret.public().as_bytes()).unwrap();
    let binding = ControllerKeyBinding::try_new(
        typed_id::<ControllerId>(41),
        ControllerKeyId::for_signing_key(&old_signing_key).unwrap(),
        AlgorithmPublicKey::new(
            SignatureAlgorithm::Ed25519.code(),
            new_secret.public().as_bytes().to_vec(),
        )
        .unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let migration = CryptoMigrationBody::try_new(
        ProtocolVersion::V1,
        typed_id::<AccountId>(1),
        CryptoSuiteDescriptor::v1()
            .unwrap()
            .crypto_suite_id()
            .unwrap(),
        CryptoSuiteDescriptor::try_new(
            ProtocolVersion::V1,
            2,
            HashAlgorithm::Blake3_256.code(),
            SignatureAlgorithm::Ed25519.code(),
            AgreementAlgorithm::X25519.code(),
            KdfAlgorithm::Blake3DeriveKey.code(),
            AeadAlgorithm::XChaCha20Poly1305.code(),
            Extensions::default(),
        )
        .unwrap(),
        vec![binding],
        None,
        [45; 32],
        Extensions::default(),
    )
    .unwrap();
    let migration_id = migration.crypto_migration_id().unwrap();
    let message = migration_id.to_canonical_bytes().unwrap();
    let proof = ControllerKeyBindingProof::try_new(
        migration_id,
        typed_id::<ControllerId>(41),
        AlgorithmSignature::new(
            SignatureAlgorithm::Ed25519.code(),
            old_secret.sign(&message).to_bytes().to_vec(),
        )
        .unwrap(),
        AlgorithmSignature::new(
            SignatureAlgorithm::Ed25519.code(),
            new_secret.sign(&message).to_bytes().to_vec(),
        )
        .unwrap(),
    )
    .unwrap();
    let begin = BeginCryptoMigration::try_new(
        ProtocolVersion::V1,
        migration,
        ControllerKeyBindingProofSet::try_new(vec![proof]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    (begin, migration_id)
}

fn crypto_migration_signature_bindings(migration: &BeginCryptoMigration) -> Vec<SignatureBinding> {
    let old_secret = SecretKey::from_bytes(&[0x11; 32]);
    let new_secret = SecretKey::from_bytes(&[0x91; 32]);
    let message = migration
        .migration()
        .crypto_migration_id()
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    migration
        .migration()
        .bindings()
        .iter()
        .zip(migration.proofs().as_slice())
        .flat_map(|(binding, proof)| {
            assert_eq!(binding.controller_id(), proof.controller_id());
            assert_eq!(
                binding.old_key_id(),
                ControllerKeyId::for_signing_key(
                    &SigningPublicKey::ed25519(*old_secret.public().as_bytes()).unwrap(),
                )
                .unwrap()
            );
            assert_eq!(
                binding.new_signing_key().as_bytes(),
                new_secret.public().as_bytes()
            );
            [
                signature_binding(
                    "migration-old-key-signature",
                    "none",
                    message.clone(),
                    &old_secret,
                    proof.old_key_signature().as_bytes().try_into().unwrap(),
                ),
                signature_binding(
                    "migration-new-key-signature",
                    "none",
                    message.clone(),
                    &new_secret,
                    proof.new_key_signature().as_bytes().try_into().unwrap(),
                ),
            ]
        })
        .enumerate()
        .map(|(index, mut binding)| {
            binding.name = format!("signature-{}", index + 1);
            binding
        })
        .collect()
}

fn interop_finalize_recovery(template: &FinalizeRecovery) -> FinalizeRecovery {
    let provider_secret = SecretKey::from_bytes(&[0x71; 32]);
    let provider = ProviderDescriptor::new(
        SigningPublicKey::ed25519(*provider_secret.public().as_bytes()).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let template_anchor = template.delay_anchor();
    let entry = ProviderLogEntryBody::new(
        provider.id().unwrap(),
        typed_id::<ProviderLogId>(32),
        template_anchor.account_id(),
        ProviderLogSubject::EventIntent(template_anchor.begin_proposal_id()),
        template_anchor.observed_at(),
        Extensions::default(),
    )
    .unwrap();
    let head_body = ProviderHeadBody::new(
        provider.id().unwrap(),
        entry.log_id(),
        ProviderKeyVersion::GENESIS,
        1,
        entry.merkle_leaf_hash().unwrap(),
        Timestamp::from_unix_millis(template_anchor.observed_at().as_unix_millis() + 1),
        Extensions::default(),
    )
    .unwrap();
    let head = SignedProviderHead::new(
        head_body.clone(),
        ProtocolSignature::ed25519(
            provider_secret
                .sign(&head_body.signing_bytes().unwrap())
                .to_bytes(),
        ),
    );
    let receipt = InclusionReceipt::new(entry, 0, Vec::new(), head).unwrap();
    receipt.verify(&provider).unwrap();
    let anchor = RecoveryDelayAnchor::try_new(
        ProtocolVersion::V1,
        template_anchor.account_id(),
        template_anchor.recovery_id(),
        template_anchor.begin_proposal_id(),
        template_anchor.provider_policy_id(),
        template_anchor.required_quorum(),
        ProviderReceipts::new(vec![receipt]).unwrap(),
        Extensions::default(),
    )
    .unwrap();
    FinalizeRecovery::try_new(
        ProtocolVersion::V1,
        template.expected_pending_recovery(),
        anchor,
        template.finalized_at(),
        Extensions::default(),
    )
    .unwrap()
}

fn recovery_delay_signature_bindings(anchor: &RecoveryDelayAnchor) -> Vec<SignatureBinding> {
    let provider_secret = SecretKey::from_bytes(&[0x71; 32]);
    anchor
        .receipts()
        .as_slice()
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let head = receipt.signed_head();
            signature_binding(
                &format!("signature-{}", index + 1),
                "KRIKOS-ID/provider-head-signature/v1",
                head.body().signing_bytes().unwrap(),
                &provider_secret,
                *head.signature().as_bytes(),
            )
        })
        .collect()
}

struct PairingMacKeyInputs {
    secret_seed: [u8; 32],
    subject_public_key: AgreementPublicKey,
    connection_public_key: AgreementPublicKey,
}

fn pairing_mac_binding(
    name: &'static str,
    key_context: &'static str,
    message_domain: &'static str,
    key_inputs: PairingMacKeyInputs,
    transcript_bytes: &[u8],
    expected_mac: &[u8; 32],
) -> MacBinding {
    let secret = StaticSecret::from(key_inputs.secret_seed);
    let connection_public = X25519PublicKey::from(*key_inputs.connection_public_key.as_bytes());
    let shared = secret.diffie_hellman(&connection_public);
    let mut key_material = [0_u8; 96];
    key_material[..32].copy_from_slice(shared.as_bytes());
    key_material[32..64].copy_from_slice(key_inputs.subject_public_key.as_bytes());
    key_material[64..].copy_from_slice(key_inputs.connection_public_key.as_bytes());
    let key = blake3::derive_key(key_context, &key_material);
    let mut message = Vec::with_capacity(message_domain.len() + 1 + transcript_bytes.len());
    message.extend_from_slice(message_domain.as_bytes());
    message.push(0);
    message.extend_from_slice(transcript_bytes);
    assert_eq!(blake3::keyed_hash(&key, &message).as_bytes(), expected_mac);
    MacBinding {
        name: name.to_owned(),
        algorithm: "BLAKE3 keyed_hash(key, message)",
        key_derivation_algorithm: "BLAKE3 derive_key(context, input)",
        key_derivation_context_ascii: key_context,
        key_derivation_input_hex: hex::encode(key_material),
        message_domain_ascii: message_domain,
        message_hex: hex::encode(message),
        expected_mac_hex: hex::encode(expected_mac),
    }
}

const INTEROP_SYNC_CURSOR_KEY: [u8; 32] = [0x51; 32];

#[derive(Deserialize)]
struct SyncCursorMacMirror {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    source_heads: Vec<EventId>,
    next_item: u64,
    delivered_bytes: u64,
    authenticator: [u8; 32],
}

fn sync_cursor_mac_binding(name: &str, cursor: &SyncCursor) -> MacBinding {
    let encoded = cursor.to_canonical_bytes().unwrap();
    let mirror: SyncCursorMacMirror = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(mirror.protocol_version, ProtocolVersion::V1);
    assert_eq!(mirror.account_id, cursor.account_id());
    assert_eq!(mirror.source_heads, cursor.source_heads());
    assert_eq!(mirror.next_item, cursor.next_item());
    assert_eq!(mirror.delivered_bytes, cursor.delivered_bytes());
    let message = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        cursor.account_id(),
        cursor.source_heads(),
        cursor.next_item(),
        cursor.delivered_bytes(),
    ))
    .unwrap();
    let expected = blake3::keyed_hash(&INTEROP_SYNC_CURSOR_KEY, &message);
    assert_eq!(expected.as_bytes(), &mirror.authenticator);
    cursor
        .verify(&CursorKey::new(INTEROP_SYNC_CURSOR_KEY).unwrap())
        .unwrap();
    MacBinding {
        name: name.to_owned(),
        algorithm: "BLAKE3 keyed_hash(key, message)",
        key_derivation_algorithm: "raw 256-bit test key",
        key_derivation_context_ascii: "none",
        key_derivation_input_hex: hex::encode(INTEROP_SYNC_CURSOR_KEY),
        message_domain_ascii: "none",
        message_hex: hex::encode(message),
        expected_mac_hex: hex::encode(mirror.authenticator),
    }
}

fn output_directory() -> PathBuf {
    let mut arguments = env::args_os();
    let _executable = arguments.next();
    let directory = arguments.next().map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors"),
        PathBuf::from,
    );
    assert!(
        arguments.next().is_none(),
        "usage: generate_interop_vectors [OUTPUT_DIRECTORY]"
    );
    directory
}

fn fuzz_seed_payload(filename: &str, expected_selector: u8) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus/identity_pairing")
        .join(filename);
    let text = fs::read_to_string(path).unwrap();
    let (selector, hexadecimal) = text.split_once("hex:").unwrap();
    assert_eq!(selector.trim().parse::<u8>().unwrap(), expected_selector);
    let compact = hexadecimal
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    hex::decode(compact).unwrap()
}

fn main() {
    let directory = output_directory();
    fs::create_dir_all(&directory).unwrap();
    for obsolete in [
        "provider-generation-export.bin",
        "provider-recovery-export.bin",
    ] {
        let path = directory.join(obsolete);
        if path.exists() {
            fs::remove_file(path).unwrap();
        }
    }
    let mut catalog = Catalog::new(directory.clone());
    add_digest_ids(&mut catalog);

    let fixture = backup::fixture();
    let mut genesis_ids = BTreeMap::new();
    genesis_ids.insert(
        "account_id",
        fixture.genesis.account_id().unwrap().to_string(),
    );
    genesis_ids.insert(
        "genesis_anchor",
        fixture.genesis.genesis_anchor().unwrap().to_string(),
    );
    catalog.add(
        "account-genesis",
        "AccountGenesis",
        &fixture.genesis,
        VectorDetails {
            expected_ids: genesis_ids,
            ..VectorDetails::default()
        },
    );

    let intent_body = EventIntentApprovalBody::new(
        fixture.event.approvals().as_slice()[0]
            .body()
            .controller_id(),
        fixture.event.body().proposal_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let intent_signature = fixture
        .signer
        .sign(&intent_body.to_canonical_bytes().unwrap())
        .to_bytes();
    let account_signing_key =
        SigningPublicKey::ed25519(*fixture.signer.public().as_bytes()).unwrap();
    let intent = SignedEventIntentApproval::new(
        intent_body.clone(),
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&account_signing_key).unwrap(),
            AlgorithmSignature::new(1, intent_signature.to_vec()).unwrap(),
        )],
    )
    .unwrap();
    let intents = EventIntentApprovals::new(vec![intent.clone()]).unwrap();
    catalog.add(
        "event-intent-approval-body",
        "EventIntentApprovalBody",
        &intent_body,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "event_intent_approval_id",
                intent_body.event_intent_approval_id().unwrap().to_string(),
            )]),
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "event-intent-approval",
        "SignedEventIntentApproval",
        &intent,
        VectorDetails {
            dependencies: vec!["event-intent-approval-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/event-intent-approval-signature/v1",
                intent_body.to_canonical_bytes().unwrap(),
                &fixture.signer,
                intent_signature,
            )
        },
    );
    catalog.add(
        "event-intent-approvals",
        "EventIntentApprovals",
        &intents,
        VectorDetails {
            dependencies: vec!["event-intent-approval".to_owned()],
            ..signature_details(
                "KRIKOS-ID/event-intent-approval-signature/v1",
                intent_body.to_canonical_bytes().unwrap(),
                &fixture.signer,
                intent_signature,
            )
        },
    );

    let event = &fixture.event;
    let mut event_ids = BTreeMap::new();
    event_ids.insert(
        "proposal_id",
        event.body().proposal_id().unwrap().to_string(),
    );
    event_ids.insert(
        "admission_evidence_id",
        event
            .admission_evidence()
            .admission_evidence_id()
            .unwrap()
            .to_string(),
    );
    event_ids.insert("event_id", event.event_id().unwrap().to_string());
    event_ids.insert(
        "event_authorization_id",
        event.event_authorization_id().unwrap().to_string(),
    );
    catalog.add(
        "event-body",
        "EventBody",
        event.body(),
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "proposal_id",
                event.body().proposal_id().unwrap().to_string(),
            )]),
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "admission-evidence",
        "AdmissionEvidence",
        event.admission_evidence(),
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "admission_evidence_id",
                event
                    .admission_evidence()
                    .admission_evidence_id()
                    .unwrap()
                    .to_string(),
            )]),
            dependencies: vec!["event-body".to_owned()],
            ..VectorDetails::default()
        },
    );
    let final_approval = &event.approvals().as_slice()[0];
    let final_signature = final_approval.signatures()[0]
        .signature()
        .as_bytes()
        .try_into()
        .unwrap();
    catalog.add(
        "final-event-controller-approval-body",
        "ControllerApprovalBody",
        final_approval.body(),
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "controller_approval_id",
                final_approval
                    .body()
                    .controller_approval_id()
                    .unwrap()
                    .to_string(),
            )]),
            dependencies: vec!["event-body".to_owned(), "admission-evidence".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "final-event-controller-approval",
        "SignedControllerApproval",
        final_approval,
        VectorDetails {
            dependencies: vec!["final-event-controller-approval-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/controller-approval-signature/v1",
                final_approval.body().to_canonical_bytes().unwrap(),
                &fixture.signer,
                final_signature,
            )
        },
    );
    catalog.add(
        "controller-approvals",
        "ControllerApprovals",
        event.approvals(),
        VectorDetails {
            dependencies: vec!["final-event-controller-approval".to_owned()],
            ..signature_details(
                "KRIKOS-ID/controller-approval-signature/v1",
                final_approval.body().to_canonical_bytes().unwrap(),
                &fixture.signer,
                final_signature,
            )
        },
    );
    catalog.add(
        "authorized-event",
        "AuthorizedEvent",
        event,
        VectorDetails {
            expected_ids: event_ids,
            dependencies: vec![
                "event-body".to_owned(),
                "admission-evidence".to_owned(),
                "final-event-controller-approval".to_owned(),
            ],
            ..signature_details(
                "KRIKOS-ID/controller-approval-signature/v1",
                final_approval.body().to_canonical_bytes().unwrap(),
                &fixture.signer,
                final_signature,
            )
        },
    );

    let direct_checkpoint_approval = &fixture
        .checkpoint
        .authorization()
        .controller_approvals()
        .unwrap()
        .as_slice()[0];
    let direct_checkpoint_signature: [u8; 64] = direct_checkpoint_approval.signatures()[0]
        .signature()
        .as_bytes()
        .try_into()
        .unwrap();
    catalog.add(
        "checkpoint-direct",
        "SignedCheckpoint",
        &fixture.checkpoint,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "checkpoint_id",
                fixture.checkpoint.checkpoint_id().unwrap().to_string(),
            )]),
            ..signature_details(
                "KRIKOS-ID/controller-approval-signature/v1",
                direct_checkpoint_approval
                    .body()
                    .to_canonical_bytes()
                    .unwrap(),
                &fixture.signer,
                direct_checkpoint_signature,
            )
        },
    );
    let (finalize_checkpoint, retire_checkpoint) = task2::transition_checkpoints();
    for (name, checkpoint) in [
        ("checkpoint-transition-finalize", finalize_checkpoint),
        ("checkpoint-transition-retire", retire_checkpoint),
    ] {
        catalog.add(
            name,
            "SignedCheckpoint",
            &checkpoint,
            VectorDetails {
                expected_ids: BTreeMap::from([(
                    "checkpoint_id",
                    checkpoint.checkpoint_id().unwrap().to_string(),
                )]),
                tamper_expectation: "identifier_or_binding_rejected",
                ..VectorDetails::default()
            },
        );
    }
    let (pending_checkpoint, dual_checkpoint) = backup::migration_checkpoints();
    for (name, checkpoint) in [
        ("checkpoint-migration-pending", pending_checkpoint),
        ("checkpoint-migration-dual", dual_checkpoint),
    ] {
        let approval = &checkpoint
            .authorization()
            .controller_approvals()
            .unwrap()
            .as_slice()[0];
        let signature: [u8; 64] = approval.signatures()[0]
            .signature()
            .as_bytes()
            .try_into()
            .unwrap();
        catalog.add(
            name,
            "SignedCheckpoint",
            &checkpoint,
            VectorDetails {
                expected_ids: BTreeMap::from([(
                    "checkpoint_id",
                    checkpoint.checkpoint_id().unwrap().to_string(),
                )]),
                ..signature_details(
                    "KRIKOS-ID/controller-approval-signature/v1",
                    approval.body().to_canonical_bytes().unwrap(),
                    &fixture.signer,
                    signature,
                )
            },
        );
    }
    catalog.add(
        "backup-authority-bundle",
        "BackupAuthorityBundle",
        &fixture.bundle,
        VectorDetails {
            dependencies: vec![
                "account-genesis".to_owned(),
                "authorized-event".to_owned(),
                "checkpoint-direct".to_owned(),
            ],
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: vec![
                signature_binding(
                    "signature-1",
                    "KRIKOS-ID/controller-approval-signature/v1",
                    final_approval.body().to_canonical_bytes().unwrap(),
                    &fixture.signer,
                    final_signature,
                ),
                signature_binding(
                    "signature-2",
                    "KRIKOS-ID/controller-approval-signature/v1",
                    direct_checkpoint_approval
                        .body()
                        .to_canonical_bytes()
                        .unwrap(),
                    &fixture.signer,
                    direct_checkpoint_signature,
                ),
            ],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "backup-envelope",
        "BackupEnvelope",
        &fixture.envelope,
        VectorDetails {
            algorithms: vec!["Argon2id", "XChaCha20-Poly1305", "BLAKE3-256"],
            dependencies: vec!["backup-authority-bundle".to_owned()],
            tamper_expectation: "authentication_or_decode_rejected",
            ..VectorDetails::default()
        },
    );

    let (proposal, begin, veto, cancel, template_finalize, _, _, _, _) = task2::recovery_values();
    let finalize = interop_finalize_recovery(&template_finalize);
    let delay_anchor = finalize.delay_anchor().clone();
    let recovery_signatures = recovery_delay_signature_bindings(&delay_anchor);
    let (migration, migration_id) = interop_crypto_migration();
    let migration_signatures = crypto_migration_signature_bindings(&migration);
    let (recovery_plan, _, fork) = task2::recovery_plan_anchor_and_fork();
    let mut account_operations = task2::operations();
    for operation in &mut account_operations {
        match operation {
            AccountOperation::BeginRecovery(_) => {
                *operation = AccountOperation::BeginRecovery(begin.clone());
            }
            AccountOperation::VetoRecovery(_) => {
                *operation = AccountOperation::VetoRecovery(veto.clone());
            }
            AccountOperation::CancelRecovery(_) => {
                *operation = AccountOperation::CancelRecovery(cancel.clone());
            }
            AccountOperation::FinalizeRecovery(_) => {
                *operation = AccountOperation::FinalizeRecovery(finalize.clone());
            }
            AccountOperation::ResolveFork(_) => {
                *operation = AccountOperation::ResolveFork(
                    ResolveFork::try_new(
                        ProtocolVersion::V1,
                        fork.clone(),
                        fork.heads()[0],
                        vec![typed_id::<ControllerId>(51)],
                        vec![typed_id::<DeviceId>(52)],
                        Extensions::default(),
                    )
                    .unwrap(),
                );
            }
            AccountOperation::BeginCryptoMigration(_) => {
                *operation = AccountOperation::BeginCryptoMigration(migration.clone());
            }
            _ => {}
        }
    }
    for (index, operation) in account_operations.iter().enumerate() {
        let code = index + 1;
        assert_eq!(usize::from(operation.kind().code()), code);
        let details = match operation {
            AccountOperation::BeginRecovery(_) => VectorDetails {
                dependencies: vec!["recovery-begin".to_owned()],
                ..VectorDetails::default()
            },
            AccountOperation::VetoRecovery(_) => VectorDetails {
                dependencies: vec!["recovery-veto".to_owned()],
                ..VectorDetails::default()
            },
            AccountOperation::CancelRecovery(_) => VectorDetails {
                dependencies: vec!["recovery-cancel".to_owned()],
                ..VectorDetails::default()
            },
            AccountOperation::FinalizeRecovery(_) => VectorDetails {
                algorithms: vec!["BLAKE3-256", "Ed25519"],
                signature_bindings: recovery_signatures.clone(),
                dependencies: vec!["recovery-finalize".to_owned()],
                tamper_expectation: "signature_invalid_or_decode_rejected",
                ..VectorDetails::default()
            },
            AccountOperation::ResolveFork(_) => VectorDetails {
                dependencies: vec!["fork-descriptor".to_owned()],
                ..VectorDetails::default()
            },
            AccountOperation::BeginCryptoMigration(_) => VectorDetails {
                algorithms: vec!["BLAKE3-256", "Ed25519"],
                signature_bindings: migration_signatures.clone(),
                dependencies: vec!["crypto-migration-begin".to_owned()],
                tamper_expectation: "signature_invalid_or_decode_rejected",
                ..VectorDetails::default()
            },
            _ => VectorDetails::default(),
        };
        catalog.add(
            format!("account-operation-{code:02}"),
            "AccountOperation",
            operation,
            details,
        );
    }
    let (guardian_secret, guardian_body, signed_guardian, guardian_set, threshold_evidence) =
        guardian_fixture::fixture();
    catalog.add(
        "recovery-authority-plan",
        "RecoveryAuthorityPlan",
        &recovery_plan,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "recovery_id",
                RecoveryProposal::try_new(
                    ProtocolVersion::V1,
                    recovery_plan.clone(),
                    Extensions::default(),
                )
                .unwrap()
                .recovery_id()
                .unwrap()
                .to_string(),
            )]),
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "recovery-proposal",
        "RecoveryProposal",
        &proposal,
        VectorDetails {
            dependencies: vec!["recovery-authority-plan".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "recovery-begin",
        "BeginRecovery",
        &begin,
        VectorDetails {
            dependencies: vec!["recovery-proposal".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "recovery-veto",
        "VetoRecovery",
        &veto,
        VectorDetails::default(),
    );
    catalog.add(
        "recovery-cancel",
        "CancelRecovery",
        &cancel,
        VectorDetails::default(),
    );
    catalog.add(
        "recovery-finalize",
        "FinalizeRecovery",
        &finalize,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: recovery_signatures.clone(),
            dependencies: vec!["recovery-delay-anchor".to_owned()],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "recovery-delay-anchor",
        "RecoveryDelayAnchor",
        &delay_anchor,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: recovery_signatures,
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "fork-descriptor",
        "ForkDescriptor",
        &fork,
        VectorDetails {
            expected_ids: BTreeMap::from([("fork_id", fork.fork_id().unwrap().to_string())]),
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "guardian-approval-body",
        "GuardianApprovalBody",
        &guardian_body,
        VectorDetails {
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "signed-guardian-approval",
        "SignedGuardianApproval",
        &signed_guardian,
        VectorDetails {
            dependencies: vec!["guardian-approval-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/guardian-approval-signature/v1",
                guardian_body.signing_bytes().unwrap(),
                &guardian_secret,
                *signed_guardian.signature().as_bytes(),
            )
        },
    );
    let guardian_bindings = guardian_set
        .as_slice()
        .iter()
        .enumerate()
        .map(|(index, approval)| {
            let seed = (1_u8..=2)
                .find(|seed| {
                    SigningPublicKey::ed25519(
                        *SecretKey::from_bytes(&[*seed; 32]).public().as_bytes(),
                    )
                    .unwrap()
                        == approval.opening().grant().guardian_signing_key()
                })
                .expect("guardian approval must resolve to its exact deterministic key");
            let secret = SecretKey::from_bytes(&[seed; 32]);
            signature_binding(
                &format!("signature-{}", index + 1),
                "KRIKOS-ID/guardian-approval-signature/v1",
                approval.body().signing_bytes().unwrap(),
                &secret,
                *approval.signature().as_bytes(),
            )
        })
        .collect::<Vec<_>>();
    catalog.add(
        "guardian-approval-set",
        "GuardianApprovalSet",
        &guardian_set,
        VectorDetails {
            dependencies: vec!["signed-guardian-approval".to_owned()],
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: guardian_bindings.clone(),
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "guardian-threshold-evidence",
        "RecoveryThresholdEvidence",
        &threshold_evidence,
        VectorDetails {
            dependencies: vec!["guardian-approval-set".to_owned()],
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: guardian_bindings,
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );

    catalog.add(
        "crypto-migration-begin",
        "BeginCryptoMigration",
        &migration,
        VectorDetails {
            expected_ids: BTreeMap::from([("crypto_migration_id", migration_id.to_string())]),
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: migration_signatures,
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "controller-key-binding-proof",
        "ControllerKeyBindingProof",
        &migration.proofs().as_slice()[0],
        VectorDetails {
            version_scope: "v1 inherited from exact crypto migration begin",
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: crypto_migration_signature_bindings(&migration),
            dependencies: vec!["crypto-migration-begin".to_owned()],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );

    let capability = capability_fixture::fixture();
    catalog.add(
        "capability-grant",
        "CapabilityGrant",
        &capability.grant,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "capability_grant_id",
                capability.grant.capability_grant_id().unwrap().to_string(),
            )]),
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "capability-root-grant",
        "CapabilityGrant",
        capability.root.grant(),
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "capability_grant_id",
                capability
                    .root
                    .grant()
                    .capability_grant_id()
                    .unwrap()
                    .to_string(),
            )]),
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "capability-root",
        "CapabilityRoot",
        &capability.root,
        VectorDetails {
            dependencies: vec!["capability-root-grant".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "delegation-body",
        "DelegationBody",
        &capability.body,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "delegation_id",
                capability.body.delegation_id().unwrap().to_string(),
            )]),
            dependencies: vec!["capability-grant".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "signed-delegation",
        "SignedDelegation",
        &capability.signed,
        VectorDetails {
            dependencies: vec!["delegation-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/capability-delegation-signature/v1",
                capability.body.to_canonical_bytes().unwrap(),
                &capability.secret,
                *capability.signed.signature().as_bytes(),
            )
        },
    );
    catalog.add(
        "delegation-chain",
        "DelegationChain",
        &capability.chain,
        VectorDetails {
            dependencies: vec!["capability-root".to_owned(), "signed-delegation".to_owned()],
            ..signature_details(
                "KRIKOS-ID/capability-delegation-signature/v1",
                capability.body.to_canonical_bytes().unwrap(),
                &capability.secret,
                *capability.signed.signature().as_bytes(),
            )
        },
    );

    let (application_secret, _, application_event) = application_fixture::fixture();
    catalog.add(
        "application-event-body",
        "ApplicationEventBody",
        application_event.body(),
        VectorDetails {
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "signed-application-event",
        "SignedApplicationEvent",
        &application_event,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "application_event_id",
                application_event
                    .application_event_id()
                    .unwrap()
                    .to_string(),
            )]),
            dependencies: vec!["application-event-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/application-event-signature/v1",
                application_event.body().signing_bytes().unwrap(),
                &application_secret,
                *application_event.signature().as_bytes(),
            )
        },
    );

    let (wrap_header, wrapped_key, recipient_wraps) = key_wrap_fixture::fixture();
    catalog.add(
        "group-key-wrap-header",
        "GroupKeyWrapHeader",
        &wrap_header,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "X25519", "XChaCha20-Poly1305"],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "wrapped-group-key",
        "WrappedGroupKey",
        &wrapped_key,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "X25519", "XChaCha20-Poly1305"],
            expected_ids: BTreeMap::from([(
                "group_key_wrap_id",
                wrapped_key.group_key_wrap_id().unwrap().to_string(),
            )]),
            dependencies: vec!["group-key-wrap-header".to_owned()],
            tamper_expectation: "key_wrap_authentication_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "recipient-key-wraps",
        "RecipientKeyWraps",
        &recipient_wraps,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "X25519", "XChaCha20-Poly1305"],
            dependencies: vec!["wrapped-group-key".to_owned()],
            ..VectorDetails::default()
        },
    );

    let (social_secret, social) = social_fixture::fixture();
    catalog.add(
        "social-attestation-body",
        "SocialAttestationBody",
        social.body(),
        VectorDetails {
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "signed-social-attestation",
        "SignedSocialAttestation",
        &social,
        VectorDetails {
            dependencies: vec!["social-attestation-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/social-attestation-signature/v1",
                social.body().signing_bytes().unwrap(),
                &social_secret,
                social.issuer_signature().as_bytes().try_into().unwrap(),
            )
        },
    );

    let (name_secret, name_claim) = name_fixture::fixture();
    catalog.add(
        "name-claim-body",
        "NameClaimBody",
        name_claim.body(),
        VectorDetails {
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "signed-name-claim",
        "SignedNameClaim",
        &name_claim,
        VectorDetails {
            dependencies: vec!["name-claim-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/name-claim-signature/v1",
                name_claim.body().signing_bytes().unwrap(),
                &name_secret,
                name_claim
                    .subject_signature()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            )
        },
    );

    let (private_context, private_envelope) = private_metadata_fixture::fixture();
    catalog.add(
        "private-artifact-context",
        "PrivateArtifactContext",
        &private_context,
        VectorDetails::default(),
    );
    catalog.add(
        "private-metadata-envelope",
        "PrivateMetadataEnvelope",
        &private_envelope,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "XChaCha20-Poly1305"],
            dependencies: vec!["private-artifact-context".to_owned()],
            tamper_expectation: "private_metadata_authentication_rejected",
            ..VectorDetails::default()
        },
    );

    let (portable_secret, credential) = portable_fixture::fixture();
    catalog.add(
        "portable-credential-body",
        "PortableCredentialBody",
        credential.body(),
        VectorDetails {
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "signed-portable-credential",
        "SignedPortableCredential",
        &credential,
        VectorDetails {
            dependencies: vec!["portable-credential-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/portable-credential-signature/v1",
                credential.body().signing_bytes().unwrap(),
                &portable_secret,
                credential.issuer_signature().as_bytes().try_into().unwrap(),
            )
        },
    );

    let provider = transparency_fixture::fixture();
    let provider_log_id = typed_id::<ProviderLogId>(0x92);
    let provider_store = MemoryProviderStore::new(
        provider.provider.clone(),
        provider_log_id,
        ProviderKeyVersion::GENESIS,
    )
    .unwrap();
    let checkpoint_bundle = build_provider_checkpoint_bundle_from_genesis(
        &fixture.genesis,
        std::slice::from_ref(&fixture.event),
        &fixture.checkpoint,
        None,
    )
    .unwrap();
    let provider_admission = checkpoint_bundle.provider_log_admission();
    let provider_request = ProviderAdmissionRequest::for_admission(&provider_admission).unwrap();
    let provider_permit = authorize_provider_append(
        provider_admission,
        provider_request,
        &AllowProviderAdmission,
    )
    .unwrap();
    provider_store
        .append(
            provider_permit,
            Timestamp::from_unix_millis(120),
            &InteropProviderSigner(&provider.secret),
        )
        .unwrap();
    let provider_generation = provider_store.export_generation().unwrap();
    let provider_audit_store =
        MemoryProviderAuditStore::new(provider.provider.clone(), provider_log_id);
    let provider_auditor = DurableProviderAuditor::new(provider_audit_store.clone());
    provider_auditor
        .observe(provider_generation.latest_head().unwrap().clone(), None)
        .unwrap();
    let rollback_body = ProviderHeadBody::new(
        provider.provider.id().unwrap(),
        provider_log_id,
        ProviderKeyVersion::GENESIS,
        provider_generation
            .latest_head()
            .unwrap()
            .body()
            .tree_size(),
        provider_generation
            .latest_head()
            .unwrap()
            .body()
            .tree_root(),
        Timestamp::from_unix_millis(119),
        Extensions::default(),
    )
    .unwrap();
    let rollback_head = SignedProviderHead::new(
        rollback_body.clone(),
        ProtocolSignature::ed25519(
            provider
                .secret
                .sign(&rollback_body.signing_bytes().unwrap())
                .to_bytes(),
        ),
    );
    assert_eq!(
        provider_auditor.observe(rollback_head.clone(), None),
        Err(IdentityError::ProviderRollback)
    );
    let provider_recovery = ProviderRecoveryExport::new(
        provider_generation.clone(),
        provider_audit_store.snapshot().unwrap(),
    )
    .unwrap();
    let provider_inventory = derive_provider_retention_inventory(&provider_recovery).unwrap();
    let provider_compaction =
        verify_provider_compaction(&provider_recovery, &provider_recovery, &provider_inventory)
            .unwrap()
            .manifest()
            .clone();
    let provider_anchor =
        OpaqueProviderAnchorCommitment::from_compaction_manifest(&provider_compaction).unwrap();
    let (provider_recovery_manifest, provider_generation_chunks, provider_audit_chunks) =
        provider_recovery.interchange_parts().unwrap();
    let provider_generation_manifest = provider_recovery_manifest.generation().clone();
    let provider_audit_manifest = provider_recovery_manifest.audit().clone();
    let provider_component = ProviderExportComponent::CheckpointBundles;
    let provider_component_descriptor = provider_generation_manifest
        .descriptor(provider_component)
        .unwrap()
        .clone();
    let provider_generation_chunk = provider_generation_chunks
        .into_iter()
        .find(|chunk| chunk.component() == Ok(provider_component))
        .expect("populated provider generation has one checkpoint-bundle chunk");
    let provider_audit_chunk = provider_audit_chunks
        .into_iter()
        .next()
        .expect("populated provider audit has one audit chunk");
    let generation_head = provider_generation.latest_head().unwrap().clone();
    let provider_entry = provider_generation.entries()[0].clone();
    let provider_receipt = provider_generation.receipts()[0].clone();
    let provider_receipts = ProviderReceipts::new(vec![provider_receipt.clone()]).unwrap();
    let conflicting_body = ProviderHeadBody::new(
        provider.provider.id().unwrap(),
        provider_log_id,
        ProviderKeyVersion::GENESIS,
        generation_head.body().tree_size(),
        Digest::new(HashAlgorithm::Blake3_256, [0x99; 32]),
        Timestamp::from_unix_millis(121),
        Extensions::default(),
    )
    .unwrap();
    let conflicting_head = SignedProviderHead::new(
        conflicting_body.clone(),
        ProtocolSignature::ed25519(
            provider
                .secret
                .sign(&conflicting_body.signing_bytes().unwrap())
                .to_bytes(),
        ),
    );
    let provider_evidence = ProviderEquivocationEvidence::new(
        &provider.provider,
        generation_head.clone(),
        conflicting_head,
    )
    .unwrap();
    catalog.add(
        "provider-log-entry",
        "ProviderLogEntryBody",
        &provider_entry,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "merkle_leaf_hash",
                provider_entry.merkle_leaf_hash().unwrap().to_string(),
            )]),
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "provider-head-body",
        "ProviderHeadBody",
        generation_head.body(),
        VectorDetails {
            dependencies: vec!["provider-log-entry".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "signed-provider-head",
        "SignedProviderHead",
        &generation_head,
        VectorDetails {
            dependencies: vec!["provider-head-body".to_owned()],
            ..signature_details(
                "KRIKOS-ID/provider-head-signature/v1",
                generation_head.body().signing_bytes().unwrap(),
                &provider.secret,
                *generation_head.signature().as_bytes(),
            )
        },
    );
    catalog.add(
        "inclusion-receipt",
        "InclusionReceipt",
        &provider_receipt,
        VectorDetails {
            dependencies: vec![
                "provider-log-entry".to_owned(),
                "signed-provider-head".to_owned(),
            ],
            ..signature_details(
                "KRIKOS-ID/provider-head-signature/v1",
                generation_head.body().signing_bytes().unwrap(),
                &provider.secret,
                *generation_head.signature().as_bytes(),
            )
        },
    );
    catalog.add(
        "provider-receipts",
        "ProviderReceipts",
        &provider_receipts,
        VectorDetails {
            dependencies: vec!["inclusion-receipt".to_owned()],
            ..signature_details(
                "KRIKOS-ID/provider-head-signature/v1",
                generation_head.body().signing_bytes().unwrap(),
                &provider.secret,
                *generation_head.signature().as_bytes(),
            )
        },
    );
    catalog.add(
        "provider-equivocation-evidence",
        "ProviderEquivocationEvidence",
        &provider_evidence,
        VectorDetails {
            dependencies: vec!["signed-provider-head".to_owned()],
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: [provider_evidence.first(), provider_evidence.second()]
                .iter()
                .enumerate()
                .map(|(index, head)| {
                    signature_binding(
                        &format!("signature-{}", index + 1),
                        "KRIKOS-ID/provider-head-signature/v1",
                        head.body().signing_bytes().unwrap(),
                        &provider.secret,
                        *head.signature().as_bytes(),
                    )
                })
                .collect(),
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    let event_approval = &fixture.event.approvals().as_slice()[0];
    let checkpoint_approval = &fixture
        .checkpoint
        .authorization()
        .controller_approvals()
        .unwrap()
        .as_slice()[0];
    let provider_checkpoint_chunk_bindings = vec![
        signature_binding(
            "signature-1",
            "KRIKOS-ID/controller-approval-signature/v1",
            event_approval.body().to_canonical_bytes().unwrap(),
            &fixture.signer,
            event_approval.signatures()[0]
                .signature()
                .as_bytes()
                .try_into()
                .unwrap(),
        ),
        signature_binding(
            "signature-2",
            "KRIKOS-ID/controller-approval-signature/v1",
            checkpoint_approval.body().to_canonical_bytes().unwrap(),
            &fixture.signer,
            checkpoint_approval.signatures()[0]
                .signature()
                .as_bytes()
                .try_into()
                .unwrap(),
        ),
    ];
    catalog.add(
        "provider-export-component",
        "ProviderExportComponent",
        &provider_component,
        VectorDetails {
            version_scope: "authoritative-provider-interchange-format-v1",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "provider-export-component-descriptor",
        "ProviderExportComponentDescriptor",
        &provider_component_descriptor,
        VectorDetails {
            version_scope: "authoritative-provider-interchange-format-v1",
            dependencies: vec!["provider-export-component".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "provider-generation-export-chunk",
        "ProviderGenerationExportChunk",
        &provider_generation_chunk,
        VectorDetails {
            version_scope: "authoritative-provider-interchange-format-v1",
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: provider_checkpoint_chunk_bindings,
            dependencies: vec![
                "account-genesis".to_owned(),
                "authorized-event".to_owned(),
                "checkpoint-direct".to_owned(),
                "provider-generation-export-manifest".to_owned(),
            ],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    let provider_audit_chunk_bindings = provider_recovery
        .audit()
        .records()
        .iter()
        .enumerate()
        .map(|(index, record)| {
            signature_binding(
                &format!("signature-{}", index + 1),
                "KRIKOS-ID/provider-head-signature/v1",
                record.head().body().signing_bytes().unwrap(),
                &provider.secret,
                *record.head().signature().as_bytes(),
            )
        })
        .collect();
    catalog.add(
        "provider-audit-export-chunk",
        "ProviderAuditExportChunk",
        &provider_audit_chunk,
        VectorDetails {
            version_scope: "authoritative-provider-interchange-format-v1",
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: provider_audit_chunk_bindings,
            dependencies: vec!["provider-audit-export-manifest".to_owned()],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    let provider_generation_manifest_binding = signature_binding(
        "signature-1",
        "KRIKOS-ID/provider-head-signature/v1",
        generation_head.body().signing_bytes().unwrap(),
        &provider.secret,
        *generation_head.signature().as_bytes(),
    );
    catalog.add(
        "provider-generation-export-manifest",
        "ProviderGenerationExportManifest",
        &provider_generation_manifest,
        VectorDetails {
            version_scope: "authoritative-provider-interchange-format-v1",
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: vec![provider_generation_manifest_binding.clone()],
            dependencies: vec![
                "provider-export-component-descriptor".to_owned(),
                "signed-provider-head".to_owned(),
            ],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    let provider_audit_manifest_binding = signature_binding(
        "signature-1",
        "KRIKOS-ID/provider-head-signature/v1",
        provider_audit_manifest
            .latest_head()
            .unwrap()
            .body()
            .signing_bytes()
            .unwrap(),
        &provider.secret,
        *provider_audit_manifest
            .latest_head()
            .unwrap()
            .signature()
            .as_bytes(),
    );
    catalog.add(
        "provider-audit-export-manifest",
        "ProviderAuditExportManifest",
        &provider_audit_manifest,
        VectorDetails {
            version_scope: "authoritative-provider-interchange-format-v1",
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: vec![provider_audit_manifest_binding.clone()],
            dependencies: vec!["signed-provider-head".to_owned()],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    let provider_recovery_bindings = vec![
        provider_generation_manifest_binding,
        signature_binding(
            "signature-2",
            "KRIKOS-ID/provider-head-signature/v1",
            provider_audit_manifest
                .latest_head()
                .unwrap()
                .body()
                .signing_bytes()
                .unwrap(),
            &provider.secret,
            *provider_audit_manifest
                .latest_head()
                .unwrap()
                .signature()
                .as_bytes(),
        ),
    ];
    catalog.add(
        "provider-recovery-export-manifest",
        "ProviderRecoveryExportManifest",
        &provider_recovery_manifest,
        VectorDetails {
            version_scope: "authoritative-provider-interchange-format-v1",
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: provider_recovery_bindings,
            dependencies: vec![
                "provider-generation-export-manifest".to_owned(),
                "provider-audit-export-manifest".to_owned(),
            ],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "provider-compaction-manifest",
        "ProviderCompactionManifest",
        &provider_compaction,
        VectorDetails {
            version_scope: "authoritative-provider-compaction-format-v1",
            dependencies: vec!["provider-recovery-export-manifest".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "opaque-provider-anchor-commitment",
        "OpaqueProviderAnchorCommitment",
        &provider_anchor,
        VectorDetails {
            version_scope: "authoritative-provider-anchor-format-v1",
            derivations: vec![provider_anchor_commitment_derivation(
                provider_anchor,
                &provider_compaction,
            )],
            dependencies: vec!["provider-compaction-manifest".to_owned()],
            ..VectorDetails::default()
        },
    );

    use krikos_identity::merkle::{MerkleSet, MerkleSetKey, MerkleSetLeaf};
    let key = MerkleSetKey::new(7, Digest::new(HashAlgorithm::Blake3_256, [0xd1; 32])).unwrap();
    let leaf = MerkleSetLeaf::new(key, Digest::new(HashAlgorithm::Blake3_256, [0xd2; 32]));
    let set = MerkleSet::new(vec![
        leaf,
        MerkleSetLeaf::new(
            MerkleSetKey::new(7, Digest::new(HashAlgorithm::Blake3_256, [0xd3; 32])).unwrap(),
            Digest::new(HashAlgorithm::Blake3_256, [0xd4; 32]),
        ),
        MerkleSetLeaf::new(
            MerkleSetKey::new(7, Digest::new(HashAlgorithm::Blake3_256, [0xd5; 32])).unwrap(),
            Digest::new(HashAlgorithm::Blake3_256, [0xd6; 32]),
        ),
    ])
    .unwrap();
    let inclusion = set.inclusion_proof(key).unwrap();
    let consistency = set.consistency_proof(1).unwrap();
    let missing_key =
        MerkleSetKey::new(7, Digest::new(HashAlgorithm::Blake3_256, [0xd0; 32])).unwrap();
    let non_membership = set.non_membership_proof(missing_key).unwrap();
    catalog.add(
        "merkle-set-key",
        "MerkleSetKey",
        &missing_key,
        VectorDetails {
            protocol_version: None,
            version_scope: "standalone Merkle structure; version inherited from enclosing v1 object",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "merkle-set-leaf",
        "MerkleSetLeaf",
        &leaf,
        VectorDetails {
            protocol_version: None,
            version_scope: "standalone Merkle structure; version inherited from enclosing v1 object",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "merkle-inclusion-proof",
        "MerkleInclusionProof",
        &inclusion,
        VectorDetails {
            protocol_version: None,
            version_scope: "standalone Merkle structure; version inherited from enclosing v1 object",
            expected_ids: BTreeMap::from([("merkle_root", set.root().unwrap().to_string())]),
            derivations: merkle_inclusion_derivations(
                &leaf,
                &inclusion,
                "merkle_leaf_hash",
                "merkle_root",
            ),
            dependencies: vec!["merkle-set-leaf".to_owned()],
            tamper_expectation: "merkle_proof_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "merkle-consistency-proof",
        "MerkleConsistencyProof",
        &consistency,
        VectorDetails {
            protocol_version: None,
            version_scope: "standalone Merkle structure; version inherited from enclosing v1 object",
            expected_ids: BTreeMap::from([
                (
                    "old_merkle_root",
                    MerkleSet::new(set.entries()[..1].to_vec())
                        .unwrap()
                        .root()
                        .unwrap()
                        .to_string(),
                ),
                ("new_merkle_root", set.root().unwrap().to_string()),
            ]),
            derivations: merkle_consistency_derivations(&leaf, &consistency),
            dependencies: vec!["merkle-set-leaf".to_owned()],
            tamper_expectation: "merkle_proof_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "merkle-non-membership-proof",
        "MerkleNonMembershipProof",
        &non_membership,
        VectorDetails {
            protocol_version: None,
            version_scope: "standalone Merkle structure; version inherited from enclosing v1 object",
            expected_ids: BTreeMap::from([
                ("merkle_root", set.root().unwrap().to_string()),
                (
                    "missing_key",
                    hex::encode(missing_key.to_canonical_bytes().unwrap()),
                ),
            ]),
            dependencies: vec!["merkle-set-key".to_owned()],
            tamper_expectation: "merkle_proof_rejected",
            ..VectorDetails::default()
        },
    );

    let pairing_ticket =
        PairingTicket::from_canonical_bytes(&fuzz_seed_payload("seed.txt", 0)).unwrap();
    let pairing_transcript = PairingTranscript::from_canonical_bytes(&fuzz_seed_payload(
        "selector-1-pairing-transcript",
        1,
    ))
    .unwrap();
    let pairing_proof = PairingPossessionProof::from_canonical_bytes(&fuzz_seed_payload(
        "selector-2-pairing-proof",
        2,
    ))
    .unwrap();
    let device_proposal = DeviceAuthorizationProposal::from_canonical_bytes(&fuzz_seed_payload(
        "selector-3-device-authorization-proposal",
        3,
    ))
    .unwrap();
    let presence_challenge = DevicePresenceChallenge::from_canonical_bytes(&fuzz_seed_payload(
        "selector-4-presence-challenge",
        4,
    ))
    .unwrap();
    let presence_proof =
        PresenceProof::from_canonical_bytes(&fuzz_seed_payload("selector-5-presence-proof", 5))
            .unwrap();
    let pairing_application_secret = SecretKey::from_bytes(&[10; 32]);
    let pairing_application_message = pairing_transcript
        .application_possession_signing_bytes()
        .unwrap();
    let pairing_endpoint_secret = SecretKey::from_bytes(&[12; 32]);
    let pairing_endpoint_message = pairing_transcript
        .endpoint_possession_signing_bytes()
        .unwrap();
    let transcript_bytes = pairing_transcript.to_canonical_bytes().unwrap();
    let pairing_macs = vec![
        pairing_mac_binding(
            "agreement-possession",
            "KRIKOS-ID/pairing-agreement-proof-key/v1",
            "KRIKOS-ID/pairing-agreement-possession/v1",
            PairingMacKeyInputs {
                secret_seed: [11; 32],
                subject_public_key: pairing_transcript.proposed_device().agreement_key(),
                connection_public_key: pairing_transcript.connection_ephemeral_public_key(),
            },
            &transcript_bytes,
            pairing_proof.agreement_mac(),
        ),
        pairing_mac_binding(
            "pairing-ephemeral-possession",
            "KRIKOS-ID/pairing-ephemeral-proof-key/v1",
            "KRIKOS-ID/pairing-ephemeral-possession/v1",
            PairingMacKeyInputs {
                secret_seed: [0x5a; 32],
                subject_public_key: pairing_transcript.pairing_ephemeral_public_key(),
                connection_public_key: pairing_transcript.connection_ephemeral_public_key(),
            },
            &transcript_bytes,
            pairing_proof.pairing_ephemeral_mac(),
        ),
    ];
    catalog.add(
        "pairing-ticket",
        "PairingTicket",
        &pairing_ticket,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "pairing_ticket_id",
                pairing_ticket.ticket_id().unwrap().as_digest().to_string(),
            )]),
            tamper_expectation: "identifier_or_binding_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "pairing-transcript",
        "PairingTranscript",
        &pairing_transcript,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "pairing_transcript_id",
                pairing_transcript
                    .transcript_id()
                    .unwrap()
                    .as_digest()
                    .to_string(),
            )]),
            dependencies: vec!["pairing-ticket".to_owned()],
            tamper_expectation: "identifier_or_binding_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "pairing-possession-proof",
        "PairingPossessionProof",
        &pairing_proof,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "pairing_proof_id",
                pairing_proof.proof_id().unwrap().as_digest().to_string(),
            )]),
            dependencies: vec!["pairing-transcript".to_owned()],
            algorithms: vec!["BLAKE3-256", "Ed25519", "X25519"],
            signature_bindings: vec![
                signature_binding(
                    "signature-1",
                    "KRIKOS-ID/pairing-application-possession/v1",
                    pairing_application_message,
                    &pairing_application_secret,
                    *pairing_proof.application_signature().as_bytes(),
                ),
                signature_binding(
                    "signature-2",
                    "KRIKOS-ID/pairing-endpoint-possession/v1",
                    pairing_endpoint_message,
                    &pairing_endpoint_secret,
                    *pairing_proof.endpoint_signature().as_bytes(),
                ),
            ],
            mac_bindings: pairing_macs,
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "pairing-confirmation-context",
        "PairingConfirmationContext",
        &device_proposal.confirmation(),
        VectorDetails {
            dependencies: vec!["pairing-transcript".to_owned()],
            tamper_expectation: "identifier_or_binding_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "device-authorization-proposal",
        "DeviceAuthorizationProposal",
        &device_proposal,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "device_authorization_proposal_id",
                device_proposal
                    .proposal_id()
                    .unwrap()
                    .as_digest()
                    .to_string(),
            )]),
            dependencies: vec![
                "pairing-ticket".to_owned(),
                "pairing-transcript".to_owned(),
                "pairing-possession-proof".to_owned(),
                "pairing-confirmation-context".to_owned(),
            ],
            tamper_expectation: "identifier_or_binding_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "presence-challenge",
        "DevicePresenceChallenge",
        &presence_challenge,
        VectorDetails {
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "presence-proof",
        "PresenceProof",
        &presence_proof,
        VectorDetails {
            expected_ids: BTreeMap::from([(
                "presence_proof_id",
                presence_proof.proof_id().unwrap().as_digest().to_string(),
            )]),
            dependencies: vec!["presence-challenge".to_owned()],
            ..signature_details(
                "KRIKOS-ID/device-presence-signature/v1",
                presence_challenge.signing_bytes().unwrap(),
                &pairing_application_secret,
                *presence_proof.signature().as_bytes(),
            )
        },
    );

    let sync_account_id = fixture.genesis.account_id().unwrap();
    let sync_head = fixture.event.event_id().unwrap();
    let sync_cursor = SyncCursor::issue(
        &CursorKey::new(INTEROP_SYNC_CURSOR_KEY).unwrap(),
        sync_account_id,
        vec![sync_head],
        1,
        512,
    )
    .unwrap();
    let sync_request = SyncRequest::new(
        sync_account_id,
        vec![sync_head],
        Some(sync_cursor.clone()),
        64,
        64 * 1024,
    )
    .unwrap();
    let sync_frame = SyncFrame::new(
        sync_account_id,
        vec![sync_head],
        vec![fixture.event.clone()],
        Some(sync_cursor.clone()),
    )
    .unwrap();
    let sync_response_frame = SyncResponse::frame(sync_frame.clone());
    let sync_response_complete = SyncResponse::complete(sync_account_id, vec![sync_head]).unwrap();
    let endpoint_authorization = EndpointAuthorizationRequest::new(
        sync_account_id,
        fixture.checkpoint.checkpoint_id().unwrap(),
        typed_id::<DeviceId>(0x93),
    );
    let authorized_sync =
        AuthorizedSyncRequest::new(endpoint_authorization, sync_request.clone()).unwrap();
    let proposal_authorization = EndpointAuthorizationRequest::new(
        device_proposal.account_id(),
        typed_id::<CheckpointId>(0x94),
        device_proposal.proposed_device_id(),
    );
    let authorized_proposal =
        AuthorizedProposalRequest::new(proposal_authorization, device_proposal.clone()).unwrap();
    let authorized_checkpoint =
        AuthorizedCheckpointRequest::new(endpoint_authorization, fixture.checkpoint.clone())
            .unwrap();
    let identity_ack = IdentityProtocolAck::for_canonical_request(
        IdentityProtocolKind::Sync,
        &sync_request.to_canonical_bytes().unwrap(),
        IdentityServiceOutcome::Accepted,
    );
    let identity_reply_ack = IdentityProtocolReply::acknowledgement(identity_ack.clone());
    let identity_reply_sync = IdentityProtocolReply::synchronization(sync_response_frame.clone());
    let identity_ack_derivation = network_request_commitment_derivation(
        &identity_ack,
        &sync_request.to_canonical_bytes().unwrap(),
    );
    let event_binding = || {
        signature_binding(
            "signature-1",
            "KRIKOS-ID/controller-approval-signature/v1",
            event_approval.body().to_canonical_bytes().unwrap(),
            &fixture.signer,
            event_approval.signatures()[0]
                .signature()
                .as_bytes()
                .try_into()
                .unwrap(),
        )
    };
    let checkpoint_binding = || {
        signature_binding(
            "signature-1",
            "KRIKOS-ID/controller-approval-signature/v1",
            checkpoint_approval.body().to_canonical_bytes().unwrap(),
            &fixture.signer,
            checkpoint_approval.signatures()[0]
                .signature()
                .as_bytes()
                .try_into()
                .unwrap(),
        )
    };
    let cursor_mac = || sync_cursor_mac_binding("cursor-authenticator-1", &sync_cursor);

    catalog.add(
        "sync-cursor",
        "SyncCursor",
        &sync_cursor,
        VectorDetails {
            algorithms: vec!["BLAKE3-256"],
            mac_bindings: vec![cursor_mac()],
            tamper_expectation: "cursor_authentication_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "sync-request",
        "SyncRequest",
        &sync_request,
        VectorDetails {
            algorithms: vec!["BLAKE3-256"],
            mac_bindings: vec![cursor_mac()],
            dependencies: vec!["sync-cursor".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "sync-frame",
        "SyncFrame",
        &sync_frame,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: vec![event_binding()],
            mac_bindings: vec![cursor_mac()],
            dependencies: vec!["authorized-event".to_owned(), "sync-cursor".to_owned()],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "sync-response-frame",
        "SyncResponse",
        &sync_response_frame,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: vec![event_binding()],
            mac_bindings: vec![cursor_mac()],
            dependencies: vec!["sync-frame".to_owned()],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "sync-response-complete",
        "SyncResponse",
        &sync_response_complete,
        VectorDetails::default(),
    );
    catalog.add(
        "endpoint-authorization-request",
        "EndpointAuthorizationRequest",
        &endpoint_authorization,
        VectorDetails::default(),
    );
    catalog.add(
        "proposal-endpoint-authorization-request",
        "EndpointAuthorizationRequest",
        &proposal_authorization,
        VectorDetails::default(),
    );
    catalog.add(
        "authorized-sync-request",
        "AuthorizedSyncRequest",
        &authorized_sync,
        VectorDetails {
            version_scope: "v1 inherited from exact nested authorization and sync request",
            algorithms: vec!["BLAKE3-256"],
            mac_bindings: vec![cursor_mac()],
            dependencies: vec![
                "endpoint-authorization-request".to_owned(),
                "sync-request".to_owned(),
            ],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "authorized-proposal-request",
        "AuthorizedProposalRequest",
        &authorized_proposal,
        VectorDetails {
            version_scope: "v1 inherited from exact nested authorization and proposal",
            dependencies: vec![
                "proposal-endpoint-authorization-request".to_owned(),
                "device-authorization-proposal".to_owned(),
            ],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "authorized-checkpoint-request",
        "AuthorizedCheckpointRequest",
        &authorized_checkpoint,
        VectorDetails {
            version_scope: "v1 inherited from exact nested authorization and checkpoint",
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: vec![checkpoint_binding()],
            dependencies: vec![
                "endpoint-authorization-request".to_owned(),
                "checkpoint-direct".to_owned(),
            ],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "identity-protocol-ack",
        "IdentityProtocolAck",
        &identity_ack,
        VectorDetails {
            derivations: vec![identity_ack_derivation.clone()],
            dependencies: vec!["sync-request".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "identity-protocol-reply-ack",
        "IdentityProtocolReply",
        &identity_reply_ack,
        VectorDetails {
            derivations: vec![identity_ack_derivation],
            dependencies: vec!["identity-protocol-ack".to_owned()],
            ..VectorDetails::default()
        },
    );
    catalog.add(
        "identity-protocol-reply-sync",
        "IdentityProtocolReply",
        &identity_reply_sync,
        VectorDetails {
            algorithms: vec!["BLAKE3-256", "Ed25519"],
            signature_bindings: vec![event_binding()],
            mac_bindings: vec![cursor_mac()],
            dependencies: vec!["sync-response-frame".to_owned()],
            tamper_expectation: "signature_invalid_or_decode_rejected",
            ..VectorDetails::default()
        },
    );

    catalog
        .vectors
        .sort_by(|left, right| left.name.cmp(&right.name));
    let deterministic_key = |name, seed| {
        let secret = SecretKey::from_bytes(&[seed; 32]);
        KeyMetadata {
            name,
            algorithm: "Ed25519",
            test_only_secret_seed_hex: hex::encode([seed; 32]),
            public_key_hex: hex::encode(secret.public().as_bytes()),
        }
    };
    let deterministic_agreement_key = |name, seed| {
        let secret = StaticSecret::from([seed; 32]);
        KeyMetadata {
            name,
            algorithm: "X25519",
            test_only_secret_seed_hex: hex::encode([seed; 32]),
            public_key_hex: hex::encode(X25519PublicKey::from(&secret).as_bytes()),
        }
    };
    let required_inventory = catalog
        .vectors
        .iter()
        .map(|vector| vector.name.clone())
        .collect();
    let manifest = Manifest {
        format: "KRIKOS-ID interoperability vectors",
        format_version: 2,
        binding_schema_version: 1,
        derivation_schema_version: 1,
        canonical_profile: "Postcard 1.1.3 / KRIKOS-ID v1",
        algorithms: BTreeMap::from([
            ("hash", "BLAKE3-256 (code 1)"),
            ("signature", "Ed25519 (code 1)"),
            ("agreement", "X25519 (code 1)"),
            ("kdf", "BLAKE3 derive-key (code 1)"),
            ("aead", "XChaCha20-Poly1305 (code 1)"),
        ]),
        deterministic_keys: vec![
            deterministic_key("guardian-1", 0x01),
            deterministic_key("guardian-2", 0x02),
            deterministic_key("pairing-presence-application", 0x0a),
            deterministic_key("pairing-endpoint", 0x0c),
            deterministic_key("account-controller-and-social-issuer", 0x11),
            deterministic_key("application-device", 0x31),
            deterministic_key("capability-delegator", 0x35),
            deterministic_key("name-and-portable-credential-issuer", 0x41),
            deterministic_key("transparency-provider", 0x71),
            deterministic_key("migration-successor-controller", 0x91),
            deterministic_agreement_key("pairing-proposed-agreement", 0x0b),
            deterministic_agreement_key("pairing-ticket-ephemeral", 0x5a),
        ],
        private_wire_exclusions: vec![
            Exclusion {
                wire_type: "GuardianGrant",
                reason: "private guardian identity and weight witness; no standalone public CanonicalWire implementation",
                covered_by: "SignedGuardianApproval private nested encoding",
            },
            Exclusion {
                wire_type: "GuardianGrantOpening",
                reason: "private blinding and membership witness; no standalone public CanonicalWire implementation",
                covered_by: "SignedGuardianApproval private nested encoding",
            },
        ],
        transient_wire_dispositions: vec![Exclusion {
            wire_type: "PairingConfirmation",
            reason: "public transient ceremony message intentionally has no CanonicalWire implementation and is consumed before retained proposal construction",
            covered_by: "pairing ceremony state-machine tests plus PairingConfirmationContext and DeviceAuthorizationProposal vectors",
        }],
        required_inventory,
        vectors: catalog.vectors,
    };
    let json = serde_json::to_vec_pretty(&manifest).unwrap();
    fs::write(directory.join("manifest.json"), json).unwrap();
}
