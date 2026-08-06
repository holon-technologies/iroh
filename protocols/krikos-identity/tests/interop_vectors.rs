#![cfg(feature = "net")]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use krikos_base::{PublicKey, SecretKey, Signature};
use krikos_identity::merkle::{
    MerkleConsistencyProof, MerkleInclusionProof, MerkleNonMembershipProof, MerkleSetKey,
    MerkleSetLeaf,
};
use krikos_identity::net::{
    AuthorizedCheckpointRequest, AuthorizedProposalRequest, AuthorizedSyncRequest,
    EndpointAuthorizationRequest, IdentityProtocolAck, IdentityProtocolKind, IdentityProtocolReply,
    IdentityServiceOutcome,
};
use krikos_identity::*;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Manifest {
    format: String,
    format_version: u16,
    binding_schema_version: u16,
    derivation_schema_version: u16,
    canonical_profile: String,
    algorithms: BTreeMap<String, String>,
    deterministic_keys: Vec<KeyMetadata>,
    private_wire_exclusions: Vec<Exclusion>,
    transient_wire_dispositions: Vec<Exclusion>,
    required_inventory: Vec<String>,
    vectors: Vec<VectorMetadata>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KeyMetadata {
    name: String,
    algorithm: String,
    test_only_secret_seed_hex: String,
    public_key_hex: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Exclusion {
    wire_type: String,
    reason: String,
    covered_by: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VectorMetadata {
    name: String,
    wire_type: String,
    canonical_file: String,
    canonical_hex: String,
    canonical_blake3_hex: String,
    encoded_length: usize,
    protocol_version: Option<u16>,
    version_scope: String,
    algorithms: Vec<String>,
    expected_ids: BTreeMap<String, String>,
    signature_bindings: Vec<SignatureBinding>,
    mac_bindings: Vec<MacBinding>,
    derivations: Vec<DerivationMetadata>,
    dependencies: Vec<String>,
    tamper_cases: Vec<TamperMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct SignatureBinding {
    name: String,
    algorithm: String,
    domain_ascii: String,
    message_hex: String,
    signer_key: String,
    public_key_hex: String,
    signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct MacBinding {
    name: String,
    algorithm: String,
    key_derivation_algorithm: String,
    key_derivation_context_ascii: String,
    key_derivation_input_hex: String,
    message_domain_ascii: String,
    message_hex: String,
    expected_mac_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct DerivationMetadata {
    output_name: String,
    algorithm: String,
    domain_or_context_ascii: String,
    message_hex: String,
    expected_output_hex: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TamperMetadata {
    name: String,
    offset: usize,
    replacement_hex: String,
    expectation: String,
}

// This is deliberately source-owned and independent of the generator/catalog. If a generator
// regression drops both a fixture and its manifest entry, this closed set still fails the build.
const REQUIRED_VECTOR_NAMES: &[&str] = &[
    "account-genesis",
    "account-operation-01",
    "account-operation-02",
    "account-operation-03",
    "account-operation-04",
    "account-operation-05",
    "account-operation-06",
    "account-operation-07",
    "account-operation-08",
    "account-operation-09",
    "account-operation-10",
    "account-operation-11",
    "account-operation-12",
    "account-operation-13",
    "account-operation-14",
    "account-operation-15",
    "account-operation-16",
    "account-operation-17",
    "account-operation-18",
    "account-operation-19",
    "account-operation-20",
    "account-operation-21",
    "account-operation-22",
    "admission-evidence",
    "application-event-body",
    "authorized-checkpoint-request",
    "authorized-event",
    "authorized-proposal-request",
    "authorized-sync-request",
    "backup-authority-bundle",
    "backup-envelope",
    "capability-grant",
    "capability-root",
    "capability-root-grant",
    "checkpoint-direct",
    "checkpoint-migration-dual",
    "checkpoint-migration-pending",
    "checkpoint-transition-finalize",
    "checkpoint-transition-retire",
    "controller-approvals",
    "controller-key-binding-proof",
    "crypto-migration-begin",
    "delegation-body",
    "delegation-chain",
    "device-authorization-proposal",
    "endpoint-authorization-request",
    "event-body",
    "event-intent-approval",
    "event-intent-approval-body",
    "event-intent-approvals",
    "final-event-controller-approval",
    "final-event-controller-approval-body",
    "fork-descriptor",
    "group-key-wrap-header",
    "guardian-approval-body",
    "guardian-approval-set",
    "guardian-threshold-evidence",
    "id-account",
    "id-admission-evidence",
    "id-application",
    "id-application-event",
    "id-capability-grant",
    "id-checkpoint",
    "id-control-policy",
    "id-controller",
    "id-controller-approval",
    "id-controller-key",
    "id-crypto-migration",
    "id-crypto-state",
    "id-crypto-suite",
    "id-delegation",
    "id-device",
    "id-event",
    "id-event-authorization",
    "id-event-intent-approval",
    "id-fork",
    "id-genesis-anchor",
    "id-group",
    "id-group-key-wrap",
    "id-guardian-grant",
    "id-proposal",
    "id-provider",
    "id-provider-log",
    "id-provider-policy",
    "id-recovery",
    "id-recovery-policy",
    "identity-protocol-ack",
    "identity-protocol-reply-ack",
    "identity-protocol-reply-sync",
    "inclusion-receipt",
    "merkle-consistency-proof",
    "merkle-inclusion-proof",
    "merkle-non-membership-proof",
    "merkle-set-key",
    "merkle-set-leaf",
    "name-claim-body",
    "opaque-provider-anchor-commitment",
    "pairing-confirmation-context",
    "pairing-possession-proof",
    "pairing-ticket",
    "pairing-transcript",
    "portable-credential-body",
    "presence-challenge",
    "presence-proof",
    "private-artifact-context",
    "private-metadata-envelope",
    "proposal-endpoint-authorization-request",
    "provider-audit-export-chunk",
    "provider-audit-export-manifest",
    "provider-compaction-manifest",
    "provider-equivocation-evidence",
    "provider-export-component",
    "provider-export-component-descriptor",
    "provider-generation-export-chunk",
    "provider-generation-export-manifest",
    "provider-head-body",
    "provider-log-entry",
    "provider-receipts",
    "provider-recovery-export-manifest",
    "recipient-key-wraps",
    "recovery-authority-plan",
    "recovery-begin",
    "recovery-cancel",
    "recovery-delay-anchor",
    "recovery-finalize",
    "recovery-proposal",
    "recovery-veto",
    "signed-application-event",
    "signed-delegation",
    "signed-guardian-approval",
    "signed-name-claim",
    "signed-portable-credential",
    "signed-provider-head",
    "signed-social-attestation",
    "social-attestation-body",
    "sync-cursor",
    "sync-frame",
    "sync-request",
    "sync-response-complete",
    "sync-response-frame",
    "wrapped-group-key",
];

const PAIRING_CONFIRMATION_DISPOSITION_REASON: &str = "public transient ceremony message intentionally has no CanonicalWire implementation and is consumed before retained proposal construction";
const PAIRING_CONFIRMATION_DISPOSITION_COVERAGE: &str = "pairing ceremony state-machine tests plus PairingConfirmationContext and DeviceAuthorizationProposal vectors";

fn required_wire_type(name: &str) -> &'static str {
    match name {
        "account-operation-01"
        | "account-operation-02"
        | "account-operation-03"
        | "account-operation-04"
        | "account-operation-05"
        | "account-operation-06"
        | "account-operation-07"
        | "account-operation-08"
        | "account-operation-09"
        | "account-operation-10"
        | "account-operation-11"
        | "account-operation-12"
        | "account-operation-13"
        | "account-operation-14"
        | "account-operation-15"
        | "account-operation-16"
        | "account-operation-17"
        | "account-operation-18"
        | "account-operation-19"
        | "account-operation-20"
        | "account-operation-21"
        | "account-operation-22" => "AccountOperation",
        "checkpoint-direct"
        | "checkpoint-migration-dual"
        | "checkpoint-migration-pending"
        | "checkpoint-transition-finalize"
        | "checkpoint-transition-retire" => "SignedCheckpoint",
        "identity-protocol-reply-ack" | "identity-protocol-reply-sync" => "IdentityProtocolReply",
        "sync-response-complete" | "sync-response-frame" => "SyncResponse",
        "account-genesis" => "AccountGenesis",
        "admission-evidence" => "AdmissionEvidence",
        "application-event-body" => "ApplicationEventBody",
        "authorized-checkpoint-request" => "AuthorizedCheckpointRequest",
        "authorized-event" => "AuthorizedEvent",
        "authorized-proposal-request" => "AuthorizedProposalRequest",
        "authorized-sync-request" => "AuthorizedSyncRequest",
        "backup-authority-bundle" => "BackupAuthorityBundle",
        "backup-envelope" => "BackupEnvelope",
        "capability-grant" | "capability-root-grant" => "CapabilityGrant",
        "capability-root" => "CapabilityRoot",
        "controller-approvals" => "ControllerApprovals",
        "controller-key-binding-proof" => "ControllerKeyBindingProof",
        "crypto-migration-begin" => "BeginCryptoMigration",
        "delegation-body" => "DelegationBody",
        "delegation-chain" => "DelegationChain",
        "device-authorization-proposal" => "DeviceAuthorizationProposal",
        "endpoint-authorization-request" | "proposal-endpoint-authorization-request" => {
            "EndpointAuthorizationRequest"
        }
        "event-body" => "EventBody",
        "event-intent-approval" => "SignedEventIntentApproval",
        "event-intent-approval-body" => "EventIntentApprovalBody",
        "event-intent-approvals" => "EventIntentApprovals",
        "final-event-controller-approval" => "SignedControllerApproval",
        "final-event-controller-approval-body" => "ControllerApprovalBody",
        "fork-descriptor" => "ForkDescriptor",
        "group-key-wrap-header" => "GroupKeyWrapHeader",
        "guardian-approval-body" => "GuardianApprovalBody",
        "guardian-approval-set" => "GuardianApprovalSet",
        "guardian-threshold-evidence" => "RecoveryThresholdEvidence",
        "id-account" => "AccountId",
        "id-admission-evidence" => "AdmissionEvidenceId",
        "id-application" => "ApplicationId",
        "id-application-event" => "ApplicationEventId",
        "id-capability-grant" => "CapabilityGrantId",
        "id-checkpoint" => "CheckpointId",
        "id-control-policy" => "ControlPolicyId",
        "id-controller" => "ControllerId",
        "id-controller-approval" => "ControllerApprovalId",
        "id-controller-key" => "ControllerKeyId",
        "id-crypto-migration" => "CryptoMigrationId",
        "id-crypto-state" => "CryptoStateId",
        "id-crypto-suite" => "CryptoSuiteId",
        "id-delegation" => "DelegationId",
        "id-device" => "DeviceId",
        "id-event" => "EventId",
        "id-event-authorization" => "EventAuthorizationId",
        "id-event-intent-approval" => "EventIntentApprovalId",
        "id-fork" => "ForkId",
        "id-genesis-anchor" => "GenesisAnchor",
        "id-group" => "GroupId",
        "id-group-key-wrap" => "GroupKeyWrapId",
        "id-guardian-grant" => "GuardianGrantId",
        "id-proposal" => "ProposalId",
        "id-provider" => "ProviderId",
        "id-provider-log" => "ProviderLogId",
        "id-provider-policy" => "ProviderPolicyId",
        "id-recovery" => "RecoveryId",
        "id-recovery-policy" => "RecoveryPolicyId",
        "identity-protocol-ack" => "IdentityProtocolAck",
        "inclusion-receipt" => "InclusionReceipt",
        "merkle-consistency-proof" => "MerkleConsistencyProof",
        "merkle-inclusion-proof" => "MerkleInclusionProof",
        "merkle-non-membership-proof" => "MerkleNonMembershipProof",
        "merkle-set-key" => "MerkleSetKey",
        "merkle-set-leaf" => "MerkleSetLeaf",
        "name-claim-body" => "NameClaimBody",
        "opaque-provider-anchor-commitment" => "OpaqueProviderAnchorCommitment",
        "pairing-confirmation-context" => "PairingConfirmationContext",
        "pairing-possession-proof" => "PairingPossessionProof",
        "pairing-ticket" => "PairingTicket",
        "pairing-transcript" => "PairingTranscript",
        "portable-credential-body" => "PortableCredentialBody",
        "presence-challenge" => "DevicePresenceChallenge",
        "presence-proof" => "PresenceProof",
        "private-artifact-context" => "PrivateArtifactContext",
        "private-metadata-envelope" => "PrivateMetadataEnvelope",
        "provider-audit-export-chunk" => "ProviderAuditExportChunk",
        "provider-audit-export-manifest" => "ProviderAuditExportManifest",
        "provider-compaction-manifest" => "ProviderCompactionManifest",
        "provider-equivocation-evidence" => "ProviderEquivocationEvidence",
        "provider-export-component" => "ProviderExportComponent",
        "provider-export-component-descriptor" => "ProviderExportComponentDescriptor",
        "provider-generation-export-chunk" => "ProviderGenerationExportChunk",
        "provider-generation-export-manifest" => "ProviderGenerationExportManifest",
        "provider-head-body" => "ProviderHeadBody",
        "provider-log-entry" => "ProviderLogEntryBody",
        "provider-receipts" => "ProviderReceipts",
        "provider-recovery-export-manifest" => "ProviderRecoveryExportManifest",
        "recipient-key-wraps" => "RecipientKeyWraps",
        "recovery-authority-plan" => "RecoveryAuthorityPlan",
        "recovery-begin" => "BeginRecovery",
        "recovery-cancel" => "CancelRecovery",
        "recovery-delay-anchor" => "RecoveryDelayAnchor",
        "recovery-finalize" => "FinalizeRecovery",
        "recovery-proposal" => "RecoveryProposal",
        "recovery-veto" => "VetoRecovery",
        "signed-application-event" => "SignedApplicationEvent",
        "signed-delegation" => "SignedDelegation",
        "signed-guardian-approval" => "SignedGuardianApproval",
        "signed-name-claim" => "SignedNameClaim",
        "signed-portable-credential" => "SignedPortableCredential",
        "signed-provider-head" => "SignedProviderHead",
        "signed-social-attestation" => "SignedSocialAttestation",
        "social-attestation-body" => "SocialAttestationBody",
        "sync-cursor" => "SyncCursor",
        "sync-frame" => "SyncFrame",
        "sync-request" => "SyncRequest",
        "wrapped-group-key" => "WrappedGroupKey",
        other => panic!("required vector {other} has no source-owned wire type"),
    }
}

fn assert_closed_inventory(manifest: &Manifest) {
    assert_eq!(
        manifest
            .required_inventory
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        REQUIRED_VECTOR_NAMES,
        "manifest required_inventory must exactly equal the source-owned closed inventory"
    );
    assert_eq!(
        manifest
            .vectors
            .iter()
            .map(|vector| vector.name.as_str())
            .collect::<Vec<_>>(),
        REQUIRED_VECTOR_NAMES,
        "manifest vectors must exactly equal the source-owned closed inventory"
    );
    for vector in &manifest.vectors {
        assert_eq!(
            vector.wire_type,
            required_wire_type(&vector.name),
            "{} must retain its source-owned wire type",
            vector.name
        );
    }
    assert_eq!(manifest.transient_wire_dispositions.len(), 1);
    let disposition = &manifest.transient_wire_dispositions[0];
    assert_eq!(disposition.wire_type, "PairingConfirmation");
    assert_eq!(disposition.reason, PAIRING_CONFIRMATION_DISPOSITION_REASON);
    assert_eq!(
        disposition.covered_by,
        PAIRING_CONFIRMATION_DISPOSITION_COVERAGE
    );
}

fn vector_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

#[test]
fn interoperability_manifest_requires_versioned_binding_and_inventory_schemas() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(vector_directory().join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["format_version"], 2);
    assert_eq!(manifest["binding_schema_version"], 1);
    assert_eq!(manifest["derivation_schema_version"], 1);
    assert_eq!(
        manifest["transient_wire_dispositions"][0]["wire_type"],
        "PairingConfirmation"
    );
    assert!(
        manifest["required_inventory"]
            .as_array()
            .is_some_and(|inventory| inventory
                .iter()
                .any(|name| name == "crypto-migration-begin")),
        "closed manifest inventory must require crypto-migration-begin independently of catalog contents"
    );
    for vector in manifest["vectors"].as_array().unwrap() {
        assert!(vector["signature_bindings"].is_array());
        assert!(vector["mac_bindings"].is_array());
        assert!(vector["derivations"].is_array());
        assert!(vector.get("message_hex").is_none());
        assert!(vector.get("public_key_hex").is_none());
        assert!(vector.get("signature_hex").is_none());
    }
}

fn checked_in_manifest() -> Manifest {
    serde_json::from_slice(&fs::read(vector_directory().join("manifest.json")).unwrap()).unwrap()
}

#[test]
fn source_owned_inventory_rejects_catalog_deletion_even_when_manifest_inventory_is_also_deleted() {
    let manifest = checked_in_manifest();
    assert_closed_inventory(&manifest);

    for victim in REQUIRED_VECTOR_NAMES {
        let mut vectors_only = manifest.clone();
        vectors_only.vectors.retain(|vector| vector.name != *victim);
        assert!(
            std::panic::catch_unwind(|| assert_closed_inventory(&vectors_only)).is_err(),
            "removing required vector {victim} must fail closed"
        );

        let mut coordinated_deletion = manifest.clone();
        coordinated_deletion
            .vectors
            .retain(|vector| vector.name != *victim);
        coordinated_deletion
            .required_inventory
            .retain(|name| name != *victim);
        assert!(
            std::panic::catch_unwind(|| assert_closed_inventory(&coordinated_deletion)).is_err(),
            "deleting {victim} from generated inventory must not hide catalog loss"
        );
    }

    let mut coordinated_type_substitution = manifest.clone();
    coordinated_type_substitution
        .vectors
        .iter_mut()
        .find(|vector| vector.name == "crypto-migration-begin")
        .unwrap()
        .wire_type = "AccountOperation".to_owned();
    assert!(
        std::panic::catch_unwind(|| assert_closed_inventory(&coordinated_type_substitution))
            .is_err(),
        "retaining a required name with a substituted wire type must fail closed"
    );

    let operation_18 = manifest
        .vectors
        .iter()
        .find(|vector| vector.name == "account-operation-18")
        .unwrap();
    let operation_17 = manifest
        .vectors
        .iter()
        .find(|vector| vector.name == "account-operation-17")
        .unwrap();
    let operation_17_bytes =
        fs::read(vector_directory().join(&operation_17.canonical_file)).unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            validate_source_owned_variant(operation_18, &operation_17_bytes)
        })
        .is_err(),
        "retaining an account-operation name with a substituted valid operation variant must fail closed"
    );

    for (target_name, replacement_name) in [
        ("checkpoint-direct", "checkpoint-migration-pending"),
        ("checkpoint-migration-pending", "checkpoint-migration-dual"),
        ("checkpoint-migration-dual", "checkpoint-migration-pending"),
        (
            "checkpoint-transition-finalize",
            "checkpoint-transition-retire",
        ),
        (
            "checkpoint-transition-retire",
            "checkpoint-transition-finalize",
        ),
    ] {
        let target = manifest
            .vectors
            .iter()
            .find(|vector| vector.name == target_name)
            .unwrap();
        let replacement = manifest
            .vectors
            .iter()
            .find(|vector| vector.name == replacement_name)
            .unwrap();
        let replacement_bytes =
            fs::read(vector_directory().join(&replacement.canonical_file)).unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                validate_source_owned_variant(target, &replacement_bytes)
            })
            .is_err(),
            "retaining {target_name} with valid {replacement_name} bytes must fail closed"
        );
    }
}

#[test]
fn every_declared_dependency_is_consumed_and_cannot_be_substituted() {
    let manifest = checked_in_manifest();
    let directory = vector_directory();
    let vectors = manifest
        .vectors
        .iter()
        .map(|vector| (vector.name.as_str(), vector))
        .collect::<BTreeMap<_, _>>();

    for vector in manifest
        .vectors
        .iter()
        .filter(|vector| !vector.dependencies.is_empty())
    {
        let bytes = fs::read(directory.join(&vector.canonical_file)).unwrap();
        for dependency_index in 0..vector.dependencies.len() {
            let replacement = manifest
                .vectors
                .iter()
                .find(|candidate| {
                    candidate.name != vector.name && !vector.dependencies.contains(&candidate.name)
                })
                .unwrap();
            let mut substituted = vector.clone();
            substituted.dependencies[dependency_index] = replacement.name.clone();
            assert!(
                std::panic::catch_unwind(|| {
                    validate_cross_vector_dependencies(&substituted, &bytes, &directory, &vectors)
                })
                .is_err(),
                "{} dependency {} accepted coordinated substitution with {}",
                vector.name,
                vector.dependencies[dependency_index],
                replacement.name
            );
        }
    }

    let mut unused_dependency = (*vectors["merkle-set-key"]).clone();
    unused_dependency.dependencies = vec!["account-genesis".to_owned()];
    let bytes = fs::read(directory.join(&unused_dependency.canonical_file)).unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            validate_cross_vector_dependencies(&unused_dependency, &bytes, &directory, &vectors)
        })
        .is_err(),
        "a source-owned vector with no dependency rule accepted an unused dependency"
    );
}

#[test]
fn merkle_nonmembership_consumes_exact_query_neighbors_and_root() {
    let manifest = checked_in_manifest();
    let directory = vector_directory();
    let vectors = manifest
        .vectors
        .iter()
        .map(|vector| (vector.name.as_str(), vector))
        .collect::<BTreeMap<_, _>>();
    let vector = vectors["merkle-non-membership-proof"];
    assert_eq!(vector.dependencies, ["merkle-set-key"]);
    let proof = MerkleNonMembershipProof::from_canonical_bytes(
        &fs::read(directory.join(&vector.canonical_file)).unwrap(),
    )
    .unwrap();
    let missing_key = MerkleSetKey::from_canonical_bytes(
        &fs::read(directory.join(&vectors["merkle-set-key"].canonical_file)).unwrap(),
    )
    .unwrap();
    let derivations = merkle_non_membership_derivations(&proof);
    let root_derivation = derivations.last().unwrap();
    assert_eq!(root_derivation.output_name, "merkle_root");
    let root = Digest::new(
        HashAlgorithm::Blake3_256,
        hex::decode(&root_derivation.expected_output_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    proof.verify(missing_key, root).unwrap();
    if let Some(predecessor) = proof.predecessor() {
        assert!(predecessor.leaf().key() < missing_key);
    }
    if let Some(successor) = proof.successor() {
        assert!(missing_key < successor.leaf().key());
    }
}

fn visit_dependency_graph(
    name: &str,
    vectors: &BTreeMap<&str, &VectorMetadata>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) {
    if visited.contains(name) {
        return;
    }
    assert!(
        visiting.insert(name.to_owned()),
        "interoperability dependency cycle reaches {name}"
    );
    for dependency in &vectors[name].dependencies {
        visit_dependency_graph(dependency, vectors, visiting, visited);
    }
    assert!(visiting.remove(name));
    assert!(visited.insert(name.to_owned()));
}

fn validate_canonical<T: CanonicalWire>(bytes: &[u8], name: &str) {
    let decoded = T::from_canonical_bytes(bytes)
        .unwrap_or_else(|error| panic!("{name} failed canonical decode: {error}"));
    assert_eq!(
        decoded.to_canonical_bytes().as_deref(),
        Ok(bytes),
        "{name} did not reproduce its checked-in canonical bytes"
    );
}

macro_rules! validate_id_type {
    ($wire_type:expr, $bytes:expr, $name:expr, $($type:ty),+ $(,)?) => {
        match $wire_type {
            $(stringify!($type) => validate_canonical::<$type>($bytes, $name),)+
            _ => unreachable!("caller checks non-ID types separately"),
        }
    };
}

fn validate_wire_type(vector: &VectorMetadata, bytes: &[u8]) {
    validate_source_owned_variant(vector, bytes);
    match vector.wire_type.as_str() {
        "GenesisAnchor"
        | "AccountId"
        | "ControllerId"
        | "ControllerKeyId"
        | "ControlPolicyId"
        | "RecoveryPolicyId"
        | "ProviderId"
        | "ProviderLogId"
        | "ProviderPolicyId"
        | "DeviceId"
        | "CapabilityGrantId"
        | "DelegationId"
        | "ProposalId"
        | "EventId"
        | "EventAuthorizationId"
        | "AdmissionEvidenceId"
        | "ControllerApprovalId"
        | "EventIntentApprovalId"
        | "CheckpointId"
        | "RecoveryId"
        | "GuardianGrantId"
        | "ForkId"
        | "CryptoSuiteId"
        | "CryptoMigrationId"
        | "CryptoStateId"
        | "ApplicationId"
        | "ApplicationEventId"
        | "GroupId"
        | "GroupKeyWrapId" => validate_id_type!(
            vector.wire_type.as_str(),
            bytes,
            &vector.name,
            GenesisAnchor,
            AccountId,
            ControllerId,
            ControllerKeyId,
            ControlPolicyId,
            RecoveryPolicyId,
            ProviderId,
            ProviderLogId,
            ProviderPolicyId,
            DeviceId,
            CapabilityGrantId,
            DelegationId,
            ProposalId,
            EventId,
            EventAuthorizationId,
            AdmissionEvidenceId,
            ControllerApprovalId,
            EventIntentApprovalId,
            CheckpointId,
            RecoveryId,
            GuardianGrantId,
            ForkId,
            CryptoSuiteId,
            CryptoMigrationId,
            CryptoStateId,
            ApplicationId,
            ApplicationEventId,
            GroupId,
            GroupKeyWrapId,
        ),
        "AccountGenesis" => validate_canonical::<AccountGenesis>(bytes, &vector.name),
        "AccountOperation" => validate_canonical::<AccountOperation>(bytes, &vector.name),
        "EventBody" => validate_canonical::<EventBody>(bytes, &vector.name),
        "AdmissionEvidence" => validate_canonical::<AdmissionEvidence>(bytes, &vector.name),
        "SignedControllerApproval" => {
            validate_canonical::<SignedControllerApproval>(bytes, &vector.name)
        }
        "AuthorizedEvent" => validate_canonical::<AuthorizedEvent>(bytes, &vector.name),
        "SignedCheckpoint" => validate_canonical::<SignedCheckpoint>(bytes, &vector.name),
        "BackupAuthorityBundle" => validate_canonical::<BackupAuthorityBundle>(bytes, &vector.name),
        "BackupEnvelope" => validate_canonical::<BackupEnvelope>(bytes, &vector.name),
        "RecoveryProposal" => validate_canonical::<RecoveryProposal>(bytes, &vector.name),
        "BeginRecovery" => validate_canonical::<BeginRecovery>(bytes, &vector.name),
        "VetoRecovery" => validate_canonical::<VetoRecovery>(bytes, &vector.name),
        "CancelRecovery" => validate_canonical::<CancelRecovery>(bytes, &vector.name),
        "FinalizeRecovery" => validate_canonical::<FinalizeRecovery>(bytes, &vector.name),
        "GuardianApprovalBody" => validate_canonical::<GuardianApprovalBody>(bytes, &vector.name),
        "SignedGuardianApproval" => {
            validate_canonical::<SignedGuardianApproval>(bytes, &vector.name)
        }
        "GuardianApprovalSet" => validate_canonical::<GuardianApprovalSet>(bytes, &vector.name),
        "RecoveryThresholdEvidence" => {
            validate_canonical::<RecoveryThresholdEvidence>(bytes, &vector.name)
        }
        "BeginCryptoMigration" => validate_canonical::<BeginCryptoMigration>(bytes, &vector.name),
        "ControllerKeyBindingProof" => {
            validate_canonical::<ControllerKeyBindingProof>(bytes, &vector.name)
        }
        "EventIntentApprovalBody" => {
            validate_canonical::<EventIntentApprovalBody>(bytes, &vector.name)
        }
        "SignedEventIntentApproval" => {
            validate_canonical::<SignedEventIntentApproval>(bytes, &vector.name)
        }
        "EventIntentApprovals" => validate_canonical::<EventIntentApprovals>(bytes, &vector.name),
        "ControllerApprovalBody" => {
            validate_canonical::<ControllerApprovalBody>(bytes, &vector.name)
        }
        "ControllerApprovals" => validate_canonical::<ControllerApprovals>(bytes, &vector.name),
        "RecoveryAuthorityPlan" => validate_canonical::<RecoveryAuthorityPlan>(bytes, &vector.name),
        "RecoveryDelayAnchor" => validate_canonical::<RecoveryDelayAnchor>(bytes, &vector.name),
        "ForkDescriptor" => validate_canonical::<ForkDescriptor>(bytes, &vector.name),
        "CapabilityGrant" => validate_canonical::<CapabilityGrant>(bytes, &vector.name),
        "CapabilityRoot" => validate_canonical::<CapabilityRoot>(bytes, &vector.name),
        "DelegationBody" => validate_canonical::<DelegationBody>(bytes, &vector.name),
        "SignedDelegation" => validate_canonical::<SignedDelegation>(bytes, &vector.name),
        "DelegationChain" => validate_canonical::<DelegationChain>(bytes, &vector.name),
        "ApplicationEventBody" => validate_canonical::<ApplicationEventBody>(bytes, &vector.name),
        "SignedApplicationEvent" => {
            validate_canonical::<SignedApplicationEvent>(bytes, &vector.name)
        }
        "GroupKeyWrapHeader" => validate_canonical::<GroupKeyWrapHeader>(bytes, &vector.name),
        "WrappedGroupKey" => validate_canonical::<WrappedGroupKey>(bytes, &vector.name),
        "RecipientKeyWraps" => validate_canonical::<RecipientKeyWraps>(bytes, &vector.name),
        "SocialAttestationBody" => validate_canonical::<SocialAttestationBody>(bytes, &vector.name),
        "SignedSocialAttestation" => {
            validate_canonical::<SignedSocialAttestation>(bytes, &vector.name)
        }
        "NameClaimBody" => validate_canonical::<NameClaimBody>(bytes, &vector.name),
        "SignedNameClaim" => validate_canonical::<SignedNameClaim>(bytes, &vector.name),
        "PrivateArtifactContext" => {
            validate_canonical::<PrivateArtifactContext>(bytes, &vector.name)
        }
        "PrivateMetadataEnvelope" => {
            validate_canonical::<PrivateMetadataEnvelope>(bytes, &vector.name)
        }
        "PortableCredentialBody" => {
            validate_canonical::<PortableCredentialBody>(bytes, &vector.name)
        }
        "SignedPortableCredential" => {
            validate_canonical::<SignedPortableCredential>(bytes, &vector.name)
        }
        "ProviderLogEntryBody" => validate_canonical::<ProviderLogEntryBody>(bytes, &vector.name),
        "ProviderHeadBody" => validate_canonical::<ProviderHeadBody>(bytes, &vector.name),
        "SignedProviderHead" => validate_canonical::<SignedProviderHead>(bytes, &vector.name),
        "InclusionReceipt" => validate_canonical::<InclusionReceipt>(bytes, &vector.name),
        "ProviderReceipts" => validate_canonical::<ProviderReceipts>(bytes, &vector.name),
        "ProviderEquivocationEvidence" => {
            validate_canonical::<ProviderEquivocationEvidence>(bytes, &vector.name)
        }
        "ProviderExportComponent" => {
            validate_canonical::<ProviderExportComponent>(bytes, &vector.name)
        }
        "ProviderExportComponentDescriptor" => {
            validate_canonical::<ProviderExportComponentDescriptor>(bytes, &vector.name)
        }
        "ProviderGenerationExportChunk" => {
            validate_canonical::<ProviderGenerationExportChunk>(bytes, &vector.name)
        }
        "ProviderAuditExportChunk" => {
            validate_canonical::<ProviderAuditExportChunk>(bytes, &vector.name)
        }
        "ProviderGenerationExportManifest" => {
            validate_canonical::<ProviderGenerationExportManifest>(bytes, &vector.name)
        }
        "ProviderAuditExportManifest" => {
            validate_canonical::<ProviderAuditExportManifest>(bytes, &vector.name)
        }
        "ProviderRecoveryExportManifest" => {
            validate_canonical::<ProviderRecoveryExportManifest>(bytes, &vector.name)
        }
        "ProviderCompactionManifest" => {
            validate_canonical::<ProviderCompactionManifest>(bytes, &vector.name)
        }
        "OpaqueProviderAnchorCommitment" => {
            validate_canonical::<OpaqueProviderAnchorCommitment>(bytes, &vector.name)
        }
        "MerkleSetKey" => validate_canonical::<MerkleSetKey>(bytes, &vector.name),
        "MerkleSetLeaf" => validate_canonical::<MerkleSetLeaf>(bytes, &vector.name),
        "MerkleInclusionProof" => validate_canonical::<MerkleInclusionProof>(bytes, &vector.name),
        "MerkleConsistencyProof" => {
            validate_canonical::<MerkleConsistencyProof>(bytes, &vector.name)
        }
        "MerkleNonMembershipProof" => {
            validate_canonical::<MerkleNonMembershipProof>(bytes, &vector.name)
        }
        "PairingTicket" => validate_canonical::<PairingTicket>(bytes, &vector.name),
        "PairingTranscript" => validate_canonical::<PairingTranscript>(bytes, &vector.name),
        "PairingPossessionProof" => {
            validate_canonical::<PairingPossessionProof>(bytes, &vector.name)
        }
        "PairingConfirmationContext" => {
            validate_canonical::<PairingConfirmationContext>(bytes, &vector.name)
        }
        "DeviceAuthorizationProposal" => {
            validate_canonical::<DeviceAuthorizationProposal>(bytes, &vector.name)
        }
        "DevicePresenceChallenge" => {
            validate_canonical::<DevicePresenceChallenge>(bytes, &vector.name)
        }
        "PresenceProof" => validate_canonical::<PresenceProof>(bytes, &vector.name),
        "SyncRequest" => validate_canonical::<SyncRequest>(bytes, &vector.name),
        "SyncCursor" => validate_canonical::<SyncCursor>(bytes, &vector.name),
        "SyncFrame" => validate_canonical::<SyncFrame>(bytes, &vector.name),
        "SyncResponse" => validate_canonical::<SyncResponse>(bytes, &vector.name),
        "EndpointAuthorizationRequest" => {
            validate_canonical::<EndpointAuthorizationRequest>(bytes, &vector.name)
        }
        "AuthorizedSyncRequest" => validate_canonical::<AuthorizedSyncRequest>(bytes, &vector.name),
        "AuthorizedProposalRequest" => {
            validate_canonical::<AuthorizedProposalRequest>(bytes, &vector.name)
        }
        "AuthorizedCheckpointRequest" => {
            validate_canonical::<AuthorizedCheckpointRequest>(bytes, &vector.name)
        }
        "IdentityProtocolAck" => validate_canonical::<IdentityProtocolAck>(bytes, &vector.name),
        "IdentityProtocolReply" => validate_canonical::<IdentityProtocolReply>(bytes, &vector.name),
        other => panic!("unhandled interop wire type {other} in {}", vector.name),
    }
}

fn validate_source_owned_variant(vector: &VectorMetadata, bytes: &[u8]) {
    if let Some(code) = vector.name.strip_prefix("account-operation-") {
        let expected_code = code.parse::<u16>().unwrap();
        let operation = AccountOperation::from_canonical_bytes(bytes).unwrap();
        assert_eq!(
            operation.kind().code(),
            expected_code,
            "{} must retain its source-owned operation variant",
            vector.name
        );
    }
    match vector.name.as_str() {
        "checkpoint-direct" => {
            let checkpoint = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            assert_eq!(checkpoint.body().lifecycle(), AccountLifecycle::Active);
            assert!(checkpoint.authorization().controller_approvals().is_some());
            assert!(checkpoint.authorization().transition_witness().is_none());
        }
        "checkpoint-migration-pending" => {
            let checkpoint = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            assert_eq!(
                checkpoint.body().lifecycle(),
                AccountLifecycle::MigrationPending
            );
            assert!(checkpoint.authorization().controller_approvals().is_some());
            assert!(checkpoint.authorization().transition_witness().is_none());
        }
        "checkpoint-migration-dual" => {
            let checkpoint = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            assert_eq!(
                checkpoint.body().lifecycle(),
                AccountLifecycle::MigrationDual
            );
            assert!(checkpoint.authorization().controller_approvals().is_some());
            assert!(checkpoint.authorization().transition_witness().is_none());
        }
        "checkpoint-transition-finalize" => {
            let checkpoint = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            assert_eq!(checkpoint.body().lifecycle(), AccountLifecycle::Active);
            assert!(checkpoint.authorization().controller_approvals().is_none());
            assert_eq!(
                checkpoint
                    .authorization()
                    .transition_witness()
                    .map(TransitionCheckpointWitness::transition_kind),
                Some(CheckpointTransitionKind::FinalizeRecovery)
            );
        }
        "checkpoint-transition-retire" => {
            let checkpoint = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            assert_eq!(checkpoint.body().lifecycle(), AccountLifecycle::Retired);
            assert!(checkpoint.authorization().controller_approvals().is_none());
            assert_eq!(
                checkpoint
                    .authorization()
                    .transition_witness()
                    .map(TransitionCheckpointWitness::transition_kind),
                Some(CheckpointTransitionKind::RetireAccount)
            );
        }
        "sync-response-frame" => assert!(
            SyncResponse::from_canonical_bytes(bytes)
                .unwrap()
                .as_frame()
                .is_some()
        ),
        "sync-response-complete" => assert!(
            SyncResponse::from_canonical_bytes(bytes)
                .unwrap()
                .as_complete()
                .is_some()
        ),
        "identity-protocol-reply-ack" => assert!(
            IdentityProtocolReply::from_canonical_bytes(bytes)
                .unwrap()
                .as_ack()
                .is_some()
        ),
        "identity-protocol-reply-sync" => assert!(
            IdentityProtocolReply::from_canonical_bytes(bytes)
                .unwrap()
                .as_sync()
                .is_some()
        ),
        "provider-export-component" => assert_eq!(
            ProviderExportComponent::from_canonical_bytes(bytes).unwrap(),
            ProviderExportComponent::CheckpointBundles
        ),
        _ => {}
    }
}

#[derive(Clone, Copy)]
enum ExactSigningKey {
    Controller(ControllerKeyId),
    Public(SigningPublicKey),
    Provider(ProviderId),
}

fn metadata_signing_key(key: &KeyMetadata) -> Option<SigningPublicKey> {
    if key.algorithm != "Ed25519" {
        return None;
    }
    let public = hex::decode(&key.public_key_hex).ok()?.try_into().ok()?;
    SigningPublicKey::ed25519(public).ok()
}

fn metadata_matches_exact_key(key: &KeyMetadata, expected: ExactSigningKey) -> bool {
    let Some(public) = metadata_signing_key(key) else {
        return false;
    };
    match expected {
        ExactSigningKey::Controller(expected_id) => {
            ControllerKeyId::for_signing_key(&public) == Ok(expected_id)
        }
        ExactSigningKey::Public(expected_public) => public == expected_public,
        ExactSigningKey::Provider(expected_id) => {
            ProviderDescriptor::new(public, Extensions::default())
                .and_then(|provider| provider.id())
                == Ok(expected_id)
        }
    }
}

fn resolved_signature_binding_for_key(
    name: String,
    domain: &str,
    message: Vec<u8>,
    signature_bytes: &[u8],
    expected_key: Option<ExactSigningKey>,
    keys: &[KeyMetadata],
) -> SignatureBinding {
    let signature = Signature::try_from(signature_bytes).unwrap();
    let matching = keys
        .iter()
        .filter_map(|key| metadata_signing_key(key).map(|public| (key, public)))
        .filter(|(key, _)| {
            expected_key.is_none_or(|expected| metadata_matches_exact_key(key, expected))
        })
        .filter(|(_, public)| {
            let public: [u8; 32] = public.as_bytes().to_owned();
            PublicKey::from_bytes(&public)
                .unwrap()
                .verify(&message, &signature)
                .is_ok()
        })
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "each decoded signature must resolve to exactly one deterministic signer"
    );
    SignatureBinding {
        name,
        algorithm: "Ed25519".to_owned(),
        domain_ascii: domain.to_owned(),
        message_hex: hex::encode(message),
        signer_key: matching[0].name.clone(),
        public_key_hex: matching[0].public_key_hex.clone(),
        signature_hex: hex::encode(signature_bytes),
    }
}

fn resolved_signature_binding(
    name: String,
    domain: &str,
    message: Vec<u8>,
    signature_bytes: &[u8],
    keys: &[KeyMetadata],
) -> SignatureBinding {
    resolved_signature_binding_for_key(name, domain, message, signature_bytes, None, keys)
}

fn append_controller_approval_bindings(
    bindings: &mut Vec<SignatureBinding>,
    approvals: &ControllerApprovals,
    keys: &[KeyMetadata],
) {
    for approval in approvals.as_slice() {
        let message = approval.body().to_canonical_bytes().unwrap();
        for signature in approval.signatures() {
            bindings.push(resolved_signature_binding_for_key(
                format!("signature-{}", bindings.len() + 1),
                "KRIKOS-ID/controller-approval-signature/v1",
                message.clone(),
                signature.signature().as_bytes(),
                Some(ExactSigningKey::Controller(signature.controller_key_id())),
                keys,
            ));
        }
    }
}

fn append_guardian_bindings(
    bindings: &mut Vec<SignatureBinding>,
    approvals: &GuardianApprovalSet,
    keys: &[KeyMetadata],
) {
    for approval in approvals.as_slice() {
        bindings.push(resolved_signature_binding_for_key(
            format!("signature-{}", bindings.len() + 1),
            "KRIKOS-ID/guardian-approval-signature/v1",
            approval.body().signing_bytes().unwrap(),
            approval.signature().as_bytes(),
            Some(ExactSigningKey::Public(
                approval.opening().grant().guardian_signing_key(),
            )),
            keys,
        ));
    }
}

fn append_provider_head_binding(
    bindings: &mut Vec<SignatureBinding>,
    head: &SignedProviderHead,
    keys: &[KeyMetadata],
) {
    bindings.push(resolved_signature_binding_for_key(
        format!("signature-{}", bindings.len() + 1),
        "KRIKOS-ID/provider-head-signature/v1",
        head.body().signing_bytes().unwrap(),
        head.signature().as_bytes(),
        Some(ExactSigningKey::Provider(head.body().provider_id())),
        keys,
    ));
}

fn append_event_intent_bindings(
    bindings: &mut Vec<SignatureBinding>,
    approvals: &EventIntentApprovals,
    keys: &[KeyMetadata],
) {
    for approval in approvals.as_slice() {
        let message = approval.body().to_canonical_bytes().unwrap();
        for signature in approval.signatures() {
            bindings.push(resolved_signature_binding_for_key(
                format!("signature-{}", bindings.len() + 1),
                "KRIKOS-ID/event-intent-approval-signature/v1",
                message.clone(),
                signature.signature().as_bytes(),
                Some(ExactSigningKey::Controller(signature.controller_key_id())),
                keys,
            ));
        }
    }
}

fn append_provider_receipt_bindings(
    bindings: &mut Vec<SignatureBinding>,
    receipts: &ProviderReceipts,
    keys: &[KeyMetadata],
) {
    for receipt in receipts.as_slice() {
        append_provider_head_binding(bindings, receipt.signed_head(), keys);
    }
}

fn append_recovery_threshold_evidence_bindings(
    bindings: &mut Vec<SignatureBinding>,
    evidence: &RecoveryThresholdEvidence,
    keys: &[KeyMetadata],
) {
    if let Some(approvals) = evidence.as_guardian_approvals() {
        append_guardian_bindings(bindings, approvals, keys);
    }
}

fn append_recovery_delay_anchor_bindings(
    bindings: &mut Vec<SignatureBinding>,
    anchor: &RecoveryDelayAnchor,
    keys: &[KeyMetadata],
) {
    append_provider_receipt_bindings(bindings, anchor.receipts(), keys);
}

fn append_crypto_migration_bindings(
    bindings: &mut Vec<SignatureBinding>,
    begin: &BeginCryptoMigration,
    keys: &[KeyMetadata],
) {
    let migration_id = begin.migration().crypto_migration_id().unwrap();
    let message = migration_id.to_canonical_bytes().unwrap();
    for (binding, proof) in begin
        .migration()
        .bindings()
        .iter()
        .zip(begin.proofs().as_slice())
    {
        assert_eq!(binding.controller_id(), proof.controller_id());
        assert_eq!(proof.migration_id(), migration_id);
        assert_eq!(
            proof.old_key_signature().algorithm_code(),
            SignatureAlgorithm::Ed25519.code()
        );
        bindings.push(resolved_signature_binding_for_key(
            format!("signature-{}", bindings.len() + 1),
            "none",
            message.clone(),
            proof.old_key_signature().as_bytes(),
            Some(ExactSigningKey::Controller(binding.old_key_id())),
            keys,
        ));

        assert_eq!(
            binding.new_signing_key().algorithm_code(),
            SignatureAlgorithm::Ed25519.code()
        );
        assert_eq!(
            proof.new_key_signature().algorithm_code(),
            SignatureAlgorithm::Ed25519.code()
        );
        let new_public: [u8; 32] = binding.new_signing_key().as_bytes().try_into().unwrap();
        bindings.push(resolved_signature_binding_for_key(
            format!("signature-{}", bindings.len() + 1),
            "none",
            message.clone(),
            proof.new_key_signature().as_bytes(),
            Some(ExactSigningKey::Public(
                SigningPublicKey::ed25519(new_public).unwrap(),
            )),
            keys,
        ));
    }
}

fn append_account_operation_bindings(
    bindings: &mut Vec<SignatureBinding>,
    operation: &AccountOperation,
    keys: &[KeyMetadata],
) {
    match operation {
        AccountOperation::BeginRecovery(begin) => {
            append_recovery_threshold_evidence_bindings(bindings, begin.threshold_evidence(), keys);
        }
        AccountOperation::CancelRecovery(cancel) => {
            append_recovery_threshold_evidence_bindings(
                bindings,
                cancel.threshold_evidence(),
                keys,
            );
        }
        AccountOperation::FinalizeRecovery(finalize) => {
            append_recovery_delay_anchor_bindings(bindings, finalize.delay_anchor(), keys);
        }
        AccountOperation::BeginCryptoMigration(begin) => {
            append_crypto_migration_bindings(bindings, begin, keys);
        }
        AccountOperation::AuthorizeDevice(_)
        | AccountOperation::UpdateDeviceAuthorization(_)
        | AccountOperation::UpdateDeviceMetadata(_)
        | AccountOperation::SuspendDevice(_)
        | AccountOperation::ReinstateDevice(_)
        | AccountOperation::RevokeDevice(_)
        | AccountOperation::RotateDeviceKeys(_)
        | AccountOperation::AddController(_)
        | AccountOperation::RemoveController(_)
        | AccountOperation::ChangeControlPolicy(_)
        | AccountOperation::ChangeRecoveryPolicy(_)
        | AccountOperation::ChangeProviderPolicy(_)
        | AccountOperation::VetoRecovery(_)
        | AccountOperation::ResolveFork(_)
        | AccountOperation::ActivateCryptoMigration(_)
        | AccountOperation::RetireCryptoSuite(_)
        | AccountOperation::UpgradeProtocol(_)
        | AccountOperation::RetireAccount(_) => {}
    }
}

fn append_admission_bindings(
    bindings: &mut Vec<SignatureBinding>,
    evidence: &AdmissionEvidence,
    keys: &[KeyMetadata],
) {
    if let Some(receipts) = evidence.freshness().provider_receipts() {
        append_provider_receipt_bindings(bindings, receipts, keys);
    }
    if let Some(approvals) = evidence.delay().intent_approvals() {
        append_event_intent_bindings(bindings, approvals, keys);
    }
    if let Some(receipts) = evidence.delay().provider_receipts() {
        append_provider_receipt_bindings(bindings, receipts, keys);
    }
}

fn append_authorized_event_bindings(
    bindings: &mut Vec<SignatureBinding>,
    event: &AuthorizedEvent,
    keys: &[KeyMetadata],
) {
    append_account_operation_bindings(bindings, event.body().operation(), keys);
    append_admission_bindings(bindings, event.admission_evidence(), keys);
    append_controller_approval_bindings(bindings, event.approvals(), keys);
}

fn append_checkpoint_bindings(
    bindings: &mut Vec<SignatureBinding>,
    checkpoint: &SignedCheckpoint,
    keys: &[KeyMetadata],
) {
    if let Some(approvals) = checkpoint.authorization().controller_approvals() {
        append_controller_approval_bindings(bindings, approvals, keys);
    }
}

fn append_provider_generation_manifest_bindings(
    bindings: &mut Vec<SignatureBinding>,
    manifest: &ProviderGenerationExportManifest,
    keys: &[KeyMetadata],
) {
    if let Some(head) = manifest.latest_head() {
        append_provider_head_binding(bindings, head, keys);
    }
}

fn append_provider_audit_manifest_bindings(
    bindings: &mut Vec<SignatureBinding>,
    manifest: &ProviderAuditExportManifest,
    keys: &[KeyMetadata],
) {
    if let Some(head) = manifest.latest_head() {
        append_provider_head_binding(bindings, head, keys);
    }
    if let Some(evidence) = manifest.equivocation_evidence() {
        append_provider_head_binding(bindings, evidence.first(), keys);
        append_provider_head_binding(bindings, evidence.second(), keys);
    }
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

#[derive(Deserialize)]
struct AuditChunkMirror {
    format_version: u16,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    audit_commitment: Digest,
    ordinal: u32,
    start_sequence: u64,
    end_sequence: u64,
    item_payload_bytes: u64,
    payload: Vec<u8>,
}

#[derive(Deserialize)]
struct ProviderAuditRecordMirror {
    sequence: u64,
    head: SignedProviderHead,
    consistency_proof: Option<MerkleConsistencyProof>,
    status_code: u16,
}

#[derive(Deserialize)]
struct ProviderAuditRecordItemMirror {
    format_version: u16,
    record: ProviderAuditRecordMirror,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
struct BackupKdfParametersMirror {
    algorithm_code: u16,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    output_bytes: u32,
}

#[derive(Deserialize)]
struct BackupEnvelopeMirror {
    protocol_version: ProtocolVersion,
    artifact_kind_code: u16,
    password_kdf: BackupKdfParametersMirror,
    wrapping_aead: AeadAlgorithm,
    content_aead: AeadAlgorithm,
    context: PrivateArtifactContext,
    salt: [u8; 16],
    wrapping_nonce: [u8; 24],
    content_nonce: [u8; 24],
    wrapped_content_key: Vec<u8>,
    ciphertext: Vec<u8>,
    extensions: Extensions,
}

#[derive(Deserialize)]
struct BackupPayloadMirror {
    protocol_version: ProtocolVersion,
    authority_bundle: BackupAuthorityBundle,
    application_data: Option<Vec<u8>>,
    extensions: Extensions,
}

fn private_artifact_domain_message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len().saturating_add(1).saturating_add(body.len()));
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(body);
    message
}

fn backup_envelope_authority_bundle(bytes: &[u8]) -> BackupAuthorityBundle {
    const BACKUP_KDF: BackupKdfParametersMirror = BackupKdfParametersMirror {
        algorithm_code: 1,
        version: 0x13,
        memory_kib: 19_456,
        iterations: 2,
        lanes: 1,
        output_bytes: 32,
    };
    const WRAP_DOMAIN: &[u8] = b"KRIKOS-ID/private-artifact-key-wrap/v1";
    const CONTENT_DOMAIN: &[u8] = b"KRIKOS-ID/private-artifact-content/v1";
    const PASSPHRASE: &[u8] = b"correct horse battery staple";

    let envelope: BackupEnvelopeMirror = postcard::from_bytes(bytes).unwrap();
    assert_eq!(envelope.protocol_version, ProtocolVersion::V1);
    assert_eq!(envelope.artifact_kind_code, 2);
    assert_eq!(envelope.password_kdf, BACKUP_KDF);
    assert_eq!(envelope.wrapping_aead, AeadAlgorithm::XChaCha20Poly1305);
    assert_eq!(envelope.content_aead, AeadAlgorithm::XChaCha20Poly1305);
    assert_eq!(envelope.wrapped_content_key.len(), 48);

    let header = postcard::to_stdvec(&(
        envelope.protocol_version,
        envelope.artifact_kind_code,
        envelope.password_kdf,
        envelope.wrapping_aead,
        envelope.content_aead,
        &envelope.context,
        envelope.salt,
        envelope.wrapping_nonce,
        envelope.content_nonce,
        &envelope.extensions,
    ))
    .unwrap();
    let parameters = Params::new(
        BACKUP_KDF.memory_kib,
        BACKUP_KDF.iterations,
        BACKUP_KDF.lanes,
        Some(BACKUP_KDF.output_bytes as usize),
    )
    .unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut wrapping_key = [0_u8; 32];
    argon2
        .hash_password_into(PASSPHRASE, &envelope.salt, &mut wrapping_key)
        .unwrap();
    let wrapping_aad = private_artifact_domain_message(WRAP_DOMAIN, &header);
    let wrapped_key_cipher = XChaCha20Poly1305::new(&Key::from(wrapping_key));
    let content_key = wrapped_key_cipher
        .decrypt(
            &XNonce::from(envelope.wrapping_nonce),
            Payload {
                msg: &envelope.wrapped_content_key,
                aad: &wrapping_aad,
            },
        )
        .unwrap();
    let content_key: [u8; 32] = content_key.try_into().unwrap();
    let content_aad_body =
        postcard::to_stdvec(&(header, envelope.wrapped_content_key.as_slice())).unwrap();
    let content_aad = private_artifact_domain_message(CONTENT_DOMAIN, &content_aad_body);
    let content_cipher = XChaCha20Poly1305::new(&Key::from(content_key));
    let plaintext = content_cipher
        .decrypt(
            &XNonce::from(envelope.content_nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &content_aad,
            },
        )
        .unwrap();
    let payload: BackupPayloadMirror = postcard::from_bytes(&plaintext).unwrap();
    assert_eq!(payload.protocol_version, ProtocolVersion::V1);
    assert!(payload.application_data.is_none());
    assert_eq!(payload.extensions, Extensions::default());
    payload.authority_bundle
}

fn chunk_items(payload: &[u8]) -> Vec<Vec<u8>> {
    postcard::from_bytes(payload).expect("validated provider chunk payload must decode")
}

fn append_provider_generation_chunk_bindings(
    bindings: &mut Vec<SignatureBinding>,
    chunk: &ProviderGenerationExportChunk,
    bytes: &[u8],
    keys: &[KeyMetadata],
) {
    let mirror: GenerationChunkMirror = postcard::from_bytes(bytes).unwrap();
    assert_eq!(mirror.format_version, 1);
    assert_eq!(mirror.provider_id, chunk.provider_id());
    assert_eq!(mirror.log_id, chunk.log_id());
    assert_eq!(mirror.key_version, chunk.key_version());
    assert_eq!(mirror.generation_commitment, chunk.generation_commitment());
    assert_eq!(mirror.component_code, chunk.component().unwrap().code());
    assert_eq!(mirror.ordinal, chunk.ordinal());
    assert_eq!(mirror.start_index, chunk.start_index());
    assert_eq!(mirror.end_index, chunk.end_index());
    assert_eq!(mirror.item_payload_bytes, chunk.item_payload_bytes());

    for item in chunk_items(&mirror.payload) {
        match chunk.component().unwrap() {
            ProviderExportComponent::Receipts => {
                let receipt = InclusionReceipt::from_canonical_bytes(&item).unwrap();
                append_provider_head_binding(bindings, receipt.signed_head(), keys);
            }
            ProviderExportComponent::CheckpointBundles => {
                let item: ProviderCheckpointBundleItemMirror = postcard::from_bytes(&item).unwrap();
                assert_eq!(item.format_version, 1);
                let _lineage_shape = (item.bundle.genesis, item.bundle.prior_checkpoint_id);
                for event in &item.bundle.events {
                    append_authorized_event_bindings(bindings, event, keys);
                }
                append_checkpoint_bindings(bindings, &item.bundle.checkpoint, keys);
                if let Some(event) = &item.bundle.transition_event {
                    append_authorized_event_bindings(bindings, event, keys);
                }
            }
            ProviderExportComponent::Entries
            | ProviderExportComponent::LeafHashes
            | ProviderExportComponent::CompactionManifests => {}
        }
    }
}

fn append_provider_audit_chunk_bindings(
    bindings: &mut Vec<SignatureBinding>,
    chunk: &ProviderAuditExportChunk,
    bytes: &[u8],
    keys: &[KeyMetadata],
) {
    let mirror: AuditChunkMirror = postcard::from_bytes(bytes).unwrap();
    assert_eq!(mirror.format_version, 1);
    assert_eq!(mirror.provider_id, chunk.provider_id());
    assert_eq!(mirror.log_id, chunk.log_id());
    assert_eq!(mirror.audit_commitment, chunk.audit_commitment());
    assert_eq!(mirror.ordinal, chunk.ordinal());
    assert_eq!(mirror.start_sequence, chunk.start_sequence());
    assert_eq!(mirror.end_sequence, chunk.end_sequence());
    assert_eq!(mirror.item_payload_bytes, chunk.item_payload_bytes());
    for item in chunk_items(&mirror.payload) {
        let item: ProviderAuditRecordItemMirror = postcard::from_bytes(&item).unwrap();
        assert_eq!(item.format_version, 1);
        let _authenticated_record_shape = (
            item.record.sequence,
            item.record.consistency_proof,
            item.record.status_code,
        );
        append_provider_head_binding(bindings, &item.record.head, keys);
    }
}

fn append_sync_frame_bindings(
    bindings: &mut Vec<SignatureBinding>,
    frame: &SyncFrame,
    keys: &[KeyMetadata],
) {
    for event in frame.events() {
        append_authorized_event_bindings(bindings, event, keys);
    }
}

fn append_sync_response_bindings(
    bindings: &mut Vec<SignatureBinding>,
    response: &SyncResponse,
    keys: &[KeyMetadata],
) {
    if let Some(frame) = response.as_frame() {
        append_sync_frame_bindings(bindings, frame, keys);
    }
}

fn append_identity_reply_bindings(
    bindings: &mut Vec<SignatureBinding>,
    reply: &IdentityProtocolReply,
    keys: &[KeyMetadata],
) {
    if let Some(response) = reply.as_sync() {
        append_sync_response_bindings(bindings, response, keys);
    }
}

fn append_backup_bundle_bindings(
    bindings: &mut Vec<SignatureBinding>,
    bundle: &BackupAuthorityBundle,
    keys: &[KeyMetadata],
) {
    for event in bundle.events() {
        append_authorized_event_bindings(bindings, event, keys);
    }
    append_checkpoint_bindings(bindings, bundle.checkpoint(), keys);
}

fn append_provider_recovery_manifest_bindings(
    bindings: &mut Vec<SignatureBinding>,
    manifest: &ProviderRecoveryExportManifest,
    keys: &[KeyMetadata],
) {
    append_provider_generation_manifest_bindings(bindings, manifest.generation(), keys);
    append_provider_audit_manifest_bindings(bindings, manifest.audit(), keys);
}

fn append_checkpoint_request_bindings(
    bindings: &mut Vec<SignatureBinding>,
    request: &AuthorizedCheckpointRequest,
    keys: &[KeyMetadata],
) {
    append_checkpoint_bindings(bindings, request.checkpoint(), keys);
}

fn expected_signature_bindings(
    vector: &VectorMetadata,
    bytes: &[u8],
    directory: &Path,
    vectors: &BTreeMap<&str, &VectorMetadata>,
    keys: &[KeyMetadata],
) -> Vec<SignatureBinding> {
    let mut bindings = Vec::new();
    match vector.wire_type.as_str() {
        "AdmissionEvidence" => append_admission_bindings(
            &mut bindings,
            &AdmissionEvidence::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "SignedEventIntentApproval" => {
            let value = SignedEventIntentApproval::from_canonical_bytes(bytes).unwrap();
            append_event_intent_bindings(
                &mut bindings,
                &EventIntentApprovals::new(vec![value]).unwrap(),
                keys,
            );
        }
        "EventIntentApprovals" => {
            let value = EventIntentApprovals::from_canonical_bytes(bytes).unwrap();
            append_event_intent_bindings(&mut bindings, &value, keys);
        }
        "SignedControllerApproval" => {
            let value = SignedControllerApproval::from_canonical_bytes(bytes).unwrap();
            let approvals = ControllerApprovals::new(vec![value]).unwrap();
            append_controller_approval_bindings(&mut bindings, &approvals, keys);
        }
        "ControllerApprovals" => {
            let value = ControllerApprovals::from_canonical_bytes(bytes).unwrap();
            append_controller_approval_bindings(&mut bindings, &value, keys);
        }
        "AccountOperation" => append_account_operation_bindings(
            &mut bindings,
            &AccountOperation::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "EventBody" => {
            let value = EventBody::from_canonical_bytes(bytes).unwrap();
            append_account_operation_bindings(&mut bindings, value.operation(), keys);
        }
        "AuthorizedEvent" => {
            let value = AuthorizedEvent::from_canonical_bytes(bytes).unwrap();
            append_authorized_event_bindings(&mut bindings, &value, keys);
        }
        "SignedCheckpoint" => {
            let value = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            append_checkpoint_bindings(&mut bindings, &value, keys);
        }
        "BackupAuthorityBundle" => {
            let value = BackupAuthorityBundle::from_canonical_bytes(bytes).unwrap();
            append_backup_bundle_bindings(&mut bindings, &value, keys);
        }
        "SignedGuardianApproval" => {
            let value = SignedGuardianApproval::from_canonical_bytes(bytes).unwrap();
            let approvals = GuardianApprovalSet::try_new(vec![value]).unwrap();
            append_guardian_bindings(&mut bindings, &approvals, keys);
        }
        "GuardianApprovalSet" => {
            let value = GuardianApprovalSet::from_canonical_bytes(bytes).unwrap();
            append_guardian_bindings(&mut bindings, &value, keys);
        }
        "RecoveryThresholdEvidence" => {
            let value = RecoveryThresholdEvidence::from_canonical_bytes(bytes).unwrap();
            append_recovery_threshold_evidence_bindings(&mut bindings, &value, keys);
        }
        "BeginRecovery" => {
            let value = BeginRecovery::from_canonical_bytes(bytes).unwrap();
            append_recovery_threshold_evidence_bindings(
                &mut bindings,
                value.threshold_evidence(),
                keys,
            );
        }
        "CancelRecovery" => {
            let value = CancelRecovery::from_canonical_bytes(bytes).unwrap();
            append_recovery_threshold_evidence_bindings(
                &mut bindings,
                value.threshold_evidence(),
                keys,
            );
        }
        "RecoveryDelayAnchor" => append_recovery_delay_anchor_bindings(
            &mut bindings,
            &RecoveryDelayAnchor::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "FinalizeRecovery" => {
            let value = FinalizeRecovery::from_canonical_bytes(bytes).unwrap();
            append_recovery_delay_anchor_bindings(&mut bindings, value.delay_anchor(), keys);
        }
        "BeginCryptoMigration" => append_crypto_migration_bindings(
            &mut bindings,
            &BeginCryptoMigration::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "ControllerKeyBindingProof" => {
            assert_eq!(vector.dependencies, ["crypto-migration-begin"]);
            let dependency = vectors["crypto-migration-begin"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let begin = BeginCryptoMigration::from_canonical_bytes(&dependency_bytes).unwrap();
            let proof = ControllerKeyBindingProof::from_canonical_bytes(bytes).unwrap();
            assert_eq!(begin.proofs().as_slice(), std::slice::from_ref(&proof));
            append_crypto_migration_bindings(&mut bindings, &begin, keys);
        }
        "SignedDelegation" => {
            let value = SignedDelegation::from_canonical_bytes(bytes).unwrap();
            bindings.push(resolved_signature_binding(
                "signature-1".to_owned(),
                "KRIKOS-ID/capability-delegation-signature/v1",
                value.body().to_canonical_bytes().unwrap(),
                value.signature().as_bytes(),
                keys,
            ));
        }
        "DelegationChain" => {
            let value = DelegationChain::from_canonical_bytes(bytes).unwrap();
            for link in value.links() {
                bindings.push(resolved_signature_binding(
                    format!("signature-{}", bindings.len() + 1),
                    "KRIKOS-ID/capability-delegation-signature/v1",
                    link.body().to_canonical_bytes().unwrap(),
                    link.signature().as_bytes(),
                    keys,
                ));
            }
        }
        "SignedApplicationEvent" => {
            let value = SignedApplicationEvent::from_canonical_bytes(bytes).unwrap();
            bindings.push(resolved_signature_binding(
                "signature-1".to_owned(),
                "KRIKOS-ID/application-event-signature/v1",
                value.body().signing_bytes().unwrap(),
                value.signature().as_bytes(),
                keys,
            ));
        }
        "SignedSocialAttestation" => {
            let value = SignedSocialAttestation::from_canonical_bytes(bytes).unwrap();
            bindings.push(resolved_signature_binding(
                "signature-1".to_owned(),
                "KRIKOS-ID/social-attestation-signature/v1",
                value.body().signing_bytes().unwrap(),
                value.issuer_signature().as_bytes(),
                keys,
            ));
        }
        "SignedNameClaim" => {
            let value = SignedNameClaim::from_canonical_bytes(bytes).unwrap();
            bindings.push(resolved_signature_binding(
                "signature-1".to_owned(),
                "KRIKOS-ID/name-claim-signature/v1",
                value.body().signing_bytes().unwrap(),
                value.subject_signature().as_bytes(),
                keys,
            ));
        }
        "SignedPortableCredential" => {
            let value = SignedPortableCredential::from_canonical_bytes(bytes).unwrap();
            bindings.push(resolved_signature_binding(
                "signature-1".to_owned(),
                "KRIKOS-ID/portable-credential-signature/v1",
                value.body().signing_bytes().unwrap(),
                value.issuer_signature().as_bytes(),
                keys,
            ));
        }
        "SignedProviderHead" => append_provider_head_binding(
            &mut bindings,
            &SignedProviderHead::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "InclusionReceipt" => append_provider_head_binding(
            &mut bindings,
            InclusionReceipt::from_canonical_bytes(bytes)
                .unwrap()
                .signed_head(),
            keys,
        ),
        "ProviderReceipts" => {
            let value = ProviderReceipts::from_canonical_bytes(bytes).unwrap();
            append_provider_receipt_bindings(&mut bindings, &value, keys);
        }
        "ProviderEquivocationEvidence" => {
            let value = ProviderEquivocationEvidence::from_canonical_bytes(bytes).unwrap();
            append_provider_head_binding(&mut bindings, value.first(), keys);
            append_provider_head_binding(&mut bindings, value.second(), keys);
        }
        "ProviderGenerationExportChunk" => {
            let chunk = ProviderGenerationExportChunk::from_canonical_bytes(bytes).unwrap();
            append_provider_generation_chunk_bindings(&mut bindings, &chunk, bytes, keys);
        }
        "ProviderAuditExportChunk" => {
            let chunk = ProviderAuditExportChunk::from_canonical_bytes(bytes).unwrap();
            append_provider_audit_chunk_bindings(&mut bindings, &chunk, bytes, keys);
        }
        "ProviderGenerationExportManifest" => {
            let manifest = ProviderGenerationExportManifest::from_canonical_bytes(bytes).unwrap();
            append_provider_generation_manifest_bindings(&mut bindings, &manifest, keys);
        }
        "ProviderAuditExportManifest" => {
            let manifest = ProviderAuditExportManifest::from_canonical_bytes(bytes).unwrap();
            append_provider_audit_manifest_bindings(&mut bindings, &manifest, keys);
        }
        "ProviderRecoveryExportManifest" => {
            let manifest = ProviderRecoveryExportManifest::from_canonical_bytes(bytes).unwrap();
            append_provider_recovery_manifest_bindings(&mut bindings, &manifest, keys);
        }
        "PairingPossessionProof" => {
            let value = PairingPossessionProof::from_canonical_bytes(bytes).unwrap();
            let dependency = vectors["pairing-transcript"];
            assert!(
                vector
                    .dependencies
                    .iter()
                    .any(|name| name == dependency.name.as_str())
            );
            let transcript = PairingTranscript::from_canonical_bytes(
                &fs::read(directory.join(&dependency.canonical_file)).unwrap(),
            )
            .unwrap();
            assert_eq!(value.transcript_id(), transcript.transcript_id().unwrap());
            bindings.push(resolved_signature_binding_for_key(
                "signature-1".to_owned(),
                "KRIKOS-ID/pairing-application-possession/v1",
                transcript.application_possession_signing_bytes().unwrap(),
                value.application_signature().as_bytes(),
                Some(ExactSigningKey::Public(
                    transcript.proposed_device().application_signing_key(),
                )),
                keys,
            ));
            bindings.push(resolved_signature_binding_for_key(
                "signature-2".to_owned(),
                "KRIKOS-ID/pairing-endpoint-possession/v1",
                transcript.endpoint_possession_signing_bytes().unwrap(),
                value.endpoint_signature().as_bytes(),
                Some(ExactSigningKey::Public(
                    transcript.proposed_device().endpoint_key().as_signing_key(),
                )),
                keys,
            ));
        }
        "PresenceProof" => {
            let value = PresenceProof::from_canonical_bytes(bytes).unwrap();
            bindings.push(resolved_signature_binding(
                "signature-1".to_owned(),
                "KRIKOS-ID/device-presence-signature/v1",
                value.challenge().signing_bytes().unwrap(),
                value.signature().as_bytes(),
                keys,
            ));
        }
        "SyncFrame" => append_sync_frame_bindings(
            &mut bindings,
            &SyncFrame::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "SyncResponse" => append_sync_response_bindings(
            &mut bindings,
            &SyncResponse::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "AuthorizedCheckpointRequest" => append_checkpoint_request_bindings(
            &mut bindings,
            &AuthorizedCheckpointRequest::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        "IdentityProtocolReply" => append_identity_reply_bindings(
            &mut bindings,
            &IdentityProtocolReply::from_canonical_bytes(bytes).unwrap(),
            keys,
        ),
        _ => {}
    }
    bindings
}

struct PairingMacKeyInputs {
    secret_seed: [u8; 32],
    subject_public_key: AgreementPublicKey,
    connection_public_key: AgreementPublicKey,
}

fn expected_pairing_mac_binding(
    name: &str,
    key_context: &str,
    message_domain: &str,
    key_inputs: PairingMacKeyInputs,
    transcript_bytes: &[u8],
    expected_mac: &[u8; 32],
) -> MacBinding {
    let secret = StaticSecret::from(key_inputs.secret_seed);
    let connection_public = X25519PublicKey::from(*key_inputs.connection_public_key.as_bytes());
    let shared = secret.diffie_hellman(&connection_public);
    let mut material = [0_u8; 96];
    material[..32].copy_from_slice(shared.as_bytes());
    material[32..64].copy_from_slice(key_inputs.subject_public_key.as_bytes());
    material[64..].copy_from_slice(key_inputs.connection_public_key.as_bytes());
    let key = blake3::derive_key(key_context, &material);
    let mut message = Vec::with_capacity(message_domain.len() + 1 + transcript_bytes.len());
    message.extend_from_slice(message_domain.as_bytes());
    message.push(0);
    message.extend_from_slice(transcript_bytes);
    assert_eq!(blake3::keyed_hash(&key, &message).as_bytes(), expected_mac);
    MacBinding {
        name: name.to_owned(),
        algorithm: "BLAKE3 keyed_hash(key, message)".to_owned(),
        key_derivation_algorithm: "BLAKE3 derive_key(context, input)".to_owned(),
        key_derivation_context_ascii: key_context.to_owned(),
        key_derivation_input_hex: hex::encode(material),
        message_domain_ascii: message_domain.to_owned(),
        message_hex: hex::encode(message),
        expected_mac_hex: hex::encode(expected_mac),
    }
}

const INTEROP_SYNC_CURSOR_KEY: [u8; 32] = [0x51; 32];

#[derive(Deserialize)]
struct SyncCursorMirror {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    source_heads: Vec<EventId>,
    next_item: u64,
    delivered_bytes: u64,
    authenticator: [u8; 32],
}

fn expected_sync_cursor_mac_binding(name: String, cursor: &SyncCursor) -> MacBinding {
    let encoded = cursor.to_canonical_bytes().unwrap();
    let mirror: SyncCursorMirror = postcard::from_bytes(&encoded).unwrap();
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
    assert!(
        cursor
            .verify(&CursorKey::new(INTEROP_SYNC_CURSOR_KEY).unwrap())
            .is_ok()
    );
    MacBinding {
        name,
        algorithm: "BLAKE3 keyed_hash(key, message)".to_owned(),
        key_derivation_algorithm: "raw 256-bit test key".to_owned(),
        key_derivation_context_ascii: "none".to_owned(),
        key_derivation_input_hex: hex::encode(INTEROP_SYNC_CURSOR_KEY),
        message_domain_ascii: "none".to_owned(),
        message_hex: hex::encode(message),
        expected_mac_hex: hex::encode(mirror.authenticator),
    }
}

fn append_sync_cursor_mac_binding(bindings: &mut Vec<MacBinding>, cursor: Option<&SyncCursor>) {
    if let Some(cursor) = cursor {
        bindings.push(expected_sync_cursor_mac_binding(
            format!("cursor-authenticator-{}", bindings.len() + 1),
            cursor,
        ));
    }
}

fn append_sync_response_mac_bindings(bindings: &mut Vec<MacBinding>, response: &SyncResponse) {
    if let Some(frame) = response.as_frame() {
        append_sync_cursor_mac_binding(bindings, frame.continuation());
    }
}

fn expected_mac_bindings(
    vector: &VectorMetadata,
    bytes: &[u8],
    directory: &Path,
    vectors: &BTreeMap<&str, &VectorMetadata>,
    keys: &[KeyMetadata],
) -> Vec<MacBinding> {
    let mut bindings = Vec::new();
    match vector.wire_type.as_str() {
        "PairingPossessionProof" => {
            let seed = |name: &str| -> [u8; 32] {
                let key = keys.iter().find(|key| key.name == name).unwrap();
                assert_eq!(key.algorithm, "X25519");
                hex::decode(&key.test_only_secret_seed_hex)
                    .unwrap()
                    .try_into()
                    .unwrap()
            };
            let proof = PairingPossessionProof::from_canonical_bytes(bytes).unwrap();
            let dependency = vectors["pairing-transcript"];
            let transcript = PairingTranscript::from_canonical_bytes(
                &fs::read(directory.join(&dependency.canonical_file)).unwrap(),
            )
            .unwrap();
            let transcript_bytes = transcript.to_canonical_bytes().unwrap();
            bindings.extend([
                expected_pairing_mac_binding(
                    "agreement-possession",
                    "KRIKOS-ID/pairing-agreement-proof-key/v1",
                    "KRIKOS-ID/pairing-agreement-possession/v1",
                    PairingMacKeyInputs {
                        secret_seed: seed("pairing-proposed-agreement"),
                        subject_public_key: transcript.proposed_device().agreement_key(),
                        connection_public_key: transcript.connection_ephemeral_public_key(),
                    },
                    &transcript_bytes,
                    proof.agreement_mac(),
                ),
                expected_pairing_mac_binding(
                    "pairing-ephemeral-possession",
                    "KRIKOS-ID/pairing-ephemeral-proof-key/v1",
                    "KRIKOS-ID/pairing-ephemeral-possession/v1",
                    PairingMacKeyInputs {
                        secret_seed: seed("pairing-ticket-ephemeral"),
                        subject_public_key: transcript.pairing_ephemeral_public_key(),
                        connection_public_key: transcript.connection_ephemeral_public_key(),
                    },
                    &transcript_bytes,
                    proof.pairing_ephemeral_mac(),
                ),
            ]);
        }
        "SyncCursor" => append_sync_cursor_mac_binding(
            &mut bindings,
            Some(&SyncCursor::from_canonical_bytes(bytes).unwrap()),
        ),
        "SyncRequest" => append_sync_cursor_mac_binding(
            &mut bindings,
            SyncRequest::from_canonical_bytes(bytes)
                .unwrap()
                .continuation(),
        ),
        "SyncFrame" => append_sync_cursor_mac_binding(
            &mut bindings,
            SyncFrame::from_canonical_bytes(bytes)
                .unwrap()
                .continuation(),
        ),
        "SyncResponse" => append_sync_response_mac_bindings(
            &mut bindings,
            &SyncResponse::from_canonical_bytes(bytes).unwrap(),
        ),
        "AuthorizedSyncRequest" => append_sync_cursor_mac_binding(
            &mut bindings,
            AuthorizedSyncRequest::from_canonical_bytes(bytes)
                .unwrap()
                .request()
                .continuation(),
        ),
        "IdentityProtocolReply" => {
            let reply = IdentityProtocolReply::from_canonical_bytes(bytes).unwrap();
            if let Some(response) = reply.as_sync() {
                append_sync_response_mac_bindings(&mut bindings, response);
            }
        }
        _ => {}
    }
    bindings
}

fn validate_signature_bindings(
    vector: &VectorMetadata,
    bytes: &[u8],
    directory: &Path,
    vectors: &BTreeMap<&str, &VectorMetadata>,
    keys: &[KeyMetadata],
) {
    assert_eq!(
        vector.signature_bindings,
        expected_signature_bindings(vector, bytes, directory, vectors, keys),
        "{} signature bindings must recursively describe its decoded canonical object",
        vector.name
    );
}

fn validate_mac_bindings(
    vector: &VectorMetadata,
    bytes: &[u8],
    directory: &Path,
    vectors: &BTreeMap<&str, &VectorMetadata>,
    keys: &[KeyMetadata],
) {
    assert_eq!(
        vector.mac_bindings,
        expected_mac_bindings(vector, bytes, directory, vectors, keys),
        "{} MAC bindings must recursively describe its decoded canonical object",
        vector.name
    );
}

fn derivation(
    output_name: &str,
    algorithm: &str,
    domain: &str,
    message: Vec<u8>,
    digest: &Digest,
) -> DerivationMetadata {
    DerivationMetadata {
        output_name: output_name.to_owned(),
        algorithm: algorithm.to_owned(),
        domain_or_context_ascii: domain.to_owned(),
        message_hex: hex::encode(message),
        expected_output_hex: hex::encode(digest.as_bytes()),
    }
}

fn domain_derivation(
    output_name: &str,
    domain: &str,
    message: Vec<u8>,
    digest: &Digest,
) -> DerivationMetadata {
    derivation(
        output_name,
        "BLAKE3-256(domain || 0x00 || message)",
        domain,
        message,
        digest,
    )
}

fn derive_key_derivation(
    output_name: &str,
    context: &str,
    message: Vec<u8>,
    digest: &Digest,
) -> DerivationMetadata {
    derivation(
        output_name,
        "BLAKE3 derive_key(context, message)",
        context,
        message,
        digest,
    )
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
    output_name: &str,
    domain: &str,
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

fn derivation_output_digest(derivation: &DerivationMetadata) -> Digest {
    Digest::new(
        HashAlgorithm::Blake3_256,
        hex::decode(&derivation.expected_output_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn merkle_leaf_derivation(output_name: &str, leaf: &MerkleSetLeaf) -> DerivationMetadata {
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
    leaf_output_name: &str,
    root_output_name: &str,
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
            let evidence_id = value.admission_evidence().admission_evidence_id().unwrap();
            let mut derivations =
                derivations_for_wire_type("EventBody", &value.body().to_canonical_bytes().unwrap());
            derivations.extend([
                domain_derivation(
                    "admission_evidence_id",
                    "KRIKOS-ID/admission-evidence/v1",
                    value.admission_evidence().to_canonical_bytes().unwrap(),
                    evidence_id.as_digest(),
                ),
                domain_derivation(
                    "event_id",
                    "KRIKOS-ID/account-event/v1",
                    postcard::to_stdvec(&(value.body(), evidence_id)).unwrap(),
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
            let value = RecoveryAuthorityPlan::from_canonical_bytes(bytes).unwrap();
            let proposal =
                RecoveryProposal::try_new(ProtocolVersion::V1, value, Extensions::default())
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
            if value.component() == Ok(ProviderExportComponent::CheckpointBundles) {
                for item in chunk_items(&mirror.payload) {
                    let item: ProviderCheckpointBundleItemMirror =
                        postcard::from_bytes(&item).unwrap();
                    if let Some(genesis) = &item.bundle.genesis {
                        derivations.extend(derivations_for_wire_type(
                            "AccountGenesis",
                            &genesis.to_canonical_bytes().unwrap(),
                        ));
                    }
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

fn expected_derivations(
    vector: &VectorMetadata,
    bytes: &[u8],
    directory: &Path,
    vectors: &BTreeMap<&str, &VectorMetadata>,
) -> Vec<DerivationMetadata> {
    let mut expected = derivations_for_wire_type(&vector.wire_type, bytes);
    match vector.wire_type.as_str() {
        "MerkleInclusionProof" => {
            assert_eq!(vector.dependencies, ["merkle-set-leaf"]);
            let dependency = vectors["merkle-set-leaf"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let leaf = MerkleSetLeaf::from_canonical_bytes(&dependency_bytes).unwrap();
            let proof = MerkleInclusionProof::from_canonical_bytes(bytes).unwrap();
            expected.extend(merkle_inclusion_derivations(
                &leaf,
                &proof,
                "merkle_leaf_hash",
                "merkle_root",
            ));
        }
        "MerkleConsistencyProof" => {
            assert_eq!(vector.dependencies, ["merkle-set-leaf"]);
            let dependency = vectors["merkle-set-leaf"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let leaf = MerkleSetLeaf::from_canonical_bytes(&dependency_bytes).unwrap();
            let proof = MerkleConsistencyProof::from_canonical_bytes(bytes).unwrap();
            expected.extend(merkle_consistency_derivations(&leaf, &proof));
        }
        "IdentityProtocolAck" => {
            assert_eq!(vector.dependencies, ["sync-request"]);
            let request_vector = vectors["sync-request"];
            assert_eq!(request_vector.wire_type, "SyncRequest");
            let request_bytes = fs::read(directory.join(&request_vector.canonical_file)).unwrap();
            let ack = IdentityProtocolAck::from_canonical_bytes(bytes).unwrap();
            assert_eq!(ack.protocol(), Ok(IdentityProtocolKind::Sync));
            expected.push(network_request_commitment_derivation(&ack, &request_bytes));
        }
        "IdentityProtocolReply" => {
            let reply = IdentityProtocolReply::from_canonical_bytes(bytes).unwrap();
            if let Some(ack) = reply.as_ack() {
                assert_eq!(vector.dependencies, ["identity-protocol-ack"]);
                let ack_vector = vectors["identity-protocol-ack"];
                let ack_bytes = fs::read(directory.join(&ack_vector.canonical_file)).unwrap();
                let dependency_ack = IdentityProtocolAck::from_canonical_bytes(&ack_bytes).unwrap();
                assert_eq!(ack, &dependency_ack);
                expected.extend(expected_derivations(
                    ack_vector, &ack_bytes, directory, vectors,
                ));
            }
        }
        "OpaqueProviderAnchorCommitment" => {
            assert_eq!(vector.dependencies, ["provider-compaction-manifest"]);
            let manifest_vector = vectors["provider-compaction-manifest"];
            let manifest_bytes = fs::read(directory.join(&manifest_vector.canonical_file)).unwrap();
            let manifest =
                ProviderCompactionManifest::from_canonical_bytes(&manifest_bytes).unwrap();
            let anchor = OpaqueProviderAnchorCommitment::from_canonical_bytes(bytes).unwrap();
            assert_eq!(
                OpaqueProviderAnchorCommitment::from_compaction_manifest(&manifest).unwrap(),
                anchor
            );
            expected.push(provider_anchor_commitment_derivation(anchor, &manifest));
        }
        _ => {}
    }
    expected
}

fn validate_derivations(
    vector: &VectorMetadata,
    bytes: &[u8],
    directory: &Path,
    vectors: &BTreeMap<&str, &VectorMetadata>,
) {
    let expected = expected_derivations(vector, bytes, directory, vectors);
    assert_eq!(
        vector.derivations, expected,
        "{} derivation metadata must come from its decoded canonical object",
        vector.name
    );
    for derivation in &vector.derivations {
        let message = hex::decode(&derivation.message_hex).unwrap();
        let output = match derivation.algorithm.as_str() {
            "BLAKE3-256(domain || 0x00 || message)" => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(derivation.domain_or_context_ascii.as_bytes());
                hasher.update(&[0]);
                hasher.update(&message);
                *hasher.finalize().as_bytes()
            }
            "BLAKE3 derive_key(context, message)" => {
                blake3::derive_key(&derivation.domain_or_context_ascii, &message)
            }
            other => panic!(
                "{} has unsupported derivation algorithm {other}",
                vector.name
            ),
        };
        assert_eq!(
            hex::encode(output),
            derivation.expected_output_hex,
            "{} derivation {} does not reproduce from its declared message",
            vector.name,
            derivation.output_name
        );
        assert_eq!(
            vector.expected_ids.get(&derivation.output_name),
            Some(&format!("b3:{}", derivation.expected_output_hex)),
            "{} must cover derivation output {} in expected_ids",
            vector.name,
            derivation.output_name
        );
    }
}

fn validate_expected_ids(vector: &VectorMetadata, bytes: &[u8]) {
    if matches!(
        vector.wire_type.as_str(),
        "MerkleInclusionProof" | "MerkleConsistencyProof" | "MerkleNonMembershipProof"
    ) {
        return;
    }
    let actual = match vector.wire_type.as_str() {
        "AccountGenesis" => {
            let value = AccountGenesis::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([
                ("account_id", value.account_id().unwrap().to_string()),
                (
                    "genesis_anchor",
                    value.genesis_anchor().unwrap().to_string(),
                ),
            ])
        }
        "EventBody" => {
            let value = EventBody::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([("proposal_id", value.proposal_id().unwrap().to_string())])
        }
        "AdmissionEvidence" => {
            let value = AdmissionEvidence::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "admission_evidence_id",
                value.admission_evidence_id().unwrap().to_string(),
            )])
        }
        "AuthorizedEvent" => {
            let value = AuthorizedEvent::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([
                (
                    "proposal_id",
                    value.body().proposal_id().unwrap().to_string(),
                ),
                (
                    "admission_evidence_id",
                    value
                        .admission_evidence()
                        .admission_evidence_id()
                        .unwrap()
                        .to_string(),
                ),
                ("event_id", value.event_id().unwrap().to_string()),
                (
                    "event_authorization_id",
                    value.event_authorization_id().unwrap().to_string(),
                ),
            ])
        }
        "SignedCheckpoint" => {
            let value = SignedCheckpoint::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([("checkpoint_id", value.checkpoint_id().unwrap().to_string())])
        }
        "BeginCryptoMigration" => {
            let value = BeginCryptoMigration::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "crypto_migration_id",
                value.migration().crypto_migration_id().unwrap().to_string(),
            )])
        }
        "EventIntentApprovalBody" => {
            let value = EventIntentApprovalBody::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "event_intent_approval_id",
                value.event_intent_approval_id().unwrap().to_string(),
            )])
        }
        "ControllerApprovalBody" => {
            let value = ControllerApprovalBody::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "controller_approval_id",
                value.controller_approval_id().unwrap().to_string(),
            )])
        }
        "RecoveryAuthorityPlan" => {
            let value = RecoveryAuthorityPlan::from_canonical_bytes(bytes).unwrap();
            let proposal =
                RecoveryProposal::try_new(ProtocolVersion::V1, value, Extensions::default())
                    .unwrap();
            BTreeMap::from([("recovery_id", proposal.recovery_id().unwrap().to_string())])
        }
        "ForkDescriptor" => {
            let value = ForkDescriptor::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([("fork_id", value.fork_id().unwrap().to_string())])
        }
        "CapabilityGrant" => {
            let value = CapabilityGrant::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "capability_grant_id",
                value.capability_grant_id().unwrap().to_string(),
            )])
        }
        "DelegationBody" => {
            let value = DelegationBody::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([("delegation_id", value.delegation_id().unwrap().to_string())])
        }
        "SignedApplicationEvent" => {
            let value = SignedApplicationEvent::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "application_event_id",
                value.application_event_id().unwrap().to_string(),
            )])
        }
        "WrappedGroupKey" => {
            let value = WrappedGroupKey::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "group_key_wrap_id",
                value.group_key_wrap_id().unwrap().to_string(),
            )])
        }
        "ProviderLogEntryBody" => {
            let value = ProviderLogEntryBody::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "merkle_leaf_hash",
                value.merkle_leaf_hash().unwrap().to_string(),
            )])
        }
        "PairingTicket" => {
            let value = PairingTicket::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "pairing_ticket_id",
                value.ticket_id().unwrap().as_digest().to_string(),
            )])
        }
        "PairingTranscript" => {
            let value = PairingTranscript::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "pairing_transcript_id",
                value.transcript_id().unwrap().as_digest().to_string(),
            )])
        }
        "PairingPossessionProof" => {
            let value = PairingPossessionProof::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "pairing_proof_id",
                value.proof_id().unwrap().as_digest().to_string(),
            )])
        }
        "DeviceAuthorizationProposal" => {
            let value = DeviceAuthorizationProposal::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "device_authorization_proposal_id",
                value.proposal_id().unwrap().as_digest().to_string(),
            )])
        }
        "PresenceProof" => {
            let value = PresenceProof::from_canonical_bytes(bytes).unwrap();
            BTreeMap::from([(
                "presence_proof_id",
                value.proof_id().unwrap().as_digest().to_string(),
            )])
        }
        _ => BTreeMap::new(),
    };
    let derived = vector
        .derivations
        .iter()
        .map(|derivation| {
            (
                derivation.output_name.as_str(),
                format!("b3:{}", derivation.expected_output_hex),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let actual_names = actual
        .keys()
        .copied()
        .chain(derived.keys().copied())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_names,
        vector
            .expected_ids
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        "{} expected_ids must be an exact decoded/derived inventory",
        vector.name
    );
    for (name, expected) in &vector.expected_ids {
        let recomputed = actual
            .get(name.as_str())
            .or_else(|| derived.get(name.as_str()));
        assert_eq!(
            recomputed,
            Some(expected),
            "{} expected ID {name} was not recomputed from its binary",
            vector.name
        );
    }
}

fn validate_version_metadata(vector: &VectorMetadata) {
    let is_digest_id = matches!(
        vector.wire_type.as_str(),
        "GenesisAnchor"
            | "AccountId"
            | "ControllerId"
            | "ControllerKeyId"
            | "ControlPolicyId"
            | "RecoveryPolicyId"
            | "ProviderId"
            | "ProviderLogId"
            | "ProviderPolicyId"
            | "DeviceId"
            | "CapabilityGrantId"
            | "DelegationId"
            | "ProposalId"
            | "EventId"
            | "EventAuthorizationId"
            | "AdmissionEvidenceId"
            | "ControllerApprovalId"
            | "EventIntentApprovalId"
            | "CheckpointId"
            | "RecoveryId"
            | "GuardianGrantId"
            | "ForkId"
            | "CryptoSuiteId"
            | "CryptoMigrationId"
            | "CryptoStateId"
            | "ApplicationId"
            | "ApplicationEventId"
            | "GroupId"
            | "GroupKeyWrapId"
    );
    let is_merkle = matches!(
        vector.wire_type.as_str(),
        "MerkleSetKey"
            | "MerkleSetLeaf"
            | "MerkleInclusionProof"
            | "MerkleConsistencyProof"
            | "MerkleNonMembershipProof"
    );
    let is_provider_interchange = matches!(
        vector.wire_type.as_str(),
        "ProviderExportComponent"
            | "ProviderExportComponentDescriptor"
            | "ProviderGenerationExportChunk"
            | "ProviderAuditExportChunk"
            | "ProviderGenerationExportManifest"
            | "ProviderAuditExportManifest"
            | "ProviderRecoveryExportManifest"
    );
    if is_digest_id {
        assert_eq!(vector.protocol_version, None);
        assert!(
            vector
                .version_scope
                .contains("standalone-algorithm-tagged-digest")
        );
    } else if is_merkle {
        assert_eq!(vector.protocol_version, None);
        assert!(vector.version_scope.contains("standalone Merkle structure"));
    } else if is_provider_interchange {
        assert_eq!(vector.protocol_version, Some(1));
        assert_eq!(
            vector.version_scope,
            "authoritative-provider-interchange-format-v1"
        );
    } else {
        let exact_scope = match vector.wire_type.as_str() {
            "EndpointAuthorizationRequest"
            | "SyncCursor"
            | "SyncRequest"
            | "SyncFrame"
            | "SyncResponse"
            | "IdentityProtocolAck"
            | "IdentityProtocolReply" => Some("authoritative-top-level-v1"),
            "AuthorizedSyncRequest" => {
                Some("v1 inherited from exact nested authorization and sync request")
            }
            "AuthorizedProposalRequest" => {
                Some("v1 inherited from exact nested authorization and proposal")
            }
            "AuthorizedCheckpointRequest" => {
                Some("v1 inherited from exact nested authorization and checkpoint")
            }
            "ControllerKeyBindingProof" => Some("v1 inherited from exact crypto migration begin"),
            "ProviderCompactionManifest" => Some("authoritative-provider-compaction-format-v1"),
            "OpaqueProviderAnchorCommitment" => Some("authoritative-provider-anchor-format-v1"),
            _ => None,
        };
        if let Some(exact_scope) = exact_scope {
            assert_eq!(vector.protocol_version, Some(1));
            assert_eq!(vector.version_scope, exact_scope);
        } else {
            assert!(!vector.version_scope.is_empty());
        }
    }
}

fn validate_cross_vector_dependencies(
    vector: &VectorMetadata,
    bytes: &[u8],
    directory: &Path,
    vectors: &BTreeMap<&str, &VectorMetadata>,
) {
    match vector.wire_type.as_str() {
        "SignedEventIntentApproval" => {
            assert_eq!(vector.dependencies, ["event-intent-approval-body"]);
            let dependency = vectors["event-intent-approval-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = EventIntentApprovalBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let approval = SignedEventIntentApproval::from_canonical_bytes(bytes).unwrap();
            assert_eq!(approval.body(), &body);
        }
        "EventIntentApprovals" => {
            assert_eq!(vector.dependencies, ["event-intent-approval"]);
            let dependency = vectors["event-intent-approval"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let approval =
                SignedEventIntentApproval::from_canonical_bytes(&dependency_bytes).unwrap();
            let approvals = EventIntentApprovals::from_canonical_bytes(bytes).unwrap();
            assert_eq!(approvals.as_slice(), std::slice::from_ref(&approval));
        }
        "AdmissionEvidence" => {
            assert_eq!(vector.dependencies, ["event-body"]);
            let dependency = vectors["event-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = EventBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let evidence = AdmissionEvidence::from_canonical_bytes(bytes).unwrap();
            assert_eq!(evidence.proposal_id(), body.proposal_id().unwrap());
        }
        "ControllerApprovalBody" => {
            assert_eq!(vector.dependencies, ["event-body", "admission-evidence"]);
            let body = EventBody::from_canonical_bytes(
                &fs::read(directory.join(&vectors["event-body"].canonical_file)).unwrap(),
            )
            .unwrap();
            let evidence = AdmissionEvidence::from_canonical_bytes(
                &fs::read(directory.join(&vectors["admission-evidence"].canonical_file)).unwrap(),
            )
            .unwrap();
            let approval_body = ControllerApprovalBody::from_canonical_bytes(bytes).unwrap();
            assert_eq!(
                approval_body.event_subject(),
                Some((
                    evidence.event_id_for_body(&body).unwrap(),
                    evidence.admission_evidence_id().unwrap(),
                ))
            );
        }
        "SignedControllerApproval" => {
            assert_eq!(
                vector.dependencies,
                ["final-event-controller-approval-body"]
            );
            let dependency = vectors["final-event-controller-approval-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = ControllerApprovalBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let approval = SignedControllerApproval::from_canonical_bytes(bytes).unwrap();
            assert_eq!(approval.body(), &body);
        }
        "ControllerApprovals" => {
            assert_eq!(vector.dependencies, ["final-event-controller-approval"]);
            let dependency = vectors["final-event-controller-approval"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let approval =
                SignedControllerApproval::from_canonical_bytes(&dependency_bytes).unwrap();
            let approvals = ControllerApprovals::from_canonical_bytes(bytes).unwrap();
            assert_eq!(approvals.as_slice(), std::slice::from_ref(&approval));
        }
        "AuthorizedEvent" => {
            assert_eq!(
                vector.dependencies,
                [
                    "event-body",
                    "admission-evidence",
                    "final-event-controller-approval"
                ]
            );
            let body = EventBody::from_canonical_bytes(
                &fs::read(directory.join(&vectors["event-body"].canonical_file)).unwrap(),
            )
            .unwrap();
            let evidence = AdmissionEvidence::from_canonical_bytes(
                &fs::read(directory.join(&vectors["admission-evidence"].canonical_file)).unwrap(),
            )
            .unwrap();
            let approval = SignedControllerApproval::from_canonical_bytes(
                &fs::read(
                    directory.join(&vectors["final-event-controller-approval"].canonical_file),
                )
                .unwrap(),
            )
            .unwrap();
            let event = AuthorizedEvent::from_canonical_bytes(bytes).unwrap();
            assert_eq!(event.body(), &body);
            assert_eq!(event.admission_evidence(), &evidence);
            assert_eq!(
                event.approvals().as_slice(),
                std::slice::from_ref(&approval)
            );
        }
        "SignedGuardianApproval" => {
            assert_eq!(vector.dependencies, ["guardian-approval-body"]);
            let dependency = vectors["guardian-approval-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = GuardianApprovalBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let approval = SignedGuardianApproval::from_canonical_bytes(bytes).unwrap();
            assert_eq!(approval.body(), &body);
        }
        "GuardianApprovalSet" => {
            assert_eq!(vector.dependencies, ["signed-guardian-approval"]);
            let dependency = vectors["signed-guardian-approval"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let approval = SignedGuardianApproval::from_canonical_bytes(&dependency_bytes).unwrap();
            let approvals = GuardianApprovalSet::from_canonical_bytes(bytes).unwrap();
            assert!(
                approvals.as_slice().contains(&approval),
                "guardian approval set must contain the exact declared signed approval"
            );
        }
        "RecoveryThresholdEvidence" => {
            assert_eq!(vector.dependencies, ["guardian-approval-set"]);
            let dependency = vectors["guardian-approval-set"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let approvals = GuardianApprovalSet::from_canonical_bytes(&dependency_bytes).unwrap();
            let evidence = RecoveryThresholdEvidence::from_canonical_bytes(bytes).unwrap();
            assert_eq!(evidence.as_guardian_approvals(), Some(&approvals));
        }
        "BackupAuthorityBundle" => {
            assert_eq!(
                vector.dependencies,
                ["account-genesis", "authorized-event", "checkpoint-direct"]
            );
            let genesis = AccountGenesis::from_canonical_bytes(
                &fs::read(directory.join(&vectors["account-genesis"].canonical_file)).unwrap(),
            )
            .unwrap();
            let event = AuthorizedEvent::from_canonical_bytes(
                &fs::read(directory.join(&vectors["authorized-event"].canonical_file)).unwrap(),
            )
            .unwrap();
            let checkpoint = SignedCheckpoint::from_canonical_bytes(
                &fs::read(directory.join(&vectors["checkpoint-direct"].canonical_file)).unwrap(),
            )
            .unwrap();
            let bundle = BackupAuthorityBundle::from_canonical_bytes(bytes).unwrap();
            assert_eq!(bundle.genesis(), &genesis);
            assert_eq!(bundle.events(), std::slice::from_ref(&event));
            assert_eq!(bundle.checkpoint(), &checkpoint);
        }
        "BackupEnvelope" => {
            assert_eq!(vector.dependencies, ["backup-authority-bundle"]);
            let dependency = vectors["backup-authority-bundle"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let bundle = BackupAuthorityBundle::from_canonical_bytes(&dependency_bytes).unwrap();
            let decrypted_bundle = backup_envelope_authority_bundle(bytes);
            assert_eq!(decrypted_bundle, bundle);
        }
        "CapabilityRoot" => {
            assert_eq!(vector.dependencies, ["capability-root-grant"]);
            let dependency = vectors["capability-root-grant"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let grant = CapabilityGrant::from_canonical_bytes(&dependency_bytes).unwrap();
            let root = CapabilityRoot::from_canonical_bytes(bytes).unwrap();
            assert_eq!(root.grant(), &grant);
        }
        "DelegationBody" => {
            assert_eq!(vector.dependencies, ["capability-grant"]);
            let dependency = vectors["capability-grant"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let grant = CapabilityGrant::from_canonical_bytes(&dependency_bytes).unwrap();
            let body = DelegationBody::from_canonical_bytes(bytes).unwrap();
            assert_eq!(body.child_grant(), &grant);
        }
        "SignedDelegation" => {
            assert_eq!(vector.dependencies, ["delegation-body"]);
            let dependency = vectors["delegation-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = DelegationBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let delegation = SignedDelegation::from_canonical_bytes(bytes).unwrap();
            assert_eq!(delegation.body(), &body);
        }
        "DelegationChain" => {
            assert_eq!(
                vector.dependencies,
                ["capability-root", "signed-delegation"]
            );
            let root = CapabilityRoot::from_canonical_bytes(
                &fs::read(directory.join(&vectors["capability-root"].canonical_file)).unwrap(),
            )
            .unwrap();
            let delegation = SignedDelegation::from_canonical_bytes(
                &fs::read(directory.join(&vectors["signed-delegation"].canonical_file)).unwrap(),
            )
            .unwrap();
            let chain = DelegationChain::from_canonical_bytes(bytes).unwrap();
            assert_eq!(chain.root(), &root);
            assert_eq!(chain.links(), std::slice::from_ref(&delegation));
        }
        "SignedApplicationEvent" => {
            assert_eq!(vector.dependencies, ["application-event-body"]);
            let dependency = vectors["application-event-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = ApplicationEventBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let event = SignedApplicationEvent::from_canonical_bytes(bytes).unwrap();
            assert_eq!(event.body(), &body);
        }
        "SignedSocialAttestation" => {
            assert_eq!(vector.dependencies, ["social-attestation-body"]);
            let dependency = vectors["social-attestation-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = SocialAttestationBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let attestation = SignedSocialAttestation::from_canonical_bytes(bytes).unwrap();
            assert_eq!(attestation.body(), &body);
        }
        "SignedNameClaim" => {
            assert_eq!(vector.dependencies, ["name-claim-body"]);
            let dependency = vectors["name-claim-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = NameClaimBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let claim = SignedNameClaim::from_canonical_bytes(bytes).unwrap();
            assert_eq!(claim.body(), &body);
        }
        "SignedPortableCredential" => {
            assert_eq!(vector.dependencies, ["portable-credential-body"]);
            let dependency = vectors["portable-credential-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = PortableCredentialBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let credential = SignedPortableCredential::from_canonical_bytes(bytes).unwrap();
            assert_eq!(credential.body(), &body);
        }
        "PrivateMetadataEnvelope" => {
            assert_eq!(vector.dependencies, ["private-artifact-context"]);
            let dependency = vectors["private-artifact-context"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let context = PrivateArtifactContext::from_canonical_bytes(&dependency_bytes).unwrap();
            let envelope = PrivateMetadataEnvelope::from_canonical_bytes(bytes).unwrap();
            assert_eq!(envelope.context(), &context);
        }
        "WrappedGroupKey" => {
            assert_eq!(vector.dependencies, ["group-key-wrap-header"]);
            let dependency = vectors["group-key-wrap-header"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let header = GroupKeyWrapHeader::from_canonical_bytes(&dependency_bytes).unwrap();
            let wrapped = WrappedGroupKey::from_canonical_bytes(bytes).unwrap();
            assert_eq!(wrapped.header(), &header);
        }
        "RecipientKeyWraps" => {
            assert_eq!(vector.dependencies, ["wrapped-group-key"]);
            let dependency = vectors["wrapped-group-key"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let wrapped = WrappedGroupKey::from_canonical_bytes(&dependency_bytes).unwrap();
            let wraps = RecipientKeyWraps::from_canonical_bytes(bytes).unwrap();
            assert_eq!(wraps.as_slice(), std::slice::from_ref(&wrapped));
        }
        "AccountOperation" => {
            let operation = AccountOperation::from_canonical_bytes(bytes).unwrap();
            match (&*vector.name, &operation) {
                ("account-operation-13", AccountOperation::BeginRecovery(begin)) => {
                    assert_eq!(vector.dependencies, ["recovery-begin"]);
                    let dependency = vectors["recovery-begin"];
                    let dependency_bytes =
                        fs::read(directory.join(&dependency.canonical_file)).unwrap();
                    let dependency_begin =
                        BeginRecovery::from_canonical_bytes(&dependency_bytes).unwrap();
                    assert_eq!(begin, &dependency_begin);
                }
                ("account-operation-14", AccountOperation::VetoRecovery(veto)) => {
                    assert_eq!(vector.dependencies, ["recovery-veto"]);
                    let dependency = vectors["recovery-veto"];
                    let dependency_bytes =
                        fs::read(directory.join(&dependency.canonical_file)).unwrap();
                    let dependency_veto =
                        VetoRecovery::from_canonical_bytes(&dependency_bytes).unwrap();
                    assert_eq!(veto, &dependency_veto);
                }
                ("account-operation-15", AccountOperation::CancelRecovery(cancel)) => {
                    assert_eq!(vector.dependencies, ["recovery-cancel"]);
                    let dependency = vectors["recovery-cancel"];
                    let dependency_bytes =
                        fs::read(directory.join(&dependency.canonical_file)).unwrap();
                    let dependency_cancel =
                        CancelRecovery::from_canonical_bytes(&dependency_bytes).unwrap();
                    assert_eq!(cancel, &dependency_cancel);
                }
                ("account-operation-16", AccountOperation::FinalizeRecovery(finalize)) => {
                    assert_eq!(vector.dependencies, ["recovery-finalize"]);
                    let dependency = vectors["recovery-finalize"];
                    let dependency_bytes =
                        fs::read(directory.join(&dependency.canonical_file)).unwrap();
                    let dependency_finalize =
                        FinalizeRecovery::from_canonical_bytes(&dependency_bytes).unwrap();
                    assert_eq!(finalize, &dependency_finalize);
                }
                ("account-operation-17", AccountOperation::ResolveFork(resolve)) => {
                    assert_eq!(vector.dependencies, ["fork-descriptor"]);
                    let dependency = vectors["fork-descriptor"];
                    let dependency_bytes =
                        fs::read(directory.join(&dependency.canonical_file)).unwrap();
                    let dependency_fork =
                        ForkDescriptor::from_canonical_bytes(&dependency_bytes).unwrap();
                    assert_eq!(resolve.fork(), &dependency_fork);
                }
                ("account-operation-18", AccountOperation::BeginCryptoMigration(begin)) => {
                    assert_eq!(vector.dependencies, ["crypto-migration-begin"]);
                    let dependency = vectors["crypto-migration-begin"];
                    let dependency_bytes =
                        fs::read(directory.join(&dependency.canonical_file)).unwrap();
                    let dependency_begin =
                        BeginCryptoMigration::from_canonical_bytes(&dependency_bytes).unwrap();
                    assert_eq!(begin, &dependency_begin);
                }
                _ => assert!(
                    vector.dependencies.is_empty(),
                    "{} has an undeclared account-operation dependency rule",
                    vector.name
                ),
            }
        }
        "FinalizeRecovery" => {
            assert_eq!(vector.dependencies, ["recovery-delay-anchor"]);
            let dependency = vectors["recovery-delay-anchor"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let dependency_anchor =
                RecoveryDelayAnchor::from_canonical_bytes(&dependency_bytes).unwrap();
            let finalize = FinalizeRecovery::from_canonical_bytes(bytes).unwrap();
            assert_eq!(finalize.delay_anchor(), &dependency_anchor);
        }
        "RecoveryProposal" => {
            assert_eq!(vector.dependencies, ["recovery-authority-plan"]);
            let dependency = vectors["recovery-authority-plan"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let dependency_plan =
                RecoveryAuthorityPlan::from_canonical_bytes(&dependency_bytes).unwrap();
            let proposal = RecoveryProposal::from_canonical_bytes(bytes).unwrap();
            assert_eq!(proposal.plan(), &dependency_plan);
        }
        "BeginRecovery" => {
            assert_eq!(vector.dependencies, ["recovery-proposal"]);
            let dependency = vectors["recovery-proposal"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let dependency_proposal =
                RecoveryProposal::from_canonical_bytes(&dependency_bytes).unwrap();
            let begin = BeginRecovery::from_canonical_bytes(bytes).unwrap();
            assert_eq!(begin.proposal(), &dependency_proposal);
        }
        "ControllerKeyBindingProof" => {
            assert_eq!(vector.dependencies, ["crypto-migration-begin"]);
            let dependency = vectors["crypto-migration-begin"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let begin = BeginCryptoMigration::from_canonical_bytes(&dependency_bytes).unwrap();
            let proof = ControllerKeyBindingProof::from_canonical_bytes(bytes).unwrap();
            assert_eq!(begin.proofs().as_slice(), std::slice::from_ref(&proof));
        }
        "RecoveryDelayAnchor" | "BeginCryptoMigration" => {
            assert!(vector.dependencies.is_empty());
        }
        "MerkleInclusionProof" => {
            assert_eq!(vector.dependencies, ["merkle-set-leaf"]);
            let dependency = vectors["merkle-set-leaf"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let leaf = MerkleSetLeaf::from_canonical_bytes(&dependency_bytes).unwrap();
            let proof = MerkleInclusionProof::from_canonical_bytes(bytes).unwrap();
            let derivations =
                merkle_inclusion_derivations(&leaf, &proof, "merkle_leaf_hash", "merkle_root");
            let root = derivation_output_digest(derivations.last().unwrap());
            assert_eq!(root.to_string(), vector.expected_ids["merkle_root"]);
            proof.verify(&leaf, root).unwrap();
        }
        "MerkleConsistencyProof" => {
            assert_eq!(vector.dependencies, ["merkle-set-leaf"]);
            let dependency = vectors["merkle-set-leaf"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let leaf = MerkleSetLeaf::from_canonical_bytes(&dependency_bytes).unwrap();
            let proof = MerkleConsistencyProof::from_canonical_bytes(bytes).unwrap();
            let derivations = merkle_consistency_derivations(&leaf, &proof);
            let old_root = derivation_output_digest(derivations.first().unwrap());
            let new_root = derivation_output_digest(derivations.last().unwrap());
            assert_eq!(old_root.to_string(), vector.expected_ids["old_merkle_root"]);
            assert_eq!(new_root.to_string(), vector.expected_ids["new_merkle_root"]);
            proof.verify(old_root, new_root).unwrap();
        }
        "MerkleNonMembershipProof" => {
            assert_eq!(vector.dependencies, ["merkle-set-key"]);
            let dependency = vectors["merkle-set-key"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let missing_key = MerkleSetKey::from_canonical_bytes(&dependency_bytes).unwrap();
            assert_eq!(
                hex::encode(missing_key.to_canonical_bytes().unwrap()),
                vector.expected_ids["missing_key"]
            );
            let proof = MerkleNonMembershipProof::from_canonical_bytes(bytes).unwrap();
            let derivations = merkle_non_membership_derivations(&proof);
            let root = derivation_output_digest(derivations.last().unwrap());
            assert_eq!(root.to_string(), vector.expected_ids["merkle_root"]);
            proof.verify(missing_key, root).unwrap();
            if let Some(predecessor) = proof.predecessor() {
                assert!(predecessor.leaf().key() < missing_key);
            }
            if let Some(successor) = proof.successor() {
                assert!(missing_key < successor.leaf().key());
            }
        }
        "IdentityProtocolAck" => {
            assert_eq!(vector.dependencies, ["sync-request"]);
            let dependency = vectors["sync-request"];
            let request_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let ack = IdentityProtocolAck::from_canonical_bytes(bytes).unwrap();
            let expected = IdentityProtocolAck::for_canonical_request(
                IdentityProtocolKind::Sync,
                &request_bytes,
                IdentityServiceOutcome::Accepted,
            );
            assert_eq!(ack, expected);
        }
        "ProviderHeadBody" => {
            assert_eq!(vector.dependencies, ["provider-log-entry"]);
            let dependency = vectors["provider-log-entry"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let entry = ProviderLogEntryBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let head = ProviderHeadBody::from_canonical_bytes(bytes).unwrap();
            assert_eq!(head.provider_id(), entry.provider_id());
            assert_eq!(head.log_id(), entry.log_id());
            assert_eq!(head.tree_size(), 1);
            assert_eq!(head.tree_root(), entry.merkle_leaf_hash().unwrap());
            assert!(head.observed_at() >= entry.observed_at());
        }
        "SignedProviderHead" => {
            assert_eq!(vector.dependencies, ["provider-head-body"]);
            let dependency = vectors["provider-head-body"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let body = ProviderHeadBody::from_canonical_bytes(&dependency_bytes).unwrap();
            let head = SignedProviderHead::from_canonical_bytes(bytes).unwrap();
            assert_eq!(head.body(), &body);
        }
        "InclusionReceipt" => {
            assert_eq!(
                vector.dependencies,
                ["provider-log-entry", "signed-provider-head"]
            );
            let entry = ProviderLogEntryBody::from_canonical_bytes(
                &fs::read(directory.join(&vectors["provider-log-entry"].canonical_file)).unwrap(),
            )
            .unwrap();
            let head = SignedProviderHead::from_canonical_bytes(
                &fs::read(directory.join(&vectors["signed-provider-head"].canonical_file)).unwrap(),
            )
            .unwrap();
            let receipt = InclusionReceipt::from_canonical_bytes(bytes).unwrap();
            assert_eq!(receipt.entry(), &entry);
            assert_eq!(receipt.signed_head(), &head);
        }
        "ProviderReceipts" => {
            assert_eq!(vector.dependencies, ["inclusion-receipt"]);
            let dependency = vectors["inclusion-receipt"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let receipt = InclusionReceipt::from_canonical_bytes(&dependency_bytes).unwrap();
            let receipts = ProviderReceipts::from_canonical_bytes(bytes).unwrap();
            assert_eq!(receipts.as_slice(), std::slice::from_ref(&receipt));
        }
        "ProviderEquivocationEvidence" => {
            assert_eq!(vector.dependencies, ["signed-provider-head"]);
            let dependency = vectors["signed-provider-head"];
            let dependency_bytes = fs::read(directory.join(&dependency.canonical_file)).unwrap();
            let head = SignedProviderHead::from_canonical_bytes(&dependency_bytes).unwrap();
            let evidence = ProviderEquivocationEvidence::from_canonical_bytes(bytes).unwrap();
            assert_eq!(evidence.first(), &head);
        }
        "PairingTranscript" => {
            assert_eq!(vector.dependencies, ["pairing-ticket"]);
            let ticket_vector = vectors["pairing-ticket"];
            let ticket_bytes = fs::read(directory.join(&ticket_vector.canonical_file)).unwrap();
            let ticket = PairingTicket::from_canonical_bytes(&ticket_bytes).unwrap();
            let transcript = PairingTranscript::from_canonical_bytes(bytes).unwrap();
            assert_eq!(transcript.ticket_id(), ticket.ticket_id().unwrap());
            assert_eq!(transcript.account_id(), ticket.account_id());
            assert_eq!(transcript.proposed_device(), ticket.proposed_device());
        }
        "PairingPossessionProof" => {
            assert_eq!(vector.dependencies, ["pairing-transcript"]);
            let transcript_vector = vectors["pairing-transcript"];
            let transcript_bytes =
                fs::read(directory.join(&transcript_vector.canonical_file)).unwrap();
            let transcript = PairingTranscript::from_canonical_bytes(&transcript_bytes).unwrap();
            let proof = PairingPossessionProof::from_canonical_bytes(bytes).unwrap();
            assert_eq!(proof.transcript_id(), transcript.transcript_id().unwrap());
        }
        "PairingConfirmationContext" => {
            assert_eq!(vector.dependencies, ["pairing-transcript"]);
            let transcript_vector = vectors["pairing-transcript"];
            let transcript_bytes =
                fs::read(directory.join(&transcript_vector.canonical_file)).unwrap();
            let transcript = PairingTranscript::from_canonical_bytes(&transcript_bytes).unwrap();
            let context = PairingConfirmationContext::from_canonical_bytes(bytes).unwrap();
            assert_eq!(context.transcript_id(), transcript.transcript_id().unwrap());
        }
        "DeviceAuthorizationProposal" => {
            assert_eq!(
                vector.dependencies,
                [
                    "pairing-ticket",
                    "pairing-transcript",
                    "pairing-possession-proof",
                    "pairing-confirmation-context"
                ]
            );
            let ticket = PairingTicket::from_canonical_bytes(
                &fs::read(directory.join(&vectors["pairing-ticket"].canonical_file)).unwrap(),
            )
            .unwrap();
            let transcript = PairingTranscript::from_canonical_bytes(
                &fs::read(directory.join(&vectors["pairing-transcript"].canonical_file)).unwrap(),
            )
            .unwrap();
            let proof = PairingPossessionProof::from_canonical_bytes(
                &fs::read(directory.join(&vectors["pairing-possession-proof"].canonical_file))
                    .unwrap(),
            )
            .unwrap();
            let confirmation = PairingConfirmationContext::from_canonical_bytes(
                &fs::read(directory.join(&vectors["pairing-confirmation-context"].canonical_file))
                    .unwrap(),
            )
            .unwrap();
            let proposal = DeviceAuthorizationProposal::from_canonical_bytes(bytes).unwrap();
            assert_eq!(proposal.account_id(), ticket.account_id());
            assert_eq!(proposal.proposed_device(), ticket.proposed_device());
            assert_eq!(proposal.proposed_device(), transcript.proposed_device());
            assert_eq!(proposal.proposed_device_id(), ticket.proposed_device_id());
            assert_eq!(proposal.ticket_id(), ticket.ticket_id().unwrap());
            assert_eq!(
                proposal.transcript_id(),
                transcript.transcript_id().unwrap()
            );
            assert_eq!(proposal.proof_id(), proof.proof_id().unwrap());
            assert_eq!(proposal.confirmation(), confirmation);
        }
        "PresenceProof" => {
            assert_eq!(vector.dependencies, ["presence-challenge"]);
            let challenge_vector = vectors["presence-challenge"];
            let challenge_bytes =
                fs::read(directory.join(&challenge_vector.canonical_file)).unwrap();
            let challenge =
                DevicePresenceChallenge::from_canonical_bytes(&challenge_bytes).unwrap();
            let proof = PresenceProof::from_canonical_bytes(bytes).unwrap();
            assert_eq!(proof.challenge(), &challenge);
        }
        "SyncRequest" => {
            assert_eq!(vector.dependencies, ["sync-cursor"]);
            let cursor_vector = vectors["sync-cursor"];
            let cursor_bytes = fs::read(directory.join(&cursor_vector.canonical_file)).unwrap();
            let cursor = SyncCursor::from_canonical_bytes(&cursor_bytes).unwrap();
            let request = SyncRequest::from_canonical_bytes(bytes).unwrap();
            assert_eq!(request.continuation(), Some(&cursor));
        }
        "SyncFrame" => {
            assert_eq!(vector.dependencies, ["authorized-event", "sync-cursor"]);
            let event_vector = vectors["authorized-event"];
            let event_bytes = fs::read(directory.join(&event_vector.canonical_file)).unwrap();
            let event = AuthorizedEvent::from_canonical_bytes(&event_bytes).unwrap();
            let cursor_vector = vectors["sync-cursor"];
            let cursor_bytes = fs::read(directory.join(&cursor_vector.canonical_file)).unwrap();
            let cursor = SyncCursor::from_canonical_bytes(&cursor_bytes).unwrap();
            let frame = SyncFrame::from_canonical_bytes(bytes).unwrap();
            assert_eq!(frame.events(), std::slice::from_ref(&event));
            assert_eq!(frame.continuation(), Some(&cursor));
        }
        "SyncResponse" => {
            let response = SyncResponse::from_canonical_bytes(bytes).unwrap();
            if let Some(frame) = response.as_frame() {
                assert_eq!(vector.dependencies, ["sync-frame"]);
                let frame_vector = vectors["sync-frame"];
                let frame_bytes = fs::read(directory.join(&frame_vector.canonical_file)).unwrap();
                let dependency_frame = SyncFrame::from_canonical_bytes(&frame_bytes).unwrap();
                assert_eq!(frame, &dependency_frame);
            } else {
                assert!(response.as_complete().is_some());
                assert!(vector.dependencies.is_empty());
            }
        }
        "AuthorizedSyncRequest" => {
            assert_eq!(
                vector.dependencies,
                ["endpoint-authorization-request", "sync-request"]
            );
            let endpoint_vector = vectors["endpoint-authorization-request"];
            let endpoint_bytes = fs::read(directory.join(&endpoint_vector.canonical_file)).unwrap();
            let endpoint =
                EndpointAuthorizationRequest::from_canonical_bytes(&endpoint_bytes).unwrap();
            let request_vector = vectors["sync-request"];
            let request_bytes = fs::read(directory.join(&request_vector.canonical_file)).unwrap();
            let request = SyncRequest::from_canonical_bytes(&request_bytes).unwrap();
            let authorized = AuthorizedSyncRequest::from_canonical_bytes(bytes).unwrap();
            assert_eq!(authorized.authorization(), endpoint);
            assert_eq!(authorized.request(), &request);
        }
        "AuthorizedProposalRequest" => {
            assert_eq!(
                vector.dependencies,
                [
                    "proposal-endpoint-authorization-request",
                    "device-authorization-proposal"
                ]
            );
            let endpoint_vector = vectors["proposal-endpoint-authorization-request"];
            let endpoint_bytes = fs::read(directory.join(&endpoint_vector.canonical_file)).unwrap();
            let endpoint =
                EndpointAuthorizationRequest::from_canonical_bytes(&endpoint_bytes).unwrap();
            let proposal_vector = vectors["device-authorization-proposal"];
            let proposal_bytes = fs::read(directory.join(&proposal_vector.canonical_file)).unwrap();
            let proposal =
                DeviceAuthorizationProposal::from_canonical_bytes(&proposal_bytes).unwrap();
            let authorized = AuthorizedProposalRequest::from_canonical_bytes(bytes).unwrap();
            assert_eq!(authorized.authorization(), endpoint);
            assert_eq!(authorized.proposal(), &proposal);
        }
        "AuthorizedCheckpointRequest" => {
            assert_eq!(
                vector.dependencies,
                ["endpoint-authorization-request", "checkpoint-direct"]
            );
            let endpoint_vector = vectors["endpoint-authorization-request"];
            let endpoint_bytes = fs::read(directory.join(&endpoint_vector.canonical_file)).unwrap();
            let endpoint =
                EndpointAuthorizationRequest::from_canonical_bytes(&endpoint_bytes).unwrap();
            let checkpoint_vector = vectors["checkpoint-direct"];
            let checkpoint_bytes =
                fs::read(directory.join(&checkpoint_vector.canonical_file)).unwrap();
            let checkpoint = SignedCheckpoint::from_canonical_bytes(&checkpoint_bytes).unwrap();
            let authorized = AuthorizedCheckpointRequest::from_canonical_bytes(bytes).unwrap();
            assert_eq!(authorized.authorization(), endpoint);
            assert_eq!(authorized.checkpoint(), &checkpoint);
        }
        "IdentityProtocolReply" => {
            let reply = IdentityProtocolReply::from_canonical_bytes(bytes).unwrap();
            if let Some(response) = reply.as_sync() {
                assert_eq!(vector.dependencies, ["sync-response-frame"]);
                let response_vector = vectors["sync-response-frame"];
                let response_bytes =
                    fs::read(directory.join(&response_vector.canonical_file)).unwrap();
                let dependency_response =
                    SyncResponse::from_canonical_bytes(&response_bytes).unwrap();
                assert_eq!(response, &dependency_response);
            } else if let Some(ack) = reply.as_ack() {
                assert_eq!(vector.dependencies, ["identity-protocol-ack"]);
                let ack_vector = vectors["identity-protocol-ack"];
                let ack_bytes = fs::read(directory.join(&ack_vector.canonical_file)).unwrap();
                let dependency_ack = IdentityProtocolAck::from_canonical_bytes(&ack_bytes).unwrap();
                assert_eq!(ack, &dependency_ack);
            } else {
                panic!("identity protocol reply must carry one exact dependency")
            }
        }
        "ProviderExportComponentDescriptor" => {
            assert_eq!(vector.dependencies, ["provider-export-component"]);
            let component_vector = vectors["provider-export-component"];
            let component_bytes =
                fs::read(directory.join(&component_vector.canonical_file)).unwrap();
            let component =
                ProviderExportComponent::from_canonical_bytes(&component_bytes).unwrap();
            let descriptor =
                ProviderExportComponentDescriptor::from_canonical_bytes(bytes).unwrap();
            assert_eq!(descriptor.component().unwrap(), component);
        }
        "ProviderGenerationExportManifest" => {
            assert_eq!(
                vector.dependencies,
                [
                    "provider-export-component-descriptor",
                    "signed-provider-head"
                ]
            );
            let descriptor_vector = vectors["provider-export-component-descriptor"];
            let descriptor_bytes =
                fs::read(directory.join(&descriptor_vector.canonical_file)).unwrap();
            let descriptor =
                ProviderExportComponentDescriptor::from_canonical_bytes(&descriptor_bytes).unwrap();
            let head_vector = vectors["signed-provider-head"];
            let head_bytes = fs::read(directory.join(&head_vector.canonical_file)).unwrap();
            let head = SignedProviderHead::from_canonical_bytes(&head_bytes).unwrap();
            let manifest = ProviderGenerationExportManifest::from_canonical_bytes(bytes).unwrap();
            assert_eq!(
                manifest
                    .descriptor(descriptor.component().unwrap())
                    .unwrap(),
                &descriptor
            );
            assert_eq!(manifest.latest_head(), Some(&head));
        }
        "ProviderAuditExportManifest" => {
            assert_eq!(vector.dependencies, ["signed-provider-head"]);
            let head_vector = vectors["signed-provider-head"];
            let head_bytes = fs::read(directory.join(&head_vector.canonical_file)).unwrap();
            let head = SignedProviderHead::from_canonical_bytes(&head_bytes).unwrap();
            let manifest = ProviderAuditExportManifest::from_canonical_bytes(bytes).unwrap();
            assert_eq!(manifest.latest_head(), Some(&head));
        }
        "ProviderGenerationExportChunk" => {
            assert_eq!(
                vector.dependencies,
                [
                    "account-genesis",
                    "authorized-event",
                    "checkpoint-direct",
                    "provider-generation-export-manifest"
                ]
            );
            let manifest_vector = vectors["provider-generation-export-manifest"];
            let manifest_bytes = fs::read(directory.join(&manifest_vector.canonical_file)).unwrap();
            let manifest =
                ProviderGenerationExportManifest::from_canonical_bytes(&manifest_bytes).unwrap();
            let chunk = ProviderGenerationExportChunk::from_canonical_bytes(bytes).unwrap();
            let component = chunk.component().unwrap();
            let descriptor = manifest.descriptor(component).unwrap();
            assert_eq!(chunk.provider_id(), manifest.provider().id().unwrap());
            assert_eq!(chunk.log_id(), manifest.log_id());
            assert_eq!(chunk.key_version(), manifest.key_version());
            assert_eq!(
                chunk.generation_commitment(),
                manifest.generation_commitment()
            );
            assert_eq!(descriptor.component().unwrap(), component);
            assert_eq!(descriptor.chunk_count(), 1);
            let chunk_commitment = chunk.commitment().unwrap();
            let chunk_list = provider_chunk_list_derivation(
                "provider_generation_chunk_list_commitment",
                "KRIKOS-ID/provider-generation-chunk-list/v1",
                component.code(),
                &[chunk_commitment],
            );
            assert_eq!(
                hex::encode(descriptor.chunk_list_commitment().as_bytes()),
                chunk_list.expected_output_hex,
                "generation descriptor must commit to the exact declared chunk"
            );
            assert_eq!(chunk.ordinal(), 0);
            assert_eq!(chunk.start_index(), 0);
            assert_eq!(chunk.end_index(), descriptor.item_count());
            assert_eq!(chunk.item_payload_bytes(), descriptor.total_payload_bytes());

            let genesis_vector = vectors["account-genesis"];
            let genesis_bytes = fs::read(directory.join(&genesis_vector.canonical_file)).unwrap();
            let genesis = AccountGenesis::from_canonical_bytes(&genesis_bytes).unwrap();
            let event_vector = vectors["authorized-event"];
            let event_bytes = fs::read(directory.join(&event_vector.canonical_file)).unwrap();
            let event = AuthorizedEvent::from_canonical_bytes(&event_bytes).unwrap();
            let checkpoint_vector = vectors["checkpoint-direct"];
            let checkpoint_bytes =
                fs::read(directory.join(&checkpoint_vector.canonical_file)).unwrap();
            let checkpoint = SignedCheckpoint::from_canonical_bytes(&checkpoint_bytes).unwrap();
            let mirror: GenerationChunkMirror = postcard::from_bytes(bytes).unwrap();
            let items = chunk_items(&mirror.payload);
            assert_eq!(items.len(), 1);
            let item: ProviderCheckpointBundleItemMirror = postcard::from_bytes(&items[0]).unwrap();
            assert_eq!(item.bundle.genesis.as_ref(), Some(&genesis));
            assert_eq!(item.bundle.events, [event]);
            assert_eq!(item.bundle.checkpoint, checkpoint);
            assert_eq!(item.bundle.transition_event, None);
        }
        "ProviderAuditExportChunk" => {
            assert_eq!(vector.dependencies, ["provider-audit-export-manifest"]);
            let manifest_vector = vectors["provider-audit-export-manifest"];
            let manifest_bytes = fs::read(directory.join(&manifest_vector.canonical_file)).unwrap();
            let manifest =
                ProviderAuditExportManifest::from_canonical_bytes(&manifest_bytes).unwrap();
            let chunk = ProviderAuditExportChunk::from_canonical_bytes(bytes).unwrap();
            assert_eq!(chunk.provider_id(), manifest.provider().id().unwrap());
            assert_eq!(chunk.log_id(), manifest.log_id());
            assert_eq!(chunk.audit_commitment(), manifest.audit_commitment());
            assert_eq!(manifest.chunk_count(), 1);
            let chunk_commitment = chunk.commitment().unwrap();
            let chunk_list = provider_chunk_list_derivation(
                "provider_audit_chunk_list_commitment",
                "KRIKOS-ID/provider-audit-chunk-list/v1",
                0,
                &[chunk_commitment],
            );
            assert_eq!(
                hex::encode(manifest.chunk_list_commitment().as_bytes()),
                chunk_list.expected_output_hex,
                "audit manifest must commit to the exact declared chunk"
            );
            assert_eq!(chunk.ordinal(), 0);
            assert_eq!(chunk.start_sequence(), 1);
            assert_eq!(
                chunk.end_sequence(),
                manifest.record_count().checked_add(1).unwrap()
            );
            assert_eq!(chunk.item_payload_bytes(), manifest.total_payload_bytes());
        }
        "ProviderRecoveryExportManifest" => {
            assert_eq!(
                vector.dependencies,
                [
                    "provider-generation-export-manifest",
                    "provider-audit-export-manifest"
                ]
            );
            let generation_vector = vectors["provider-generation-export-manifest"];
            let generation_bytes =
                fs::read(directory.join(&generation_vector.canonical_file)).unwrap();
            let generation =
                ProviderGenerationExportManifest::from_canonical_bytes(&generation_bytes).unwrap();
            let audit_vector = vectors["provider-audit-export-manifest"];
            let audit_bytes = fs::read(directory.join(&audit_vector.canonical_file)).unwrap();
            let audit = ProviderAuditExportManifest::from_canonical_bytes(&audit_bytes).unwrap();
            let recovery = ProviderRecoveryExportManifest::from_canonical_bytes(bytes).unwrap();
            assert_eq!(recovery.generation(), &generation);
            assert_eq!(recovery.audit(), &audit);
            assert_eq!(
                recovery.generation_manifest_commitment(),
                generation.commitment().unwrap()
            );
            assert_eq!(
                recovery.audit_manifest_commitment(),
                audit.commitment().unwrap()
            );
            assert_eq!(
                recovery.generation_commitment(),
                generation.generation_commitment()
            );
            assert_eq!(recovery.audit_commitment(), audit.audit_commitment());
            assert_eq!(recovery.artifact_commitment(), audit.artifact_commitment());
        }
        "ProviderCompactionManifest" => {
            assert_eq!(vector.dependencies, ["provider-recovery-export-manifest"]);
            let recovery_vector = vectors["provider-recovery-export-manifest"];
            let recovery_bytes = fs::read(directory.join(&recovery_vector.canonical_file)).unwrap();
            let recovery =
                ProviderRecoveryExportManifest::from_canonical_bytes(&recovery_bytes).unwrap();
            let compaction = ProviderCompactionManifest::from_canonical_bytes(bytes).unwrap();
            let generation = recovery.generation();
            assert_eq!(
                compaction.provider_id(),
                generation.provider().id().unwrap()
            );
            assert_eq!(compaction.log_id(), generation.log_id());
            assert_eq!(compaction.key_version(), generation.key_version());
            assert_eq!(compaction.source_tree_size(), generation.tree_size());
            assert_eq!(compaction.source_tree_root(), generation.tree_root());
            assert_eq!(
                compaction.archive_commitment(),
                recovery.recovery_commitment()
            );
            assert_eq!(
                compaction.generation_commitment(),
                recovery.generation_commitment()
            );
            assert_eq!(compaction.audit_commitment(), recovery.audit_commitment());
            assert_eq!(
                compaction.audit_artifact_commitment(),
                recovery.artifact_commitment()
            );
        }
        "OpaqueProviderAnchorCommitment" => {
            assert_eq!(vector.dependencies, ["provider-compaction-manifest"]);
            let manifest_vector = vectors["provider-compaction-manifest"];
            let manifest_bytes = fs::read(directory.join(&manifest_vector.canonical_file)).unwrap();
            let manifest =
                ProviderCompactionManifest::from_canonical_bytes(&manifest_bytes).unwrap();
            let anchor = OpaqueProviderAnchorCommitment::from_canonical_bytes(bytes).unwrap();
            assert_eq!(
                anchor,
                OpaqueProviderAnchorCommitment::from_compaction_manifest(&manifest).unwrap(),
                "opaque anchor must commit to the exact declared compaction manifest"
            );
        }
        _ => assert!(
            vector.dependencies.is_empty(),
            "{} has declared dependencies but no source-owned semantic validator",
            vector.name
        ),
    }
}

fn digest_from_display(value: &str) -> Digest {
    let hexadecimal = value
        .strip_prefix("b3:")
        .unwrap_or_else(|| panic!("unsupported digest display {value}"));
    let bytes: [u8; 32] = hex::decode(hexadecimal).unwrap().try_into().unwrap();
    Digest::new(HashAlgorithm::Blake3_256, bytes)
}

fn validate_tamper(vector: &VectorMetadata, bytes: &[u8], tamper: &TamperMetadata) {
    assert!(!tamper.name.is_empty(), "tamper case name must be nonempty");
    let replacement = hex::decode(&tamper.replacement_hex).unwrap();
    assert_eq!(replacement.len(), 1, "tamper replacement is one byte");
    let mut changed = bytes.to_vec();
    let target = changed
        .get_mut(tamper.offset)
        .unwrap_or_else(|| panic!("{} tamper offset is out of bounds", vector.name));
    assert_ne!(*target, replacement[0], "tamper must change a byte");
    *target = replacement[0];
    assert_ne!(
        blake3::hash(&changed),
        blake3::hash(bytes),
        "{} tamper did not change the canonical digest",
        vector.name
    );
    match tamper.expectation.as_str() {
        "canonical_digest_mismatch" => {}
        "signature_invalid_or_decode_rejected" => {
            let changed_signature = match vector.wire_type.as_str() {
                "SignedEventIntentApproval" => {
                    SignedEventIntentApproval::from_canonical_bytes(&changed)
                        .ok()
                        .map(|value| value.signatures()[0].signature().as_bytes().to_vec())
                }
                "SignedControllerApproval" => {
                    SignedControllerApproval::from_canonical_bytes(&changed)
                        .ok()
                        .map(|value| value.signatures()[0].signature().as_bytes().to_vec())
                }
                "SignedDelegation" => SignedDelegation::from_canonical_bytes(&changed)
                    .ok()
                    .map(|value| value.signature().as_bytes().to_vec()),
                "SignedApplicationEvent" => SignedApplicationEvent::from_canonical_bytes(&changed)
                    .ok()
                    .map(|value| value.signature().as_bytes().to_vec()),
                "SignedGuardianApproval" => SignedGuardianApproval::from_canonical_bytes(&changed)
                    .ok()
                    .map(|value| value.signature().as_bytes().to_vec()),
                "SignedSocialAttestation" => {
                    SignedSocialAttestation::from_canonical_bytes(&changed)
                        .ok()
                        .map(|value| value.issuer_signature().as_bytes().to_vec())
                }
                "SignedNameClaim" => SignedNameClaim::from_canonical_bytes(&changed)
                    .ok()
                    .map(|value| value.subject_signature().as_bytes().to_vec()),
                "SignedPortableCredential" => {
                    SignedPortableCredential::from_canonical_bytes(&changed)
                        .ok()
                        .map(|value| value.issuer_signature().as_bytes().to_vec())
                }
                "SignedProviderHead" => SignedProviderHead::from_canonical_bytes(&changed)
                    .ok()
                    .map(|value| value.signature().as_bytes().to_vec()),
                _ => None,
            };
            let changed_signature = changed_signature.unwrap_or_else(|| {
                let end = tamper.offset.checked_add(1).unwrap();
                let start = end.checked_sub(64).unwrap_or_else(|| {
                    panic!("{} signature tamper does not cover 64 bytes", vector.name)
                });
                changed[start..end].to_vec()
            });
            let binding = vector
                .signature_bindings
                .first()
                .expect("signature tamper requires a decoded-object signature binding");
            let message = hex::decode(&binding.message_hex).unwrap();
            let public_key: [u8; 32] = hex::decode(&binding.public_key_hex)
                .unwrap()
                .try_into()
                .unwrap();
            let changed_signature = Signature::try_from(changed_signature.as_slice()).unwrap();
            assert!(
                PublicKey::from_bytes(&public_key)
                    .unwrap()
                    .verify(&message, &changed_signature)
                    .is_err(),
                "{} tampered signature still verified over the exact declared message",
                vector.name
            );
        }
        "authentication_or_decode_rejected" => {
            if let Ok(envelope) = BackupEnvelope::from_canonical_bytes(&changed) {
                let passphrase =
                    BackupPassphrase::try_new(b"correct horse battery staple".to_vec()).unwrap();
                assert!(
                    envelope.restore(&passphrase).is_err(),
                    "{} tampered backup authenticated",
                    vector.name
                );
            }
        }
        "private_metadata_authentication_rejected" => {
            let envelope = PrivateMetadataEnvelope::from_canonical_bytes(&changed)
                .expect("ciphertext tamper must retain a decodable envelope");
            let key = PrivateMetadataKey::try_new([0x31; 32]).unwrap();
            assert!(
                envelope.open(&key).is_err(),
                "{} tampered private metadata authenticated",
                vector.name
            );
        }
        "cursor_authentication_rejected" => {
            let cursor = SyncCursor::from_canonical_bytes(&changed)
                .expect("cursor authenticator tamper must preserve canonical shape");
            assert!(
                cursor
                    .verify(&CursorKey::new(INTEROP_SYNC_CURSOR_KEY).unwrap())
                    .is_err(),
                "{} tampered cursor authenticator verified",
                vector.name
            );
        }
        "key_wrap_authentication_rejected" => {
            let wrapped = WrappedGroupKey::from_canonical_bytes(&changed)
                .expect("ciphertext tamper must retain a decodable group-key wrap");
            let recipient_secret = StaticSecret::from([0x20; 32]);
            let ephemeral_public =
                X25519PublicKey::from(*wrapped.header().ephemeral_public_key().as_bytes());
            let recipient_public = X25519PublicKey::from(&recipient_secret);
            let shared = recipient_secret.diffie_hellman(&ephemeral_public);
            let mut material = [0_u8; 96];
            material[..32].copy_from_slice(shared.as_bytes());
            material[32..64].copy_from_slice(ephemeral_public.as_bytes());
            material[64..].copy_from_slice(recipient_public.as_bytes());
            let key = blake3::derive_key("KRIKOS-ID/group-key-wrap-key/v1", &material);
            let associated_data =
                postcard::to_stdvec(&(wrapped.header(), wrapped.extensions())).unwrap();
            let cipher = XChaCha20Poly1305::new(&Key::from(key));
            assert!(
                cipher
                    .decrypt(
                        &XNonce::from(*wrapped.header().nonce().as_bytes()),
                        Payload {
                            msg: wrapped.ciphertext(),
                            aad: &associated_data,
                        },
                    )
                    .is_err(),
                "{} tampered key wrap authenticated",
                vector.name
            );
        }
        "merkle_proof_rejected" => match vector.wire_type.as_str() {
            "MerkleInclusionProof" => {
                assert_eq!(vector.dependencies, ["merkle-set-leaf"]);
                let leaf_bytes = fs::read(vector_directory().join("merkle-set-leaf.bin")).unwrap();
                let leaf = MerkleSetLeaf::from_canonical_bytes(&leaf_bytes).unwrap();
                let root = digest_from_display(&vector.expected_ids["merkle_root"]);
                let proof = MerkleInclusionProof::from_canonical_bytes(&changed)
                    .expect("Merkle path tamper must retain canonical shape");
                assert!(proof.verify(&leaf, root).is_err());
            }
            "MerkleConsistencyProof" => {
                let old_root = digest_from_display(&vector.expected_ids["old_merkle_root"]);
                let new_root = digest_from_display(&vector.expected_ids["new_merkle_root"]);
                let proof = MerkleConsistencyProof::from_canonical_bytes(&changed)
                    .expect("Merkle path tamper must retain canonical shape");
                assert!(proof.verify(old_root, new_root).is_err());
            }
            "MerkleNonMembershipProof" => {
                let root = digest_from_display(&vector.expected_ids["merkle_root"]);
                let key = MerkleSetKey::from_canonical_bytes(
                    &hex::decode(&vector.expected_ids["missing_key"]).unwrap(),
                )
                .unwrap();
                let proof = MerkleNonMembershipProof::from_canonical_bytes(&changed)
                    .expect("Merkle path tamper must retain canonical shape");
                assert!(proof.verify(key, root).is_err());
            }
            other => panic!("{} has invalid Merkle tamper type {other}", vector.name),
        },
        "identifier_or_binding_rejected" => match vector.wire_type.as_str() {
            "SignedCheckpoint" => {
                if let Ok(value) = SignedCheckpoint::from_canonical_bytes(&changed) {
                    assert_ne!(
                        value.checkpoint_id().unwrap().to_string(),
                        vector.expected_ids["checkpoint_id"]
                    );
                }
            }
            "PairingTicket" => {
                if let Ok(value) = PairingTicket::from_canonical_bytes(&changed) {
                    assert_ne!(
                        value.ticket_id().unwrap().as_digest().to_string(),
                        vector.expected_ids["pairing_ticket_id"]
                    );
                }
            }
            "PairingTranscript" => {
                if let Ok(value) = PairingTranscript::from_canonical_bytes(&changed) {
                    assert_ne!(
                        value.transcript_id().unwrap().as_digest().to_string(),
                        vector.expected_ids["pairing_transcript_id"]
                    );
                }
            }
            "PairingConfirmationContext" => assert!(
                PairingConfirmationContext::from_canonical_bytes(&changed).is_err(),
                "{} changed confirmation context retained its transcript/SAS binding",
                vector.name
            ),
            "DeviceAuthorizationProposal" => {
                if let Ok(value) = DeviceAuthorizationProposal::from_canonical_bytes(&changed) {
                    assert_ne!(
                        value.proposal_id().unwrap().as_digest().to_string(),
                        vector.expected_ids["device_authorization_proposal_id"]
                    );
                }
            }
            other => panic!("{} has invalid identifier tamper type {other}", vector.name),
        },
        other => panic!("{} has unknown tamper expectation {other}", vector.name),
    }
}

#[test]
fn authenticator_and_derivation_metadata_rejects_omission_and_reordering() {
    let manifest = checked_in_manifest();
    let directory = vector_directory();
    let vectors = manifest
        .vectors
        .iter()
        .map(|vector| (vector.name.as_str(), vector))
        .collect::<BTreeMap<_, _>>();

    let recovery = vectors["provider-recovery-export-manifest"];
    let recovery_bytes = fs::read(directory.join(&recovery.canonical_file)).unwrap();
    let expected_signatures = expected_signature_bindings(
        recovery,
        &recovery_bytes,
        &directory,
        &vectors,
        &manifest.deterministic_keys,
    );
    assert!(expected_signatures.len() >= 2);
    let mut omitted_signature = (*recovery).clone();
    omitted_signature.signature_bindings.pop();
    assert!(
        std::panic::catch_unwind(|| {
            validate_signature_bindings(
                &omitted_signature,
                &recovery_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact signature validator must reject an omitted nested signature"
    );
    let mut swapped_signatures = (*recovery).clone();
    swapped_signatures.signature_bindings.swap(0, 1);
    assert!(
        std::panic::catch_unwind(|| {
            validate_signature_bindings(
                &swapped_signatures,
                &recovery_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact signature validator must reject reordered nested signatures"
    );

    let migration = vectors["crypto-migration-begin"];
    let migration_bytes = fs::read(directory.join(&migration.canonical_file)).unwrap();
    let expected_migration_signatures = expected_signature_bindings(
        migration,
        &migration_bytes,
        &directory,
        &vectors,
        &manifest.deterministic_keys,
    );
    assert_eq!(expected_migration_signatures.len(), 2);
    let mut omitted_migration_signature = (*migration).clone();
    omitted_migration_signature.signature_bindings.pop();
    assert!(
        std::panic::catch_unwind(|| {
            validate_signature_bindings(
                &omitted_migration_signature,
                &migration_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact signature validator must reject an omitted migration cross-signature"
    );
    let mut swapped_migration_signatures = (*migration).clone();
    swapped_migration_signatures.signature_bindings.swap(0, 1);
    assert!(
        std::panic::catch_unwind(|| {
            validate_signature_bindings(
                &swapped_migration_signatures,
                &migration_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact signature validator must reject reordered old/new migration signatures"
    );

    let recovery_anchor = vectors["recovery-delay-anchor"];
    let recovery_anchor_bytes = fs::read(directory.join(&recovery_anchor.canonical_file)).unwrap();
    let expected_recovery_signatures = expected_signature_bindings(
        recovery_anchor,
        &recovery_anchor_bytes,
        &directory,
        &vectors,
        &manifest.deterministic_keys,
    );
    assert_eq!(expected_recovery_signatures.len(), 1);
    let mut omitted_recovery_signature = (*recovery_anchor).clone();
    omitted_recovery_signature.signature_bindings.clear();
    assert!(
        std::panic::catch_unwind(|| {
            validate_signature_bindings(
                &omitted_recovery_signature,
                &recovery_anchor_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact signature validator must reject an omitted recovery receipt signature"
    );
    let mut unrelated_recovery_signature = (*recovery_anchor).clone();
    unrelated_recovery_signature.signature_bindings[0] =
        vectors["provider-receipts"].signature_bindings[0].clone();
    assert!(
        std::panic::catch_unwind(|| {
            validate_signature_bindings(
                &unrelated_recovery_signature,
                &recovery_anchor_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact signature validator must reject a same-provider signature from an unrelated recovery receipt"
    );

    let controller_approval = vectors["final-event-controller-approval"];
    let event_intent_approval = vectors["event-intent-approval"];
    assert_eq!(controller_approval.signature_bindings.len(), 1);
    assert_eq!(event_intent_approval.signature_bindings.len(), 1);
    assert_eq!(
        controller_approval.signature_bindings[0].signer_key,
        event_intent_approval.signature_bindings[0].signer_key,
        "adversarial fixtures intentionally share one valid deterministic signer"
    );
    let controller_approval_bytes =
        fs::read(directory.join(&controller_approval.canonical_file)).unwrap();
    let mut unrelated_signature = (*controller_approval).clone();
    unrelated_signature.signature_bindings[0] = event_intent_approval.signature_bindings[0].clone();
    assert!(
        std::panic::catch_unwind(|| {
            validate_signature_bindings(
                &unrelated_signature,
                &controller_approval_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact signature validator must reject valid metadata from an unrelated signed vector"
    );

    let pairing = vectors["pairing-possession-proof"];
    let pairing_bytes = fs::read(directory.join(&pairing.canonical_file)).unwrap();
    let expected_macs = expected_mac_bindings(
        pairing,
        &pairing_bytes,
        &directory,
        &vectors,
        &manifest.deterministic_keys,
    );
    assert_eq!(expected_macs.len(), 2);
    let mut omitted_mac = (*pairing).clone();
    omitted_mac.mac_bindings.pop();
    assert!(
        std::panic::catch_unwind(|| {
            validate_mac_bindings(
                &omitted_mac,
                &pairing_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact MAC validator must reject an omitted authenticator"
    );
    let mut swapped_macs = (*pairing).clone();
    swapped_macs.mac_bindings.swap(0, 1);
    assert!(
        std::panic::catch_unwind(|| {
            validate_mac_bindings(
                &swapped_macs,
                &pairing_bytes,
                &directory,
                &vectors,
                &manifest.deterministic_keys,
            )
        })
        .is_err(),
        "the exact MAC validator must reject reordered authenticators"
    );

    let event = vectors["authorized-event"];
    let event_bytes = fs::read(directory.join(&event.canonical_file)).unwrap();
    let authorized_event = AuthorizedEvent::from_canonical_bytes(&event_bytes).unwrap();
    let approval = &authorized_event.approvals().as_slice()[0];
    let keyed_signature = &approval.signatures()[0];
    let exact_binding = resolved_signature_binding_for_key(
        "signature-1".to_owned(),
        "KRIKOS-ID/controller-approval-signature/v1",
        approval.body().to_canonical_bytes().unwrap(),
        keyed_signature.signature().as_bytes(),
        Some(ExactSigningKey::Controller(
            keyed_signature.controller_key_id(),
        )),
        &manifest.deterministic_keys,
    );
    assert_eq!(exact_binding, event.signature_bindings[0]);
    let wrong_controller_key_id = manifest
        .deterministic_keys
        .iter()
        .filter_map(metadata_signing_key)
        .filter_map(|public| ControllerKeyId::for_signing_key(&public).ok())
        .find(|key_id| *key_id != keyed_signature.controller_key_id())
        .unwrap();
    let wrong_key_resolution = std::panic::catch_unwind(|| {
        resolved_signature_binding_for_key(
            "signature-1".to_owned(),
            "KRIKOS-ID/controller-approval-signature/v1",
            approval.body().to_canonical_bytes().unwrap(),
            keyed_signature.signature().as_bytes(),
            Some(ExactSigningKey::Controller(wrong_controller_key_id)),
            &manifest.deterministic_keys,
        )
    });
    assert!(
        wrong_key_resolution.is_err(),
        "signature resolution must reject a valid signature paired with a different controller key ID"
    );

    let event_expected_derivations =
        expected_derivations(event, &event_bytes, &directory, &vectors);
    assert!(event_expected_derivations.len() >= 2);
    let mut omitted_derivation = (*event).clone();
    omitted_derivation.derivations.pop();
    assert!(
        std::panic::catch_unwind(|| {
            validate_derivations(&omitted_derivation, &event_bytes, &directory, &vectors)
        })
        .is_err(),
        "the exact derivation validator must reject an omitted nested derivation"
    );
    let mut swapped_derivations = (*event).clone();
    swapped_derivations.derivations.swap(0, 1);
    assert!(
        std::panic::catch_unwind(|| {
            validate_derivations(&swapped_derivations, &event_bytes, &directory, &vectors)
        })
        .is_err(),
        "the exact derivation validator must reject reordered nested derivations"
    );

    let migration_operation = vectors["account-operation-18"];
    let migration_operation_bytes =
        fs::read(directory.join(&migration_operation.canonical_file)).unwrap();
    assert_eq!(
        expected_derivations(
            migration_operation,
            &migration_operation_bytes,
            &directory,
            &vectors,
        )
        .len(),
        1
    );
    let mut omitted_operation_derivation = (*migration_operation).clone();
    omitted_operation_derivation.derivations.clear();
    assert!(
        std::panic::catch_unwind(|| {
            validate_derivations(
                &omitted_operation_derivation,
                &migration_operation_bytes,
                &directory,
                &vectors,
            )
        })
        .is_err(),
        "the exact derivation validator must reject an omitted AccountOperation nested derivation"
    );

    let mut substituted_dependency = (*event).clone();
    substituted_dependency.dependencies[0] = "application-event-body".to_owned();
    assert!(
        std::panic::catch_unwind(|| {
            validate_cross_vector_dependencies(
                &substituted_dependency,
                &event_bytes,
                &directory,
                &vectors,
            )
        })
        .is_err(),
        "the exact dependency validator must reject substitution with an unrelated valid vector"
    );
}

#[test]
fn checked_in_interop_catalog_is_complete_and_self_validating() {
    let directory = vector_directory();
    let manifest_path = directory.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).unwrap_or_else(|error| {
        panic!(
            "identity interop validation requires checked-in {}: {error}",
            manifest_path.display()
        )
    });
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(
        serde_json::to_vec_pretty(&manifest).unwrap(),
        manifest_bytes,
        "manifest.json must remain in deterministic generator order and formatting"
    );
    assert_eq!(manifest.format, "KRIKOS-ID interoperability vectors");
    assert_eq!(manifest.format_version, 2);
    assert_eq!(manifest.binding_schema_version, 1);
    assert_eq!(manifest.derivation_schema_version, 1);
    assert!(manifest.canonical_profile.contains("Postcard 1.1.3"));
    assert_eq!(manifest.algorithms.len(), 5);
    assert_closed_inventory(&manifest);
    assert!(!manifest.deterministic_keys.is_empty());
    let mut key_names = BTreeSet::new();
    let mut key_seeds = BTreeSet::new();
    let mut key_publics = BTreeSet::new();
    for key in &manifest.deterministic_keys {
        assert!(!key.name.is_empty());
        assert!(matches!(key.algorithm.as_str(), "Ed25519" | "X25519"));
        assert!(
            key_names.insert(key.name.as_str()),
            "duplicate test key name"
        );
        assert!(
            key_seeds.insert(key.test_only_secret_seed_hex.as_str()),
            "duplicate test-only secret seed"
        );
        assert!(
            key_publics.insert(key.public_key_hex.as_str()),
            "duplicate deterministic public key"
        );
        let seed: [u8; 32] = hex::decode(&key.test_only_secret_seed_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let expected_public = hex::decode(&key.public_key_hex).unwrap();
        match key.algorithm.as_str() {
            "Ed25519" => assert_eq!(
                SecretKey::from_bytes(&seed).public().as_bytes().as_slice(),
                expected_public.as_slice()
            ),
            "X25519" => assert_eq!(
                X25519PublicKey::from(&StaticSecret::from(seed))
                    .as_bytes()
                    .as_slice(),
                expected_public.as_slice()
            ),
            _ => unreachable!(),
        }
    }

    let exclusions = manifest
        .private_wire_exclusions
        .iter()
        .map(|exclusion| exclusion.wire_type.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        exclusions,
        BTreeSet::from(["GuardianGrant", "GuardianGrantOpening"])
    );
    for exclusion in &manifest.private_wire_exclusions {
        assert!(exclusion.reason.contains("private"));
        assert!(exclusion.covered_by.contains("SignedGuardianApproval"));
    }

    let mut names = BTreeSet::new();
    let mut files = BTreeSet::new();
    for vector in &manifest.vectors {
        assert!(names.insert(vector.name.as_str()), "duplicate vector name");
        assert!(
            files.insert(vector.canonical_file.as_str()),
            "duplicate canonical fixture file"
        );
    }
    assert!(
        manifest
            .vectors
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name),
        "manifest vectors must remain in strict deterministic name order"
    );
    let vectors = manifest
        .vectors
        .iter()
        .map(|vector| (vector.name.as_str(), vector))
        .collect::<BTreeMap<_, _>>();
    for vector in &manifest.vectors {
        let mut declared = BTreeSet::new();
        for dependency in &vector.dependencies {
            assert_ne!(dependency, &vector.name, "vector cannot depend on itself");
            assert!(
                declared.insert(dependency.as_str()),
                "{} repeats dependency {dependency}",
                vector.name
            );
            let dependency_vector = vectors.get(dependency.as_str()).unwrap_or_else(|| {
                panic!("{} names undeclared dependency {dependency}", vector.name)
            });
            let dependency_bytes =
                fs::read(directory.join(&dependency_vector.canonical_file)).unwrap();
            assert_eq!(
                blake3::hash(&dependency_bytes).to_hex().as_str(),
                dependency_vector.canonical_blake3_hex,
                "{} dependency {dependency} is stale",
                vector.name
            );
        }
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for name in &names {
        visit_dependency_graph(name, &vectors, &mut visiting, &mut visited);
    }

    for vector in &manifest.vectors {
        assert!(!vector.algorithms.is_empty());
        validate_version_metadata(vector);
        assert!(
            vector.protocol_version.is_none() || vector.protocol_version == Some(1),
            "{} has an unsupported protocol version",
            vector.name
        );
        assert_eq!(Path::new(&vector.canonical_file).components().count(), 1);
        let bytes = fs::read(directory.join(&vector.canonical_file)).unwrap();
        assert_eq!(bytes.len(), vector.encoded_length, "{} length", vector.name);
        assert_eq!(
            hex::encode(&bytes),
            vector.canonical_hex,
            "{} hex",
            vector.name
        );
        assert_eq!(
            blake3::hash(&bytes).to_hex().as_str(),
            vector.canonical_blake3_hex,
            "{} digest",
            vector.name
        );
        validate_wire_type(vector, &bytes);
        validate_cross_vector_dependencies(vector, &bytes, &directory, &vectors);
        validate_signature_bindings(
            vector,
            &bytes,
            &directory,
            &vectors,
            &manifest.deterministic_keys,
        );
        validate_mac_bindings(
            vector,
            &bytes,
            &directory,
            &vectors,
            &manifest.deterministic_keys,
        );
        for binding in &vector.signature_bindings {
            assert!(
                key_publics.contains(binding.public_key_hex.as_str()),
                "{} signature public key lacks a test-only deterministic key declaration",
                vector.name
            );
        }
        validate_derivations(vector, &bytes, &directory, &vectors);
        validate_expected_ids(vector, &bytes);
        assert!(!vector.tamper_cases.is_empty());
        let mut tamper_names = BTreeSet::new();
        let mut tamper_offsets = BTreeSet::new();
        for tamper in &vector.tamper_cases {
            assert!(
                tamper_names.insert(tamper.name.as_str()),
                "{} has duplicate tamper case name",
                vector.name
            );
            assert!(
                tamper_offsets.insert(tamper.offset),
                "{} has duplicate tamper offset",
                vector.name
            );
            validate_tamper(vector, &bytes, tamper);
        }
    }
    let checked_in_files = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".bin"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        checked_in_files,
        files.into_iter().map(str::to_owned).collect(),
        "every checked-in binary must appear exactly once in manifest.json"
    );
}
