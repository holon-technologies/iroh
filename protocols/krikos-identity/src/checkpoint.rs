//! Canonical checkpoint and transparency evidence schemas.

use std::fmt;

use krikos_base::{PublicKey, Signature};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeTuple};

use crate::{
    AccountId, AccountOperation, AuthorizedEvent, CanonicalWire, CheckpointId, ControlPolicyId,
    ControllerApprovals, CryptoStateId, Digest, Epoch, EventAuthorizationId, EventId, Extensions,
    IdentityError, ProposalId, ProtocolSignature, ProtocolVersion, ProviderDescriptor, ProviderId,
    ProviderKeyVersion, ProviderLogId, ProviderPolicyId, RecoveryPolicyId, Sequence, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_MERKLE_LOG_LEAVES, MAX_MERKLE_PROOF_HASHES, MAX_TRANSPARENCY_PROVIDERS},
    merkle::{
        MerkleConsistencyProof, MerkleInclusionProof, MerkleSet, MerkleSetKey, MerkleSetLeaf,
        empty_merkle_root,
    },
    schema::BoundedVec,
    types::{HashDomain, hash_bytes},
};

/// Frozen Merkle-set type tag for the cache-free account projection metadata leaf.
pub const CHECKPOINT_STATE_METADATA_TYPE_TAG: u16 = 1;
/// Frozen Merkle-set type tag for projected controller records in the complete state root.
pub const CHECKPOINT_STATE_CONTROLLER_TYPE_TAG: u16 = 2;
/// Frozen Merkle-set type tag for projected device records in the complete state root.
pub const CHECKPOINT_STATE_DEVICE_TYPE_TAG: u16 = 3;
/// Frozen Merkle-set type tag for active devices in the authorized-device root.
pub const CHECKPOINT_AUTHORIZED_DEVICE_TYPE_TAG: u16 = 4;
/// Frozen Merkle-set type tag for revoked devices in the tombstone root.
pub const CHECKPOINT_REVOKED_DEVICE_TYPE_TAG: u16 = 5;

const PROVIDER_HEAD_SIGNATURE_DOMAIN: &[u8] = b"KRIKOS-ID/provider-head-signature/v1";

macro_rules! canonical_schema {
    ($name:ty, $resource:literal) => {
        impl CanonicalCodec for $name {
            const RESOURCE: &'static str = $resource;

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(self)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                decode_wire(bytes)
            }
        }
    };
}

/// Subject committed by one transparency-provider log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLogSubject {
    /// A fully authorized account checkpoint.
    Checkpoint(CheckpointId),
    /// A threshold-approved proposal intent used to start a policy delay.
    EventIntent(ProposalId),
}

impl ProviderLogSubject {
    /// Stable v1 subject codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::Checkpoint(_) => 1,
            Self::EventIntent(_) => 2,
        }
    }
}

impl Serialize for ProviderLogSubject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.code())?;
        match self {
            Self::Checkpoint(id) => tuple.serialize_element(id)?,
            Self::EventIntent(id) => tuple.serialize_element(id)?,
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for ProviderLogSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ProviderLogSubject;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a v1 provider log subject")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => Ok(ProviderLogSubject::Checkpoint(
                        sequence
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    )),
                    2 => Ok(ProviderLogSubject::EventIntent(
                        sequence
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    )),
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "provider log subject",
                        code: unsupported,
                    })),
                }
            }
        }

        deserializer.deserialize_tuple(2, Visitor)
    }
}

/// Canonical body appended to a transparency provider's log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderLogEntryBody {
    protocol_version: ProtocolVersion,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    account_id: AccountId,
    subject: ProviderLogSubject,
    observed_at: Timestamp,
    extensions: Extensions,
}

impl ProviderLogEntryBody {
    /// Construct a v1 provider-log entry body.
    pub fn new(
        provider_id: ProviderId,
        log_id: ProviderLogId,
        account_id: AccountId,
        subject: ProviderLogSubject,
        observed_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            provider_id,
            log_id,
            account_id,
            subject,
            observed_at,
            extensions,
        })
    }

    /// Provider that observed this subject.
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Provider-wide log generation.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Account whose object was observed.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Logged checkpoint or proposal intent.
    pub const fn subject(&self) -> ProviderLogSubject {
        self.subject
    }

    /// Provider-signed observation time.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Derive the domain-separated leaf hash committed by the provider's append-only tree.
    pub fn merkle_leaf_hash(&self) -> Result<Digest, IdentityError> {
        Ok(hash_bytes(
            HashDomain::ProviderLogEntry,
            &self.to_canonical_bytes()?,
        ))
    }
}

impl<'de> Deserialize<'de> for ProviderLogEntryBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            provider_id: ProviderId,
            log_id: ProviderLogId,
            account_id: AccountId,
            subject: ProviderLogSubject,
            observed_at: Timestamp,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::new(
            wire.provider_id,
            wire.log_id,
            wire.account_id,
            wire.subject,
            wire.observed_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(ProviderLogEntryBody, "provider log entry bytes");

/// Canonical signed-tree-head body for one provider-wide log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderHeadBody {
    protocol_version: ProtocolVersion,
    provider_id: ProviderId,
    log_id: ProviderLogId,
    key_version: ProviderKeyVersion,
    tree_size: u64,
    tree_root: Digest,
    observed_at: Timestamp,
    extensions: Extensions,
}

impl ProviderHeadBody {
    /// Construct a signed-tree-head body. Tree size zero represents an empty log.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: ProviderId,
        log_id: ProviderLogId,
        key_version: ProviderKeyVersion,
        tree_size: u64,
        tree_root: Digest,
        observed_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let maximum_tree_size = u64::try_from(MAX_MERKLE_LOG_LEAVES).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "provider Merkle log maximum tree size",
            }
        })?;
        if tree_size > maximum_tree_size {
            return Err(IdentityError::limit(
                "provider Merkle log tree size",
                usize::try_from(tree_size).unwrap_or(usize::MAX),
                MAX_MERKLE_LOG_LEAVES,
            ));
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            provider_id,
            log_id,
            key_version,
            tree_size,
            tree_root,
            observed_at,
            extensions,
        })
    }

    /// Provider signing this head.
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Provider-wide log generation.
    pub const fn log_id(&self) -> ProviderLogId {
        self.log_id
    }

    /// Signing-key generation.
    pub const fn key_version(&self) -> ProviderKeyVersion {
        self.key_version
    }

    /// Number of leaves committed by this head.
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Root of the exact provider-wide append-only tree size.
    pub const fn tree_root(&self) -> Digest {
        self.tree_root
    }

    /// Provider-observed head time.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Literal domain-separated bytes signed by the configured provider key.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let body = self.to_canonical_bytes()?;
        let capacity = PROVIDER_HEAD_SIGNATURE_DOMAIN
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(body.len()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "provider head signing message length",
            })?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(PROVIDER_HEAD_SIGNATURE_DOMAIN);
        message.push(0);
        message.extend_from_slice(&body);
        Ok(message)
    }
}

impl<'de> Deserialize<'de> for ProviderHeadBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            provider_id: ProviderId,
            log_id: ProviderLogId,
            key_version: ProviderKeyVersion,
            tree_size: u64,
            tree_root: Digest,
            observed_at: Timestamp,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::new(
            wire.provider_id,
            wire.log_id,
            wire.key_version,
            wire.tree_size,
            wire.tree_root,
            wire.observed_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(ProviderHeadBody, "provider head bytes");

/// Provider head paired with its provider signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedProviderHead {
    body: ProviderHeadBody,
    signature: ProtocolSignature,
}

impl SignedProviderHead {
    /// Attach a provider signature to a head body.
    pub const fn new(body: ProviderHeadBody, signature: ProtocolSignature) -> Self {
        Self { body, signature }
    }

    /// Signed head body.
    pub const fn body(&self) -> &ProviderHeadBody {
        &self.body
    }

    /// Provider signature bytes.
    pub const fn signature(&self) -> ProtocolSignature {
        self.signature
    }

    /// Verify this head under the exact configured v1 provider descriptor.
    pub fn verify(&self, provider: &ProviderDescriptor) -> Result<(), IdentityError> {
        if provider.id()? != self.body.provider_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider head configured descriptor",
            });
        }
        if self.body.key_version != ProviderKeyVersion::GENESIS {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider head signing key version",
            });
        }
        if self.body.tree_size == 0 && self.body.tree_root != empty_merkle_root() {
            return Err(IdentityError::InvalidProof);
        }
        let public_key = PublicKey::from_bytes(provider.signing_key().as_bytes())
            .map_err(|_| IdentityError::InvalidSignature)?;
        let signature = Signature::try_from(self.signature.as_bytes().as_slice())
            .map_err(|_| IdentityError::InvalidSignature)?;
        public_key
            .verify(&self.body.signing_bytes()?, &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

canonical_schema!(SignedProviderHead, "signed provider head bytes");

/// Two authenticated same-size heads proving that one provider equivocated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderEquivocationEvidence {
    first: SignedProviderHead,
    second: SignedProviderHead,
}

impl ProviderEquivocationEvidence {
    /// Validate and retain a pair of conflicting signed heads from one configured provider.
    pub fn new(
        provider: &ProviderDescriptor,
        first: SignedProviderHead,
        second: SignedProviderHead,
    ) -> Result<Self, IdentityError> {
        first.verify(provider)?;
        second.verify(provider)?;
        Self::from_heads(first, second)
    }

    fn from_heads(
        first: SignedProviderHead,
        second: SignedProviderHead,
    ) -> Result<Self, IdentityError> {
        if first.body.provider_id != second.body.provider_id
            || first.body.log_id != second.body.log_id
            || first.body.tree_size != second.body.tree_size
            || first.body.tree_root == second.body.tree_root
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider equivocation head pair",
            });
        }
        Ok(Self { first, second })
    }

    /// First conflicting signed head.
    pub const fn first(&self) -> &SignedProviderHead {
        &self.first
    }

    /// Second conflicting signed head.
    pub const fn second(&self) -> &SignedProviderHead {
        &self.second
    }

    /// Reverify both signatures and the same-size/different-root relationship.
    pub fn verify(&self, provider: &ProviderDescriptor) -> Result<(), IdentityError> {
        self.first.verify(provider)?;
        self.second.verify(provider)?;
        Self::from_heads(self.first.clone(), self.second.clone()).map(|_| ())
    }
}

impl<'de> Deserialize<'de> for ProviderEquivocationEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (first, second) =
            <(SignedProviderHead, SignedProviderHead)>::deserialize(deserializer)?;
        Self::from_heads(first, second).map_err(de::Error::custom)
    }
}

canonical_schema!(
    ProviderEquivocationEvidence,
    "provider equivocation evidence bytes"
);

/// Verify monotonic append-only progression between two authenticated provider heads.
pub fn verify_provider_head_progression(
    provider: &ProviderDescriptor,
    older: &SignedProviderHead,
    newer: &SignedProviderHead,
    consistency_proof: &MerkleConsistencyProof,
) -> Result<(), IdentityError> {
    older.verify(provider)?;
    newer.verify(provider)?;
    if older.body.provider_id != newer.body.provider_id || older.body.log_id != newer.body.log_id {
        return Err(IdentityError::InvalidRelationship {
            resource: "provider head progression log",
        });
    }
    if newer.body.tree_size < older.body.tree_size
        || newer.body.observed_at < older.body.observed_at
    {
        return Err(IdentityError::ProviderRollback);
    }
    if newer.body.tree_size == older.body.tree_size && newer.body.tree_root != older.body.tree_root
    {
        return Err(IdentityError::ProviderEquivocation);
    }
    if consistency_proof.old_size() != older.body.tree_size
        || consistency_proof.new_size() != newer.body.tree_size
    {
        return Err(IdentityError::InvalidProof);
    }
    consistency_proof.verify(older.body.tree_root, newer.body.tree_root)
}

/// Bounded inclusion evidence for one provider log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InclusionReceipt {
    entry: ProviderLogEntryBody,
    leaf_index: u64,
    audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
    signed_head: SignedProviderHead,
}

impl InclusionReceipt {
    /// Construct structurally consistent bounded inclusion evidence.
    pub fn new(
        entry: ProviderLogEntryBody,
        leaf_index: u64,
        audit_path: Vec<Digest>,
        signed_head: SignedProviderHead,
    ) -> Result<Self, IdentityError> {
        if entry.provider_id() != signed_head.body().provider_id()
            || entry.log_id() != signed_head.body().log_id()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider receipt entry/head",
            });
        }
        if leaf_index >= signed_head.body().tree_size() {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider receipt leaf index/tree size",
            });
        }
        Ok(Self {
            entry,
            leaf_index,
            audit_path: BoundedVec::new("Merkle audit path", audit_path)?,
            signed_head,
        })
    }

    /// Provider that issued this receipt.
    pub const fn provider_id(&self) -> ProviderId {
        self.entry.provider_id()
    }

    /// Zero-based provider-log leaf index.
    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Logged entry.
    pub const fn entry(&self) -> &ProviderLogEntryBody {
        &self.entry
    }

    /// Signed provider head that commits the entry and supplies the historical observation time.
    pub const fn signed_head(&self) -> &SignedProviderHead {
        &self.signed_head
    }

    /// Bottom-up Merkle audit path.
    pub fn audit_path(&self) -> &[Digest] {
        self.audit_path.as_slice()
    }

    /// Verify provider identity/signature, observation ordering, and exact Merkle inclusion.
    pub fn verify(&self, provider: &ProviderDescriptor) -> Result<(), IdentityError> {
        self.signed_head.verify(provider)?;
        if self.entry.provider_id != self.signed_head.body.provider_id
            || self.entry.log_id != self.signed_head.body.log_id
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider receipt entry/head",
            });
        }
        if self.signed_head.body.observed_at < self.entry.observed_at {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider head observation time",
            });
        }
        MerkleInclusionProof::new(
            self.leaf_index,
            self.signed_head.body.tree_size,
            self.audit_path.as_slice().to_vec(),
        )?
        .verify_leaf_hash(
            self.entry.merkle_leaf_hash()?,
            self.signed_head.body.tree_root,
        )
    }
}

impl<'de> Deserialize<'de> for InclusionReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            entry: ProviderLogEntryBody,
            leaf_index: u64,
            audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
            signed_head: SignedProviderHead,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.entry,
            wire.leaf_index,
            wire.audit_path.into_vec(),
            wire.signed_head,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(InclusionReceipt, "provider inclusion receipt bytes");

/// Sorted, duplicate-free receipts for one account subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProviderReceipts(BoundedVec<InclusionReceipt, MAX_TRANSPARENCY_PROVIDERS>);

impl ProviderReceipts {
    /// Sort and construct receipts from distinct providers for one subject.
    pub fn new(mut receipts: Vec<InclusionReceipt>) -> Result<Self, IdentityError> {
        receipts.sort_unstable_by_key(InclusionReceipt::provider_id);
        Self::from_sorted(receipts)
    }

    /// Canonically ordered receipts.
    pub fn as_slice(&self) -> &[InclusionReceipt] {
        self.0.as_slice()
    }

    fn from_sorted(receipts: Vec<InclusionReceipt>) -> Result<Self, IdentityError> {
        let receipts = BoundedVec::new("provider receipts", receipts)?;
        for pair in receipts.as_slice().windows(2) {
            if pair[0].provider_id() == pair[1].provider_id() {
                return Err(IdentityError::DuplicateElement {
                    resource: "provider receipts",
                });
            }
            if pair[0].provider_id() > pair[1].provider_id() {
                return Err(IdentityError::NonCanonical);
            }
        }
        if let Some(first) = receipts.as_slice().first() {
            for receipt in &receipts.as_slice()[1..] {
                if receipt.entry().account_id() != first.entry().account_id()
                    || receipt.entry().subject() != first.entry().subject()
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "provider receipt subject set",
                    });
                }
            }
        }
        Ok(Self(receipts))
    }
}

impl<'de> Deserialize<'de> for ProviderReceipts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let receipts =
            BoundedVec::<InclusionReceipt, MAX_TRANSPARENCY_PROVIDERS>::deserialize(deserializer)?;
        Self::from_sorted(receipts.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(ProviderReceipts, "provider receipt set bytes");

/// Account lifecycle committed by a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountLifecycle {
    /// Ordinary active authority.
    Active,
    /// One authoritative recovery is pending.
    RecoveryPending,
    /// A new controller-signature suite is staged.
    MigrationPending,
    /// Old and new controller suites are both required.
    MigrationDual,
    /// A protocol-major upgrade was authorized; v1 is read-only.
    UpgradePending,
    /// Terminally retired account.
    Retired,
}

impl AccountLifecycle {
    /// Stable v1 lifecycle codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::Active => 1,
            Self::RecoveryPending => 2,
            Self::MigrationPending => 3,
            Self::MigrationDual => 4,
            Self::UpgradePending => 5,
            Self::Retired => 6,
        }
    }
}

impl<'de> Deserialize<'de> for AccountLifecycle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u16::deserialize(deserializer)? {
            1 => Ok(Self::Active),
            2 => Ok(Self::RecoveryPending),
            3 => Ok(Self::MigrationPending),
            4 => Ok(Self::MigrationDual),
            5 => Ok(Self::UpgradePending),
            6 => Ok(Self::Retired),
            code => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "account lifecycle",
                code,
            })),
        }
    }
}

impl Serialize for AccountLifecycle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

/// Canonical account-state checkpoint body. Authorization is an outer envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointBody {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    account_epoch: Epoch,
    sequence: Sequence,
    event_head: EventId,
    state_root: Digest,
    authorized_set_root: Digest,
    revoked_set_root: Digest,
    control_policy_id: ControlPolicyId,
    recovery_policy_id: RecoveryPolicyId,
    provider_policy_id: ProviderPolicyId,
    crypto_state_id: CryptoStateId,
    lifecycle: AccountLifecycle,
    issued_at: Timestamp,
    extensions: Extensions,
}

impl CheckpointBody {
    /// Construct a canonical single-head checkpoint body.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        account_epoch: Epoch,
        sequence: Sequence,
        event_head: EventId,
        state_root: Digest,
        authorized_set_root: Digest,
        revoked_set_root: Digest,
        control_policy_id: ControlPolicyId,
        recovery_policy_id: RecoveryPolicyId,
        provider_policy_id: ProviderPolicyId,
        crypto_state_id: CryptoStateId,
        lifecycle: AccountLifecycle,
        issued_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            account_epoch,
            sequence,
            event_head,
            state_root,
            authorized_set_root,
            revoked_set_root,
            control_policy_id,
            recovery_policy_id,
            provider_policy_id,
            crypto_state_id,
            lifecycle,
            issued_at,
            extensions,
        })
    }

    /// Derive the stable body-only checkpoint identifier.
    pub fn checkpoint_id(&self) -> Result<CheckpointId, IdentityError> {
        CheckpointId::derive(self)
    }

    /// Account committed by this checkpoint.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Security epoch committed by this checkpoint.
    pub const fn account_epoch(&self) -> Epoch {
        self.account_epoch
    }

    /// Account-event sequence committed by this checkpoint.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Authoritative event head committed by this checkpoint.
    pub const fn event_head(&self) -> EventId {
        self.event_head
    }

    /// Complete deterministic projected-state root.
    pub const fn state_root(&self) -> Digest {
        self.state_root
    }

    /// Active authorized-device set root.
    pub const fn authorized_set_root(&self) -> Digest {
        self.authorized_set_root
    }

    /// Permanent revoked-device tombstone set root.
    pub const fn revoked_set_root(&self) -> Digest {
        self.revoked_set_root
    }

    /// Control policy active at this checkpoint.
    pub const fn control_policy_id(&self) -> ControlPolicyId {
        self.control_policy_id
    }

    /// Recovery policy active at this checkpoint.
    pub const fn recovery_policy_id(&self) -> RecoveryPolicyId {
        self.recovery_policy_id
    }

    /// Provider policy active at this checkpoint.
    pub const fn provider_policy_id(&self) -> ProviderPolicyId {
        self.provider_policy_id
    }

    /// Projected controller-signature migration state.
    pub const fn crypto_state_id(&self) -> CryptoStateId {
        self.crypto_state_id
    }

    /// Projected account lifecycle committed by this checkpoint.
    pub const fn lifecycle(&self) -> AccountLifecycle {
        self.lifecycle
    }

    /// Account-supplied issuance metadata, never an authority time source.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }
}

impl<'de> Deserialize<'de> for CheckpointBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            account_epoch: Epoch,
            sequence: Sequence,
            event_head: EventId,
            state_root: Digest,
            authorized_set_root: Digest,
            revoked_set_root: Digest,
            control_policy_id: ControlPolicyId,
            recovery_policy_id: RecoveryPolicyId,
            provider_policy_id: ProviderPolicyId,
            crypto_state_id: CryptoStateId,
            lifecycle: AccountLifecycle,
            issued_at: Timestamp,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        Self::new(
            wire.account_id,
            wire.account_epoch,
            wire.sequence,
            wire.event_head,
            wire.state_root,
            wire.authorized_set_root,
            wire.revoked_set_root,
            wire.control_policy_id,
            wire.recovery_policy_id,
            wire.provider_policy_id,
            wire.crypto_state_id,
            wire.lifecycle,
            wire.issued_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(CheckpointBody, "account checkpoint body bytes");

/// Authority-destructive transition eligible to authorize its immediate checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CheckpointTransitionKind {
    /// Successful recovery finalization installed replacement authority.
    FinalizeRecovery,
    /// Terminal account retirement removed all ordinary authority.
    RetireAccount,
}

impl CheckpointTransitionKind {
    /// Stable v1 transition-witness codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::FinalizeRecovery => 1,
            Self::RetireAccount => 2,
        }
    }
}

impl Serialize for CheckpointTransitionKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CheckpointTransitionKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u16::deserialize(deserializer)? {
            1 => Ok(Self::FinalizeRecovery),
            2 => Ok(Self::RetireAccount),
            code => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "checkpoint transition kind",
                code,
            })),
        }
    }
}

canonical_schema!(CheckpointTransitionKind, "checkpoint transition kind bytes");

/// Typed reference to the complete proof for an authority-destructive account event.
///
/// The corresponding [`AuthorizedEvent`] remains in the offline proof bundle. Verification
/// resolves both identifiers, confirms the operation kind, and recomputes the checkpoint body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionCheckpointWitness {
    protocol_version: ProtocolVersion,
    transition_kind: CheckpointTransitionKind,
    event_id: EventId,
    event_authorization_id: EventAuthorizationId,
}

impl TransitionCheckpointWitness {
    fn from_authorized_event(event: &AuthorizedEvent) -> Result<Self, IdentityError> {
        let transition_kind = match event.body().operation() {
            AccountOperation::FinalizeRecovery(_) => CheckpointTransitionKind::FinalizeRecovery,
            AccountOperation::RetireAccount(_) => CheckpointTransitionKind::RetireAccount,
            _ => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "checkpoint transition witness operation",
                });
            }
        };
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            transition_kind,
            event_id: event.event_id()?,
            event_authorization_id: event.event_authorization_id()?,
        })
    }

    /// Eligible transition class represented by this witness.
    pub const fn transition_kind(&self) -> CheckpointTransitionKind {
        self.transition_kind
    }

    /// Body-only identifier of the authority-destructive event.
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// Domain-separated identifier of the exact retained authorization envelope.
    pub const fn event_authorization_id(&self) -> EventAuthorizationId {
        self.event_authorization_id
    }
}

canonical_schema!(
    TransitionCheckpointWitness,
    "transition checkpoint witness bytes"
);

#[derive(Debug, Clone, PartialEq, Eq)]
enum CheckpointAuthorizationKind {
    Controllers(ControllerApprovals),
    TransitionDerived(TransitionCheckpointWitness),
}

/// Authorization for a checkpoint body, excluded from [`CheckpointId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointAuthorization(CheckpointAuthorizationKind);

impl CheckpointAuthorization {
    /// Construct direct mergeable controller approvals for one checkpoint ID.
    pub fn controllers(
        checkpoint_id: CheckpointId,
        approvals: ControllerApprovals,
    ) -> Result<Self, IdentityError> {
        if approvals
            .as_slice()
            .iter()
            .any(|approval| approval.body().checkpoint_id() != Some(checkpoint_id))
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "checkpoint controller approval subject",
            });
        }
        Ok(Self(CheckpointAuthorizationKind::Controllers(approvals)))
    }

    /// Reference an eligible fully authorized event that deterministically yields the body.
    pub fn transition_derived(event: &AuthorizedEvent) -> Result<Self, IdentityError> {
        Ok(Self(CheckpointAuthorizationKind::TransitionDerived(
            TransitionCheckpointWitness::from_authorized_event(event)?,
        )))
    }

    /// Transition witness when this is transition-derived authorization.
    pub const fn transition_witness(&self) -> Option<&TransitionCheckpointWitness> {
        match &self.0 {
            CheckpointAuthorizationKind::Controllers(_) => None,
            CheckpointAuthorizationKind::TransitionDerived(witness) => Some(witness),
        }
    }

    /// Mergeable controller approvals when this is direct authorization.
    pub const fn controller_approvals(&self) -> Option<&ControllerApprovals> {
        match &self.0 {
            CheckpointAuthorizationKind::Controllers(approvals) => Some(approvals),
            CheckpointAuthorizationKind::TransitionDerived(_) => None,
        }
    }
}

impl Serialize for CheckpointAuthorization {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            CheckpointAuthorizationKind::Controllers(approvals) => {
                (1u16, approvals).serialize(serializer)
            }
            CheckpointAuthorizationKind::TransitionDerived(witness) => {
                (2u16, witness).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for CheckpointAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = CheckpointAuthorization;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("v1 checkpoint authorization")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => Ok(CheckpointAuthorization(
                        CheckpointAuthorizationKind::Controllers(
                            sequence
                                .next_element()?
                                .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                        ),
                    )),
                    2 => Ok(CheckpointAuthorization(
                        CheckpointAuthorizationKind::TransitionDerived(
                            sequence
                                .next_element()?
                                .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                        ),
                    )),
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "checkpoint authorization",
                        code: unsupported,
                    })),
                }
            }
        }
        deserializer.deserialize_tuple(2, Visitor)
    }
}

canonical_schema!(CheckpointAuthorization, "checkpoint authorization bytes");

/// Checkpoint body paired with mergeable or transition-derived authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedCheckpoint {
    body: CheckpointBody,
    authorization: CheckpointAuthorization,
}

impl SignedCheckpoint {
    /// Construct an authorized checkpoint without changing its body-derived ID.
    pub fn new(
        body: CheckpointBody,
        authorization: CheckpointAuthorization,
    ) -> Result<Self, IdentityError> {
        match &authorization.0 {
            CheckpointAuthorizationKind::Controllers(approvals) => {
                let checkpoint_id = body.checkpoint_id()?;
                if approvals
                    .as_slice()
                    .iter()
                    .any(|approval| approval.body().checkpoint_id() != Some(checkpoint_id))
                {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "signed checkpoint approval subject",
                    });
                }
            }
            CheckpointAuthorizationKind::TransitionDerived(witness) => {
                let lifecycle_matches = match witness.transition_kind() {
                    CheckpointTransitionKind::FinalizeRecovery => {
                        body.lifecycle() == AccountLifecycle::Active
                    }
                    CheckpointTransitionKind::RetireAccount => {
                        body.lifecycle() == AccountLifecycle::Retired
                    }
                };
                if witness.event_id() != body.event_head() || !lifecycle_matches {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "signed checkpoint transition witness",
                    });
                }
            }
        }
        Ok(Self {
            body,
            authorization,
        })
    }

    /// Canonical checkpoint body.
    pub const fn body(&self) -> &CheckpointBody {
        &self.body
    }

    /// Stable body-only checkpoint identifier.
    pub fn checkpoint_id(&self) -> Result<CheckpointId, IdentityError> {
        self.body.checkpoint_id()
    }

    /// Direct or transition-derived authorization excluded from [`CheckpointId`].
    pub const fn authorization(&self) -> &CheckpointAuthorization {
        &self.authorization
    }

    /// Merge two authorization envelopes for the same checkpoint body.
    ///
    /// Direct controller approvals are a bounded canonical union. Transition-derived
    /// authorization is deterministic and must match exactly. Authorization modes and bodies
    /// never mix.
    pub fn merge(&self, other: &Self) -> Result<Self, IdentityError> {
        if self.body != other.body {
            return Err(IdentityError::InvalidRelationship {
                resource: "checkpoint authorization body",
            });
        }
        let authorization = match (&self.authorization.0, &other.authorization.0) {
            (
                CheckpointAuthorizationKind::Controllers(left),
                CheckpointAuthorizationKind::Controllers(right),
            ) => CheckpointAuthorization::controllers(self.checkpoint_id()?, left.merge(right)?)?,
            (
                CheckpointAuthorizationKind::TransitionDerived(left),
                CheckpointAuthorizationKind::TransitionDerived(right),
            ) if left == right => {
                CheckpointAuthorization(CheckpointAuthorizationKind::TransitionDerived(*left))
            }
            (
                CheckpointAuthorizationKind::Controllers(_),
                CheckpointAuthorizationKind::TransitionDerived(_),
            )
            | (
                CheckpointAuthorizationKind::TransitionDerived(_),
                CheckpointAuthorizationKind::Controllers(_),
            ) => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "checkpoint authorization mode",
                });
            }
            (
                CheckpointAuthorizationKind::TransitionDerived(_),
                CheckpointAuthorizationKind::TransitionDerived(_),
            ) => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "checkpoint transition witness",
                });
            }
        };
        Self::new(self.body.clone(), authorization)
    }
}

impl<'de> Deserialize<'de> for SignedCheckpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            body: CheckpointBody,
            authorization: CheckpointAuthorization,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.body, wire.authorization).map_err(de::Error::custom)
    }
}

canonical_schema!(SignedCheckpoint, "signed checkpoint bytes");

/// Result of bounded checkpoint bootstrap from genesis or a prior verified anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCheckpointBootstrap {
    state: crate::AccountState,
    checkpoint: VerifiedCheckpoint,
    freshness: crate::FreshnessDecision,
}

impl TrustedCheckpointBootstrap {
    /// Fully projected account state named by the trusted checkpoint.
    pub const fn state(&self) -> &crate::AccountState {
        &self.state
    }

    /// Checkpoint verified against the complete bounded proof chain.
    pub const fn checkpoint(&self) -> &VerifiedCheckpoint {
        &self.checkpoint
    }

    /// Exact checkpoint/epoch/provider-time basis of bootstrap acceptance.
    pub const fn freshness(&self) -> crate::FreshnessDecision {
        self.freshness
    }
}

/// Checkpoint whose complete body and authorization were verified against projected state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    checkpoint: SignedCheckpoint,
    checkpoint_id: CheckpointId,
    transition_event: Option<AuthorizedEvent>,
}

impl VerifiedCheckpoint {
    /// Fully verified signed checkpoint.
    pub const fn checkpoint(&self) -> &SignedCheckpoint {
        &self.checkpoint
    }

    /// Stable body-only checkpoint identifier.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Complete retained destructive transition, when transition-derived authorization was used.
    pub const fn transition_event(&self) -> Option<&AuthorizedEvent> {
        self.transition_event.as_ref()
    }
}

/// Trust anchor carried by one bounded provider-served checkpoint lineage link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCheckpointLineage {
    /// Self-contained lineage beginning at the stable account genesis.
    Genesis(Box<crate::AccountGenesis>),
    /// Bounded continuation from a prior checkpoint retained by the same provider.
    Prior(CheckpointId),
}

/// Bounded verified checkpoint plus the authority material a provider must retain and serve.
///
/// A provider log leaf commits only the checkpoint ID, so retaining this bundle is what lets a
/// previously unprovisioned verifier retrieve the signed checkpoint and replay its authenticated
/// lineage instead of learning only an opaque digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCheckpointBundle {
    lineage: ProviderCheckpointLineage,
    events: Vec<AuthorizedEvent>,
    verified_checkpoint: VerifiedCheckpoint,
}

impl ProviderCheckpointBundle {
    /// Genesis anchor when this link is independently replayable from account creation.
    pub fn genesis(&self) -> Option<&crate::AccountGenesis> {
        match &self.lineage {
            ProviderCheckpointLineage::Genesis(genesis) => Some(genesis.as_ref()),
            ProviderCheckpointLineage::Prior(_) => None,
        }
    }

    /// Prior checkpoint required before replaying this continuation link.
    pub const fn prior_checkpoint_id(&self) -> Option<CheckpointId> {
        match self.lineage {
            ProviderCheckpointLineage::Genesis(_) => None,
            ProviderCheckpointLineage::Prior(checkpoint_id) => Some(checkpoint_id),
        }
    }

    /// Exact bounded advancing event chain in semantic order.
    pub fn events(&self) -> &[AuthorizedEvent] {
        &self.events
    }

    /// Checkpoint verified against the state produced by this lineage link.
    pub const fn verified_checkpoint(&self) -> &VerifiedCheckpoint {
        &self.verified_checkpoint
    }

    /// Create the only public checkpoint-shaped provider admission capability.
    pub fn provider_log_admission(&self) -> crate::ProviderLogAdmission {
        crate::ProviderLogAdmission::checkpoint(self.clone())
    }

    /// Merge independently verified authorization evidence for the same retained lineage link.
    ///
    /// The checkpoint ID commits only the body, so providers may observe valid controller
    /// approval subsets in either order. Lineage and transition evidence must still match exactly;
    /// only the already-verified direct approval envelope is mergeable.
    pub(crate) fn merge_approval_evidence(&self, other: &Self) -> Result<Self, IdentityError> {
        if self.lineage != other.lineage
            || self.events != other.events
            || self.verified_checkpoint.transition_event
                != other.verified_checkpoint.transition_event
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "provider checkpoint lineage merge",
            });
        }
        let checkpoint = self
            .verified_checkpoint
            .checkpoint
            .merge(&other.verified_checkpoint.checkpoint)?;
        let checkpoint_id = checkpoint.checkpoint_id()?;
        if checkpoint_id != self.verified_checkpoint.checkpoint_id
            || checkpoint_id != other.verified_checkpoint.checkpoint_id
        {
            return Err(IdentityError::InvalidProof);
        }
        Ok(Self {
            lineage: self.lineage.clone(),
            events: self.events.clone(),
            verified_checkpoint: VerifiedCheckpoint {
                checkpoint,
                checkpoint_id,
                transition_event: self.verified_checkpoint.transition_event.clone(),
            },
        })
    }
}

/// Build a bounded provider-served checkpoint bundle by replaying from account genesis.
pub fn build_provider_checkpoint_bundle_from_genesis(
    genesis: &crate::AccountGenesis,
    events: &[AuthorizedEvent],
    checkpoint: &SignedCheckpoint,
    transition_event: Option<&AuthorizedEvent>,
) -> Result<ProviderCheckpointBundle, IdentityError> {
    let mut state = crate::AccountState::from_genesis(genesis)?;
    advance_checkpoint_lineage(&mut state, events)?;
    let verified_checkpoint = verify_checkpoint(&state, checkpoint, transition_event)?;
    Ok(ProviderCheckpointBundle {
        lineage: ProviderCheckpointLineage::Genesis(Box::new(genesis.clone())),
        events: events.to_vec(),
        verified_checkpoint,
    })
}

/// Build a bounded provider-served continuation from a prior verified checkpoint.
pub fn build_provider_checkpoint_bundle_from_prior(
    prior_state: &crate::AccountState,
    prior_checkpoint: &VerifiedCheckpoint,
    events: &[AuthorizedEvent],
    checkpoint: &SignedCheckpoint,
    transition_event: Option<&AuthorizedEvent>,
) -> Result<ProviderCheckpointBundle, IdentityError> {
    let prior_expected =
        build_checkpoint_body(prior_state, prior_checkpoint.checkpoint.body.issued_at)?;
    if prior_checkpoint.checkpoint.body != prior_expected {
        return Err(IdentityError::InvalidProof);
    }
    let mut state = prior_state.clone();
    advance_checkpoint_lineage(&mut state, events)?;
    let verified_checkpoint = verify_checkpoint(&state, checkpoint, transition_event)?;
    Ok(ProviderCheckpointBundle {
        lineage: ProviderCheckpointLineage::Prior(prior_checkpoint.checkpoint_id),
        events: events.to_vec(),
        verified_checkpoint,
    })
}

fn advance_checkpoint_lineage(
    state: &mut crate::AccountState,
    events: &[AuthorizedEvent],
) -> Result<(), IdentityError> {
    validate_bootstrap_bounds(events, &[])?;
    for event in events {
        // Complete bounded lineage may pass through a detected fork only so a later, fully
        // authorized ResolveFork event can consume the exact retained branches. The final
        // lifecycle check below still rejects every unresolved or reopened fork.
        match state.validate_and_apply(event)?.disposition() {
            crate::ApplyDisposition::Applied | crate::ApplyDisposition::ForkDetected => {}
            crate::ApplyDisposition::Replay | crate::ApplyDisposition::ApprovalsMerged => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "checkpoint lineage advancing event chain",
                });
            }
        }
    }
    if state.lifecycle() == crate::ProjectionLifecycle::Forked {
        return Err(IdentityError::AccountForked);
    }
    Ok(())
}

/// Complete deterministic Merkle sets committed by one checkpoint projection.
///
/// The retained sets let full-state holders serve exact inclusion and adjacent-neighbor
/// non-membership proofs without reimplementing the frozen checkpoint leaf schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointMerkleSets {
    state: MerkleSet,
    authorized_devices: MerkleSet,
    revoked_devices: MerkleSet,
}

impl CheckpointMerkleSets {
    /// Complete authority-relevant state set, including metadata, controllers, and all devices.
    pub const fn state(&self) -> &MerkleSet {
        &self.state
    }

    /// Devices currently active at this projection revision.
    pub const fn authorized_devices(&self) -> &MerkleSet {
        &self.authorized_devices
    }

    /// Permanent revoked-device tombstones at this projection revision.
    pub const fn revoked_devices(&self) -> &MerkleSet {
        &self.revoked_devices
    }
}

/// Deterministically derive a complete single-head checkpoint body from projected account state.
pub fn build_checkpoint_body(
    state: &crate::AccountState,
    issued_at: Timestamp,
) -> Result<CheckpointBody, IdentityError> {
    let [event_head] = state.heads() else {
        return Err(if state.lifecycle() == crate::ProjectionLifecycle::Forked {
            IdentityError::AccountForked
        } else {
            IdentityError::InvalidRelationship {
                resource: "checkpoint single event head",
            }
        });
    };
    let lifecycle = checkpoint_lifecycle(state.lifecycle())?;
    let (state_root, authorized_set_root, revoked_set_root) = checkpoint_roots(state)?;
    CheckpointBody::new(
        state.account_id(),
        state.epoch(),
        state.sequence(),
        *event_head,
        state_root,
        authorized_set_root,
        revoked_set_root,
        state.control_policy_id(),
        state.recovery_policy_id(),
        state.provider_policy_id(),
        state.crypto_state_id()?,
        lifecycle,
        issued_at,
        Extensions::default(),
    )
}

/// Verify checkpoint roots, exact projection fields, and direct or transition authorization.
///
/// Checkpoints do not advance account state. Direct authorization uses the current
/// `ChangeProviderPolicy` selector and weighted threshold because that existing v1 authority
/// controls which transparency providers receive the checkpoint. Destructive transition
/// authorization instead retains and replays the exact event.
pub fn verify_checkpoint(
    state: &crate::AccountState,
    checkpoint: &SignedCheckpoint,
    transition_event: Option<&AuthorizedEvent>,
) -> Result<VerifiedCheckpoint, IdentityError> {
    let expected = build_checkpoint_body(state, checkpoint.body.issued_at)?;
    if checkpoint.body != expected {
        return Err(IdentityError::InvalidProof);
    }
    let checkpoint_id = checkpoint.checkpoint_id()?;
    let retained_transition = match &checkpoint.authorization.0 {
        CheckpointAuthorizationKind::Controllers(approvals) => {
            if transition_event.is_some() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "direct checkpoint transition event",
                });
            }
            if approvals.as_slice().is_empty() {
                return Err(IdentityError::AuthorizationDenied);
            }
            for approval in approvals.as_slice() {
                if approval.body().checkpoint_id() != Some(checkpoint_id) {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "verified checkpoint approval subject",
                    });
                }
            }
            crate::verifier::verify_checkpoint_approvals(state, approvals)?;
            None
        }
        CheckpointAuthorizationKind::TransitionDerived(witness) => {
            let event = transition_event.ok_or(IdentityError::InvalidProof)?;
            if event.event_id()? != witness.event_id
                || event.event_authorization_id()? != witness.event_authorization_id
                || event.body().account_id() != state.account_id()
                || event.event_id()? != checkpoint.body.event_head
            {
                return Err(IdentityError::InvalidProof);
            }
            let mut replay = state.clone();
            let disposition = replay.validate_and_apply(event)?.disposition();
            if !matches!(
                disposition,
                crate::ApplyDisposition::Replay | crate::ApplyDisposition::ApprovalsMerged
            ) {
                return Err(IdentityError::InvalidProof);
            }
            Some(event.clone())
        }
    };
    Ok(VerifiedCheckpoint {
        checkpoint: checkpoint.clone(),
        checkpoint_id,
        transition_event: retained_transition,
    })
}

/// Bootstrap a checkpoint through a bounded authenticated event chain from account genesis.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_checkpoint_from_genesis(
    genesis: &crate::AccountGenesis,
    events: &[AuthorizedEvent],
    checkpoint: &SignedCheckpoint,
    transition_event: Option<&AuthorizedEvent>,
    evidence: &crate::FreshnessEvidence,
    caller_requirement: crate::FreshnessRequirement,
    verified_at: Timestamp,
    known_conflicts: &[EventId],
) -> Result<TrustedCheckpointBootstrap, IdentityError> {
    let state = crate::AccountState::from_genesis(genesis)?;
    bootstrap_checkpoint(
        state,
        events,
        checkpoint,
        transition_event,
        evidence,
        caller_requirement,
        verified_at,
        known_conflicts,
    )
}

/// Advance from a prior verified checkpoint through a bounded policy-compatible proof chain.
#[allow(clippy::too_many_arguments)]
pub fn bootstrap_checkpoint_from_prior(
    prior_state: &crate::AccountState,
    prior_checkpoint: &VerifiedCheckpoint,
    events: &[AuthorizedEvent],
    checkpoint: &SignedCheckpoint,
    transition_event: Option<&AuthorizedEvent>,
    evidence: &crate::FreshnessEvidence,
    caller_requirement: crate::FreshnessRequirement,
    verified_at: Timestamp,
    known_conflicts: &[EventId],
) -> Result<TrustedCheckpointBootstrap, IdentityError> {
    let prior_expected =
        build_checkpoint_body(prior_state, prior_checkpoint.checkpoint.body.issued_at)?;
    if prior_checkpoint.checkpoint.body != prior_expected {
        return Err(IdentityError::InvalidProof);
    }
    bootstrap_checkpoint(
        prior_state.clone(),
        events,
        checkpoint,
        transition_event,
        evidence,
        caller_requirement,
        verified_at,
        known_conflicts,
    )
}

#[allow(clippy::too_many_arguments)]
fn bootstrap_checkpoint(
    mut state: crate::AccountState,
    events: &[AuthorizedEvent],
    checkpoint: &SignedCheckpoint,
    transition_event: Option<&AuthorizedEvent>,
    evidence: &crate::FreshnessEvidence,
    caller_requirement: crate::FreshnessRequirement,
    verified_at: Timestamp,
    known_conflicts: &[EventId],
) -> Result<TrustedCheckpointBootstrap, IdentityError> {
    if !known_conflicts.is_empty() {
        validate_bootstrap_bounds(events, known_conflicts)?;
        return Err(IdentityError::AccountForked);
    }
    advance_checkpoint_lineage(&mut state, events)?;
    let verified = verify_checkpoint(&state, checkpoint, transition_event)?;
    let context =
        crate::AuthorizationContext::new(state.account_id(), state.epoch(), verified.checkpoint_id);
    let account_requirement = match state.provider_policy().mode() {
        crate::ProviderMode::LocalOnly => crate::FreshnessRequirement::latest_known(),
        crate::ProviderMode::Replicated(policy) => {
            crate::FreshnessRequirement::provider_quorum(crate::ProviderFreshness::new(
                policy.sufficient_threshold(),
                policy.maximum_evidence_age(),
            )?)
        }
    };
    let freshness = crate::evaluate_freshness(
        context,
        state.provider_policy(),
        account_requirement,
        caller_requirement,
        evidence,
        verified_at,
    )?;
    Ok(TrustedCheckpointBootstrap {
        state,
        checkpoint: verified,
        freshness,
    })
}

fn validate_bootstrap_bounds(
    events: &[AuthorizedEvent],
    known_conflicts: &[EventId],
) -> Result<(), IdentityError> {
    if events.len() > crate::limits::MAX_HISTORY_PAGE_EVENTS {
        return Err(IdentityError::limit(
            "checkpoint bootstrap events",
            events.len(),
            crate::limits::MAX_HISTORY_PAGE_EVENTS,
        ));
    }
    if known_conflicts.len() > crate::limits::MAX_FORK_HEADS {
        return Err(IdentityError::limit(
            "checkpoint bootstrap known conflicts",
            known_conflicts.len(),
            crate::limits::MAX_FORK_HEADS,
        ));
    }
    let mut bytes = 0_usize;
    for event in events {
        bytes = bytes.checked_add(event.to_canonical_bytes()?.len()).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "checkpoint bootstrap proof bytes",
            },
        )?;
        if bytes > crate::limits::MAX_HISTORY_PAGE_BYTES {
            return Err(IdentityError::limit(
                "checkpoint bootstrap proof bytes",
                bytes,
                crate::limits::MAX_HISTORY_PAGE_BYTES,
            ));
        }
    }
    Ok(())
}

/// Build the exact sorted sets whose roots are committed by [`build_checkpoint_body`].
pub fn build_checkpoint_merkle_sets(
    state: &crate::AccountState,
) -> Result<CheckpointMerkleSets, IdentityError> {
    let state_material = state.checkpoint_state_material()?;
    let metadata_key = MerkleSetKey::new(
        CHECKPOINT_STATE_METADATA_TYPE_TAG,
        hash_bytes(HashDomain::StateRoot, b"checkpoint-state-metadata-key"),
    )?;
    let mut state_leaves = vec![MerkleSetLeaf::new(
        metadata_key,
        hash_bytes(HashDomain::StateRoot, &state_material),
    )];

    for (controller, active) in state
        .active_controllers()
        .iter()
        .map(|controller| (controller, true))
        .chain(
            state
                .revoked_controllers()
                .iter()
                .map(|controller| (controller, false)),
        )
    {
        let value = encode_wire(&(controller.id(), controller.descriptor(), active))?;
        state_leaves.push(MerkleSetLeaf::new(
            MerkleSetKey::new(
                CHECKPOINT_STATE_CONTROLLER_TYPE_TAG,
                *controller.id().as_digest(),
            )?,
            hash_bytes(HashDomain::StateRoot, &value),
        ));
    }

    let mut authorized_leaves = Vec::new();
    let mut revoked_leaves = Vec::new();
    for device in state.devices() {
        let lifecycle_code = projected_device_lifecycle_code(device.lifecycle());
        let value = encode_wire(&(
            device.id(),
            device.descriptor(),
            device.device_class(),
            device.metadata_commitment(),
            device.capabilities(),
            device.authorization_epoch(),
            lifecycle_code,
        ))?;
        state_leaves.push(MerkleSetLeaf::new(
            MerkleSetKey::new(CHECKPOINT_STATE_DEVICE_TYPE_TAG, *device.id().as_digest())?,
            hash_bytes(HashDomain::StateRoot, &value),
        ));
        match device.lifecycle() {
            crate::ProjectedDeviceLifecycle::Active => {
                authorized_leaves.push(MerkleSetLeaf::new(
                    MerkleSetKey::new(
                        CHECKPOINT_AUTHORIZED_DEVICE_TYPE_TAG,
                        *device.id().as_digest(),
                    )?,
                    hash_bytes(HashDomain::AuthorizedSet, &value),
                ));
            }
            crate::ProjectedDeviceLifecycle::Suspended => {}
            crate::ProjectedDeviceLifecycle::Revoked => {
                revoked_leaves.push(MerkleSetLeaf::new(
                    MerkleSetKey::new(
                        CHECKPOINT_REVOKED_DEVICE_TYPE_TAG,
                        *device.id().as_digest(),
                    )?,
                    hash_bytes(HashDomain::RevokedSet, &value),
                ));
            }
        }
    }

    Ok(CheckpointMerkleSets {
        state: MerkleSet::new(state_leaves)?,
        authorized_devices: MerkleSet::new(authorized_leaves)?,
        revoked_devices: MerkleSet::new(revoked_leaves)?,
    })
}

fn checkpoint_roots(
    state: &crate::AccountState,
) -> Result<(Digest, Digest, Digest), IdentityError> {
    let sets = build_checkpoint_merkle_sets(state)?;
    Ok((
        sets.state.root()?,
        sets.authorized_devices.root()?,
        sets.revoked_devices.root()?,
    ))
}

fn checkpoint_lifecycle(
    lifecycle: crate::ProjectionLifecycle,
) -> Result<AccountLifecycle, IdentityError> {
    match lifecycle {
        crate::ProjectionLifecycle::Active => Ok(AccountLifecycle::Active),
        crate::ProjectionLifecycle::RecoveryPending => Ok(AccountLifecycle::RecoveryPending),
        crate::ProjectionLifecycle::MigrationPending => Ok(AccountLifecycle::MigrationPending),
        crate::ProjectionLifecycle::MigrationDual => Ok(AccountLifecycle::MigrationDual),
        crate::ProjectionLifecycle::UpgradePending => Ok(AccountLifecycle::UpgradePending),
        crate::ProjectionLifecycle::Retired => Ok(AccountLifecycle::Retired),
        crate::ProjectionLifecycle::Forked => Err(IdentityError::AccountForked),
    }
}

const fn projected_device_lifecycle_code(lifecycle: crate::ProjectedDeviceLifecycle) -> u16 {
    match lifecycle {
        crate::ProjectedDeviceLifecycle::Active => 1,
        crate::ProjectedDeviceLifecycle::Suspended => 2,
        crate::ProjectedDeviceLifecycle::Revoked => 3,
    }
}
