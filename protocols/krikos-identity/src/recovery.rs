//! Bounded recovery-ceremony and explicit fork-resolution wire schemas.

use std::{fmt, sync::Arc};

use crate::{
    AccountId, BlindingSecret, CheckpointId, ControlPolicy, ControlPolicyId, ControllerDescriptor,
    ControllerId, ControllerWeight, DeviceId, Digest, Epoch, EventId, Extensions, ForkId,
    FreshnessEvidence, GenesisAnchor, GuardianGrantId, GuardianSetRoot, IdentityError, ProposalId,
    ProtocolSignature, ProtocolVersion, ProviderPolicyId, ProviderQuorum, ProviderReceipts,
    RecoveryAuthority, RecoveryId, RecoveryPolicy, RecoveryPolicyId, RecoveryPolicyVersion,
    SigningPublicKey, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{
        MAX_ACCOUNT_EVENT_BYTES, MAX_CONTROLLERS, MAX_DEVICES, MAX_FORK_HEADS,
        MAX_MERKLE_PROOF_HASHES, MAX_RECOVERY_GUARDIANS,
    },
    merkle::{MerkleInclusionProof, MerkleSetKey, MerkleSetLeaf},
    schema::BoundedVec,
    types::{HashDomain, hash_bytes},
};
use krikos_base::{PublicKey, Signature};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Frozen Merkle-set type tag for one non-circular blinded guardian-grant leaf.
pub const GUARDIAN_GRANT_LEAF_TYPE_TAG: u16 = 1;

const GUARDIAN_APPROVAL_SIGNATURE_DOMAIN: &[u8] = b"KRIKOS-ID/guardian-approval/v1";
const GUARDIAN_GRANT_LEAF_BODY_CODE: u16 = 1;
const GUARDIAN_GRANT_LEAF_VALUE_CODE: u16 = 2;

macro_rules! canonical_schema {
    ($name:ty, $resource:literal) => {
        impl CanonicalCodec for $name {
            const RESOURCE: &'static str = $resource;
            const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(self)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                decode_wire(bytes)
            }
        }
    };
}

fn validate_v1(version: ProtocolVersion) -> Result<(), IdentityError> {
    if version != ProtocolVersion::V1 {
        return Err(IdentityError::UnsupportedVersion {
            version: version.get(),
        });
    }
    Ok(())
}

fn validate_strictly_sorted<T: Ord>(
    values: &[T],
    resource: &'static str,
) -> Result<(), IdentityError> {
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(IdentityError::DuplicateElement { resource });
        }
        if pair[0] > pair[1] {
            return Err(IdentityError::NonCanonical);
        }
    }
    Ok(())
}

fn sorted_controller_descriptors(
    controllers: Vec<ControllerDescriptor>,
) -> Result<Vec<ControllerDescriptor>, IdentityError> {
    if controllers.is_empty() {
        return Err(IdentityError::EmptyCollection {
            resource: "replacement controllers",
        });
    }
    if controllers.len() > MAX_CONTROLLERS {
        return Err(IdentityError::limit(
            "replacement controllers",
            controllers.len(),
            MAX_CONTROLLERS,
        ));
    }

    let mut identified = Vec::with_capacity(controllers.len());
    for controller in controllers {
        identified.push((controller.id()?, controller));
    }
    identified.sort_unstable_by_key(|(controller_id, _)| *controller_id);
    for pair in identified.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(IdentityError::DuplicateElement {
                resource: "replacement controller identifiers",
            });
        }
    }
    for left in 0..identified.len() {
        for right in (left + 1)..identified.len() {
            if identified[left].1.signing_key() == identified[right].1.signing_key() {
                return Err(IdentityError::DuplicateSigningKey);
            }
        }
    }
    Ok(identified
        .into_iter()
        .map(|(_, controller)| controller)
        .collect())
}

fn validate_sorted_controller_descriptors(
    controllers: &[ControllerDescriptor],
) -> Result<(), IdentityError> {
    if controllers.is_empty() {
        return Err(IdentityError::EmptyCollection {
            resource: "replacement controllers",
        });
    }
    if controllers.len() > MAX_CONTROLLERS {
        return Err(IdentityError::limit(
            "replacement controllers",
            controllers.len(),
            MAX_CONTROLLERS,
        ));
    }

    let mut previous = None;
    for controller in controllers {
        let controller_id = controller.id()?;
        if let Some(previous_id) = previous {
            if previous_id == controller_id {
                return Err(IdentityError::DuplicateElement {
                    resource: "replacement controller identifiers",
                });
            }
            if previous_id > controller_id {
                return Err(IdentityError::NonCanonical);
            }
        }
        previous = Some(controller_id);
    }
    for left in 0..controllers.len() {
        for right in (left + 1)..controllers.len() {
            if controllers[left].signing_key() == controllers[right].signing_key() {
                return Err(IdentityError::DuplicateSigningKey);
            }
        }
    }
    Ok(())
}

/// Complete authority state that a successful recovery installs atomically.
///
/// Devices in `retained_devices` remain authorized. Every other active device is
/// revoked by the recovery transition; omission is therefore never interpreted as
/// implicit retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryAuthorityPlan {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    prior_checkpoint_id: CheckpointId,
    prior_event_head: EventId,
    recovery_policy_id: RecoveryPolicyId,
    recovery_policy_version: RecoveryPolicyVersion,
    nonce: [u8; 32],
    replacement_controllers: BoundedVec<ControllerDescriptor, MAX_CONTROLLERS>,
    replacement_control_policy: ControlPolicy,
    replacement_recovery_policy: RecoveryPolicy,
    retained_devices: BoundedVec<DeviceId, MAX_DEVICES>,
    expires_at: Timestamp,
    extensions: Extensions,
}

impl RecoveryAuthorityPlan {
    /// Construct and canonicalize a complete v1 replacement-authority plan.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        protocol_version: ProtocolVersion,
        account_id: AccountId,
        prior_checkpoint_id: CheckpointId,
        prior_event_head: EventId,
        recovery_policy_id: RecoveryPolicyId,
        recovery_policy_version: RecoveryPolicyVersion,
        nonce: [u8; 32],
        replacement_controllers: Vec<ControllerDescriptor>,
        replacement_control_policy: ControlPolicy,
        replacement_recovery_policy: RecoveryPolicy,
        mut retained_devices: Vec<DeviceId>,
        expires_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let replacement_controllers = sorted_controller_descriptors(replacement_controllers)?;
        retained_devices.sort_unstable();
        Self::from_sorted(
            protocol_version,
            account_id,
            prior_checkpoint_id,
            prior_event_head,
            recovery_policy_id,
            recovery_policy_version,
            nonce,
            replacement_controllers,
            replacement_control_policy,
            replacement_recovery_policy,
            retained_devices,
            expires_at,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_sorted(
        protocol_version: ProtocolVersion,
        account_id: AccountId,
        prior_checkpoint_id: CheckpointId,
        prior_event_head: EventId,
        recovery_policy_id: RecoveryPolicyId,
        recovery_policy_version: RecoveryPolicyVersion,
        nonce: [u8; 32],
        replacement_controllers: Vec<ControllerDescriptor>,
        replacement_control_policy: ControlPolicy,
        replacement_recovery_policy: RecoveryPolicy,
        retained_devices: Vec<DeviceId>,
        expires_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if nonce == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "recovery nonce",
            });
        }
        if expires_at.as_unix_millis() == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "recovery expiry",
            });
        }
        validate_sorted_controller_descriptors(&replacement_controllers)?;
        validate_strictly_sorted(&retained_devices, "retained recovery devices")?;
        let retained_devices = BoundedVec::new("retained recovery devices", retained_devices)?;

        replacement_control_policy.validate_satisfiable(&replacement_controllers)?;
        replacement_recovery_policy.validate_controller_authority(&replacement_controllers)?;
        let replacement_version = replacement_recovery_policy.policy_version();
        if replacement_version < recovery_policy_version {
            return Err(IdentityError::InvalidRelationship {
                resource: "recovery policy version rollback",
            });
        }
        if replacement_version == recovery_policy_version
            && replacement_recovery_policy.id()? != recovery_policy_id
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "same-version replacement recovery policy",
            });
        }
        extensions.validate_critical(&[])?;

        Ok(Self {
            protocol_version,
            account_id,
            prior_checkpoint_id,
            prior_event_head,
            recovery_policy_id,
            recovery_policy_version,
            nonce,
            replacement_controllers: BoundedVec::new(
                "replacement controllers",
                replacement_controllers,
            )?,
            replacement_control_policy,
            replacement_recovery_policy,
            retained_devices,
            expires_at,
            extensions,
        })
    }

    /// Account whose authority will be replaced.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Checkpoint against which the recovery was proposed.
    pub const fn prior_checkpoint_id(&self) -> CheckpointId {
        self.prior_checkpoint_id
    }

    /// Exact event head committed by the prior checkpoint.
    pub const fn prior_event_head(&self) -> EventId {
        self.prior_event_head
    }

    /// Recovery policy committed by the prior checkpoint.
    pub const fn recovery_policy_id(&self) -> RecoveryPolicyId {
        self.recovery_policy_id
    }

    /// Monotonic version of the pre-recovery policy.
    pub const fn recovery_policy_version(&self) -> RecoveryPolicyVersion {
        self.recovery_policy_version
    }

    /// Fresh, nonzero proposal nonce.
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Controllers installed on successful finalization.
    pub fn replacement_controllers(&self) -> &[ControllerDescriptor] {
        self.replacement_controllers.as_slice()
    }

    /// Control policy installed on successful finalization.
    pub const fn replacement_control_policy(&self) -> &ControlPolicy {
        &self.replacement_control_policy
    }

    /// Recovery policy installed on successful finalization.
    pub const fn replacement_recovery_policy(&self) -> &RecoveryPolicy {
        &self.replacement_recovery_policy
    }

    /// Explicitly retained devices; all omitted active devices are revoked.
    pub fn retained_devices(&self) -> &[DeviceId] {
        self.retained_devices.as_slice()
    }

    /// Latest instant at which this plan may be finalized.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl<'de> Deserialize<'de> for RecoveryAuthorityPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            prior_checkpoint_id: CheckpointId,
            prior_event_head: EventId,
            recovery_policy_id: RecoveryPolicyId,
            recovery_policy_version: RecoveryPolicyVersion,
            nonce: [u8; 32],
            replacement_controllers: BoundedVec<ControllerDescriptor, MAX_CONTROLLERS>,
            replacement_control_policy: ControlPolicy,
            replacement_recovery_policy: RecoveryPolicy,
            retained_devices: BoundedVec<DeviceId, MAX_DEVICES>,
            expires_at: Timestamp,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_sorted(
            wire.protocol_version,
            wire.account_id,
            wire.prior_checkpoint_id,
            wire.prior_event_head,
            wire.recovery_policy_id,
            wire.recovery_policy_version,
            wire.nonce,
            wire.replacement_controllers.into_vec(),
            wire.replacement_control_policy,
            wire.replacement_recovery_policy,
            wire.retained_devices.into_vec(),
            wire.expires_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(RecoveryAuthorityPlan, "recovery authority plan bytes");

/// Body-only recovery proposal. Its [`RecoveryId`] excludes all later approvals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryProposal {
    protocol_version: ProtocolVersion,
    plan: RecoveryAuthorityPlan,
    extensions: Extensions,
}

impl RecoveryProposal {
    /// Construct a v1 recovery proposal.
    pub fn try_new(
        protocol_version: ProtocolVersion,
        plan: RecoveryAuthorityPlan,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            plan,
            extensions,
        })
    }

    /// Complete authority plan committed by the proposal.
    pub const fn plan(&self) -> &RecoveryAuthorityPlan {
        &self.plan
    }

    /// Derive the stable body-only recovery identifier.
    pub fn recovery_id(&self) -> Result<RecoveryId, IdentityError> {
        RecoveryId::derive(self)
    }
}

impl<'de> Deserialize<'de> for RecoveryProposal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            plan: RecoveryAuthorityPlan,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(wire.protocol_version, wire.plan, wire.extensions).map_err(de::Error::custom)
    }
}

canonical_schema!(RecoveryProposal, "recovery proposal bytes");

/// Private identity and authority assigned to one explicit recovery guardian.
///
/// Raw guardian relationships deliberately have no public canonical export:
///
/// ```compile_fail
/// use krikos_identity::{CanonicalWire, GuardianGrant};
/// fn require_public_wire<T: CanonicalWire>() {}
/// require_public_wire::<GuardianGrant>();
/// ```
///
/// ```compile_fail
/// use krikos_identity::GuardianGrant;
/// fn require_clone<T: Clone>() {}
/// require_clone::<GuardianGrant>();
/// ```
#[derive(PartialEq, Eq)]
pub struct GuardianGrant {
    protocol_version: ProtocolVersion,
    protected_account_id: AccountId,
    recovery_policy_id: RecoveryPolicyId,
    guardian_account_id: AccountId,
    guardian_signing_key: SigningPublicKey,
    weight: ControllerWeight,
    valid_from_epoch: Epoch,
    expires_at: Option<Timestamp>,
    extensions: Extensions,
}

impl fmt::Debug for GuardianGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuardianGrant(<redacted>)")
    }
}

impl GuardianGrant {
    /// Construct a private guardian grant.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        protocol_version: ProtocolVersion,
        protected_account_id: AccountId,
        recovery_policy_id: RecoveryPolicyId,
        guardian_account_id: AccountId,
        guardian_signing_key: SigningPublicKey,
        weight: ControllerWeight,
        valid_from_epoch: Epoch,
        expires_at: Option<Timestamp>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if expires_at.is_some_and(|expiry| expiry.as_unix_millis() == 0) {
            return Err(IdentityError::ZeroValue {
                resource: "guardian grant expiry",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            protected_account_id,
            recovery_policy_id,
            guardian_account_id,
            guardian_signing_key,
            weight,
            valid_from_epoch,
            expires_at,
            extensions,
        })
    }

    /// Derive the canonical non-circular blinded leaf committed by a guardian-set root.
    ///
    /// The current recovery-policy identifier is intentionally excluded: the policy identifier
    /// commits the guardian-set root, so including it in the root's leaves would create a circular
    /// hash dependency. The protected account, guardian identity and key, weight, validity bounds,
    /// extensions, and fresh blinding remain committed. Verification separately requires the
    /// opened grant's policy identifier to equal the exact authoritative policy identifier.
    pub fn blinded_merkle_leaf(
        &self,
        blinding: &BlindingSecret,
    ) -> Result<MerkleSetLeaf, IdentityError> {
        let leaf_body = encode_wire(&(
            GUARDIAN_GRANT_LEAF_BODY_CODE,
            self.protocol_version,
            self.protected_account_id,
            self.guardian_account_id,
            self.guardian_signing_key,
            self.weight,
            self.valid_from_epoch,
            self.expires_at,
            &self.extensions,
            blinding.as_bytes(),
        ))?;
        let leaf_id = hash_bytes(HashDomain::GuardianGrant, &leaf_body);
        let value_body = encode_wire(&(GUARDIAN_GRANT_LEAF_VALUE_CODE, leaf_id))?;
        let value_hash = hash_bytes(HashDomain::GuardianGrant, &value_body);
        Ok(MerkleSetLeaf::new(
            MerkleSetKey::new(GUARDIAN_GRANT_LEAF_TYPE_TAG, leaf_id)?,
            value_hash,
        ))
    }

    /// Account protected by this private grant.
    pub const fn protected_account_id(&self) -> AccountId {
        self.protected_account_id
    }

    /// Recovery policy to whose hidden guardian set this grant belongs.
    pub const fn recovery_policy_id(&self) -> RecoveryPolicyId {
        self.recovery_policy_id
    }

    /// Guardian account revealed only when this grant is opened.
    pub const fn guardian_account_id(&self) -> AccountId {
        self.guardian_account_id
    }

    /// Signing key authorized by the private grant.
    pub const fn guardian_signing_key(&self) -> SigningPublicKey {
        self.guardian_signing_key
    }

    /// Nonzero guardian weight.
    pub const fn weight(&self) -> ControllerWeight {
        self.weight
    }

    /// First account epoch at which this grant may approve recovery.
    pub const fn valid_from_epoch(&self) -> Epoch {
        self.valid_from_epoch
    }

    /// Optional exclusive expiry instant.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }
}

#[derive(Serialize)]
struct GuardianGrantWireRef<'a> {
    protocol_version: ProtocolVersion,
    protected_account_id: AccountId,
    recovery_policy_id: RecoveryPolicyId,
    guardian_account_id: AccountId,
    guardian_signing_key: SigningPublicKey,
    weight: ControllerWeight,
    valid_from_epoch: Epoch,
    expires_at: Option<Timestamp>,
    extensions: &'a Extensions,
}

impl<'a> From<&'a GuardianGrant> for GuardianGrantWireRef<'a> {
    fn from(grant: &'a GuardianGrant) -> Self {
        Self {
            protocol_version: grant.protocol_version,
            protected_account_id: grant.protected_account_id,
            recovery_policy_id: grant.recovery_policy_id,
            guardian_account_id: grant.guardian_account_id,
            guardian_signing_key: grant.guardian_signing_key,
            weight: grant.weight,
            valid_from_epoch: grant.valid_from_epoch,
            expires_at: grant.expires_at,
            extensions: &grant.extensions,
        }
    }
}

#[derive(Deserialize)]
struct GuardianGrantWire {
    protocol_version: ProtocolVersion,
    protected_account_id: AccountId,
    recovery_policy_id: RecoveryPolicyId,
    guardian_account_id: AccountId,
    guardian_signing_key: SigningPublicKey,
    weight: ControllerWeight,
    valid_from_epoch: Epoch,
    expires_at: Option<Timestamp>,
    extensions: Extensions,
}

impl GuardianGrantWire {
    fn into_grant(self) -> Result<GuardianGrant, IdentityError> {
        GuardianGrant::try_new(
            self.protocol_version,
            self.protected_account_id,
            self.recovery_policy_id,
            self.guardian_account_id,
            self.guardian_signing_key,
            self.weight,
            self.valid_from_epoch,
            self.expires_at,
            self.extensions,
        )
    }
}

/// Blinded guardian grant plus bounded membership-opening material.
///
/// Revealed witness material is owned by a signed approval and cannot be freely cloned:
///
/// ```compile_fail
/// use krikos_identity::GuardianGrantOpening;
/// fn require_clone<T: Clone>() {}
/// require_clone::<GuardianGrantOpening>();
/// ```
///
/// ```compile_fail
/// use krikos_identity::{CanonicalWire, GuardianGrantOpening};
/// fn require_public_wire<T: CanonicalWire>() {}
/// require_public_wire::<GuardianGrantOpening>();
/// ```
#[derive(PartialEq, Eq)]
pub struct GuardianGrantOpening {
    protocol_version: ProtocolVersion,
    guardian_grant_id: GuardianGrantId,
    grant: GuardianGrant,
    blinding: BlindingSecret,
    guardian_set_root: GuardianSetRoot,
    leaf_index: u16,
    audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
    extensions: Extensions,
}

impl fmt::Debug for GuardianGrantOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuardianGrantOpening(<redacted>)")
    }
}

impl GuardianGrantOpening {
    /// Construct an opening and derive its blinded grant identifier.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        protocol_version: ProtocolVersion,
        grant: GuardianGrant,
        blinding: BlindingSecret,
        guardian_set_root: GuardianSetRoot,
        leaf_index: u16,
        audit_path: Vec<Digest>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let guardian_grant_id =
            Self::derive_grant_id(protocol_version, &grant, blinding.as_bytes())?;
        Self::from_wire(
            protocol_version,
            guardian_grant_id,
            grant,
            blinding,
            guardian_set_root,
            leaf_index,
            audit_path,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_wire(
        protocol_version: ProtocolVersion,
        guardian_grant_id: GuardianGrantId,
        grant: GuardianGrant,
        blinding: BlindingSecret,
        guardian_set_root: GuardianSetRoot,
        leaf_index: u16,
        audit_path: Vec<Digest>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if usize::from(leaf_index) >= MAX_RECOVERY_GUARDIANS {
            return Err(IdentityError::limit(
                "guardian membership leaf index",
                usize::from(leaf_index),
                MAX_RECOVERY_GUARDIANS - 1,
            ));
        }
        if guardian_grant_id
            != Self::derive_grant_id(protocol_version, &grant, blinding.as_bytes())?
        {
            return Err(IdentityError::InvalidIdentifier {
                resource: "guardian grant opening",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            guardian_grant_id,
            grant,
            blinding,
            guardian_set_root,
            leaf_index,
            audit_path: BoundedVec::new("guardian membership audit path", audit_path)?,
            extensions,
        })
    }

    fn derive_grant_id(
        protocol_version: ProtocolVersion,
        grant: &GuardianGrant,
        blinding: &[u8; 32],
    ) -> Result<GuardianGrantId, IdentityError> {
        let encoded = encode_wire(&(
            protocol_version,
            GuardianGrantWireRef::from(grant),
            blinding,
        ))?;
        Ok(GuardianGrantId::from_digest(hash_bytes(
            HashDomain::GuardianGrant,
            &encoded,
        )))
    }

    /// Blinded identifier recomputed from the grant and fresh secret.
    pub const fn guardian_grant_id(&self) -> GuardianGrantId {
        self.guardian_grant_id
    }

    /// Revealed private guardian grant.
    pub const fn grant(&self) -> &GuardianGrant {
        &self.grant
    }

    /// Public aggregate guardian-set root to which this proof is addressed.
    pub const fn guardian_set_root(&self) -> GuardianSetRoot {
        self.guardian_set_root
    }

    /// Bounded leaf position in the committed guardian set.
    pub const fn leaf_index(&self) -> u16 {
        self.leaf_index
    }

    /// Bounded Merkle membership path, verified by the projection layer.
    pub fn audit_path(&self) -> &[Digest] {
        self.audit_path.as_slice()
    }
}

#[derive(Serialize)]
struct GuardianGrantOpeningWireRef<'a> {
    protocol_version: ProtocolVersion,
    guardian_grant_id: GuardianGrantId,
    grant: GuardianGrantWireRef<'a>,
    blinding: &'a [u8; 32],
    guardian_set_root: GuardianSetRoot,
    leaf_index: u16,
    audit_path: &'a BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
    extensions: &'a Extensions,
}

impl<'a> From<&'a GuardianGrantOpening> for GuardianGrantOpeningWireRef<'a> {
    fn from(opening: &'a GuardianGrantOpening) -> Self {
        Self {
            protocol_version: opening.protocol_version,
            guardian_grant_id: opening.guardian_grant_id,
            grant: GuardianGrantWireRef::from(&opening.grant),
            blinding: opening.blinding.as_bytes(),
            guardian_set_root: opening.guardian_set_root,
            leaf_index: opening.leaf_index,
            audit_path: &opening.audit_path,
            extensions: &opening.extensions,
        }
    }
}

#[derive(Deserialize)]
struct GuardianGrantOpeningWire {
    protocol_version: ProtocolVersion,
    guardian_grant_id: GuardianGrantId,
    grant: GuardianGrantWire,
    blinding: [u8; 32],
    guardian_set_root: GuardianSetRoot,
    leaf_index: u16,
    audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
    extensions: Extensions,
}

impl GuardianGrantOpeningWire {
    fn into_opening(self) -> Result<GuardianGrantOpening, IdentityError> {
        GuardianGrantOpening::from_wire(
            self.protocol_version,
            self.guardian_grant_id,
            self.grant.into_grant()?,
            BlindingSecret::try_new(self.blinding)?,
            self.guardian_set_root,
            self.leaf_index,
            self.audit_path.into_vec(),
            self.extensions,
        )
    }
}

/// Recovery decision signed by a private guardian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuardianApprovalDecision {
    /// Approve beginning the exact recovery proposal.
    Begin,
    /// Approve canceling the exact pending recovery under the same threshold.
    Cancel,
}

impl GuardianApprovalDecision {
    /// Stable v1 decision codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::Begin => 1,
            Self::Cancel => 2,
        }
    }
}

impl Serialize for GuardianApprovalDecision {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GuardianApprovalDecision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u16::deserialize(deserializer)? {
            1 => Ok(Self::Begin),
            2 => Ok(Self::Cancel),
            code => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "guardian recovery decision",
                code,
            })),
        }
    }
}

canonical_schema!(GuardianApprovalDecision, "guardian recovery decision bytes");

/// Exact body signed by one private recovery guardian.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardianApprovalBody {
    protocol_version: ProtocolVersion,
    protected_account_id: AccountId,
    recovery_id: RecoveryId,
    decision: GuardianApprovalDecision,
    guardian_grant_id: GuardianGrantId,
    account_epoch: Epoch,
    approved_at: Timestamp,
    extensions: Extensions,
}

impl GuardianApprovalBody {
    /// Construct one exact guardian decision body.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        protocol_version: ProtocolVersion,
        protected_account_id: AccountId,
        recovery_id: RecoveryId,
        decision: GuardianApprovalDecision,
        guardian_grant_id: GuardianGrantId,
        account_epoch: Epoch,
        approved_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if approved_at.as_unix_millis() == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "guardian approval time",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            protected_account_id,
            recovery_id,
            decision,
            guardian_grant_id,
            account_epoch,
            approved_at,
            extensions,
        })
    }

    /// Build the exact domain-separated bytes signed by the private guardian key.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let body = encode_wire(self)?;
        let capacity = GUARDIAN_APPROVAL_SIGNATURE_DOMAIN
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(body.len()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "guardian approval signing message bytes",
            })?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(GUARDIAN_APPROVAL_SIGNATURE_DOMAIN);
        message.push(0);
        message.extend_from_slice(&body);
        Ok(message)
    }

    /// Account protected by this signed decision.
    pub const fn protected_account_id(&self) -> AccountId {
        self.protected_account_id
    }

    /// Exact proposal or pending recovery being decided.
    pub const fn recovery_id(&self) -> RecoveryId {
        self.recovery_id
    }

    /// Begin or cancellation decision.
    pub const fn decision(&self) -> GuardianApprovalDecision {
        self.decision
    }

    /// Blinded grant used for this decision.
    pub const fn guardian_grant_id(&self) -> GuardianGrantId {
        self.guardian_grant_id
    }

    /// Account epoch against which grant validity is checked.
    pub const fn account_epoch(&self) -> Epoch {
        self.account_epoch
    }

    /// Explicit signing time used only for grant validity bounds.
    pub const fn approved_at(&self) -> Timestamp {
        self.approved_at
    }
}

impl<'de> Deserialize<'de> for GuardianApprovalBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            protected_account_id: AccountId,
            recovery_id: RecoveryId,
            decision: GuardianApprovalDecision,
            guardian_grant_id: GuardianGrantId,
            account_epoch: Epoch,
            approved_at: Timestamp,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(
            wire.protocol_version,
            wire.protected_account_id,
            wire.recovery_id,
            wire.decision,
            wire.guardian_grant_id,
            wire.account_epoch,
            wire.approved_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(GuardianApprovalBody, "guardian approval body bytes");

/// One signed guardian decision paired with the private grant opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGuardianApproval {
    body: GuardianApprovalBody,
    opening: Arc<GuardianGrantOpening>,
    signature: ProtocolSignature,
}

impl SignedGuardianApproval {
    /// Attach a signature after validating the opened grant's structural bounds.
    pub fn try_new(
        body: GuardianApprovalBody,
        opening: GuardianGrantOpening,
        signature: ProtocolSignature,
    ) -> Result<Self, IdentityError> {
        let grant = opening.grant();
        if body.guardian_grant_id() != opening.guardian_grant_id() {
            return Err(IdentityError::InvalidIdentifier {
                resource: "guardian approval grant",
            });
        }
        if body.protected_account_id() != grant.protected_account_id() {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian approval protected account",
            });
        }
        if body.account_epoch() < grant.valid_from_epoch() {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian grant start epoch",
            });
        }
        if grant
            .expires_at()
            .is_some_and(|expiry| body.approved_at() >= expiry)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "expired guardian grant",
            });
        }
        Ok(Self {
            body,
            opening: Arc::new(opening),
            signature,
        })
    }

    /// Signed guardian approval body.
    pub const fn body(&self) -> &GuardianApprovalBody {
        &self.body
    }

    /// Private grant opening carried with this approval.
    pub fn opening(&self) -> &GuardianGrantOpening {
        self.opening.as_ref()
    }

    /// Guardian signature bytes.
    pub const fn signature(&self) -> ProtocolSignature {
        self.signature
    }

    /// Replace only the signature while sharing the already revealed, validated witness.
    ///
    /// This supports independently produced signature candidates without duplicating the raw
    /// guardian grant, opening, or blinding in memory.
    pub fn with_signature(&self, signature: ProtocolSignature) -> Self {
        Self {
            body: self.body.clone(),
            opening: Arc::clone(&self.opening),
            signature,
        }
    }
}

impl Serialize for SignedGuardianApproval {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            body: &'a GuardianApprovalBody,
            opening: GuardianGrantOpeningWireRef<'a>,
            signature: ProtocolSignature,
        }

        Wire {
            body: &self.body,
            opening: GuardianGrantOpeningWireRef::from(self.opening()),
            signature: self.signature,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignedGuardianApproval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            body: GuardianApprovalBody,
            opening: GuardianGrantOpeningWire,
            signature: ProtocolSignature,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(
            wire.body,
            wire.opening.into_opening().map_err(de::Error::custom)?,
            wire.signature,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(SignedGuardianApproval, "signed guardian approval bytes");

/// Bounded, mergeable decisions from distinct private guardians.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardianApprovalSet(BoundedVec<SignedGuardianApproval, MAX_RECOVERY_GUARDIANS>);

impl GuardianApprovalSet {
    /// Sort and construct approvals from distinct guardian grants.
    pub fn try_new(mut approvals: Vec<SignedGuardianApproval>) -> Result<Self, IdentityError> {
        approvals.sort_unstable_by_key(|approval| approval.body().guardian_grant_id());
        Self::from_sorted(approvals)
    }

    fn from_sorted(approvals: Vec<SignedGuardianApproval>) -> Result<Self, IdentityError> {
        if approvals.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "guardian recovery approvals",
            });
        }
        let approvals = BoundedVec::new("guardian recovery approvals", approvals)?;
        let values = approvals.as_slice();
        for pair in values.windows(2) {
            let left = pair[0].body().guardian_grant_id();
            let right = pair[1].body().guardian_grant_id();
            if left == right {
                return Err(IdentityError::DuplicateElement {
                    resource: "guardian recovery approvals",
                });
            }
            if left > right {
                return Err(IdentityError::NonCanonical);
            }
        }

        let first = &values[0];
        for approval in &values[1..] {
            if approval.body().protected_account_id() != first.body().protected_account_id()
                || approval.body().recovery_id() != first.body().recovery_id()
                || approval.body().decision() != first.body().decision()
                || approval.opening().guardian_set_root() != first.opening().guardian_set_root()
                || approval.opening().grant().recovery_policy_id()
                    != first.opening().grant().recovery_policy_id()
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "guardian approval set subject",
                });
            }
        }
        for left in 0..values.len() {
            for right in (left + 1)..values.len() {
                let left_grant = values[left].opening().grant();
                let right_grant = values[right].opening().grant();
                if left_grant.guardian_account_id() == right_grant.guardian_account_id()
                    || left_grant.guardian_signing_key() == right_grant.guardian_signing_key()
                    || values[left].opening().leaf_index() == values[right].opening().leaf_index()
                {
                    return Err(IdentityError::DuplicateElement {
                        resource: "guardian authority",
                    });
                }
            }
        }
        Ok(Self(approvals))
    }

    /// Merge two compatible partial approval sets idempotently.
    pub fn merge(&self, other: &Self) -> Result<Self, IdentityError> {
        if self.recovery_id() != other.recovery_id()
            || self.decision() != other.decision()
            || self.protected_account_id() != other.protected_account_id()
            || self.guardian_set_root() != other.guardian_set_root()
            || self.recovery_policy_id() != other.recovery_policy_id()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian approval merge subject",
            });
        }

        let mut merged = self.as_slice().to_vec();
        for approval in other.as_slice() {
            let grant_id = approval.body().guardian_grant_id();
            match merged
                .iter()
                .find(|candidate| candidate.body().guardian_grant_id() == grant_id)
            {
                Some(existing) if existing == approval => {}
                Some(_) => {
                    return Err(IdentityError::InvalidRelationship {
                        resource: "conflicting guardian approval",
                    });
                }
                None => {
                    if merged.len() == MAX_RECOVERY_GUARDIANS {
                        return Err(IdentityError::limit(
                            "guardian recovery approvals",
                            merged.len() + 1,
                            MAX_RECOVERY_GUARDIANS,
                        ));
                    }
                    merged.push(approval.clone());
                }
            }
        }
        Self::try_new(merged)
    }

    /// Canonically sorted signed approvals.
    pub fn as_slice(&self) -> &[SignedGuardianApproval] {
        self.0.as_slice()
    }

    /// Account protected by every approval.
    pub fn protected_account_id(&self) -> AccountId {
        self.0.as_slice()[0].body().protected_account_id()
    }

    /// Recovery proposal or pending attempt shared by every approval.
    pub fn recovery_id(&self) -> RecoveryId {
        self.0.as_slice()[0].body().recovery_id()
    }

    /// Shared begin or cancel decision.
    pub fn decision(&self) -> GuardianApprovalDecision {
        self.0.as_slice()[0].body().decision()
    }

    /// Public guardian-set root addressed by every opening.
    pub fn guardian_set_root(&self) -> GuardianSetRoot {
        self.0.as_slice()[0].opening().guardian_set_root()
    }

    /// Recovery policy shared by every private grant.
    pub fn recovery_policy_id(&self) -> RecoveryPolicyId {
        self.0.as_slice()[0].opening().grant().recovery_policy_id()
    }

    /// Checked aggregate weight of distinct opened grants.
    pub fn total_weight(&self) -> Result<u64, IdentityError> {
        let mut total = 0_u64;
        for approval in self.as_slice() {
            total = total
                .checked_add(u64::from(approval.opening().grant().weight().get()))
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "guardian approval weight",
                })?;
        }
        Ok(total)
    }

    /// Check aggregate root/count/weight against one authoritative recovery policy.
    pub fn validate_threshold(&self, policy: &RecoveryPolicy) -> Result<(), IdentityError> {
        if policy.id()? != self.recovery_policy_id() {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian approval recovery policy",
            });
        }
        let RecoveryAuthority::GuardianThreshold(threshold) = policy.authority() else {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian approvals for controller recovery policy",
            });
        };
        if threshold.guardian_set_root() != self.guardian_set_root()
            || self.as_slice().len() > usize::from(threshold.guardian_count())
            || self.total_weight()? < u64::from(threshold.required_weight().get())
        {
            return Err(IdentityError::UnsatisfiableThreshold);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for GuardianApprovalSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let approvals = BoundedVec::<SignedGuardianApproval, MAX_RECOVERY_GUARDIANS>::deserialize(
            deserializer,
        )?;
        Self::from_sorted(approvals.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(GuardianApprovalSet, "guardian approval set bytes");

/// Exact immutable facts against which private guardian approvals are verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardianAuthorityContext {
    protected_account_id: AccountId,
    recovery_id: RecoveryId,
    recovery_policy_id: RecoveryPolicyId,
    recovery_policy_version: RecoveryPolicyVersion,
    account_epoch: Epoch,
    decision: GuardianApprovalDecision,
    authority_time: Timestamp,
}

impl GuardianAuthorityContext {
    /// Construct an exact pre-recovery authority context using authenticated explicit time.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        protected_account_id: AccountId,
        recovery_id: RecoveryId,
        recovery_policy_id: RecoveryPolicyId,
        recovery_policy_version: RecoveryPolicyVersion,
        account_epoch: Epoch,
        decision: GuardianApprovalDecision,
        authority_time: Timestamp,
    ) -> Result<Self, IdentityError> {
        if authority_time.as_unix_millis() == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "guardian authority time",
            });
        }
        Ok(Self {
            protected_account_id,
            recovery_id,
            recovery_policy_id,
            recovery_policy_version,
            account_epoch,
            decision,
            authority_time,
        })
    }

    /// Protected account named by every approval and grant.
    pub const fn protected_account_id(self) -> AccountId {
        self.protected_account_id
    }

    /// Exact complete recovery proposal or pending recovery being decided.
    pub const fn recovery_id(self) -> RecoveryId {
        self.recovery_id
    }

    /// Exact authoritative pre-recovery policy identifier.
    pub const fn recovery_policy_id(self) -> RecoveryPolicyId {
        self.recovery_policy_id
    }

    /// Exact authoritative pre-recovery policy version.
    pub const fn recovery_policy_version(self) -> RecoveryPolicyVersion {
        self.recovery_policy_version
    }

    /// Exact pre-recovery account epoch.
    pub const fn account_epoch(self) -> Epoch {
        self.account_epoch
    }

    /// Begin or Cancel decision required from every guardian.
    pub const fn decision(self) -> GuardianApprovalDecision {
        self.decision
    }

    /// Authenticated time at which the approval set is evaluated.
    pub const fn authority_time(self) -> Timestamp {
        self.authority_time
    }
}

/// Unforgeable result proving that exact private guardian authority met its threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGuardianAuthority {
    context: GuardianAuthorityContext,
    guardian_set_root: GuardianSetRoot,
    approval_count: u16,
    total_weight: u64,
}

impl VerifiedGuardianAuthority {
    /// Exact recovery proposal or pending recovery authorized by the guardians.
    pub const fn recovery_id(&self) -> RecoveryId {
        self.context.recovery_id
    }

    /// Exact pre-recovery policy whose private grant set was proven.
    pub const fn recovery_policy_id(&self) -> RecoveryPolicyId {
        self.context.recovery_policy_id
    }

    /// Exact committed guardian-set root verified for every approval.
    pub const fn guardian_set_root(&self) -> GuardianSetRoot {
        self.guardian_set_root
    }

    /// Number of distinct verified guardian grants counted once.
    pub const fn approval_count(&self) -> u16 {
        self.approval_count
    }

    /// Checked aggregate weight of the distinct verified grants.
    pub const fn total_weight(&self) -> u64 {
        self.total_weight
    }
}

/// Verify exact private guardian membership, validity, signatures, and threshold authority.
pub fn verify_guardian_authority(
    policy: &RecoveryPolicy,
    approvals: &GuardianApprovalSet,
    context: &GuardianAuthorityContext,
) -> Result<VerifiedGuardianAuthority, IdentityError> {
    if policy.id()? != context.recovery_policy_id
        || policy.policy_version() != context.recovery_policy_version
    {
        return Err(IdentityError::PolicyVersionMismatch);
    }
    let RecoveryAuthority::GuardianThreshold(threshold) = policy.authority() else {
        return Err(IdentityError::InvalidRelationship {
            resource: "guardian approvals for controller recovery policy",
        });
    };
    if approvals.protected_account_id() != context.protected_account_id
        || approvals.recovery_id() != context.recovery_id
        || approvals.decision() != context.decision
        || approvals.recovery_policy_id() != context.recovery_policy_id
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "guardian approval authority subject",
        });
    }
    if approvals.guardian_set_root() != threshold.guardian_set_root()
        || approvals.as_slice().len() > usize::from(threshold.guardian_count())
    {
        return Err(IdentityError::InvalidProof);
    }

    let mut total_weight = 0_u64;
    for approval in approvals.as_slice() {
        let body = approval.body();
        let opening = approval.opening();
        let grant = opening.grant();
        if body.protected_account_id() != context.protected_account_id
            || body.recovery_id() != context.recovery_id
            || body.decision() != context.decision
            || body.account_epoch() != context.account_epoch
            || body.guardian_grant_id() != opening.guardian_grant_id()
            || grant.protected_account_id() != context.protected_account_id
            || grant.recovery_policy_id() != context.recovery_policy_id
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian approval projected pre-state",
            });
        }
        if body.approved_at() > context.authority_time
            || grant.valid_from_epoch() > context.account_epoch
            || grant
                .expires_at()
                .is_some_and(|expiry| context.authority_time >= expiry)
        {
            return Err(IdentityError::StaleEvidence);
        }

        let proof = MerkleInclusionProof::new(
            u64::from(opening.leaf_index()),
            u64::from(threshold.guardian_count()),
            opening.audit_path().to_vec(),
        )?;
        let leaf = grant.blinded_merkle_leaf(&opening.blinding)?;
        proof.verify(&leaf, *threshold.guardian_set_root().as_digest())?;

        let public_key = PublicKey::from_bytes(grant.guardian_signing_key().as_bytes())
            .map_err(|_| IdentityError::InvalidSignature)?;
        let signature_bytes = approval.signature();
        let signature = Signature::try_from(signature_bytes.as_bytes().as_slice())
            .map_err(|_| IdentityError::InvalidSignature)?;
        public_key
            .verify(&body.signing_bytes()?, &signature)
            .map_err(|_| IdentityError::InvalidSignature)?;

        total_weight = total_weight
            .checked_add(u64::from(grant.weight().get()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "verified guardian approval weight",
            })?;
    }
    if total_weight < u64::from(threshold.required_weight().get()) {
        return Err(IdentityError::UnsatisfiableThreshold);
    }
    if total_weight > threshold.total_weight() {
        return Err(IdentityError::InvalidProof);
    }
    let approval_count = u16::try_from(approvals.as_slice().len()).map_err(|_| {
        IdentityError::ArithmeticOverflow {
            resource: "verified guardian approval count",
        }
    })?;
    Ok(VerifiedGuardianAuthority {
        context: *context,
        guardian_set_root: threshold.guardian_set_root(),
        approval_count,
        total_weight,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecoveryThresholdEvidenceKind {
    ControllerPolicy,
    GuardianApprovals(GuardianApprovalSet),
}

/// Recovery-policy threshold evidence, kept non-circular with account event approval.
///
/// Controller-policy evidence is completed by the containing event's outer controller
/// approvals. Guardian-policy evidence carries mergeable private guardian approvals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryThresholdEvidence {
    recovery_policy_id: RecoveryPolicyId,
    recovery_policy_version: RecoveryPolicyVersion,
    kind: RecoveryThresholdEvidenceKind,
}

impl RecoveryThresholdEvidence {
    /// Name a controller-threshold policy evaluated against outer event approvals.
    pub const fn controller_policy(
        recovery_policy_id: RecoveryPolicyId,
        recovery_policy_version: RecoveryPolicyVersion,
    ) -> Self {
        Self {
            recovery_policy_id,
            recovery_policy_version,
            kind: RecoveryThresholdEvidenceKind::ControllerPolicy,
        }
    }

    /// Attach mergeable approvals from a private guardian threshold.
    pub fn guardian_approvals(
        recovery_policy_id: RecoveryPolicyId,
        recovery_policy_version: RecoveryPolicyVersion,
        approvals: GuardianApprovalSet,
    ) -> Result<Self, IdentityError> {
        if approvals.recovery_policy_id() != recovery_policy_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian evidence recovery policy",
            });
        }
        Ok(Self {
            recovery_policy_id,
            recovery_policy_version,
            kind: RecoveryThresholdEvidenceKind::GuardianApprovals(approvals),
        })
    }

    /// Exact pre-recovery policy identifier.
    pub const fn recovery_policy_id(&self) -> RecoveryPolicyId {
        self.recovery_policy_id
    }

    /// Exact pre-recovery policy version.
    pub const fn recovery_policy_version(&self) -> RecoveryPolicyVersion {
        self.recovery_policy_version
    }

    /// Guardian approvals when the policy uses private guardians.
    pub const fn as_guardian_approvals(&self) -> Option<&GuardianApprovalSet> {
        match &self.kind {
            RecoveryThresholdEvidenceKind::ControllerPolicy => None,
            RecoveryThresholdEvidenceKind::GuardianApprovals(approvals) => Some(approvals),
        }
    }
}

impl Serialize for RecoveryThresholdEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.kind {
            RecoveryThresholdEvidenceKind::ControllerPolicy => (
                1_u16,
                (self.recovery_policy_id, self.recovery_policy_version),
            )
                .serialize(serializer),
            RecoveryThresholdEvidenceKind::GuardianApprovals(approvals) => (
                2_u16,
                (
                    self.recovery_policy_id,
                    self.recovery_policy_version,
                    approvals,
                ),
            )
                .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RecoveryThresholdEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = RecoveryThresholdEvidence;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("v1 recovery threshold evidence")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => {
                        let (policy_id, policy_version) = sequence
                            .next_element::<(RecoveryPolicyId, RecoveryPolicyVersion)>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        Ok(RecoveryThresholdEvidence::controller_policy(
                            policy_id,
                            policy_version,
                        ))
                    }
                    2 => {
                        let (policy_id, policy_version, approvals) = sequence
                            .next_element::<(
                                RecoveryPolicyId,
                                RecoveryPolicyVersion,
                                GuardianApprovalSet,
                            )>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        RecoveryThresholdEvidence::guardian_approvals(
                            policy_id,
                            policy_version,
                            approvals,
                        )
                        .map_err(de::Error::custom)
                    }
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "recovery threshold evidence",
                        code: unsupported,
                    })),
                }
            }
        }
        deserializer.deserialize_tuple(2, Visitor)
    }
}

canonical_schema!(
    RecoveryThresholdEvidence,
    "recovery threshold evidence bytes"
);

/// Start one authoritative recovery only if the durable recovery slot is vacant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BeginRecovery {
    protocol_version: ProtocolVersion,
    expected_pending_recovery: Option<RecoveryId>,
    recovery_id: RecoveryId,
    proposal: RecoveryProposal,
    threshold_evidence: RecoveryThresholdEvidence,
    extensions: Extensions,
}

impl BeginRecovery {
    /// Construct a begin transition with an explicit vacant-slot precondition.
    pub fn try_new(
        protocol_version: ProtocolVersion,
        proposal: RecoveryProposal,
        threshold_evidence: RecoveryThresholdEvidence,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let recovery_id = proposal.recovery_id()?;
        Self::from_wire(
            protocol_version,
            None,
            recovery_id,
            proposal,
            threshold_evidence,
            extensions,
        )
    }

    fn from_wire(
        protocol_version: ProtocolVersion,
        expected_pending_recovery: Option<RecoveryId>,
        recovery_id: RecoveryId,
        proposal: RecoveryProposal,
        threshold_evidence: RecoveryThresholdEvidence,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if expected_pending_recovery.is_some() {
            return Err(IdentityError::InvalidRelationship {
                resource: "begin recovery occupied slot",
            });
        }
        if threshold_evidence.recovery_policy_id() != proposal.plan().recovery_policy_id()
            || threshold_evidence.recovery_policy_version()
                != proposal.plan().recovery_policy_version()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "begin recovery policy evidence",
            });
        }
        if proposal.recovery_id()? != recovery_id {
            return Err(IdentityError::InvalidIdentifier {
                resource: "begin recovery proposal",
            });
        }
        if let Some(approvals) = threshold_evidence.as_guardian_approvals()
            && (approvals.recovery_id() != recovery_id
                || approvals.protected_account_id() != proposal.plan().account_id()
                || approvals.decision() != GuardianApprovalDecision::Begin)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "begin guardian approval subject",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            expected_pending_recovery,
            recovery_id,
            proposal,
            threshold_evidence,
            extensions,
        })
    }

    /// Whether application requires the single authoritative recovery slot vacant.
    pub const fn requires_vacant_recovery_slot(&self) -> bool {
        self.expected_pending_recovery.is_none()
    }

    /// Stable identifier installed into the pending recovery slot.
    pub const fn recovery_id(&self) -> RecoveryId {
        self.recovery_id
    }

    /// Body-only proposal installed by this transition.
    pub const fn proposal(&self) -> &RecoveryProposal {
        &self.proposal
    }

    /// Threshold evidence evaluated under the exact pre-recovery policy.
    pub const fn threshold_evidence(&self) -> &RecoveryThresholdEvidence {
        &self.threshold_evidence
    }
}

impl<'de> Deserialize<'de> for BeginRecovery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            expected_pending_recovery: Option<RecoveryId>,
            recovery_id: RecoveryId,
            proposal: RecoveryProposal,
            threshold_evidence: RecoveryThresholdEvidence,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_wire(
            wire.protocol_version,
            wire.expected_pending_recovery,
            wire.recovery_id,
            wire.proposal,
            wire.threshold_evidence,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(BeginRecovery, "begin recovery operation bytes");

/// Veto an exact pending recovery under the pre-recovery control policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VetoRecovery {
    protocol_version: ProtocolVersion,
    expected_pending_recovery: RecoveryId,
    pre_recovery_control_policy_id: ControlPolicyId,
    freshness: FreshnessEvidence,
    extensions: Extensions,
}

impl VetoRecovery {
    /// Construct a control-policy veto for one exact pending recovery.
    pub fn try_new(
        protocol_version: ProtocolVersion,
        expected_pending_recovery: RecoveryId,
        pre_recovery_control_policy_id: ControlPolicyId,
        freshness: FreshnessEvidence,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            expected_pending_recovery,
            pre_recovery_control_policy_id,
            freshness,
            extensions,
        })
    }

    /// Pending recovery that must exist when this veto is applied.
    pub const fn expected_pending_recovery(&self) -> RecoveryId {
        self.expected_pending_recovery
    }

    /// Pre-recovery control policy used to authorize the outer event approvals.
    pub const fn pre_recovery_control_policy_id(&self) -> ControlPolicyId {
        self.pre_recovery_control_policy_id
    }

    /// Freshness basis required by the pre-recovery veto rule.
    pub const fn freshness(&self) -> &FreshnessEvidence {
        &self.freshness
    }
}

impl<'de> Deserialize<'de> for VetoRecovery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            expected_pending_recovery: RecoveryId,
            pre_recovery_control_policy_id: ControlPolicyId,
            freshness: FreshnessEvidence,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(
            wire.protocol_version,
            wire.expected_pending_recovery,
            wire.pre_recovery_control_policy_id,
            wire.freshness,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(VetoRecovery, "veto recovery operation bytes");

/// Cancel an exact pending recovery with fresh evidence under the same recovery policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CancelRecovery {
    protocol_version: ProtocolVersion,
    expected_pending_recovery: RecoveryId,
    threshold_evidence: RecoveryThresholdEvidence,
    freshness: FreshnessEvidence,
    extensions: Extensions,
}

impl CancelRecovery {
    /// Construct a recovery-policy cancellation for one exact pending attempt.
    pub fn try_new(
        protocol_version: ProtocolVersion,
        expected_pending_recovery: RecoveryId,
        threshold_evidence: RecoveryThresholdEvidence,
        freshness: FreshnessEvidence,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if let Some(approvals) = threshold_evidence.as_guardian_approvals()
            && (approvals.recovery_id() != expected_pending_recovery
                || approvals.decision() != GuardianApprovalDecision::Cancel)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "cancel guardian approval subject",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            expected_pending_recovery,
            threshold_evidence,
            freshness,
            extensions,
        })
    }

    /// Pending recovery that must exist when this cancellation is applied.
    pub const fn expected_pending_recovery(&self) -> RecoveryId {
        self.expected_pending_recovery
    }

    /// Same pre-recovery threshold evidence required by the original begin.
    pub const fn threshold_evidence(&self) -> &RecoveryThresholdEvidence {
        &self.threshold_evidence
    }

    /// Freshness basis for cancellation under the original recovery policy.
    pub const fn freshness(&self) -> &FreshnessEvidence {
        &self.freshness
    }
}

impl<'de> Deserialize<'de> for CancelRecovery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            expected_pending_recovery: RecoveryId,
            threshold_evidence: RecoveryThresholdEvidence,
            freshness: FreshnessEvidence,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(
            wire.protocol_version,
            wire.expected_pending_recovery,
            wire.threshold_evidence,
            wire.freshness,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(CancelRecovery, "cancel recovery operation bytes");

/// Provider-observed begin intent and its deterministic quorum delay anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryDelayAnchor {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    recovery_id: RecoveryId,
    begin_proposal_id: ProposalId,
    provider_policy_id: ProviderPolicyId,
    required_quorum: ProviderQuorum,
    observed_at: Timestamp,
    receipts: ProviderReceipts,
    extensions: Extensions,
}

impl RecoveryDelayAnchor {
    /// Construct evidence whose anchor is the quorum-th earliest distinct observation.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        protocol_version: ProtocolVersion,
        account_id: AccountId,
        recovery_id: RecoveryId,
        begin_proposal_id: ProposalId,
        provider_policy_id: ProviderPolicyId,
        required_quorum: ProviderQuorum,
        receipts: ProviderReceipts,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let observed_at =
            Self::derive_observed_at(account_id, begin_proposal_id, required_quorum, &receipts)?;
        Self::from_wire(
            protocol_version,
            account_id,
            recovery_id,
            begin_proposal_id,
            provider_policy_id,
            required_quorum,
            observed_at,
            receipts,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_wire(
        protocol_version: ProtocolVersion,
        account_id: AccountId,
        recovery_id: RecoveryId,
        begin_proposal_id: ProposalId,
        provider_policy_id: ProviderPolicyId,
        required_quorum: ProviderQuorum,
        observed_at: Timestamp,
        receipts: ProviderReceipts,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        let expected =
            Self::derive_observed_at(account_id, begin_proposal_id, required_quorum, &receipts)?;
        if observed_at != expected {
            return Err(IdentityError::InvalidRelationship {
                resource: "recovery delay anchor timestamp",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            account_id,
            recovery_id,
            begin_proposal_id,
            provider_policy_id,
            required_quorum,
            observed_at,
            receipts,
            extensions,
        })
    }

    fn derive_observed_at(
        account_id: AccountId,
        begin_proposal_id: ProposalId,
        required_quorum: ProviderQuorum,
        receipts: &ProviderReceipts,
    ) -> Result<Timestamp, IdentityError> {
        let quorum = usize::from(required_quorum.get());
        if receipts.as_slice().len() < quorum {
            return Err(IdentityError::UnsatisfiableThreshold);
        }
        let mut observations = Vec::with_capacity(receipts.as_slice().len());
        for receipt in receipts.as_slice() {
            if receipt.entry().account_id() != account_id
                || receipt.entry().subject()
                    != crate::ProviderLogSubject::EventIntent(begin_proposal_id)
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "recovery delay receipt subject",
                });
            }
            observations.push(receipt.entry().observed_at());
        }
        observations.sort_unstable();
        Ok(observations[quorum - 1])
    }

    /// Account whose recovery begin intent was observed.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact recovery proposal whose delay is anchored.
    pub const fn recovery_id(&self) -> RecoveryId {
        self.recovery_id
    }

    /// Exact begin-event proposal whose provider observations started the delay.
    pub const fn begin_proposal_id(&self) -> ProposalId {
        self.begin_proposal_id
    }

    /// Pre-recovery provider policy under which the observation quorum was evaluated.
    pub const fn provider_policy_id(&self) -> ProviderPolicyId {
        self.provider_policy_id
    }

    /// Minimum number of distinct configured provider observations required.
    pub const fn required_quorum(&self) -> ProviderQuorum {
        self.required_quorum
    }

    /// Deterministic quorum-th earliest provider observation.
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Sorted receipts from distinct providers.
    pub const fn receipts(&self) -> &ProviderReceipts {
        &self.receipts
    }
}

impl<'de> Deserialize<'de> for RecoveryDelayAnchor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            recovery_id: RecoveryId,
            begin_proposal_id: ProposalId,
            provider_policy_id: ProviderPolicyId,
            required_quorum: ProviderQuorum,
            observed_at: Timestamp,
            receipts: ProviderReceipts,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_wire(
            wire.protocol_version,
            wire.account_id,
            wire.recovery_id,
            wire.begin_proposal_id,
            wire.provider_policy_id,
            wire.required_quorum,
            wire.observed_at,
            wire.receipts,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(RecoveryDelayAnchor, "recovery delay anchor bytes");

/// Finalize the exact authoritative pending recovery after its provider-observed delay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FinalizeRecovery {
    protocol_version: ProtocolVersion,
    expected_pending_recovery: RecoveryId,
    delay_anchor: RecoveryDelayAnchor,
    finalized_at: Timestamp,
    extensions: Extensions,
}

impl FinalizeRecovery {
    /// Construct finalization for one exact occupied recovery slot.
    pub fn try_new(
        protocol_version: ProtocolVersion,
        expected_pending_recovery: RecoveryId,
        delay_anchor: RecoveryDelayAnchor,
        finalized_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if expected_pending_recovery != delay_anchor.recovery_id() {
            return Err(IdentityError::InvalidRelationship {
                resource: "finalize recovery delay anchor",
            });
        }
        if finalized_at < delay_anchor.observed_at() {
            return Err(IdentityError::InvalidRelationship {
                resource: "finalize recovery time",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            expected_pending_recovery,
            delay_anchor,
            finalized_at,
            extensions,
        })
    }

    /// Pending recovery that must exist when finalization is applied.
    pub const fn expected_pending_recovery(&self) -> RecoveryId {
        self.expected_pending_recovery
    }

    /// Quorum-observed delay anchor for the begin intent.
    pub const fn delay_anchor(&self) -> &RecoveryDelayAnchor {
        &self.delay_anchor
    }

    /// Explicit historical finalization time checked against the delay and expiry.
    pub const fn finalized_at(&self) -> Timestamp {
        self.finalized_at
    }
}

impl<'de> Deserialize<'de> for FinalizeRecovery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            expected_pending_recovery: RecoveryId,
            delay_anchor: RecoveryDelayAnchor,
            finalized_at: Timestamp,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(
            wire.protocol_version,
            wire.expected_pending_recovery,
            wire.delay_anchor,
            wire.finalized_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(FinalizeRecovery, "finalize recovery operation bytes");

/// Exact last authority object shared by every branch in a fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkCommonAncestor {
    /// The branches conflict at the first account event.
    Genesis(GenesisAnchor),
    /// The branches share one ordinary account event.
    Event(EventId),
}

impl ForkCommonAncestor {
    /// Genesis anchor when the conflict is between first events.
    pub const fn genesis_anchor(self) -> Option<GenesisAnchor> {
        match self {
            Self::Genesis(anchor) => Some(anchor),
            Self::Event(_) => None,
        }
    }

    /// Ordinary common event when at least one event precedes the branches.
    pub const fn event_id(self) -> Option<EventId> {
        match self {
            Self::Genesis(_) => None,
            Self::Event(event_id) => Some(event_id),
        }
    }
}

impl Serialize for ForkCommonAncestor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Genesis(anchor) => (1_u16, anchor).serialize(serializer),
            Self::Event(event_id) => (2_u16, event_id).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ForkCommonAncestor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ForkCommonAncestor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("v1 fork common ancestor")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => sequence
                        .next_element::<GenesisAnchor>()?
                        .map(ForkCommonAncestor::Genesis)
                        .ok_or_else(|| de::Error::invalid_length(1, &self)),
                    2 => sequence
                        .next_element::<EventId>()?
                        .map(ForkCommonAncestor::Event)
                        .ok_or_else(|| de::Error::invalid_length(1, &self)),
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "fork common ancestor",
                        code: unsupported,
                    })),
                }
            }
        }
        deserializer.deserialize_tuple(2, Visitor)
    }
}

canonical_schema!(ForkCommonAncestor, "fork common ancestor bytes");

/// Complete bounded descriptor of all currently known heads of one account fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ForkDescriptor {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    common_ancestor: ForkCommonAncestor,
    heads: BoundedVec<EventId, MAX_FORK_HEADS>,
    extensions: Extensions,
}

impl ForkDescriptor {
    /// Sort and construct a complete set of at least two distinct branch heads.
    pub fn try_new(
        protocol_version: ProtocolVersion,
        account_id: AccountId,
        common_ancestor: ForkCommonAncestor,
        mut heads: Vec<EventId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        heads.sort_unstable();
        Self::from_sorted(
            protocol_version,
            account_id,
            common_ancestor,
            heads,
            extensions,
        )
    }

    fn from_sorted(
        protocol_version: ProtocolVersion,
        account_id: AccountId,
        common_ancestor: ForkCommonAncestor,
        heads: Vec<EventId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if heads.len() < 2 {
            return Err(IdentityError::EmptyCollection {
                resource: "fork branch heads",
            });
        }
        validate_strictly_sorted(&heads, "fork branch heads")?;
        if common_ancestor
            .event_id()
            .is_some_and(|ancestor| heads.binary_search(&ancestor).is_ok())
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "fork ancestor/head",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            account_id,
            common_ancestor,
            heads: BoundedVec::new("fork branch heads", heads)?,
            extensions,
        })
    }

    /// Account whose control history forked.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Last authority object shared by every declared branch.
    pub const fn common_ancestor(&self) -> ForkCommonAncestor {
        self.common_ancestor
    }

    /// Complete sorted set of currently known branch heads.
    pub fn heads(&self) -> &[EventId] {
        self.heads.as_slice()
    }

    /// Derive the identifier from only the common ancestor and complete head set.
    pub fn fork_id(&self) -> Result<ForkId, IdentityError> {
        let encoded = encode_wire(&(self.common_ancestor, self.heads.as_slice()))?;
        Ok(ForkId::from_digest(hash_bytes(HashDomain::Fork, &encoded)))
    }
}

impl<'de> Deserialize<'de> for ForkDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            common_ancestor: ForkCommonAncestor,
            heads: BoundedVec<EventId, MAX_FORK_HEADS>,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_sorted(
            wire.protocol_version,
            wire.account_id,
            wire.common_ancestor,
            wire.heads.into_vec(),
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(ForkDescriptor, "fork descriptor bytes");

/// V1 fork resolution: choose one declared branch and add monotonic revocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolveFork {
    protocol_version: ProtocolVersion,
    fork_id: ForkId,
    fork: ForkDescriptor,
    selected_head: EventId,
    revoked_controllers: BoundedVec<ControllerId, MAX_CONTROLLERS>,
    revoked_devices: BoundedVec<DeviceId, MAX_DEVICES>,
    extensions: Extensions,
}

impl ResolveFork {
    /// Construct a choose-one-branch resolution with sorted additive revocations.
    pub fn try_new(
        protocol_version: ProtocolVersion,
        fork: ForkDescriptor,
        selected_head: EventId,
        mut revoked_controllers: Vec<ControllerId>,
        mut revoked_devices: Vec<DeviceId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let fork_id = fork.fork_id()?;
        revoked_controllers.sort_unstable();
        revoked_devices.sort_unstable();
        Self::from_sorted(
            protocol_version,
            fork_id,
            fork,
            selected_head,
            revoked_controllers,
            revoked_devices,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_sorted(
        protocol_version: ProtocolVersion,
        fork_id: ForkId,
        fork: ForkDescriptor,
        selected_head: EventId,
        revoked_controllers: Vec<ControllerId>,
        revoked_devices: Vec<DeviceId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1(protocol_version)?;
        if fork.fork_id()? != fork_id {
            return Err(IdentityError::InvalidIdentifier {
                resource: "fork resolution descriptor",
            });
        }
        if fork.heads().binary_search(&selected_head).is_err() {
            return Err(IdentityError::InvalidRelationship {
                resource: "fork selected branch",
            });
        }
        validate_strictly_sorted(&revoked_controllers, "fork controller revocations")?;
        validate_strictly_sorted(&revoked_devices, "fork device revocations")?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version,
            fork_id,
            fork,
            selected_head,
            revoked_controllers: BoundedVec::new(
                "fork controller revocations",
                revoked_controllers,
            )?,
            revoked_devices: BoundedVec::new("fork device revocations", revoked_devices)?,
            extensions,
        })
    }

    /// Complete fork descriptor whose revision/head set must still match.
    pub const fn fork(&self) -> &ForkDescriptor {
        &self.fork
    }

    /// Exact existing branch selected as the authority basis.
    pub const fn selected_head(&self) -> EventId {
        self.selected_head
    }

    /// Sorted controller revocations added to the selected branch state.
    pub fn revoked_controllers(&self) -> &[ControllerId] {
        self.revoked_controllers.as_slice()
    }

    /// Sorted device revocations added to the selected branch state.
    pub fn revoked_devices(&self) -> &[DeviceId] {
        self.revoked_devices.as_slice()
    }
}

impl<'de> Deserialize<'de> for ResolveFork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            fork_id: ForkId,
            fork: ForkDescriptor,
            selected_head: EventId,
            revoked_controllers: BoundedVec<ControllerId, MAX_CONTROLLERS>,
            revoked_devices: BoundedVec<DeviceId, MAX_DEVICES>,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_sorted(
            wire.protocol_version,
            wire.fork_id,
            wire.fork,
            wire.selected_head,
            wire.revoked_controllers.into_vec(),
            wire.revoked_devices.into_vec(),
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(ResolveFork, "resolve fork operation bytes");
