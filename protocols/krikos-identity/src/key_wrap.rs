//! Canonical application group-key wrap headers and recipient sets.

use std::fmt;

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::CryptoRng;
use serde::{Deserialize, Deserializer, Serialize, de};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    AccountId, AccountRevision, AccountState, AgreementPublicKey, ApplicationId, CryptoSuiteId,
    DeviceAuthorization, DeviceId, Digest, Epoch, Extensions, GroupId, GroupKeyEpoch,
    GroupKeyWrapId, IdentityError, ProjectedDeviceLifecycle, ProjectionLifecycle, ProtocolVersion,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_DEVICES, MAX_ENCODED_OBJECT_BYTES, MAX_KEY_WRAP_BYTES},
    schema::{BoundedBytes, BoundedVec},
    types::{HashDomain, hash_bytes},
};

const GROUP_KEY_BYTES: usize = 32;
const KEY_WRAP_TAG_BYTES: usize = 16;
const KEY_WRAP_CIPHERTEXT_BYTES: usize = GROUP_KEY_BYTES + KEY_WRAP_TAG_BYTES;
const KEY_WRAP_KDF_CONTEXT: &str = "KRIKOS-ID/group-key-wrap-key/v1";
const KEY_WRAP_KDF_MATERIAL_BYTES: usize = 32 + 32 + 32;

fn v1_crypto_suite_id() -> Result<CryptoSuiteId, IdentityError> {
    crate::CryptoSuiteDescriptor::v1()?.crypto_suite_id()
}

fn validate_v1_crypto_suite(crypto_suite_id: CryptoSuiteId) -> Result<(), IdentityError> {
    if crypto_suite_id != v1_crypto_suite_id()? {
        return Err(IdentityError::UnsupportedKeyWrapSuite);
    }
    Ok(())
}

fn validate_distribution_lifecycle(state: &AccountState) -> Result<(), IdentityError> {
    match state.lifecycle() {
        ProjectionLifecycle::Active
        | ProjectionLifecycle::MigrationPending
        | ProjectionLifecycle::MigrationDual => Ok(()),
        ProjectionLifecycle::RecoveryPending => Err(IdentityError::RecoveryPending),
        ProjectionLifecycle::Forked => Err(IdentityError::AccountForked),
        ProjectionLifecycle::UpgradePending => Err(IdentityError::ProtocolUpgradeReadOnly),
        ProjectionLifecycle::Retired => Err(IdentityError::AccountRetired),
    }
}

/// A fixed-size application group key which erases its bytes when dropped.
pub struct GroupKey(Zeroizing<[u8; GROUP_KEY_BYTES]>);

impl GroupKey {
    /// Take ownership of an exact 256-bit application group key.
    pub fn new(bytes: [u8; GROUP_KEY_BYTES]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the exact group-key bytes.
    pub fn as_bytes(&self) -> &[u8; GROUP_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for GroupKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GroupKey(<redacted>)")
    }
}

/// A reusable recipient X25519 secret which erases its bytes when dropped.
///
/// This type is intentionally neither `Copy` nor `Clone`.
pub struct AgreementSecretKey(StaticSecret);

impl AgreementSecretKey {
    /// Take ownership of 32 bytes of X25519 secret-key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Derive the public X25519 key corresponding to this secret.
    pub fn public_key(&self) -> Result<AgreementPublicKey, IdentityError> {
        let public_key = PublicKey::from(&self.0);
        AgreementPublicKey::x25519(public_key.to_bytes())
    }

    /// Derive a contributory X25519 shared secret for another crate-owned protocol.
    pub(crate) fn diffie_hellman(
        &self,
        peer: AgreementPublicKey,
    ) -> Result<SharedSecret, IdentityError> {
        let peer = PublicKey::from(*peer.as_bytes());
        let shared_secret = self.0.diffie_hellman(&peer);
        validate_contributory(&shared_secret)?;
        Ok(shared_secret)
    }
}

impl fmt::Debug for AgreementSecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AgreementSecretKey(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DistributionRecipient {
    device_id: DeviceId,
    agreement_public_key: AgreementPublicKey,
    authorization_epoch: Epoch,
}

/// Validated application-group membership at one authoritative account revision.
///
/// Construction derives every device authorization and lifecycle from [`AccountState`].
/// The caller supplies the complete application-defined group membership as device IDs;
/// the resulting private recipient records cannot be forged or lifecycle-labelled later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKeyDistributionSnapshot {
    crypto_suite_id: CryptoSuiteId,
    account_id: AccountId,
    application_id: ApplicationId,
    group_id: GroupId,
    authorizing_account_epoch: Epoch,
    group_key_epoch: GroupKeyEpoch,
    account_revision: AccountRevision,
    recipients: Vec<DistributionRecipient>,
}

impl GroupKeyDistributionSnapshot {
    /// Validate and capture a complete application-group membership from account post-state.
    ///
    /// `expected_recipient_ids` is the application's complete membership decision for this
    /// exact group and revision. Every named device must exist, be active, and already be
    /// authorized at the state's exact epoch. Input order is not significant. Active,
    /// migration-pending, and migration-dual projections are eligible; signature-suite
    /// migration leaves the fixed v1 key-wrap KEM/KDF/AEAD profile unchanged. Recovery,
    /// forked, upgraded/read-only, and retired projections fail before recipient processing.
    pub fn from_post_state(
        state: &AccountState,
        application_id: ApplicationId,
        group_id: GroupId,
        group_key_epoch: GroupKeyEpoch,
        mut expected_recipient_ids: Vec<DeviceId>,
    ) -> Result<Self, IdentityError> {
        // Candidate and dual migration states intentionally remain eligible: the fixed
        // v1 X25519/BLAKE3/XChaCha20-Poly1305 wrap suite does not use controller
        // signature keys and is unchanged throughout the signature-suite migration.
        validate_distribution_lifecycle(state)?;
        if expected_recipient_ids.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "group key distribution membership",
            });
        }
        if expected_recipient_ids.len() > MAX_DEVICES {
            return Err(IdentityError::limit(
                "group key distribution membership",
                expected_recipient_ids.len(),
                MAX_DEVICES,
            ));
        }
        expected_recipient_ids.sort_unstable();
        if expected_recipient_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(IdentityError::DuplicateElement {
                resource: "group key distribution membership",
            });
        }

        let mut recipients = Vec::with_capacity(expected_recipient_ids.len());
        for device_id in expected_recipient_ids {
            let device = state
                .devices()
                .binary_search_by_key(&device_id, |candidate| candidate.id())
                .ok()
                .map(|index| &state.devices()[index])
                .ok_or(IdentityError::DeviceNotAuthorized)?;
            match device.lifecycle() {
                ProjectedDeviceLifecycle::Active => {}
                ProjectedDeviceLifecycle::Suspended => {
                    return Err(IdentityError::DeviceSuspended);
                }
                ProjectedDeviceLifecycle::Revoked => return Err(IdentityError::DeviceRevoked),
            }
            if device.authorization_epoch() > state.epoch() {
                return Err(IdentityError::InvalidEpoch);
            }
            recipients.push(DistributionRecipient {
                device_id,
                agreement_public_key: device.descriptor().agreement_key(),
                authorization_epoch: device.authorization_epoch(),
            });
        }

        Ok(Self {
            crypto_suite_id: v1_crypto_suite_id()?,
            account_id: state.account_id(),
            application_id,
            group_id,
            authorizing_account_epoch: state.epoch(),
            group_key_epoch,
            account_revision: state.revision_token(),
            recipients,
        })
    }

    /// Fixed cryptographic suite expected for the distribution.
    pub const fn crypto_suite_id(&self) -> CryptoSuiteId {
        self.crypto_suite_id
    }

    /// Account owning the captured post-state.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Application namespace owning the group.
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Application-defined group identifier.
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// Exact post-transition account epoch used for recipient selection.
    pub const fn authorizing_account_epoch(&self) -> Epoch {
        self.authorizing_account_epoch
    }

    /// New application group-key epoch.
    pub const fn group_key_epoch(&self) -> GroupKeyEpoch {
        self.group_key_epoch
    }

    /// Complete authoritative account revision, including the exact sorted head set.
    pub const fn account_revision(&self) -> &AccountRevision {
        &self.account_revision
    }

    /// Complete sorted application-group membership captured by this snapshot.
    pub fn expected_recipient_ids(&self) -> impl ExactSizeIterator<Item = DeviceId> + '_ {
        self.recipients.iter().map(|recipient| recipient.device_id)
    }

    fn recipient(&self, device_id: DeviceId) -> Result<&DistributionRecipient, IdentityError> {
        self.recipients
            .binary_search_by_key(&device_id, |recipient| recipient.device_id)
            .ok()
            .map(|index| &self.recipients[index])
            .ok_or(IdentityError::DeviceNotAuthorized)
    }

    fn validate_header(&self, header: &GroupKeyWrapHeader) -> Result<(), IdentityError> {
        validate_v1_crypto_suite(self.crypto_suite_id)?;
        if header.crypto_suite_id != self.crypto_suite_id {
            return Err(IdentityError::UnsupportedKeyWrapSuite);
        }
        if header.account_id != self.account_id {
            return Err(IdentityError::AccountMismatch);
        }
        if header.authorizing_account_epoch != self.authorizing_account_epoch {
            return Err(IdentityError::InvalidEpoch);
        }
        if header.application_id != self.application_id
            || header.group_id != self.group_id
            || header.group_key_epoch != self.group_key_epoch
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "group key wrap distribution context",
            });
        }
        Ok(())
    }

    fn validate_output(&self, wraps: &RecipientKeyWraps) -> Result<(), IdentityError> {
        if wraps.as_slice().len() != self.recipients.len()
            || !wraps
                .as_slice()
                .iter()
                .map(WrappedGroupKey::recipient_device_id)
                .eq(self.expected_recipient_ids())
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "group key rotation snapshot output",
            });
        }
        for wrap in wraps.as_slice() {
            self.validate_header(wrap.header())?;
            let recipient = self.recipient(wrap.recipient_device_id())?;
            wrap.header()
                .validate_recipient_binding(recipient.device_id, recipient.agreement_public_key)?;
        }
        Ok(())
    }
}

/// Revision-bound local result of one complete application group-key rotation.
///
/// This artifact is intentionally not a canonical wire type. Persistence must accept
/// the complete artifact, revalidate its account revision immediately before an atomic
/// compare-and-swap, and persist its recipient wraps only as part of that transaction.
/// No constructor or consuming accessor exposes a bare, unbound rotation result.
#[derive(Debug)]
pub struct GroupKeyRotation {
    crypto_suite_id: CryptoSuiteId,
    account_revision: AccountRevision,
    account_id: AccountId,
    application_id: ApplicationId,
    group_id: GroupId,
    authorizing_account_epoch: Epoch,
    group_key_epoch: GroupKeyEpoch,
    expected_recipient_ids: Vec<DeviceId>,
    recipient_key_wraps: RecipientKeyWraps,
}

impl GroupKeyRotation {
    fn from_snapshot(
        snapshot: &GroupKeyDistributionSnapshot,
        recipient_key_wraps: RecipientKeyWraps,
    ) -> Result<Self, IdentityError> {
        snapshot.validate_output(&recipient_key_wraps)?;
        if snapshot.account_revision.account_id() != snapshot.account_id {
            return Err(IdentityError::StorageCorruption);
        }
        Ok(Self {
            crypto_suite_id: snapshot.crypto_suite_id,
            account_revision: snapshot.account_revision.clone(),
            account_id: snapshot.account_id,
            application_id: snapshot.application_id,
            group_id: snapshot.group_id,
            authorizing_account_epoch: snapshot.authorizing_account_epoch,
            group_key_epoch: snapshot.group_key_epoch,
            expected_recipient_ids: snapshot.expected_recipient_ids().collect(),
            recipient_key_wraps,
        })
    }

    /// Fixed v1 wrap suite captured with this rotation.
    pub const fn crypto_suite_id(&self) -> CryptoSuiteId {
        self.crypto_suite_id
    }

    /// Exact account revision that must still be current at persistence time.
    pub const fn account_revision(&self) -> &AccountRevision {
        &self.account_revision
    }

    /// Account owning the rotation.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Application namespace owning the rotated key.
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Application-defined group whose key was rotated.
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// Exact account epoch used to authorize the recipient membership.
    pub const fn authorizing_account_epoch(&self) -> Epoch {
        self.authorizing_account_epoch
    }

    /// New application group-key epoch.
    pub const fn group_key_epoch(&self) -> GroupKeyEpoch {
        self.group_key_epoch
    }

    /// Complete sorted recipient membership captured by the rotation.
    pub fn expected_recipient_ids(&self) -> impl ExactSizeIterator<Item = DeviceId> + '_ {
        self.expected_recipient_ids.iter().copied()
    }

    /// Borrow the recipient wraps while retaining their revision-bound artifact.
    pub const fn recipient_key_wraps(&self) -> &RecipientKeyWraps {
        &self.recipient_key_wraps
    }

    /// Verify that persistence still targets the exact authoritative account revision.
    ///
    /// A fork is reported distinctly so callers cannot treat an unresolved multi-head
    /// projection as an ordinary compare-and-swap race.
    pub fn validate_current_revision(&self, state: &AccountState) -> Result<(), IdentityError> {
        if state.account_id() != self.account_id {
            return Err(IdentityError::AccountMismatch);
        }
        validate_distribution_lifecycle(state)?;
        if state.revision_token() != self.account_revision
            || state.epoch() != self.authorizing_account_epoch
        {
            return Err(IdentityError::StaleRevision);
        }
        Ok(())
    }
}

/// Domain-separated identifier of one device's exact public agreement-key binding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgreementKeyId(Digest);

impl AgreementKeyId {
    /// Derive an identifier bound to both the recipient device and its agreement key.
    pub fn derive(
        device_id: DeviceId,
        agreement_key: AgreementPublicKey,
    ) -> Result<Self, IdentityError> {
        let binding = encode_wire(&(device_id, agreement_key))?;
        Ok(Self(hash_bytes(HashDomain::AgreementKey, &binding)))
    }

    /// Algorithm-tagged digest bytes.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for AgreementKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AgreementKeyId")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for AgreementKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl CanonicalCodec for AgreementKeyId {
    const RESOURCE: &'static str = "agreement key identifier bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Exact 24-byte XChaCha20-Poly1305 nonce used for one recipient wrap.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct KeyWrapNonce([u8; 24]);

impl KeyWrapNonce {
    /// Construct an exact nonce. Freshness and uniqueness are producer/state invariants.
    pub const fn new(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Exact nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

impl fmt::Debug for KeyWrapNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("KeyWrapNonce")
            .field(&"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for KeyWrapNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::new(<[u8; 24]>::deserialize(deserializer)?))
    }
}

impl CanonicalCodec for KeyWrapNonce {
    const RESOURCE: &'static str = "group key wrap nonce bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Canonical associated-data header for one recipient's wrapped application group key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GroupKeyWrapHeader {
    protocol_version: ProtocolVersion,
    crypto_suite_id: CryptoSuiteId,
    account_id: AccountId,
    application_id: ApplicationId,
    group_id: GroupId,
    authorizing_account_epoch: Epoch,
    group_key_epoch: GroupKeyEpoch,
    recipient_device_id: DeviceId,
    recipient_agreement_key_id: AgreementKeyId,
    ephemeral_public_key: AgreementPublicKey,
    nonce: KeyWrapNonce,
    extensions: Extensions,
}

impl GroupKeyWrapHeader {
    /// Construct a header directly from the current recipient authorization.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_recipient(
        crypto_suite_id: CryptoSuiteId,
        account_id: AccountId,
        application_id: ApplicationId,
        group_id: GroupId,
        authorizing_account_epoch: Epoch,
        group_key_epoch: GroupKeyEpoch,
        recipient: &DeviceAuthorization,
        ephemeral_public_key: AgreementPublicKey,
        nonce: KeyWrapNonce,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if recipient.authorization_epoch() > authorizing_account_epoch {
            return Err(IdentityError::InvalidEpoch);
        }
        let recipient_key = recipient.descriptor().agreement_key();
        Self::new_for_binding(
            crypto_suite_id,
            account_id,
            application_id,
            group_id,
            authorizing_account_epoch,
            group_key_epoch,
            recipient.device_id(),
            recipient_key,
            ephemeral_public_key,
            nonce,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_for_binding(
        crypto_suite_id: CryptoSuiteId,
        account_id: AccountId,
        application_id: ApplicationId,
        group_id: GroupId,
        authorizing_account_epoch: Epoch,
        group_key_epoch: GroupKeyEpoch,
        recipient_device_id: DeviceId,
        recipient_agreement_key: AgreementPublicKey,
        ephemeral_public_key: AgreementPublicKey,
        nonce: KeyWrapNonce,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if ephemeral_public_key == recipient_agreement_key {
            return Err(IdentityError::InvalidRelationship {
                resource: "ephemeral and recipient agreement keys",
            });
        }
        let recipient_agreement_key_id =
            AgreementKeyId::derive(recipient_device_id, recipient_agreement_key)?;
        Self::from_fields(
            crypto_suite_id,
            account_id,
            application_id,
            group_id,
            authorizing_account_epoch,
            group_key_epoch,
            recipient_device_id,
            recipient_agreement_key_id,
            ephemeral_public_key,
            nonce,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_fields(
        crypto_suite_id: CryptoSuiteId,
        account_id: AccountId,
        application_id: ApplicationId,
        group_id: GroupId,
        authorizing_account_epoch: Epoch,
        group_key_epoch: GroupKeyEpoch,
        recipient_device_id: DeviceId,
        recipient_agreement_key_id: AgreementKeyId,
        ephemeral_public_key: AgreementPublicKey,
        nonce: KeyWrapNonce,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_v1_crypto_suite(crypto_suite_id)?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            crypto_suite_id,
            account_id,
            application_id,
            group_id,
            authorizing_account_epoch,
            group_key_epoch,
            recipient_device_id,
            recipient_agreement_key_id,
            ephemeral_public_key,
            nonce,
            extensions,
        })
    }

    /// Cryptographic suite governing KEM, KDF, and AEAD interpretation.
    pub const fn crypto_suite_id(&self) -> CryptoSuiteId {
        self.crypto_suite_id
    }

    /// Account whose state authorizes the recipient set.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Application namespace owning the group.
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Application-defined group identifier.
    pub const fn group_id(&self) -> GroupId {
        self.group_id
    }

    /// Account epoch against which the recipient authorization was evaluated.
    pub const fn authorizing_account_epoch(&self) -> Epoch {
        self.authorizing_account_epoch
    }

    /// Independent application group-key epoch.
    pub const fn group_key_epoch(&self) -> GroupKeyEpoch {
        self.group_key_epoch
    }

    /// Intended recipient device.
    pub const fn recipient_device_id(&self) -> DeviceId {
        self.recipient_device_id
    }

    /// Recipient agreement-key binding identifier.
    pub const fn recipient_agreement_key_id(&self) -> AgreementKeyId {
        self.recipient_agreement_key_id
    }

    /// Fresh X25519 public key generated for this one recipient wrap.
    pub const fn ephemeral_public_key(&self) -> AgreementPublicKey {
        self.ephemeral_public_key
    }

    /// Fresh XChaCha20-Poly1305 nonce generated for this one recipient wrap.
    pub const fn nonce(&self) -> KeyWrapNonce {
        self.nonce
    }

    /// Authenticated associated-data extension fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Validate this wire header against a state-supplied recipient authorization.
    pub fn validate_recipient(&self, recipient: &DeviceAuthorization) -> Result<(), IdentityError> {
        self.validate_recipient_binding(
            recipient.device_id(),
            recipient.descriptor().agreement_key(),
        )
    }

    fn validate_recipient_binding(
        &self,
        recipient_device_id: DeviceId,
        recipient_agreement_key: AgreementPublicKey,
    ) -> Result<(), IdentityError> {
        if self.recipient_device_id != recipient_device_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "group key wrap recipient device",
            });
        }
        let expected_key_id = AgreementKeyId::derive(recipient_device_id, recipient_agreement_key)?;
        if self.recipient_agreement_key_id != expected_key_id {
            return Err(IdentityError::InvalidIdentifier {
                resource: "recipient agreement key",
            });
        }
        if self.ephemeral_public_key == recipient_agreement_key {
            return Err(IdentityError::InvalidRelationship {
                resource: "ephemeral and recipient agreement keys",
            });
        }
        Ok(())
    }

    fn same_distribution_context(&self, other: &Self) -> bool {
        self.crypto_suite_id == other.crypto_suite_id
            && self.account_id == other.account_id
            && self.application_id == other.application_id
            && self.group_id == other.group_id
            && self.authorizing_account_epoch == other.authorizing_account_epoch
            && self.group_key_epoch == other.group_key_epoch
            && self.extensions == other.extensions
    }
}

impl<'de> Deserialize<'de> for GroupKeyWrapHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            crypto_suite_id: CryptoSuiteId,
            account_id: AccountId,
            application_id: ApplicationId,
            group_id: GroupId,
            authorizing_account_epoch: Epoch,
            group_key_epoch: GroupKeyEpoch,
            recipient_device_id: DeviceId,
            recipient_agreement_key_id: AgreementKeyId,
            ephemeral_public_key: AgreementPublicKey,
            nonce: KeyWrapNonce,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::from_fields(
            wire.crypto_suite_id,
            wire.account_id,
            wire.application_id,
            wire.group_id,
            wire.authorizing_account_epoch,
            wire.group_key_epoch,
            wire.recipient_device_id,
            wire.recipient_agreement_key_id,
            wire.ephemeral_public_key,
            wire.nonce,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for GroupKeyWrapHeader {
    const RESOURCE: &'static str = "group key wrap header bytes";
    const MAX_ENCODED_BYTES: usize = MAX_KEY_WRAP_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

fn derive_wrapping_key(
    shared_secret: &SharedSecret,
    ephemeral_public_key: AgreementPublicKey,
    recipient_public_key: AgreementPublicKey,
) -> Zeroizing<[u8; GROUP_KEY_BYTES]> {
    let mut key_material = Zeroizing::new([0_u8; KEY_WRAP_KDF_MATERIAL_BYTES]);
    key_material[..32].copy_from_slice(shared_secret.as_bytes());
    key_material[32..64].copy_from_slice(ephemeral_public_key.as_bytes());
    key_material[64..].copy_from_slice(recipient_public_key.as_bytes());
    Zeroizing::new(blake3::derive_key(KEY_WRAP_KDF_CONTEXT, &key_material[..]))
}

fn wrap_associated_data(
    header: &GroupKeyWrapHeader,
    outer_extensions: &Extensions,
) -> Result<Vec<u8>, IdentityError> {
    encode_wire(&(header, outer_extensions))
}

#[cfg(any(feature = "os-rng", test))]
fn generate_wrap_randomness_with<F, E>(
    mut fill: F,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 24]), IdentityError>
where
    F: FnMut(&mut [u8]) -> Result<(), E>,
{
    let mut ephemeral_secret = Zeroizing::new([0_u8; 32]);
    fill(&mut ephemeral_secret[..]).map_err(|_| IdentityError::EntropyUnavailable)?;
    let mut nonce = [0_u8; 24];
    fill(&mut nonce).map_err(|_| IdentityError::EntropyUnavailable)?;
    Ok((ephemeral_secret, nonce))
}

fn validate_contributory(shared_secret: &SharedSecret) -> Result<(), IdentityError> {
    if !shared_secret.was_contributory() {
        return Err(IdentityError::InvalidPublicKey {
            kind: crate::AlgorithmKind::Agreement,
        });
    }
    Ok(())
}

fn wrap_group_key_with_material(
    snapshot: &GroupKeyDistributionSnapshot,
    group_key: &GroupKey,
    recipient: &DistributionRecipient,
    ephemeral_secret_bytes: Zeroizing<[u8; 32]>,
    nonce_bytes: [u8; 24],
) -> Result<WrappedGroupKey, IdentityError> {
    validate_v1_crypto_suite(snapshot.crypto_suite_id)?;
    if recipient.authorization_epoch > snapshot.authorizing_account_epoch {
        return Err(IdentityError::InvalidEpoch);
    }
    let ephemeral_secret = StaticSecret::from(*ephemeral_secret_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let ephemeral_public_key = AgreementPublicKey::x25519(ephemeral_public.to_bytes())?;
    let recipient_public_key = recipient.agreement_public_key;
    let recipient_public = PublicKey::from(*recipient_public_key.as_bytes());
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    validate_contributory(&shared_secret)?;
    let wrapping_key =
        derive_wrapping_key(&shared_secret, ephemeral_public_key, recipient_public_key);
    let nonce = KeyWrapNonce::new(nonce_bytes);
    let header = GroupKeyWrapHeader::new_for_binding(
        snapshot.crypto_suite_id,
        snapshot.account_id,
        snapshot.application_id,
        snapshot.group_id,
        snapshot.authorizing_account_epoch,
        snapshot.group_key_epoch,
        recipient.device_id,
        recipient_public_key,
        ephemeral_public_key,
        nonce,
        Extensions::default(),
    )?;
    let outer_extensions = Extensions::default();
    let associated_data = wrap_associated_data(&header, &outer_extensions)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*wrapping_key));
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce_bytes),
            Payload {
                msg: group_key.as_bytes(),
                aad: &associated_data,
            },
        )
        .map_err(|_| IdentityError::KeyWrapAuthenticationFailed)?;
    WrappedGroupKey::new(header, ciphertext, outer_extensions)
}

/// Authenticate and unwrap one exact 32-byte application group key.
///
/// Wrong secrets, modified ciphertext, and modified associated data all return
/// the same non-oracular authentication error after public context validation.
pub fn unwrap_group_key(
    snapshot: &GroupKeyDistributionSnapshot,
    wrapped: &WrappedGroupKey,
    recipient_secret: &AgreementSecretKey,
) -> Result<GroupKey, IdentityError> {
    snapshot.validate_header(wrapped.header())?;
    let recipient = snapshot.recipient(wrapped.recipient_device_id())?;
    wrapped
        .header()
        .validate_recipient_binding(recipient.device_id, recipient.agreement_public_key)?;

    let ephemeral_public_key = wrapped.header().ephemeral_public_key();
    let ephemeral_public = PublicKey::from(*ephemeral_public_key.as_bytes());
    let shared_secret = recipient_secret.0.diffie_hellman(&ephemeral_public);
    validate_contributory(&shared_secret)?;
    let recipient_public_key = recipient.agreement_public_key;
    let wrapping_key =
        derive_wrapping_key(&shared_secret, ephemeral_public_key, recipient_public_key);
    let associated_data = wrap_associated_data(wrapped.header(), wrapped.extensions())?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*wrapping_key));
    let plaintext = cipher
        .decrypt(
            &XNonce::from(*wrapped.header().nonce().as_bytes()),
            Payload {
                msg: wrapped.ciphertext(),
                aad: &associated_data,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| IdentityError::KeyWrapAuthenticationFailed)?;
    let group_key_bytes: [u8; GROUP_KEY_BYTES] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| IdentityError::KeyWrapAuthenticationFailed)?;
    Ok(GroupKey::new(group_key_bytes))
}

/// Produce a revision-bound complete rotation using an explicit cryptographic RNG.
///
/// All post-state recipient records are validated before randomness is consumed.
/// Each recipient then receives an independent ephemeral secret and nonce, and
/// the private artifact constructor rejects reuse or incomplete recipient coverage.
pub fn rotate_group_key_with_rng<R: CryptoRng + ?Sized>(
    snapshot: &GroupKeyDistributionSnapshot,
    group_key: &GroupKey,
    rng: &mut R,
) -> Result<GroupKeyRotation, IdentityError> {
    let mut wraps = Vec::with_capacity(snapshot.recipients.len());
    for recipient in &snapshot.recipients {
        let mut ephemeral_secret = Zeroizing::new([0_u8; 32]);
        rng.fill_bytes(&mut ephemeral_secret[..]);
        let mut nonce = [0_u8; 24];
        rng.fill_bytes(&mut nonce);
        wraps.push(wrap_group_key_with_material(
            snapshot,
            group_key,
            recipient,
            ephemeral_secret,
            nonce,
        )?);
    }
    let wraps = RecipientKeyWraps::new(wraps)?;
    GroupKeyRotation::from_snapshot(snapshot, wraps)
}

/// Produce a revision-bound complete rotation using operating-system entropy.
///
/// Entropy failure aborts the complete operation without returning a partial artifact.
#[cfg(feature = "os-rng")]
#[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
pub fn rotate_group_key(
    snapshot: &GroupKeyDistributionSnapshot,
    group_key: &GroupKey,
) -> Result<GroupKeyRotation, IdentityError> {
    let mut wraps = Vec::with_capacity(snapshot.recipients.len());
    for recipient in &snapshot.recipients {
        let (ephemeral_secret, nonce) = generate_wrap_randomness_with(getrandom::fill)?;
        wraps.push(wrap_group_key_with_material(
            snapshot,
            group_key,
            recipient,
            ephemeral_secret,
            nonce,
        )?);
    }
    let wraps = RecipientKeyWraps::new(wraps)?;
    GroupKeyRotation::from_snapshot(snapshot, wraps)
}

/// One bounded ciphertext carrying a group key to the recipient named by its header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WrappedGroupKey {
    header: GroupKeyWrapHeader,
    ciphertext: BoundedBytes<MAX_KEY_WRAP_BYTES>,
    extensions: Extensions,
}

impl WrappedGroupKey {
    /// Construct one recipient wrap and enforce both ciphertext and complete-envelope bounds.
    pub fn new(
        header: GroupKeyWrapHeader,
        ciphertext: Vec<u8>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if ciphertext.len() != KEY_WRAP_CIPHERTEXT_BYTES {
            return Err(IdentityError::InvalidRelationship {
                resource: "group key wrap ciphertext length",
            });
        }
        let ciphertext = BoundedBytes::new("group key wrap ciphertext bytes", ciphertext)?;
        extensions.validate_critical(&[])?;
        let wrapped = Self {
            header,
            ciphertext,
            extensions,
        };
        let encoded_len = encode_wire(&wrapped)?.len();
        if encoded_len > MAX_KEY_WRAP_BYTES {
            return Err(IdentityError::limit(
                "wrapped group key bytes",
                encoded_len,
                MAX_KEY_WRAP_BYTES,
            ));
        }
        Ok(wrapped)
    }

    /// Exact AEAD associated-data header.
    pub const fn header(&self) -> &GroupKeyWrapHeader {
        &self.header
    }

    /// Recipient device named by the header.
    pub const fn recipient_device_id(&self) -> DeviceId {
        self.header.recipient_device_id
    }

    /// Exact bounded AEAD ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }

    /// Authenticated forward-compatible fields outside the associated-data header.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Derive the identifier of this complete canonical recipient wrap.
    pub fn group_key_wrap_id(&self) -> Result<GroupKeyWrapId, IdentityError> {
        GroupKeyWrapId::derive(self)
    }
}

impl<'de> Deserialize<'de> for WrappedGroupKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            header: GroupKeyWrapHeader,
            ciphertext: BoundedBytes<MAX_KEY_WRAP_BYTES>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.header, wire.ciphertext.into_vec(), wire.extensions)
            .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for WrappedGroupKey {
    const RESOURCE: &'static str = "wrapped group key bytes";
    const MAX_ENCODED_BYTES: usize = MAX_KEY_WRAP_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Canonically sorted, duplicate-free recipient wraps for one group-key distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecipientKeyWraps(BoundedVec<WrappedGroupKey, MAX_DEVICES>);

impl RecipientKeyWraps {
    /// Construct a nonempty set sorted by recipient `DeviceId`.
    pub fn new(mut wraps: Vec<WrappedGroupKey>) -> Result<Self, IdentityError> {
        if wraps.len() > MAX_DEVICES {
            return Err(IdentityError::limit(
                "recipient key wraps",
                wraps.len(),
                MAX_DEVICES,
            ));
        }
        wraps.sort_unstable_by_key(WrappedGroupKey::recipient_device_id);
        Self::from_fields(wraps)
    }

    fn from_fields(wraps: Vec<WrappedGroupKey>) -> Result<Self, IdentityError> {
        if wraps.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "recipient key wraps",
            });
        }
        let wraps = BoundedVec::new("recipient key wraps", wraps)?;
        let first = &wraps.as_slice()[0];
        for pair in wraps.as_slice().windows(2) {
            if pair[0].recipient_device_id() == pair[1].recipient_device_id() {
                return Err(IdentityError::DuplicateElement {
                    resource: "recipient key wrap devices",
                });
            }
            if pair[0].recipient_device_id() > pair[1].recipient_device_id() {
                return Err(IdentityError::NonCanonical);
            }
        }
        for wrap in wraps.as_slice() {
            if !first.header.same_distribution_context(&wrap.header) {
                return Err(IdentityError::InvalidRelationship {
                    resource: "recipient key wrap distribution context",
                });
            }
        }
        for (index, wrap) in wraps.as_slice().iter().enumerate() {
            for other in &wraps.as_slice()[index.saturating_add(1)..] {
                if wrap.header.ephemeral_public_key == other.header.ephemeral_public_key {
                    return Err(IdentityError::DuplicateElement {
                        resource: "recipient key wrap ephemeral public keys",
                    });
                }
                if wrap.header.nonce == other.header.nonce {
                    return Err(IdentityError::DuplicateElement {
                        resource: "recipient key wrap nonces",
                    });
                }
            }
        }

        let set = Self(wraps);
        let encoded_len = encode_wire(&set)?.len();
        if encoded_len > MAX_ENCODED_OBJECT_BYTES {
            return Err(IdentityError::limit(
                "recipient key wrap set bytes",
                encoded_len,
                MAX_ENCODED_OBJECT_BYTES,
            ));
        }
        Ok(set)
    }

    /// Borrow wraps in canonical recipient order.
    pub fn as_slice(&self) -> &[WrappedGroupKey] {
        self.0.as_slice()
    }
}

impl<'de> Deserialize<'de> for RecipientKeyWraps {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wraps = BoundedVec::<WrappedGroupKey, MAX_DEVICES>::deserialize(deserializer)?;
        Self::from_fields(wraps.into_vec()).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for RecipientKeyWraps {
    const RESOURCE: &'static str = "recipient key wrap set bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ENCODED_OBJECT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::generate_wrap_randomness_with;
    use crate::IdentityError;

    #[test]
    fn fallible_entropy_failure_is_reported_without_fallback() {
        let result = generate_wrap_randomness_with(|_| Err(()));
        assert!(matches!(result, Err(IdentityError::EntropyUnavailable)));

        let calls = Cell::new(0_u8);
        let result = generate_wrap_randomness_with(|bytes| {
            calls.set(
                calls
                    .get()
                    .checked_add(1)
                    .expect("test makes exactly two calls"),
            );
            if calls.get() == 1 {
                bytes.fill(0x5a);
                Ok(())
            } else {
                Err(())
            }
        });
        assert!(matches!(result, Err(IdentityError::EntropyUnavailable)));
        assert_eq!(calls.get(), 2);
    }
}
