//! Foundational protocol types and cryptographic algorithm registry.

use std::fmt;

use curve25519_dalek::montgomery::MontgomeryPoint;
use data_encoding::HEXLOWER;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    AlgorithmKind, IdentityError,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
};

macro_rules! algorithm {
    ($name:ident, $kind:expr, $variant:ident, $code:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum $name {
            #[doc = concat!("The v1 ", $doc, ".")]
            $variant,
        }

        impl $name {
            /// Stable v1 wire codepoint.
            pub const fn code(self) -> u16 {
                match self {
                    Self::$variant => $code,
                }
            }

            pub(crate) const fn from_code(code: u16) -> Result<Self, IdentityError> {
                match code {
                    $code => Ok(Self::$variant),
                    other => Err(IdentityError::unsupported_algorithm($kind, other)),
                }
            }
        }

        impl CanonicalCodec for $name {
            const RESOURCE: &'static str = stringify!($name);

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(&self.code())
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                Self::from_code(decode_wire(bytes)?)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.code().serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::from_code(u16::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

algorithm!(
    HashAlgorithm,
    AlgorithmKind::Hash,
    Blake3_256,
    1,
    "BLAKE3-256 hash algorithm"
);
algorithm!(
    SignatureAlgorithm,
    AlgorithmKind::Signature,
    Ed25519,
    1,
    "Ed25519 signature algorithm"
);
algorithm!(
    AgreementAlgorithm,
    AlgorithmKind::Agreement,
    X25519,
    1,
    "X25519 key-agreement algorithm"
);
algorithm!(
    KdfAlgorithm,
    AlgorithmKind::Kdf,
    Blake3DeriveKey,
    1,
    "BLAKE3 derive-key algorithm"
);
algorithm!(
    AeadAlgorithm,
    AlgorithmKind::Aead,
    XChaCha20Poly1305,
    1,
    "XChaCha20-Poly1305 authenticated-encryption algorithm"
);

/// Reserved v1 codepoint for the design's checkpoint-publication record.
///
/// Publication is an availability-plane journal record rather than an authoritative
/// account operation, so this codepoint is never accepted by [`OperationKind`].
pub const RESERVED_PUBLISH_CHECKPOINT_CODE: u16 = 23;

/// Closed registry of authoritative v1 account operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OperationKind {
    /// Authorize a new independently identified device.
    AuthorizeDevice,
    /// Change security-relevant device authorization or capabilities.
    UpdateDeviceAuthorization,
    /// Change only an opaque device metadata commitment.
    UpdateDeviceMetadata,
    /// Temporarily suspend a device.
    SuspendDevice,
    /// Reinstate a suspended device.
    ReinstateDevice,
    /// Terminally revoke a device identifier.
    RevokeDevice,
    /// Replace a device identifier with independently generated keys.
    RotateDeviceKeys,
    /// Add an account controller.
    AddController,
    /// Terminally remove an account controller identifier.
    RemoveController,
    /// Change the account-control policy under the previous policy.
    ChangeControlPolicy,
    /// Change the explicit recovery policy.
    ChangeRecoveryPolicy,
    /// Change the account's minimum transparency-provider policy.
    ChangeProviderPolicy,
    /// Begin a durable delayed recovery attempt.
    BeginRecovery,
    /// Veto a pending recovery under its pre-existing veto policy.
    VetoRecovery,
    /// Cancel a pending recovery.
    CancelRecovery,
    /// Finalize a sufficiently authorized and delayed recovery.
    FinalizeRecovery,
    /// Resolve a complete bounded fork under the common pre-fork policy.
    ResolveFork,
    /// Begin a cross-signed cryptographic-suite migration.
    BeginCryptoMigration,
    /// Activate the overlapping cryptographic suite.
    ActivateCryptoMigration,
    /// Retire the old suite after the overlap period.
    RetireCryptoSuite,
    /// Upgrade the account protocol major version.
    UpgradeProtocol,
    /// Terminally retire the account.
    RetireAccount,
}

impl OperationKind {
    /// Stable v1 operation codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::AuthorizeDevice => 1,
            Self::UpdateDeviceAuthorization => 2,
            Self::UpdateDeviceMetadata => 3,
            Self::SuspendDevice => 4,
            Self::ReinstateDevice => 5,
            Self::RevokeDevice => 6,
            Self::RotateDeviceKeys => 7,
            Self::AddController => 8,
            Self::RemoveController => 9,
            Self::ChangeControlPolicy => 10,
            Self::ChangeRecoveryPolicy => 11,
            Self::ChangeProviderPolicy => 12,
            Self::BeginRecovery => 13,
            Self::VetoRecovery => 14,
            Self::CancelRecovery => 15,
            Self::FinalizeRecovery => 16,
            Self::ResolveFork => 17,
            Self::BeginCryptoMigration => 18,
            Self::ActivateCryptoMigration => 19,
            Self::RetireCryptoSuite => 20,
            Self::UpgradeProtocol => 21,
            Self::RetireAccount => 22,
        }
    }

    /// Decode one closed v1 operation codepoint.
    pub const fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::AuthorizeDevice),
            2 => Ok(Self::UpdateDeviceAuthorization),
            3 => Ok(Self::UpdateDeviceMetadata),
            4 => Ok(Self::SuspendDevice),
            5 => Ok(Self::ReinstateDevice),
            6 => Ok(Self::RevokeDevice),
            7 => Ok(Self::RotateDeviceKeys),
            8 => Ok(Self::AddController),
            9 => Ok(Self::RemoveController),
            10 => Ok(Self::ChangeControlPolicy),
            11 => Ok(Self::ChangeRecoveryPolicy),
            12 => Ok(Self::ChangeProviderPolicy),
            13 => Ok(Self::BeginRecovery),
            14 => Ok(Self::VetoRecovery),
            15 => Ok(Self::CancelRecovery),
            16 => Ok(Self::FinalizeRecovery),
            17 => Ok(Self::ResolveFork),
            18 => Ok(Self::BeginCryptoMigration),
            19 => Ok(Self::ActivateCryptoMigration),
            20 => Ok(Self::RetireCryptoSuite),
            21 => Ok(Self::UpgradeProtocol),
            22 => Ok(Self::RetireAccount),
            RESERVED_PUBLISH_CHECKPOINT_CODE => Err(IdentityError::ReservedCodepoint {
                registry: "account operation",
                code,
            }),
            unsupported => Err(IdentityError::UnsupportedCodepoint {
                registry: "account operation",
                code: unsupported,
            }),
        }
    }
}

impl CanonicalCodec for OperationKind {
    const RESOURCE: &'static str = "account operation kind bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&self.code())
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        Self::from_code(decode_wire(bytes)?)
    }
}

impl Serialize for OperationKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OperationKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_code(u16::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// A 256-bit algorithm-tagged digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest {
    algorithm: HashAlgorithm,
    bytes: [u8; 32],
}

impl Digest {
    /// Construct a digest from its algorithm and exact bytes.
    pub const fn new(algorithm: HashAlgorithm, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }

    /// Hash algorithm used to create this digest.
    pub const fn algorithm(self) -> HashAlgorithm {
        self.algorithm
    }

    /// Digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest")
            .field(&self.to_string())
            .finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.algorithm {
            HashAlgorithm::Blake3_256 => "b3",
        };
        write!(formatter, "{prefix}:{}", HEXLOWER.encode(&self.bytes))
    }
}

impl CanonicalCodec for Digest {
    const RESOURCE: &'static str = "digest bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&(self.algorithm.code(), self.bytes))
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (algorithm, digest): (u16, [u8; 32]) = decode_wire(bytes)?;
        Ok(Self::new(HashAlgorithm::from_code(algorithm)?, digest))
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.algorithm.code(), self.bytes).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (algorithm, bytes) = <(u16, [u8; 32])>::deserialize(deserializer)?;
        let algorithm = HashAlgorithm::from_code(algorithm).map_err(de::Error::custom)?;
        Ok(Self::new(algorithm, bytes))
    }
}

/// Domain separators for protocol-owned v1 identity hashes.
#[allow(dead_code)] // Variants are consumed incrementally by the complete Task 2 schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub(crate) enum HashDomain {
    /// Stable foundation conformance vector.
    TestVector,
    /// Canonical genesis record.
    AccountGenesis,
    /// Domain-separated predecessor of an account's first event.
    GenesisAnchor,
    /// Stable account identifier.
    AccountId,
    /// Controller descriptor identifier.
    ControllerDescriptor,
    /// Controller signing-key binding identifier.
    ControllerKey,
    /// Control-policy identifier.
    ControlPolicy,
    /// Recovery-policy identifier.
    RecoveryPolicy,
    /// Transparency-provider descriptor identifier.
    Provider,
    /// Transparency-provider log identifier.
    ProviderLog,
    /// Account provider-policy identifier.
    ProviderPolicy,
    /// Device public descriptor identifier.
    DeviceDescriptor,
    /// Device-bound agreement-key identifier used by recipient wraps.
    AgreementKey,
    /// Unsigned account event proposal.
    AccountProposal,
    /// Authorized account event.
    AccountEvent,
    /// Exact complete authorization envelope for an account event.
    EventAuthorization,
    /// Account checkpoint.
    AccountCheckpoint,
    /// Signed proposal intent from one controller.
    EventIntentApproval,
    /// Final controller approval body.
    ControllerApproval,
    /// Historical admission evidence.
    AdmissionEvidence,
    /// Capability grant identifier.
    CapabilityGrant,
    /// Capability delegation identifier.
    CapabilityDelegation,
    /// Complete account-state root.
    StateRoot,
    /// Authorized-device set root.
    AuthorizedSet,
    /// Revoked-device set root.
    RevokedSet,
    /// Pairing ticket commitment.
    PairingTicket,
    /// Complete pairing transcript.
    PairingTranscript,
    /// Device presence proof.
    PresenceProof,
    /// Signed application event.
    ApplicationEvent,
    /// Wrapped application group key.
    GroupKeyWrap,
    /// Transparency Merkle leaf.
    MerkleLeaf,
    /// Transparency Merkle interior node.
    MerkleNode,
    /// Empty transparency Merkle tree.
    MerkleEmpty,
    /// Transparency provider signed head.
    ProviderHead,
    /// Transparency provider log entry.
    ProviderLogEntry,
    /// Recovery proposal identifier.
    Recovery,
    /// Recovery guardian grant identifier.
    GuardianGrant,
    /// Complete fork descriptor identifier.
    Fork,
    /// Cryptographic suite descriptor identifier.
    CryptoSuite,
    /// Cryptographic migration identifier.
    CryptoMigration,
    /// Controller old/new key cross-binding.
    CryptoKeyBinding,
    /// Projected cryptographic state identifier.
    CryptoState,
    /// Application namespace identifier.
    ApplicationId,
    /// Application group identifier.
    GroupId,
    /// Private social attestation.
    SocialAttestation,
    /// Pairwise account pseudonym.
    PairwiseId,
    /// Optional public-ledger anchor commitment.
    AnchorCommitment,
}

impl HashDomain {
    pub(crate) const fn prefix(self) -> &'static [u8] {
        match self {
            Self::TestVector => b"KRIKOS-ID/test/v1",
            Self::AccountGenesis => b"KRIKOS-ID/account-genesis/v1",
            Self::GenesisAnchor => b"KRIKOS-ID/genesis-anchor/v1",
            Self::AccountId => b"KRIKOS-ID/account-id/v1",
            Self::ControllerDescriptor => b"KRIKOS-ID/controller/v1",
            Self::ControllerKey => b"KRIKOS-ID/controller-key/v1",
            Self::ControlPolicy => b"KRIKOS-ID/control-policy/v1",
            Self::RecoveryPolicy => b"KRIKOS-ID/recovery-policy/v1",
            Self::Provider => b"KRIKOS-ID/provider/v1",
            Self::ProviderLog => b"KRIKOS-ID/provider-log/v1",
            Self::ProviderPolicy => b"KRIKOS-ID/provider-policy/v1",
            Self::DeviceDescriptor => b"KRIKOS-ID/device/v1",
            Self::AgreementKey => b"KRIKOS-ID/agreement-key/v1",
            Self::AccountProposal => b"KRIKOS-ID/account-proposal/v1",
            Self::AccountEvent => b"KRIKOS-ID/account-event/v1",
            Self::EventAuthorization => b"KRIKOS-ID/event-authorization/v1",
            Self::AccountCheckpoint => b"KRIKOS-ID/account-checkpoint/v1",
            Self::EventIntentApproval => b"KRIKOS-ID/event-intent-approval/v1",
            Self::ControllerApproval => b"KRIKOS-ID/controller-approval/v1",
            Self::AdmissionEvidence => b"KRIKOS-ID/admission-evidence/v1",
            Self::CapabilityGrant => b"KRIKOS-ID/capability-grant/v1",
            Self::CapabilityDelegation => b"KRIKOS-ID/capability-delegation/v1",
            Self::StateRoot => b"KRIKOS-ID/state-root/v1",
            Self::AuthorizedSet => b"KRIKOS-ID/authorized-set/v1",
            Self::RevokedSet => b"KRIKOS-ID/revoked-set/v1",
            Self::PairingTicket => b"KRIKOS-ID/pairing-ticket/v1",
            Self::PairingTranscript => b"KRIKOS-ID/pairing-transcript/v1",
            Self::PresenceProof => b"KRIKOS-ID/presence-proof/v1",
            Self::ApplicationEvent => b"KRIKOS-ID/application-event/v1",
            Self::GroupKeyWrap => b"KRIKOS-ID/group-key-wrap/v1",
            Self::MerkleLeaf => b"KRIKOS-ID/merkle-leaf/v1",
            Self::MerkleNode => b"KRIKOS-ID/merkle-node/v1",
            Self::MerkleEmpty => b"KRIKOS-ID/merkle-empty/v1",
            Self::ProviderHead => b"KRIKOS-ID/provider-head/v1",
            Self::ProviderLogEntry => b"KRIKOS-ID/provider-log-entry/v1",
            Self::Recovery => b"KRIKOS-ID/recovery/v1",
            Self::GuardianGrant => b"KRIKOS-ID/guardian-grant/v1",
            Self::Fork => b"KRIKOS-ID/fork/v1",
            Self::CryptoSuite => b"KRIKOS-ID/crypto-suite/v1",
            Self::CryptoMigration => b"KRIKOS-ID/crypto-migration/v1",
            Self::CryptoKeyBinding => b"KRIKOS-ID/crypto-key-binding/v1",
            Self::CryptoState => b"KRIKOS-ID/crypto-state/v1",
            Self::ApplicationId => b"KRIKOS-ID/application-id/v1",
            Self::GroupId => b"KRIKOS-ID/group-id/v1",
            Self::SocialAttestation => b"KRIKOS-ID/social-attestation/v1",
            Self::PairwiseId => b"KRIKOS-ID/pairwise-id/v1",
            Self::AnchorCommitment => b"KRIKOS-ID/anchor/v1",
        }
    }
}

/// Hash bytes using the v1 algorithm and a mandatory protocol domain separator.
#[allow(dead_code)] // Typed schema derivations are introduced incrementally in Task 2.
pub(crate) fn hash_bytes(domain: HashDomain, payload: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.prefix());
    hasher.update(&[0]);
    hasher.update(payload);
    Digest::new(HashAlgorithm::Blake3_256, *hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{HashDomain, hash_bytes};

    #[test]
    fn domain_separated_hash_vector_is_frozen() {
        let digest = hash_bytes(HashDomain::TestVector, b"abc");
        assert_eq!(
            digest.to_string(),
            "b3:5d2f1aacba9c5e36c83962fd211e1382725e0bd71e4601019730afd05ea06b53"
        );
    }
}

/// Algorithm-tagged Ed25519 public signing key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SigningPublicKey {
    algorithm: SignatureAlgorithm,
    bytes: [u8; 32],
}

impl SigningPublicKey {
    /// Validate and construct an Ed25519 public key.
    pub fn ed25519(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        let key = krikos_base::PublicKey::from_bytes(&bytes).map_err(|_| {
            IdentityError::InvalidPublicKey {
                kind: AlgorithmKind::Signature,
            }
        })?;
        if key.as_verifying_key().is_weak() {
            return Err(IdentityError::InvalidPublicKey {
                kind: AlgorithmKind::Signature,
            });
        }
        Ok(Self {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes,
        })
    }

    /// Signature algorithm for this key.
    pub const fn algorithm(self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Exact public-key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for SigningPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningPublicKey")
            .field("algorithm", &self.algorithm)
            .field("key", &HEXLOWER.encode(&self.bytes))
            .finish()
    }
}

impl CanonicalCodec for SigningPublicKey {
    const RESOURCE: &'static str = "signing public key bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&(self.algorithm.code(), self.bytes))
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (algorithm, key): (u16, [u8; 32]) = decode_wire(bytes)?;
        match SignatureAlgorithm::from_code(algorithm)? {
            SignatureAlgorithm::Ed25519 => Self::ed25519(key),
        }
    }
}

impl Serialize for SigningPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.algorithm.code(), self.bytes).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SigningPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (algorithm, bytes) = <(u16, [u8; 32])>::deserialize(deserializer)?;
        match SignatureAlgorithm::from_code(algorithm).map_err(de::Error::custom)? {
            SignatureAlgorithm::Ed25519 => Self::ed25519(bytes).map_err(de::Error::custom),
        }
    }
}

/// Algorithm-tagged X25519 public agreement key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgreementPublicKey {
    algorithm: AgreementAlgorithm,
    bytes: [u8; 32],
}

impl AgreementPublicKey {
    /// Validate and construct an X25519 public key.
    pub fn x25519(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        if !x25519_public_key_is_valid(&bytes) {
            return Err(IdentityError::InvalidPublicKey {
                kind: AlgorithmKind::Agreement,
            });
        }
        Ok(Self {
            algorithm: AgreementAlgorithm::X25519,
            bytes,
        })
    }

    /// Agreement algorithm for this key.
    pub const fn algorithm(self) -> AgreementAlgorithm {
        self.algorithm
    }

    /// Exact public-key bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

fn x25519_public_key_is_valid(bytes: &[u8; 32]) -> bool {
    // RFC 7748 decoders mask the high bit and reduce non-canonical field
    // encodings. Device identity hashes the encoded key, so accepting those
    // aliases would give one agreement key multiple DeviceIds.
    const FIELD_MODULUS: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    if !little_endian_less_than(bytes, &FIELD_MODULUS) {
        return false;
    }

    // A clamped scalar is a multiple of the cofactor, so every low-order input
    // produces the all-zero X25519 result. The fixed scalar is only a validation
    // probe; no secret material is involved.
    MontgomeryPoint(*bytes).mul_clamped([0x42; 32]).0 != [0; 32]
}

fn little_endian_less_than(left: &[u8; 32], right: &[u8; 32]) -> bool {
    for index in (0..left.len()).rev() {
        if left[index] < right[index] {
            return true;
        }
        if left[index] > right[index] {
            return false;
        }
    }
    false
}

impl fmt::Debug for AgreementPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgreementPublicKey")
            .field("algorithm", &self.algorithm)
            .field("key", &HEXLOWER.encode(&self.bytes))
            .finish()
    }
}

impl CanonicalCodec for AgreementPublicKey {
    const RESOURCE: &'static str = "agreement public key bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&(self.algorithm.code(), self.bytes))
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (algorithm, key): (u16, [u8; 32]) = decode_wire(bytes)?;
        match AgreementAlgorithm::from_code(algorithm)? {
            AgreementAlgorithm::X25519 => Self::x25519(key),
        }
    }
}

impl Serialize for AgreementPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.algorithm.code(), self.bytes).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AgreementPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (algorithm, bytes) = <(u16, [u8; 32])>::deserialize(deserializer)?;
        match AgreementAlgorithm::from_code(algorithm).map_err(de::Error::custom)? {
            AgreementAlgorithm::X25519 => Self::x25519(bytes).map_err(de::Error::custom),
        }
    }
}

/// Algorithm-tagged digital signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProtocolSignature {
    algorithm: SignatureAlgorithm,
    bytes: [u8; 64],
}

impl ProtocolSignature {
    /// Construct an Ed25519 signature from its exact bytes.
    pub const fn ed25519(bytes: [u8; 64]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes,
        }
    }

    /// Signature algorithm.
    pub const fn algorithm(self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Exact signature bytes.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

impl fmt::Debug for ProtocolSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolSignature")
            .field("algorithm", &self.algorithm)
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl CanonicalCodec for ProtocolSignature {
    const RESOURCE: &'static str = "signature bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&(self.algorithm.code(), SignatureBytes(self.bytes)))
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (algorithm, signature): (u16, SignatureBytes) = decode_wire(bytes)?;
        match SignatureAlgorithm::from_code(algorithm)? {
            SignatureAlgorithm::Ed25519 => Ok(Self::ed25519(signature.0)),
        }
    }
}

impl Serialize for ProtocolSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.algorithm.code(), SignatureBytes(self.bytes)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProtocolSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (algorithm, signature) = <(u16, SignatureBytes)>::deserialize(deserializer)?;
        match SignatureAlgorithm::from_code(algorithm).map_err(de::Error::custom)? {
            SignatureAlgorithm::Ed25519 => Ok(Self::ed25519(signature.0)),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SignatureBytes(#[serde(with = "signature_bytes")] [u8; 64]);

mod signature_bytes {
    use std::fmt;

    use serde::{Deserializer, Serializer, de, ser::SerializeTuple};

    pub(super) fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(bytes.len())?;
        for byte in bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an exact 64-byte signature")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut bytes = [0; 64];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_tuple(64, Visitor)
    }
}

macro_rules! counter {
    ($name:ident, $zero:ident, $resource:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Initial zero value.
            pub const $zero: Self = Self(0);

            /// Construct from the exact wire value.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Return the underlying value.
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Advance by exactly one, rejecting exhaustion.
            pub fn checked_next(self) -> Result<Self, IdentityError> {
                self.0
                    .checked_add(1)
                    .map(Self)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: $resource,
                    })
            }
        }

        impl CanonicalCodec for $name {
            const RESOURCE: &'static str = $resource;

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(&self.0)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                Ok(Self(decode_wire(bytes)?))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Ok(Self(u64::deserialize(deserializer)?))
            }
        }
    };
}

counter!(
    Epoch,
    GENESIS,
    "account epoch",
    "Security-relevant account epoch."
);
counter!(
    Sequence,
    GENESIS,
    "account sequence",
    "Linear account-event sequence number."
);

/// Identity protocol major version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    /// The only protocol version supported by this implementation.
    pub const V1: Self = Self(1);

    /// Validate a protocol major version.
    pub const fn new(version: u16) -> Result<Self, IdentityError> {
        match version {
            1 => Ok(Self::V1),
            unsupported => Err(IdentityError::UnsupportedVersion {
                version: unsupported,
            }),
        }
    }

    /// Stable wire value.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl CanonicalCodec for ProtocolVersion {
    const RESOURCE: &'static str = "protocol version bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&self.0)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        Self::new(decode_wire(bytes)?)
    }
}

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u16::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Milliseconds since the Unix epoch, supplied explicitly by an effect boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Construct an explicit Unix timestamp.
    pub const fn from_unix_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    /// Return milliseconds since the Unix epoch.
    pub const fn as_unix_millis(self) -> u64 {
        self.0
    }

    /// Add a protocol duration, rejecting overflow.
    pub fn checked_add(self, duration: DurationMillis) -> Result<Self, IdentityError> {
        self.0
            .checked_add(duration.get())
            .map(Self)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "timestamp milliseconds",
            })
    }
}

impl CanonicalCodec for Timestamp {
    const RESOURCE: &'static str = "timestamp bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&self.0)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        Ok(Self(decode_wire(bytes)?))
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_unix_millis(u64::deserialize(deserializer)?))
    }
}

/// Explicit duration measured in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DurationMillis(u64);

impl DurationMillis {
    /// Construct an exact millisecond duration.
    pub const fn new(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    /// Return the exact number of milliseconds.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl CanonicalCodec for DurationMillis {
    const RESOURCE: &'static str = "duration milliseconds bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&self.0)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        Ok(Self(decode_wire(bytes)?))
    }
}

impl Serialize for DurationMillis {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DurationMillis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::new(u64::deserialize(deserializer)?))
    }
}
