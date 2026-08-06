//! Encrypted private artifacts and privacy-preserving identity primitives.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::TryCryptoRng;
use serde::{Deserialize, Deserializer, Serialize, de};
use zeroize::Zeroizing;

use crate::{
    AccountGenesis, AccountId, AccountOperation, AccountState, AdmissionEvidence, AeadAlgorithm,
    AlgorithmSignature, ApplicationId, ApplyDisposition, AuthorizedEvent, CanonicalWire,
    CheckpointId, ControllerApprovalBody, ControllerDescriptor, Digest, Epoch, EventBody,
    Extensions, HashAlgorithm, IdentityError, KdfAlgorithm, OperationKind, ProtocolVersion,
    ProviderId, SignedCheckpoint, SigningPublicKey, Timestamp, VerifiedCheckpoint,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{
        MAX_ACTIVE_CRYPTO_SUITES, MAX_APPLICATION_BACKUP_DATA_BYTES,
        MAX_CREDENTIAL_CLAIM_NAME_BYTES, MAX_CREDENTIAL_CLAIM_VALUE_BYTES, MAX_CREDENTIAL_CLAIMS,
        MAX_HISTORY_PAGE_EVENTS, MAX_OFFLINE_SIGNING_REQUEST_BYTES, MAX_PORTABLE_CREDENTIAL_BYTES,
        MAX_PRIVATE_BACKUP_BYTES, MAX_PRIVATE_LABEL_BYTES, MAX_PRIVATE_METADATA_BYTES,
        MAX_RELYING_PARTY_CONTEXT_BYTES,
    },
    schema::{BoundedBytes, BoundedVec},
    verify_checkpoint,
};

const PRIVATE_METADATA_KEY_BYTES: usize = 32;
const PRIVATE_ARTIFACT_SALT_BYTES: usize = 16;
const PRIVATE_ARTIFACT_NONCE_BYTES: usize = 24;
const PRIVATE_ARTIFACT_CONTENT_KEY_BYTES: usize = 32;
const PRIVATE_ARTIFACT_TAG_BYTES: usize = 16;
const PRIVATE_ARTIFACT_WRAPPED_KEY_BYTES: usize =
    PRIVATE_ARTIFACT_CONTENT_KEY_BYTES + PRIVATE_ARTIFACT_TAG_BYTES;
const PRIVATE_ARTIFACT_HEADER_RESERVE_BYTES: usize = 1024;
const MAX_PRIVATE_METADATA_PLAINTEXT_BYTES: usize =
    MAX_PRIVATE_METADATA_BYTES - PRIVATE_ARTIFACT_HEADER_RESERVE_BYTES;
const PRIVATE_METADATA_KIND_CODE: u16 = 1;
const PRIVATE_BACKUP_KIND_CODE: u16 = 2;
const PRIVATE_METADATA_KDF_CONTEXT: &str = "KRIKOS-ID/private-metadata-kek/v1";
const PRIVATE_BACKUP_ARGON2ID_CODE: u16 = 1;
const PRIVATE_BACKUP_ARGON2_VERSION: u32 = 0x13;
const PRIVATE_BACKUP_ARGON2_MEMORY_KIB: u32 = 19_456;
const PRIVATE_BACKUP_ARGON2_ITERATIONS: u32 = 2;
const PRIVATE_BACKUP_ARGON2_LANES: u32 = 1;
const PRIVATE_BACKUP_ARGON2_OUTPUT_BYTES: u32 = 32;
const PRIVATE_BACKUP_PASSPHRASE_BYTES: usize = 1024;
const PRIVATE_BACKUP_HEADER_RESERVE_BYTES: usize = 4 * 1024;
const MAX_PRIVATE_BACKUP_PLAINTEXT_BYTES: usize =
    MAX_PRIVATE_BACKUP_BYTES - PRIVATE_BACKUP_HEADER_RESERVE_BYTES;
const PRIVATE_ARTIFACT_WRAP_DOMAIN: &[u8] = b"KRIKOS-ID/private-artifact-key-wrap/v1";
const PRIVATE_ARTIFACT_CONTENT_DOMAIN: &[u8] = b"KRIKOS-ID/private-artifact-content/v1";
const RELATIONSHIP_LABEL_COMMITMENT_CODE: u16 = 1;
const RELATIONSHIP_LABEL_COMMITMENT_DOMAIN: &[u8] = b"KRIKOS-ID/relationship-label/v1";
const LOOKUP_HANDLE_DOMAIN: &[u8] = b"KRIKOS-ID/private-checkpoint-lookup/v1";
const PAIRWISE_IDENTIFIER_DOMAIN: &[u8] = b"KRIKOS-ID/pairwise-identifier/v1";
const PORTABLE_CREDENTIAL_SIGNING_DOMAIN: &[u8] = b"KRIKOS-ID/portable-credential/v1";

/// Exact public context authenticated by a private artifact envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivateArtifactContext {
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    account_epoch: Epoch,
    application_id: Option<ApplicationId>,
    generation: u64,
    extensions: Extensions,
}

impl PrivateArtifactContext {
    /// Construct an exact account/checkpoint/application artifact context.
    pub fn try_new(
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        account_epoch: Epoch,
        application_id: Option<ApplicationId>,
        generation: u64,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            account_id,
            checkpoint_id,
            account_epoch,
            application_id,
            generation,
            extensions,
        })
    }

    /// Account that owns the private artifact.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact account checkpoint authenticated with the ciphertext.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Exact account epoch authenticated with the ciphertext.
    pub const fn account_epoch(&self) -> Epoch {
        self.account_epoch
    }

    /// Optional application namespace owning the private artifact.
    pub const fn application_id(&self) -> Option<ApplicationId> {
        self.application_id
    }

    /// Caller-managed rotation generation authenticated with the ciphertext.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl<'de> Deserialize<'de> for PrivateArtifactContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            account_id: AccountId,
            checkpoint_id: CheckpointId,
            account_epoch: Epoch,
            application_id: Option<ApplicationId>,
            generation: u64,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(
            wire.account_id,
            wire.checkpoint_id,
            wire.account_epoch,
            wire.application_id,
            wire.generation,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for PrivateArtifactContext {
    const RESOURCE: &'static str = "private artifact context bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// High-entropy metadata key which erases its bytes when dropped.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
pub struct PrivateMetadataKey(Zeroizing<[u8; PRIVATE_METADATA_KEY_BYTES]>);

impl PrivateMetadataKey {
    /// Take ownership of one nonzero 256-bit metadata key.
    pub fn try_new(bytes: [u8; PRIVATE_METADATA_KEY_BYTES]) -> Result<Self, IdentityError> {
        if bytes == [0; PRIVATE_METADATA_KEY_BYTES] {
            return Err(IdentityError::ZeroValue {
                resource: "private metadata key",
            });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn as_bytes(&self) -> &[u8; PRIVATE_METADATA_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for PrivateMetadataKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateMetadataKey(<redacted>)")
    }
}

/// Bounded private metadata plaintext which erases its bytes when dropped.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
#[derive(PartialEq, Eq)]
pub struct PrivateMetadata(Zeroizing<Vec<u8>>);

impl PrivateMetadata {
    /// Take ownership of nonempty metadata which fits in one bounded encrypted envelope.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "private metadata plaintext",
            });
        }
        if bytes.len() > MAX_PRIVATE_METADATA_PLAINTEXT_BYTES {
            return Err(IdentityError::limit(
                "private metadata plaintext",
                bytes.len(),
                MAX_PRIVATE_METADATA_PLAINTEXT_BYTES,
            ));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrow the decrypted metadata bytes while retaining zeroizing ownership.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for PrivateMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateMetadata(<redacted>)")
    }
}

/// Canonical versioned envelope containing only encrypted private metadata.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PrivateMetadataEnvelope {
    protocol_version: ProtocolVersion,
    artifact_kind_code: u16,
    kdf: KdfAlgorithm,
    wrapping_aead: AeadAlgorithm,
    content_aead: AeadAlgorithm,
    context: PrivateArtifactContext,
    salt: [u8; PRIVATE_ARTIFACT_SALT_BYTES],
    wrapping_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
    content_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
    wrapped_content_key: BoundedBytes<PRIVATE_ARTIFACT_WRAPPED_KEY_BYTES>,
    ciphertext: BoundedBytes<MAX_PRIVATE_METADATA_BYTES>,
    extensions: Extensions,
}

impl PrivateMetadataEnvelope {
    /// Encrypt metadata using fallible operating-system entropy.
    #[cfg(feature = "os-rng")]
    #[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
    pub fn seal(
        context: PrivateArtifactContext,
        key: &PrivateMetadataKey,
        plaintext: &PrivateMetadata,
    ) -> Result<Self, IdentityError> {
        let mut salt = [0; PRIVATE_ARTIFACT_SALT_BYTES];
        let mut wrapping_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_key = Zeroizing::new([0; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]);
        getrandom::fill(&mut salt).map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(&mut wrapping_nonce).map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(&mut content_nonce).map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(content_key.as_mut()).map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::seal_with_randomness(
            context,
            key,
            plaintext,
            salt,
            wrapping_nonce,
            content_nonce,
            content_key,
        )
    }

    /// Encrypt metadata using injected fallible cryptographic entropy for vectors and tests.
    pub fn seal_with_rng(
        context: PrivateArtifactContext,
        key: &PrivateMetadataKey,
        plaintext: &PrivateMetadata,
        rng: &mut impl TryCryptoRng,
    ) -> Result<Self, IdentityError> {
        let mut salt = [0; PRIVATE_ARTIFACT_SALT_BYTES];
        let mut wrapping_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_key = Zeroizing::new([0; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]);
        rng.try_fill_bytes(&mut salt)
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(&mut wrapping_nonce)
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(&mut content_nonce)
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(content_key.as_mut())
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::seal_with_randomness(
            context,
            key,
            plaintext,
            salt,
            wrapping_nonce,
            content_nonce,
            content_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_with_randomness(
        context: PrivateArtifactContext,
        key: &PrivateMetadataKey,
        plaintext: &PrivateMetadata,
        salt: [u8; PRIVATE_ARTIFACT_SALT_BYTES],
        wrapping_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
        content_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
        content_key: Zeroizing<[u8; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]>,
    ) -> Result<Self, IdentityError> {
        if salt == [0; PRIVATE_ARTIFACT_SALT_BYTES]
            || wrapping_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
            || content_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
            || content_key.as_ref() == [0; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]
        {
            return Err(IdentityError::EntropyUnavailable);
        }
        let mut envelope = Self {
            protocol_version: ProtocolVersion::V1,
            artifact_kind_code: PRIVATE_METADATA_KIND_CODE,
            kdf: KdfAlgorithm::Blake3DeriveKey,
            wrapping_aead: AeadAlgorithm::XChaCha20Poly1305,
            content_aead: AeadAlgorithm::XChaCha20Poly1305,
            context,
            salt,
            wrapping_nonce,
            content_nonce,
            wrapped_content_key: BoundedBytes::new("wrapped private content key", Vec::new())?,
            ciphertext: BoundedBytes::new("private metadata ciphertext", Vec::new())?,
            extensions: Extensions::default(),
        };
        let wrapping_key = derive_metadata_wrapping_key(key, &envelope.salt);
        let wrapping_aad = envelope.wrapping_aad()?;
        let wrapping_cipher = XChaCha20Poly1305::new(&Key::from(*wrapping_key));
        let wrapped_content_key = wrapping_cipher
            .encrypt(
                &XNonce::from(envelope.wrapping_nonce),
                Payload {
                    msg: content_key.as_ref(),
                    aad: &wrapping_aad,
                },
            )
            .map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "private content-key wrapping",
            })?;
        envelope.wrapped_content_key =
            BoundedBytes::new("wrapped private content key", wrapped_content_key)?;

        let content_aad = envelope.content_aad()?;
        let content_cipher = XChaCha20Poly1305::new(&Key::from(*content_key));
        let ciphertext = content_cipher
            .encrypt(
                &XNonce::from(envelope.content_nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &content_aad,
                },
            )
            .map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "private metadata encryption",
            })?;
        envelope.ciphertext = BoundedBytes::new("private metadata ciphertext", ciphertext)?;
        envelope.validate()?;
        let encoded_len = encode_wire(&envelope)?.len();
        if encoded_len > MAX_PRIVATE_METADATA_BYTES {
            return Err(IdentityError::limit(
                "private metadata envelope bytes",
                encoded_len,
                MAX_PRIVATE_METADATA_BYTES,
            ));
        }
        Ok(envelope)
    }

    /// Authenticate and decrypt the metadata without distinguishing wrong keys from corruption.
    pub fn open(&self, key: &PrivateMetadataKey) -> Result<PrivateMetadata, IdentityError> {
        self.validate()?;
        let wrapping_key = derive_metadata_wrapping_key(key, &self.salt);
        let wrapping_aad = self.wrapping_aad()?;
        let wrapping_cipher = XChaCha20Poly1305::new(&Key::from(*wrapping_key));
        let content_key = wrapping_cipher
            .decrypt(
                &XNonce::from(self.wrapping_nonce),
                Payload {
                    msg: self.wrapped_content_key.as_slice(),
                    aad: &wrapping_aad,
                },
            )
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
        let content_key: [u8; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES] = content_key
            .try_into()
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
        let content_key = Zeroizing::new(content_key);
        let content_aad = self.content_aad()?;
        let content_cipher = XChaCha20Poly1305::new(&Key::from(*content_key));
        let plaintext = content_cipher
            .decrypt(
                &XNonce::from(self.content_nonce),
                Payload {
                    msg: self.ciphertext.as_slice(),
                    aad: &content_aad,
                },
            )
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
        PrivateMetadata::try_new(plaintext)
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)
    }

    /// Exact public context authenticated by both key wrapping and content encryption.
    pub const fn context(&self) -> &PrivateArtifactContext {
        &self.context
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.protocol_version.get(),
            });
        }
        if self.artifact_kind_code != PRIVATE_METADATA_KIND_CODE {
            return Err(IdentityError::UnsupportedCodepoint {
                registry: "private artifact kind",
                code: self.artifact_kind_code,
            });
        }
        if self.kdf != KdfAlgorithm::Blake3DeriveKey
            || self.wrapping_aead != AeadAlgorithm::XChaCha20Poly1305
            || self.content_aead != AeadAlgorithm::XChaCha20Poly1305
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "private metadata cryptographic profile",
            });
        }
        if self.salt == [0; PRIVATE_ARTIFACT_SALT_BYTES]
            || self.wrapping_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
            || self.content_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
        {
            return Err(IdentityError::ZeroValue {
                resource: "private artifact salt or nonce",
            });
        }
        if self.wrapped_content_key.len() != PRIVATE_ARTIFACT_WRAPPED_KEY_BYTES
            || self.ciphertext.len() <= PRIVATE_ARTIFACT_TAG_BYTES
        {
            return Err(IdentityError::InvalidEncoding);
        }
        self.extensions.validate_critical(&[])
    }

    fn header_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&(
            self.protocol_version,
            self.artifact_kind_code,
            self.kdf,
            self.wrapping_aead,
            self.content_aead,
            &self.context,
            self.salt,
            self.wrapping_nonce,
            self.content_nonce,
            &self.extensions,
        ))
    }

    fn wrapping_aad(&self) -> Result<Vec<u8>, IdentityError> {
        domain_message(PRIVATE_ARTIFACT_WRAP_DOMAIN, &self.header_bytes()?)
    }

    fn content_aad(&self) -> Result<Vec<u8>, IdentityError> {
        let body = encode_wire(&(self.header_bytes()?, self.wrapped_content_key.as_slice()))?;
        domain_message(PRIVATE_ARTIFACT_CONTENT_DOMAIN, &body)
    }
}

impl fmt::Debug for PrivateMetadataEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateMetadataEnvelope")
            .field("context", &self.context)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for PrivateMetadataEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            artifact_kind_code: u16,
            kdf: KdfAlgorithm,
            wrapping_aead: AeadAlgorithm,
            content_aead: AeadAlgorithm,
            context: PrivateArtifactContext,
            salt: [u8; PRIVATE_ARTIFACT_SALT_BYTES],
            wrapping_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
            content_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
            wrapped_content_key: BoundedBytes<PRIVATE_ARTIFACT_WRAPPED_KEY_BYTES>,
            ciphertext: BoundedBytes<MAX_PRIVATE_METADATA_BYTES>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        let envelope = Self {
            protocol_version: wire.protocol_version,
            artifact_kind_code: wire.artifact_kind_code,
            kdf: wire.kdf,
            wrapping_aead: wire.wrapping_aead,
            content_aead: wire.content_aead,
            context: wire.context,
            salt: wire.salt,
            wrapping_nonce: wire.wrapping_nonce,
            content_nonce: wire.content_nonce,
            wrapped_content_key: wire.wrapped_content_key,
            ciphertext: wire.ciphertext,
            extensions: wire.extensions,
        };
        envelope.validate().map_err(de::Error::custom)?;
        Ok(envelope)
    }
}

impl CanonicalCodec for PrivateMetadataEnvelope {
    const RESOURCE: &'static str = "private metadata envelope bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_METADATA_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Fresh high-entropy blinding material for a single public commitment.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
///
/// ```compile_fail
/// use krikos_identity::BlindingSecret;
/// fn require_clone<T: Clone>() {}
/// require_clone::<BlindingSecret>();
/// ```
#[derive(PartialEq, Eq)]
pub struct BlindingSecret(Zeroizing<[u8; 32]>);

impl BlindingSecret {
    /// Take ownership of one nonzero 256-bit blinding.
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        Ok(Self(nonzero_secret(bytes, "blinding secret")?))
    }

    /// Generate fresh blinding material from fallible operating-system entropy.
    #[cfg(feature = "os-rng")]
    #[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
    pub fn generate() -> Result<Self, IdentityError> {
        Ok(Self(os_secret()?))
    }

    /// Generate deterministic or injected blinding material for tests and vectors.
    pub fn generate_with_rng(rng: &mut impl TryCryptoRng) -> Result<Self, IdentityError> {
        Ok(Self(rng_secret(rng)?))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BlindingSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BlindingSecret(<redacted>)")
    }
}

/// Bounded private relationship label used only before a blinded commitment is derived.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
pub struct PrivateLabel(Zeroizing<Vec<u8>>);

impl PrivateLabel {
    /// Take ownership of one nonempty private label.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "private relationship label",
            });
        }
        if bytes.len() > MAX_PRIVATE_LABEL_BYTES {
            return Err(IdentityError::limit(
                "private relationship label",
                bytes.len(),
                MAX_PRIVATE_LABEL_BYTES,
            ));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for PrivateLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateLabel(<redacted>)")
    }
}

/// Public domain-separated commitment which reveals neither a private label nor its blinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BlindedCommitment {
    protocol_version: ProtocolVersion,
    purpose_code: u16,
    digest: Digest,
}

impl BlindedCommitment {
    /// Commit to a private relationship label with one fresh 256-bit blinding.
    pub fn relationship_label(
        label: &PrivateLabel,
        blinding: &BlindingSecret,
    ) -> Result<Self, IdentityError> {
        let digest = keyed_digest(
            blinding.as_bytes(),
            RELATIONSHIP_LABEL_COMMITMENT_DOMAIN,
            label.as_bytes(),
        )?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            purpose_code: RELATIONSHIP_LABEL_COMMITMENT_CODE,
            digest,
        })
    }

    /// Domain-separated public commitment digest.
    pub const fn digest(self) -> Digest {
        self.digest
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.protocol_version.get(),
            });
        }
        if self.purpose_code != RELATIONSHIP_LABEL_COMMITMENT_CODE {
            return Err(IdentityError::UnsupportedCodepoint {
                registry: "blinded commitment purpose",
                code: self.purpose_code,
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for BlindedCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (protocol_version, purpose_code, digest) =
            <(ProtocolVersion, u16, Digest)>::deserialize(deserializer)?;
        let commitment = Self {
            protocol_version,
            purpose_code,
            digest,
        };
        commitment.validate().map_err(de::Error::custom)?;
        Ok(commitment)
    }
}

impl CanonicalCodec for BlindedCommitment {
    const RESOURCE: &'static str = "blinded private commitment bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Account-held secret used only to derive rotating private checkpoint lookup handles.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
pub struct LookupHandleSecret(Zeroizing<[u8; 32]>);

impl LookupHandleSecret {
    /// Take ownership of one nonzero 256-bit lookup secret.
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        Ok(Self(nonzero_secret(bytes, "private lookup-handle secret")?))
    }

    /// Generate a fresh lookup secret from fallible operating-system entropy.
    #[cfg(feature = "os-rng")]
    #[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
    pub fn generate() -> Result<Self, IdentityError> {
        Ok(Self(os_secret()?))
    }

    /// Generate an injected lookup secret for tests and vectors.
    pub fn generate_with_rng(rng: &mut impl TryCryptoRng) -> Result<Self, IdentityError> {
        Ok(Self(rng_secret(rng)?))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LookupHandleSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LookupHandleSecret(<redacted>)")
    }
}

/// Rotating opaque checkpoint lookup handle scoped to one provider and generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivateCheckpointLookupHandle {
    protocol_version: ProtocolVersion,
    provider_id: ProviderId,
    generation: u64,
    handle: Digest,
    extensions: Extensions,
}

impl PrivateCheckpointLookupHandle {
    /// Derive an opaque handle bound to the exact provider, hidden account, and generation.
    pub fn derive(
        secret: &LookupHandleSecret,
        provider_id: ProviderId,
        account_id: AccountId,
        generation: u64,
    ) -> Result<Self, IdentityError> {
        if generation == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "private lookup-handle generation",
            });
        }
        let payload = encode_wire(&(provider_id, account_id, generation))?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            provider_id,
            generation,
            handle: keyed_digest(secret.as_bytes(), LOOKUP_HANDLE_DOMAIN, &payload)?,
            extensions: Extensions::default(),
        })
    }

    /// Provider namespace to which this handle may be sent.
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    /// Caller-managed lookup generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Opaque domain-separated lookup digest.
    pub const fn digest(&self) -> Digest {
        self.handle
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.protocol_version.get(),
            });
        }
        if self.generation == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "private lookup-handle generation",
            });
        }
        self.extensions.validate_critical(&[])
    }
}

impl<'de> Deserialize<'de> for PrivateCheckpointLookupHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            provider_id: ProviderId,
            generation: u64,
            handle: Digest,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        let handle = Self {
            protocol_version: wire.protocol_version,
            provider_id: wire.provider_id,
            generation: wire.generation,
            handle: wire.handle,
            extensions: wire.extensions,
        };
        handle.validate().map_err(de::Error::custom)?;
        Ok(handle)
    }
}

impl CanonicalCodec for PrivateCheckpointLookupHandle {
    const RESOURCE: &'static str = "private checkpoint lookup handle bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Account-held secret used only for pairwise relying-party identifiers.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
pub struct PairwiseMasterSecret(Zeroizing<[u8; 32]>);

impl PairwiseMasterSecret {
    /// Take ownership of one nonzero 256-bit pairwise master secret.
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        Ok(Self(nonzero_secret(bytes, "pairwise master secret")?))
    }

    /// Generate a pairwise master secret from fallible operating-system entropy.
    #[cfg(feature = "os-rng")]
    #[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
    pub fn generate() -> Result<Self, IdentityError> {
        Ok(Self(os_secret()?))
    }

    /// Generate an injected pairwise master secret for tests and vectors.
    pub fn generate_with_rng(rng: &mut impl TryCryptoRng) -> Result<Self, IdentityError> {
        Ok(Self(rng_secret(rng)?))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PairwiseMasterSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairwiseMasterSecret(<redacted>)")
    }
}

/// Lowercase ASCII DNS-style relying-party namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RelyingPartyContext(String);

impl RelyingPartyContext {
    /// Normalize and validate one bounded ASCII DNS-style relying-party context.
    pub fn try_new(value: &str) -> Result<Self, IdentityError> {
        let normalized = normalize_dns_context(value, "relying-party context")?;
        Ok(Self(normalized))
    }

    /// Canonical lowercase relying-party context.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RelyingPartyContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_new(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for RelyingPartyContext {
    const RESOURCE: &'static str = "relying-party context bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Stable pseudonymous identifier unlinkable across normalized relying-party contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PairwiseIdentifier(Digest);

impl PairwiseIdentifier {
    /// Derive one account- and relying-party-bound pairwise identifier.
    pub fn derive(
        master: &PairwiseMasterSecret,
        account_id: AccountId,
        context: &RelyingPartyContext,
    ) -> Result<Self, IdentityError> {
        let payload = encode_wire(&(account_id, context))?;
        Ok(Self(keyed_digest(
            master.as_bytes(),
            PAIRWISE_IDENTIFIER_DOMAIN,
            &payload,
        )?))
    }

    /// Public pairwise digest.
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl CanonicalCodec for PairwiseIdentifier {
    const RESOURCE: &'static str = "pairwise identifier bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// One explicitly disclosed, bounded portable-credential claim.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CredentialClaim {
    name: String,
    value: BoundedBytes<MAX_CREDENTIAL_CLAIM_VALUE_BYTES>,
}

impl CredentialClaim {
    /// Construct one normalized claim whose value is intentionally disclosed by this export.
    pub fn try_new(name: &str, value: Vec<u8>) -> Result<Self, IdentityError> {
        let name = normalize_claim_name(name)?;
        if value.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "portable credential claim value",
            });
        }
        Ok(Self {
            name,
            value: BoundedBytes::new("portable credential claim value", value)?,
        })
    }

    /// Canonical lowercase claim name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Explicitly disclosed claim value.
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl fmt::Debug for CredentialClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialClaim")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for CredentialClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            name: String,
            value: BoundedBytes<MAX_CREDENTIAL_CLAIM_VALUE_BYTES>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::try_new(&wire.name, wire.value.into_vec()).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for CredentialClaim {
    const RESOURCE: &'static str = "portable credential claim bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Exact domain of an offline signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningPurpose {
    /// Sign an explicitly selected portable credential export.
    PortableCredential,
    /// Sign an exact canonical account-approval body.
    AccountApproval,
}

impl SigningPurpose {
    const fn code(self) -> u16 {
        match self {
            Self::PortableCredential => 1,
            Self::AccountApproval => 2,
        }
    }

    fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::PortableCredential),
            2 => Ok(Self::AccountApproval),
            code => Err(IdentityError::UnsupportedCodepoint {
                registry: "offline signing purpose",
                code,
            }),
        }
    }
}

impl Serialize for SigningPurpose {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SigningPurpose {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_code(u16::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Bounded exact bytes and derived public context presented to an offline signer.
///
/// Arbitrary metadata-plus-bytes construction is intentionally unavailable:
///
/// ```compile_fail
/// use krikos_identity::CanonicalSigningRequest;
/// let _ = CanonicalSigningRequest::try_new();
/// ```
pub struct CanonicalSigningRequest {
    purpose: SigningPurpose,
    account_id: AccountId,
    signer_account_id: AccountId,
    account_epoch: Epoch,
    operation_kind: Option<OperationKind>,
    expected_signing_key: SigningPublicKey,
    canonical_message: BoundedBytes<MAX_OFFLINE_SIGNING_REQUEST_BYTES>,
}

impl CanonicalSigningRequest {
    /// Construct a request for the exact selectively disclosed credential body.
    pub fn for_portable_credential(body: &PortableCredentialBody) -> Result<Self, IdentityError> {
        Self::from_validated_parts(
            SigningPurpose::PortableCredential,
            body.account_id(),
            body.issuer_account_id(),
            body.account_epoch(),
            None,
            body.issuer_signing_key(),
            body.signing_bytes()?,
        )
    }

    /// Construct a request for one exact final account-event controller approval.
    ///
    /// The event, admission evidence, approval subject, controller identifier, immutable scope,
    /// signing key, and signer-visible context are validated before any request is returned.
    pub fn for_account_approval(
        event_body: &EventBody,
        admission_evidence: &AdmissionEvidence,
        approval_body: &ControllerApprovalBody,
        controller: &ControllerDescriptor,
    ) -> Result<Self, IdentityError> {
        let event_id = admission_evidence.event_id_for_body(event_body)?;
        let admission_evidence_id = admission_evidence.admission_evidence_id()?;
        if approval_body.event_subject() != Some((event_id, admission_evidence_id)) {
            return Err(IdentityError::InvalidRelationship {
                resource: "offline account approval subject",
            });
        }
        if approval_body.controller_id() != controller.id()? {
            return Err(IdentityError::InvalidRelationship {
                resource: "offline account approval controller",
            });
        }
        let operation_kind = event_body.operation().kind();
        if !controller.scope().allows(operation_kind) {
            return Err(IdentityError::IneligibleController);
        }
        if let AccountOperation::BeginRecovery(begin) = event_body.operation()
            && admission_evidence.preceding_checkpoint()
                != begin.proposal().plan().prior_checkpoint_id()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "offline begin recovery admission checkpoint",
            });
        }

        Self::from_validated_parts(
            SigningPurpose::AccountApproval,
            event_body.account_id(),
            event_body.account_id(),
            event_body.resulting_epoch(),
            Some(operation_kind),
            controller.signing_key(),
            approval_body.to_canonical_bytes()?,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_validated_parts(
        purpose: SigningPurpose,
        account_id: AccountId,
        signer_account_id: AccountId,
        account_epoch: Epoch,
        operation_kind: Option<OperationKind>,
        expected_signing_key: SigningPublicKey,
        canonical_message: Vec<u8>,
    ) -> Result<Self, IdentityError> {
        if canonical_message.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "offline canonical signing message",
            });
        }
        Ok(Self {
            purpose,
            account_id,
            signer_account_id,
            account_epoch,
            operation_kind,
            expected_signing_key,
            canonical_message: BoundedBytes::new(
                "offline canonical signing message",
                canonical_message,
            )?,
        })
    }

    /// Exact purpose displayed by the offline signer.
    pub const fn purpose(&self) -> SigningPurpose {
        self.purpose
    }

    /// Account whose credential or authority event is being signed.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Account that owns the requested signing key.
    pub const fn signer_account_id(&self) -> AccountId {
        self.signer_account_id
    }

    /// Exact account epoch derived from the signed protocol object.
    pub const fn account_epoch(&self) -> Epoch {
        self.account_epoch
    }

    /// Exact event operation, or `None` for a portable-credential export.
    pub const fn operation_kind(&self) -> Option<OperationKind> {
        self.operation_kind
    }

    /// Public key whose corresponding signer is requested.
    pub const fn expected_signing_key(&self) -> SigningPublicKey {
        self.expected_signing_key
    }

    /// Exact canonical message bytes to sign, without hidden context or ambient authority.
    pub fn canonical_message(&self) -> &[u8] {
        self.canonical_message.as_slice()
    }

    /// Verify a returned typed signature against the exact request bytes.
    pub fn verify_response(&self, signature: &AlgorithmSignature) -> Result<(), IdentityError> {
        verify_exact_signature(
            self.expected_signing_key,
            signature,
            self.canonical_message(),
        )
    }
}

impl fmt::Debug for CanonicalSigningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalSigningRequest")
            .field("purpose", &self.purpose)
            .field("account_id", &self.account_id)
            .field("signer_account_id", &self.signer_account_id)
            .field("account_epoch", &self.account_epoch)
            .field("operation_kind", &self.operation_kind)
            .field("expected_signing_key", &self.expected_signing_key)
            .field("canonical_message", &"<redacted>")
            .finish()
    }
}

/// Pure boundary for an offline signer which receives only exact public request bytes.
pub trait OfflineSigner {
    /// Sign the exact canonical message in `request` with its requested key.
    fn sign_exact(
        &self,
        request: &CanonicalSigningRequest,
    ) -> Result<AlgorithmSignature, IdentityError>;
}

/// Exact account-approval request presented to a hardware controller.
///
/// ```compile_fail
/// use krikos_identity::HardwareApprovalRequest;
/// let _ = HardwareApprovalRequest::try_new();
/// ```
pub struct HardwareApprovalRequest {
    signing_request: CanonicalSigningRequest,
    operation_kind: OperationKind,
}

impl HardwareApprovalRequest {
    /// Construct a hardware request from one fully related account-approval object set.
    pub fn for_account_approval(
        event_body: &EventBody,
        admission_evidence: &AdmissionEvidence,
        approval_body: &ControllerApprovalBody,
        controller: &ControllerDescriptor,
    ) -> Result<Self, IdentityError> {
        let operation_kind = event_body.operation().kind();
        Ok(Self {
            signing_request: CanonicalSigningRequest::for_account_approval(
                event_body,
                admission_evidence,
                approval_body,
                controller,
            )?,
            operation_kind,
        })
    }

    /// Protocol version displayed and accepted by the hardware boundary.
    pub const fn protocol_version(&self) -> ProtocolVersion {
        ProtocolVersion::V1
    }

    /// Exact account displayed by the hardware boundary.
    pub const fn account_id(&self) -> AccountId {
        self.signing_request.account_id()
    }

    /// Exact resulting account epoch displayed by the hardware boundary.
    pub const fn resulting_epoch(&self) -> Epoch {
        self.signing_request.account_epoch()
    }

    /// Exact account-operation kind displayed by the hardware boundary.
    pub const fn operation_kind(&self) -> OperationKind {
        self.operation_kind
    }

    /// Public signing key whose corresponding hardware key is requested.
    pub const fn expected_signing_key(&self) -> SigningPublicKey {
        self.signing_request.expected_signing_key()
    }

    /// Exact canonical approval bytes, without a private key or hidden storage/network capability.
    pub fn canonical_message(&self) -> &[u8] {
        self.signing_request.canonical_message()
    }

    /// Verify a returned typed signature against the exact request bytes.
    pub fn verify_response(&self, signature: &AlgorithmSignature) -> Result<(), IdentityError> {
        self.signing_request.verify_response(signature)
    }
}

impl fmt::Debug for HardwareApprovalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HardwareApprovalRequest")
            .field("protocol_version", &self.protocol_version())
            .field("account_id", &self.account_id())
            .field("resulting_epoch", &self.resulting_epoch())
            .field("operation_kind", &self.operation_kind())
            .field("expected_signing_key", &self.expected_signing_key())
            .field("canonical_message", &"<redacted>")
            .finish()
    }
}

/// Pure hardware-controller boundary limited to one exact approval signature.
pub trait HardwareController {
    /// Approve the exact canonical bytes after displaying the typed public context.
    fn approve_exact(
        &self,
        request: &HardwareApprovalRequest,
    ) -> Result<AlgorithmSignature, IdentityError>;
}

/// Exact selectively disclosed body signed for one portable credential export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortableCredentialBody {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    account_epoch: Epoch,
    subject_keys: BoundedVec<SigningPublicKey, MAX_ACTIVE_CRYPTO_SUITES>,
    issuer_account_id: AccountId,
    issuer_signing_key: SigningPublicKey,
    issued_at: Timestamp,
    expires_at: Timestamp,
    claims: BoundedVec<CredentialClaim, MAX_CREDENTIAL_CLAIMS>,
    extensions: Extensions,
}

impl PortableCredentialBody {
    /// Construct one sorted selective export bound to exact account authority and issuer facts.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        account_epoch: Epoch,
        subject_keys: Vec<SigningPublicKey>,
        issuer_account_id: AccountId,
        issuer_signing_key: SigningPublicKey,
        issued_at: Timestamp,
        expires_at: Timestamp,
        claims: Vec<CredentialClaim>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_parts(
            account_id,
            checkpoint_id,
            account_epoch,
            subject_keys,
            issuer_account_id,
            issuer_signing_key,
            issued_at,
            expires_at,
            claims,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        account_epoch: Epoch,
        mut subject_keys: Vec<SigningPublicKey>,
        issuer_account_id: AccountId,
        issuer_signing_key: SigningPublicKey,
        issued_at: Timestamp,
        expires_at: Timestamp,
        mut claims: Vec<CredentialClaim>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if subject_keys.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "portable credential subject keys",
            });
        }
        if claims.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "portable credential selected claims",
            });
        }
        if issued_at >= expires_at {
            return Err(IdentityError::InvalidRelationship {
                resource: "portable credential validity interval",
            });
        }
        extensions.validate_critical(&[])?;
        subject_keys.sort_unstable();
        if subject_keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(IdentityError::DuplicateElement {
                resource: "portable credential subject keys",
            });
        }
        claims.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        if claims.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(IdentityError::DuplicateElement {
                resource: "portable credential claim names",
            });
        }
        let body = Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            checkpoint_id,
            account_epoch,
            subject_keys: BoundedVec::new("portable credential subject keys", subject_keys)?,
            issuer_account_id,
            issuer_signing_key,
            issued_at,
            expires_at,
            claims: BoundedVec::new("portable credential selected claims", claims)?,
            extensions,
        };
        let encoded_len = encode_wire(&body)?.len();
        if encoded_len > MAX_PORTABLE_CREDENTIAL_BYTES {
            return Err(IdentityError::limit(
                "portable credential body bytes",
                encoded_len,
                MAX_PORTABLE_CREDENTIAL_BYTES,
            ));
        }
        Ok(body)
    }

    /// Domain-separated canonical bytes which the issuer signs exactly.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        domain_message(PORTABLE_CREDENTIAL_SIGNING_DOMAIN, &encode_wire(self)?)
    }

    /// Stable subject account.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact subject checkpoint.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Exact subject account epoch.
    pub const fn account_epoch(&self) -> Epoch {
        self.account_epoch
    }

    /// Sorted public subject keys.
    pub fn subject_keys(&self) -> &[SigningPublicKey] {
        self.subject_keys.as_slice()
    }

    /// Account naming the issuer.
    pub const fn issuer_account_id(&self) -> AccountId {
        self.issuer_account_id
    }

    /// Exact issuer signing key.
    pub const fn issuer_signing_key(&self) -> SigningPublicKey {
        self.issuer_signing_key
    }

    /// Explicit issuance time.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Exclusive credential expiry time.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Sorted claims deliberately disclosed by this export.
    pub fn claims(&self) -> &[CredentialClaim] {
        self.claims.as_slice()
    }
}

impl<'de> Deserialize<'de> for PortableCredentialBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            checkpoint_id: CheckpointId,
            account_epoch: Epoch,
            subject_keys: BoundedVec<SigningPublicKey, MAX_ACTIVE_CRYPTO_SUITES>,
            issuer_account_id: AccountId,
            issuer_signing_key: SigningPublicKey,
            issued_at: Timestamp,
            expires_at: Timestamp,
            claims: BoundedVec<CredentialClaim, MAX_CREDENTIAL_CLAIMS>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::from_parts(
            wire.account_id,
            wire.checkpoint_id,
            wire.account_epoch,
            wire.subject_keys.into_vec(),
            wire.issuer_account_id,
            wire.issuer_signing_key,
            wire.issued_at,
            wire.expires_at,
            wire.claims.into_vec(),
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for PortableCredentialBody {
    const RESOURCE: &'static str = "portable credential body bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PORTABLE_CREDENTIAL_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Issuer-signed selectively disclosed portable credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedPortableCredential {
    body: PortableCredentialBody,
    issuer_signature: AlgorithmSignature,
}

impl SignedPortableCredential {
    /// Validate and retain one exact issuer signature.
    pub fn try_new(
        body: PortableCredentialBody,
        issuer_signature: AlgorithmSignature,
    ) -> Result<Self, IdentityError> {
        verify_exact_signature(
            body.issuer_signing_key,
            &issuer_signature,
            &body.signing_bytes()?,
        )?;
        let credential = Self {
            body,
            issuer_signature,
        };
        let encoded_len = encode_wire(&credential)?.len();
        if encoded_len > MAX_PORTABLE_CREDENTIAL_BYTES {
            return Err(IdentityError::limit(
                "signed portable credential bytes",
                encoded_len,
                MAX_PORTABLE_CREDENTIAL_BYTES,
            ));
        }
        Ok(credential)
    }

    /// Exact signed credential body.
    pub const fn body(&self) -> &PortableCredentialBody {
        &self.body
    }

    /// Typed issuer signature.
    pub const fn issuer_signature(&self) -> &AlgorithmSignature {
        &self.issuer_signature
    }
}

impl<'de> Deserialize<'de> for SignedPortableCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (body, signature) =
            <(PortableCredentialBody, AlgorithmSignature)>::deserialize(deserializer)?;
        Self::try_new(body, signature).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for SignedPortableCredential {
    const RESOURCE: &'static str = "signed portable credential bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PORTABLE_CREDENTIAL_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Caller-supplied exact authority and time expected for credential verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialVerificationContext {
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    account_epoch: Epoch,
    issuer_account_id: AccountId,
    issuer_signing_key: SigningPublicKey,
    authority_time: Timestamp,
}

impl CredentialVerificationContext {
    /// Construct an explicit credential verification context without ambient time or lookup.
    pub const fn try_new(
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        account_epoch: Epoch,
        issuer_account_id: AccountId,
        issuer_signing_key: SigningPublicKey,
        authority_time: Timestamp,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            account_id,
            checkpoint_id,
            account_epoch,
            issuer_account_id,
            issuer_signing_key,
            authority_time,
        })
    }
}

/// Verified portable-credential fact; it grants no account authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPortableCredential {
    body: PortableCredentialBody,
}

impl VerifiedPortableCredential {
    /// Explicit claims selected for and revealed by this verified export.
    pub fn claims(&self) -> &[CredentialClaim] {
        self.body.claims()
    }

    /// Exact subject keys bound by the issuer signature.
    pub fn subject_keys(&self) -> &[SigningPublicKey] {
        self.body.subject_keys()
    }
}

/// Verify an exact signed credential against caller-authenticated account, issuer, and time facts.
pub fn verify_portable_credential(
    credential: &SignedPortableCredential,
    context: &CredentialVerificationContext,
) -> Result<VerifiedPortableCredential, IdentityError> {
    let body = credential.body();
    if body.account_id != context.account_id
        || body.checkpoint_id != context.checkpoint_id
        || body.account_epoch != context.account_epoch
        || body.issuer_account_id != context.issuer_account_id
        || body.issuer_signing_key != context.issuer_signing_key
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "portable credential verification context",
        });
    }
    if context.authority_time < body.issued_at || context.authority_time >= body.expires_at {
        return Err(IdentityError::StaleEvidence);
    }
    verify_exact_signature(
        body.issuer_signing_key,
        credential.issuer_signature(),
        &body.signing_bytes()?,
    )?;
    Ok(VerifiedPortableCredential { body: body.clone() })
}

/// Secret passphrase used only to unwrap one encrypted account backup.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
pub struct BackupPassphrase(Zeroizing<Vec<u8>>);

impl BackupPassphrase {
    /// Take ownership of a nonempty, bounded passphrase.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "backup passphrase",
            });
        }
        if bytes.len() > PRIVATE_BACKUP_PASSPHRASE_BYTES {
            return Err(IdentityError::limit(
                "backup passphrase",
                bytes.len(),
                PRIVATE_BACKUP_PASSPHRASE_BYTES,
            ));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for BackupPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackupPassphrase(<redacted>)")
    }
}

/// Bounded application-private material carried separately from account authority.
///
/// This type is intentionally neither `Copy` nor `Clone` and never implements a wire codec.
#[derive(PartialEq, Eq)]
pub struct ApplicationBackupData(Zeroizing<Vec<u8>>);

impl ApplicationBackupData {
    /// Take ownership of nonempty application-private backup bytes.
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "application backup data",
            });
        }
        if bytes.len() > MAX_APPLICATION_BACKUP_DATA_BYTES {
            return Err(IdentityError::limit(
                "application backup data",
                bytes.len(),
                MAX_APPLICATION_BACKUP_DATA_BYTES,
            ));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Borrow restored application-private bytes while retaining zeroizing ownership.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for ApplicationBackupData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplicationBackupData(<redacted>)")
    }
}

/// Bounded public authority material sufficient to reconstruct and verify one account checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupAuthorityBundle {
    protocol_version: ProtocolVersion,
    genesis: AccountGenesis,
    events: BoundedVec<AuthorizedEvent, MAX_HISTORY_PAGE_EVENTS>,
    checkpoint: SignedCheckpoint,
    checkpoint_id: CheckpointId,
    extensions: Extensions,
}

impl BackupAuthorityBundle {
    /// Construct and fully validate a bounded genesis-to-checkpoint authority chain.
    pub fn try_new(
        genesis: AccountGenesis,
        events: Vec<AuthorizedEvent>,
        checkpoint: SignedCheckpoint,
    ) -> Result<Self, IdentityError> {
        Self::from_parts(genesis, events, checkpoint, Extensions::default())
    }

    fn from_parts(
        genesis: AccountGenesis,
        events: Vec<AuthorizedEvent>,
        checkpoint: SignedCheckpoint,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if events.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "backup authority events",
            });
        }
        extensions.validate_critical(&[])?;
        let checkpoint_id = checkpoint.checkpoint_id()?;
        let bundle = Self {
            protocol_version: ProtocolVersion::V1,
            genesis,
            events: BoundedVec::new("backup authority events", events)?,
            checkpoint,
            checkpoint_id,
            extensions,
        };
        bundle.validate_authority()?;
        let encoded_len = encode_wire(&bundle)?.len();
        if encoded_len > MAX_PRIVATE_BACKUP_BYTES {
            return Err(IdentityError::limit(
                "backup authority bundle bytes",
                encoded_len,
                MAX_PRIVATE_BACKUP_BYTES,
            ));
        }
        Ok(bundle)
    }

    /// Account named by the fully verified backup checkpoint.
    pub const fn account_id(&self) -> AccountId {
        self.checkpoint.body().account_id()
    }

    /// Stable identifier of the fully verified backup checkpoint.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Account epoch named by the fully verified backup checkpoint.
    pub const fn account_epoch(&self) -> Epoch {
        self.checkpoint.body().account_epoch()
    }

    /// Canonical account genesis retained by this authority backup.
    pub const fn genesis(&self) -> &AccountGenesis {
        &self.genesis
    }

    /// Bounded advancing account events retained in semantic order.
    pub fn events(&self) -> &[AuthorizedEvent] {
        self.events.as_slice()
    }

    /// Signed checkpoint retained in the authority bundle.
    pub const fn checkpoint(&self) -> &SignedCheckpoint {
        &self.checkpoint
    }

    fn validate_authority(&self) -> Result<RestoredAccountAuthority, IdentityError> {
        if self.protocol_version != ProtocolVersion::V1
            || self.checkpoint.checkpoint_id()? != self.checkpoint_id
            || self.genesis.account_id()? != self.account_id()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "backup authority checkpoint",
            });
        }
        self.extensions.validate_critical(&[])?;
        let mut state = AccountState::from_genesis(&self.genesis)?;
        for event in self.events.as_slice() {
            if state.validate_and_apply(event)?.disposition() != ApplyDisposition::Applied {
                return Err(IdentityError::InvalidRelationship {
                    resource: "backup authority advancing event chain",
                });
            }
        }
        let verified_checkpoint =
            verify_checkpoint(&state, &self.checkpoint, None).or_else(|_| {
                let transition_event =
                    self.events
                        .as_slice()
                        .last()
                        .ok_or(IdentityError::EmptyCollection {
                            resource: "backup authority events",
                        })?;
                verify_checkpoint(&state, &self.checkpoint, Some(transition_event))
            })?;
        Ok(RestoredAccountAuthority {
            state,
            checkpoint: verified_checkpoint,
        })
    }
}

impl<'de> Deserialize<'de> for BackupAuthorityBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            genesis: AccountGenesis,
            events: BoundedVec<AuthorizedEvent, MAX_HISTORY_PAGE_EVENTS>,
            checkpoint: SignedCheckpoint,
            checkpoint_id: CheckpointId,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        let bundle = Self::from_parts(
            wire.genesis,
            wire.events.into_vec(),
            wire.checkpoint,
            wire.extensions,
        )
        .map_err(de::Error::custom)?;
        if bundle.checkpoint_id != wire.checkpoint_id {
            return Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "backup authority checkpoint identifier",
            }));
        }
        Ok(bundle)
    }
}

impl CanonicalCodec for BackupAuthorityBundle {
    const RESOURCE: &'static str = "backup authority bundle bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_BACKUP_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Fully replayed account authority recovered from an authenticated backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredAccountAuthority {
    state: AccountState,
    checkpoint: VerifiedCheckpoint,
}

impl RestoredAccountAuthority {
    /// Fully validated projected account state.
    pub const fn state(&self) -> &AccountState {
        &self.state
    }

    /// Stable identifier of the checkpoint verified against the restored state.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint.checkpoint_id()
    }

    /// Fully verified signed checkpoint and any retained transition witness.
    pub const fn checkpoint(&self) -> &VerifiedCheckpoint {
        &self.checkpoint
    }
}

/// Result for application-private data, deliberately independent of account authority recovery.
pub enum ApplicationDataRestoration {
    /// No application-private bytes were present in the authenticated backup.
    Unavailable,
    /// Application-private bytes were authenticated and restored.
    Restored(ApplicationBackupData),
}

impl fmt::Debug for ApplicationDataRestoration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("Unavailable"),
            Self::Restored(_) => formatter.write_str("Restored(<redacted>)"),
        }
    }
}

/// Authenticated backup outcome with account authority and application data reported separately.
pub struct BackupRestoration {
    account_authority: RestoredAccountAuthority,
    application_data: ApplicationDataRestoration,
}

impl BackupRestoration {
    /// Fully validated account authority, independent of application-data availability.
    pub const fn account_authority(&self) -> &RestoredAccountAuthority {
        &self.account_authority
    }

    /// Authenticated application-data outcome.
    pub const fn application_data(&self) -> &ApplicationDataRestoration {
        &self.application_data
    }
}

impl fmt::Debug for BackupRestoration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupRestoration")
            .field("account_authority", &self.account_authority)
            .field("application_data", &self.application_data)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct BackupKdfParameters {
    algorithm_code: u16,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    output_bytes: u32,
}

impl BackupKdfParameters {
    const FIXED_V1: Self = Self {
        algorithm_code: PRIVATE_BACKUP_ARGON2ID_CODE,
        version: PRIVATE_BACKUP_ARGON2_VERSION,
        memory_kib: PRIVATE_BACKUP_ARGON2_MEMORY_KIB,
        iterations: PRIVATE_BACKUP_ARGON2_ITERATIONS,
        lanes: PRIVATE_BACKUP_ARGON2_LANES,
        output_bytes: PRIVATE_BACKUP_ARGON2_OUTPUT_BYTES,
    };

    fn validate(self) -> Result<(), IdentityError> {
        if self != Self::FIXED_V1 {
            return Err(IdentityError::InvalidRelationship {
                resource: "backup password KDF profile",
            });
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct BackupPayloadRef<'a> {
    protocol_version: ProtocolVersion,
    authority_bundle: &'a BackupAuthorityBundle,
    application_data: Option<&'a [u8]>,
    extensions: &'a Extensions,
}

#[derive(Deserialize)]
struct BackupPayload {
    protocol_version: ProtocolVersion,
    authority_bundle: BackupAuthorityBundle,
    application_data: Option<BoundedBytes<MAX_APPLICATION_BACKUP_DATA_BYTES>>,
    extensions: Extensions,
}

/// Canonical versioned envelope containing encrypted authority and optional application data.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BackupEnvelope {
    protocol_version: ProtocolVersion,
    artifact_kind_code: u16,
    password_kdf: BackupKdfParameters,
    wrapping_aead: AeadAlgorithm,
    content_aead: AeadAlgorithm,
    context: PrivateArtifactContext,
    salt: [u8; PRIVATE_ARTIFACT_SALT_BYTES],
    wrapping_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
    content_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
    wrapped_content_key: BoundedBytes<PRIVATE_ARTIFACT_WRAPPED_KEY_BYTES>,
    ciphertext: BoundedBytes<MAX_PRIVATE_BACKUP_BYTES>,
    extensions: Extensions,
}

impl BackupEnvelope {
    /// Encrypt a validated account backup using fallible operating-system entropy.
    #[cfg(feature = "os-rng")]
    #[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
    pub fn seal(
        context: PrivateArtifactContext,
        passphrase: &BackupPassphrase,
        authority_bundle: &BackupAuthorityBundle,
        application_data: Option<&ApplicationBackupData>,
    ) -> Result<Self, IdentityError> {
        let mut salt = [0; PRIVATE_ARTIFACT_SALT_BYTES];
        let mut wrapping_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_key = Zeroizing::new([0; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]);
        getrandom::fill(&mut salt).map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(&mut wrapping_nonce).map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(&mut content_nonce).map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(content_key.as_mut()).map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::seal_with_randomness(
            context,
            passphrase,
            authority_bundle,
            application_data,
            salt,
            wrapping_nonce,
            content_nonce,
            content_key,
        )
    }

    /// Encrypt a validated account backup using injected fallible cryptographic entropy.
    pub fn seal_with_rng(
        context: PrivateArtifactContext,
        passphrase: &BackupPassphrase,
        authority_bundle: &BackupAuthorityBundle,
        application_data: Option<&ApplicationBackupData>,
        rng: &mut impl TryCryptoRng,
    ) -> Result<Self, IdentityError> {
        let mut salt = [0; PRIVATE_ARTIFACT_SALT_BYTES];
        let mut wrapping_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_nonce = [0; PRIVATE_ARTIFACT_NONCE_BYTES];
        let mut content_key = Zeroizing::new([0; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]);
        rng.try_fill_bytes(&mut salt)
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(&mut wrapping_nonce)
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(&mut content_nonce)
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(content_key.as_mut())
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::seal_with_randomness(
            context,
            passphrase,
            authority_bundle,
            application_data,
            salt,
            wrapping_nonce,
            content_nonce,
            content_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_with_randomness(
        context: PrivateArtifactContext,
        passphrase: &BackupPassphrase,
        authority_bundle: &BackupAuthorityBundle,
        application_data: Option<&ApplicationBackupData>,
        salt: [u8; PRIVATE_ARTIFACT_SALT_BYTES],
        wrapping_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
        content_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
        content_key: Zeroizing<[u8; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]>,
    ) -> Result<Self, IdentityError> {
        if salt == [0; PRIVATE_ARTIFACT_SALT_BYTES]
            || wrapping_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
            || content_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
            || content_key.as_ref() == [0; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]
        {
            return Err(IdentityError::EntropyUnavailable);
        }
        validate_backup_context(&context, authority_bundle)?;
        let payload_extensions = Extensions::default();
        let payload = BackupPayloadRef {
            protocol_version: ProtocolVersion::V1,
            authority_bundle,
            application_data: application_data.map(ApplicationBackupData::as_bytes),
            extensions: &payload_extensions,
        };
        let plaintext = Zeroizing::new(encode_wire(&payload)?);
        if plaintext.len() > MAX_PRIVATE_BACKUP_PLAINTEXT_BYTES {
            return Err(IdentityError::limit(
                "private backup plaintext bytes",
                plaintext.len(),
                MAX_PRIVATE_BACKUP_PLAINTEXT_BYTES,
            ));
        }
        let mut envelope = Self {
            protocol_version: ProtocolVersion::V1,
            artifact_kind_code: PRIVATE_BACKUP_KIND_CODE,
            password_kdf: BackupKdfParameters::FIXED_V1,
            wrapping_aead: AeadAlgorithm::XChaCha20Poly1305,
            content_aead: AeadAlgorithm::XChaCha20Poly1305,
            context,
            salt,
            wrapping_nonce,
            content_nonce,
            wrapped_content_key: BoundedBytes::new("wrapped backup content key", Vec::new())?,
            ciphertext: BoundedBytes::new("private backup ciphertext", Vec::new())?,
            extensions: Extensions::default(),
        };
        let wrapping_key = derive_backup_wrapping_key(passphrase, &envelope.salt)?;
        let wrapping_aad = envelope.wrapping_aad()?;
        let wrapping_cipher = XChaCha20Poly1305::new(&Key::from(*wrapping_key));
        let wrapped_content_key = wrapping_cipher
            .encrypt(
                &XNonce::from(envelope.wrapping_nonce),
                Payload {
                    msg: content_key.as_ref(),
                    aad: &wrapping_aad,
                },
            )
            .map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "backup content-key wrapping",
            })?;
        envelope.wrapped_content_key =
            BoundedBytes::new("wrapped backup content key", wrapped_content_key)?;

        let content_aad = envelope.content_aad()?;
        let content_cipher = XChaCha20Poly1305::new(&Key::from(*content_key));
        let ciphertext = content_cipher
            .encrypt(
                &XNonce::from(envelope.content_nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &content_aad,
                },
            )
            .map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "private backup encryption",
            })?;
        envelope.ciphertext = BoundedBytes::new("private backup ciphertext", ciphertext)?;
        envelope.validate()?;
        let encoded_len = encode_wire(&envelope)?.len();
        if encoded_len > MAX_PRIVATE_BACKUP_BYTES {
            return Err(IdentityError::limit(
                "private backup envelope bytes",
                encoded_len,
                MAX_PRIVATE_BACKUP_BYTES,
            ));
        }
        Ok(envelope)
    }

    /// Authenticate, decrypt, and revalidate all restored account authority.
    pub fn restore(
        &self,
        passphrase: &BackupPassphrase,
    ) -> Result<BackupRestoration, IdentityError> {
        self.validate()?;
        let wrapping_key = derive_backup_wrapping_key(passphrase, &self.salt)?;
        let wrapping_aad = self.wrapping_aad()?;
        let wrapping_cipher = XChaCha20Poly1305::new(&Key::from(*wrapping_key));
        let content_key = wrapping_cipher
            .decrypt(
                &XNonce::from(self.wrapping_nonce),
                Payload {
                    msg: self.wrapped_content_key.as_slice(),
                    aad: &wrapping_aad,
                },
            )
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
        let content_key: [u8; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES] = content_key
            .try_into()
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
        let content_key = Zeroizing::new(content_key);
        let content_aad = self.content_aad()?;
        let content_cipher = XChaCha20Poly1305::new(&Key::from(*content_key));
        let plaintext = Zeroizing::new(
            content_cipher
                .decrypt(
                    &XNonce::from(self.content_nonce),
                    Payload {
                        msg: self.ciphertext.as_slice(),
                        aad: &content_aad,
                    },
                )
                .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?,
        );
        let (payload, remaining) = postcard::take_from_bytes::<BackupPayload>(plaintext.as_slice())
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
        if !remaining.is_empty()
            || payload.protocol_version != ProtocolVersion::V1
            || payload.extensions.validate_critical(&[]).is_err()
            || validate_backup_context(&self.context, &payload.authority_bundle).is_err()
        {
            return Err(IdentityError::PrivateArtifactAuthenticationFailed);
        }
        let account_authority = payload
            .authority_bundle
            .validate_authority()
            .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
        let application_data = match payload.application_data {
            Some(bytes) => ApplicationDataRestoration::Restored(
                ApplicationBackupData::try_new(bytes.into_vec())
                    .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?,
            ),
            None => ApplicationDataRestoration::Unavailable,
        };
        Ok(BackupRestoration {
            account_authority,
            application_data,
        })
    }

    /// Exact public context authenticated by both backup encryption layers.
    pub const fn context(&self) -> &PrivateArtifactContext {
        &self.context
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.protocol_version.get(),
            });
        }
        if self.artifact_kind_code != PRIVATE_BACKUP_KIND_CODE {
            return Err(IdentityError::UnsupportedCodepoint {
                registry: "private artifact kind",
                code: self.artifact_kind_code,
            });
        }
        self.password_kdf.validate()?;
        if self.wrapping_aead != AeadAlgorithm::XChaCha20Poly1305
            || self.content_aead != AeadAlgorithm::XChaCha20Poly1305
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "private backup cryptographic profile",
            });
        }
        if self.salt == [0; PRIVATE_ARTIFACT_SALT_BYTES]
            || self.wrapping_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
            || self.content_nonce == [0; PRIVATE_ARTIFACT_NONCE_BYTES]
        {
            return Err(IdentityError::ZeroValue {
                resource: "private backup salt or nonce",
            });
        }
        if self.wrapped_content_key.len() != PRIVATE_ARTIFACT_WRAPPED_KEY_BYTES
            || self.ciphertext.len() <= PRIVATE_ARTIFACT_TAG_BYTES
        {
            return Err(IdentityError::InvalidEncoding);
        }
        self.extensions.validate_critical(&[])
    }

    fn header_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&(
            self.protocol_version,
            self.artifact_kind_code,
            self.password_kdf,
            self.wrapping_aead,
            self.content_aead,
            &self.context,
            self.salt,
            self.wrapping_nonce,
            self.content_nonce,
            &self.extensions,
        ))
    }

    fn wrapping_aad(&self) -> Result<Vec<u8>, IdentityError> {
        domain_message(PRIVATE_ARTIFACT_WRAP_DOMAIN, &self.header_bytes()?)
    }

    fn content_aad(&self) -> Result<Vec<u8>, IdentityError> {
        let body = encode_wire(&(self.header_bytes()?, self.wrapped_content_key.as_slice()))?;
        domain_message(PRIVATE_ARTIFACT_CONTENT_DOMAIN, &body)
    }
}

impl fmt::Debug for BackupEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupEnvelope")
            .field("context", &self.context)
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for BackupEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            artifact_kind_code: u16,
            password_kdf: BackupKdfParameters,
            wrapping_aead: AeadAlgorithm,
            content_aead: AeadAlgorithm,
            context: PrivateArtifactContext,
            salt: [u8; PRIVATE_ARTIFACT_SALT_BYTES],
            wrapping_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
            content_nonce: [u8; PRIVATE_ARTIFACT_NONCE_BYTES],
            wrapped_content_key: BoundedBytes<PRIVATE_ARTIFACT_WRAPPED_KEY_BYTES>,
            ciphertext: BoundedBytes<MAX_PRIVATE_BACKUP_BYTES>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        let envelope = Self {
            protocol_version: wire.protocol_version,
            artifact_kind_code: wire.artifact_kind_code,
            password_kdf: wire.password_kdf,
            wrapping_aead: wire.wrapping_aead,
            content_aead: wire.content_aead,
            context: wire.context,
            salt: wire.salt,
            wrapping_nonce: wire.wrapping_nonce,
            content_nonce: wire.content_nonce,
            wrapped_content_key: wire.wrapped_content_key,
            ciphertext: wire.ciphertext,
            extensions: wire.extensions,
        };
        envelope.validate().map_err(de::Error::custom)?;
        Ok(envelope)
    }
}

impl CanonicalCodec for BackupEnvelope {
    const RESOURCE: &'static str = "private backup envelope bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PRIVATE_BACKUP_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

fn validate_backup_context(
    context: &PrivateArtifactContext,
    authority_bundle: &BackupAuthorityBundle,
) -> Result<(), IdentityError> {
    if context.account_id() != authority_bundle.account_id()
        || context.checkpoint_id() != authority_bundle.checkpoint_id()
        || context.account_epoch() != authority_bundle.account_epoch()
        || context.application_id().is_some()
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "private backup authenticated context",
        });
    }
    Ok(())
}

fn nonzero_secret(
    bytes: [u8; 32],
    resource: &'static str,
) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    if bytes == [0; 32] {
        return Err(IdentityError::ZeroValue { resource });
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(feature = "os-rng")]
fn os_secret() -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| IdentityError::EntropyUnavailable)?;
    if bytes == [0; 32] {
        return Err(IdentityError::EntropyUnavailable);
    }
    Ok(Zeroizing::new(bytes))
}

fn rng_secret(rng: &mut impl TryCryptoRng) -> Result<Zeroizing<[u8; 32]>, IdentityError> {
    let mut bytes = [0; 32];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|_| IdentityError::EntropyUnavailable)?;
    if bytes == [0; 32] {
        return Err(IdentityError::EntropyUnavailable);
    }
    Ok(Zeroizing::new(bytes))
}

fn keyed_digest(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> Result<Digest, IdentityError> {
    let message = domain_message(domain, payload)?;
    Ok(Digest::new(
        HashAlgorithm::Blake3_256,
        *blake3::keyed_hash(key, &message).as_bytes(),
    ))
}

fn normalize_dns_context(value: &str, resource: &'static str) -> Result<String, IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::EmptyCollection { resource });
    }
    if !value.is_ascii() || value.len() > MAX_RELYING_PARTY_CONTEXT_BYTES {
        return Err(IdentityError::limit(
            resource,
            value.len(),
            MAX_RELYING_PARTY_CONTEXT_BYTES,
        ));
    }
    let normalized = value.to_ascii_lowercase();
    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(IdentityError::InvalidEncoding);
        }
    }
    Ok(normalized)
}

fn normalize_claim_name(value: &str) -> Result<String, IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::EmptyCollection {
            resource: "portable credential claim name",
        });
    }
    if !value.is_ascii() || value.len() > MAX_CREDENTIAL_CLAIM_NAME_BYTES {
        return Err(IdentityError::limit(
            "portable credential claim name",
            value.len(),
            MAX_CREDENTIAL_CLAIM_NAME_BYTES,
        ));
    }
    let normalized = value.to_ascii_lowercase();
    if !normalized
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        || !normalized
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IdentityError::InvalidEncoding);
    }
    Ok(normalized)
}

fn verify_exact_signature(
    signing_key: SigningPublicKey,
    signature: &AlgorithmSignature,
    message: &[u8],
) -> Result<(), IdentityError> {
    crate::verifier::verify_algorithm_signature(
        signing_key.algorithm().code(),
        signing_key.as_bytes(),
        signature,
        message,
    )
}

fn derive_backup_wrapping_key(
    passphrase: &BackupPassphrase,
    salt: &[u8; PRIVATE_ARTIFACT_SALT_BYTES],
) -> Result<Zeroizing<[u8; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]>, IdentityError> {
    let parameters = Params::new(
        PRIVATE_BACKUP_ARGON2_MEMORY_KIB,
        PRIVATE_BACKUP_ARGON2_ITERATIONS,
        PRIVATE_BACKUP_ARGON2_LANES,
        Some(PRIVATE_ARTIFACT_CONTENT_KEY_BYTES),
    )
    .map_err(|_| IdentityError::InvalidRelationship {
        resource: "fixed backup password KDF parameters",
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut wrapping_key = Zeroizing::new([0; PRIVATE_ARTIFACT_CONTENT_KEY_BYTES]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, wrapping_key.as_mut())
        .map_err(|_| IdentityError::PrivateArtifactAuthenticationFailed)?;
    Ok(wrapping_key)
}

fn derive_metadata_wrapping_key(
    key: &PrivateMetadataKey,
    salt: &[u8; PRIVATE_ARTIFACT_SALT_BYTES],
) -> Zeroizing<[u8; PRIVATE_METADATA_KEY_BYTES]> {
    let mut material =
        Zeroizing::new([0_u8; PRIVATE_METADATA_KEY_BYTES + PRIVATE_ARTIFACT_SALT_BYTES]);
    material[..PRIVATE_METADATA_KEY_BYTES].copy_from_slice(key.as_bytes());
    material[PRIVATE_METADATA_KEY_BYTES..].copy_from_slice(salt);
    Zeroizing::new(blake3::derive_key(
        PRIVATE_METADATA_KDF_CONTEXT,
        material.as_ref(),
    ))
}

fn domain_message(domain: &[u8], body: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let capacity = domain
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(body.len()))
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "private artifact associated-data bytes",
        })?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(body);
    Ok(message)
}
