//! Bounded cryptographic migration, protocol upgrade, and retirement wire schemas.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    AccountId, AeadAlgorithm, AgreementAlgorithm, AlgorithmPublicKey, AlgorithmSignature,
    ControllerId, ControllerKeyId, CryptoMigrationId, CryptoSuiteId, Digest, EventId, Extensions,
    HashAlgorithm, IdentityError, KdfAlgorithm, ProtocolMajor, ProtocolVersion,
    RevocationReasonCode,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_ACCOUNT_EVENT_BYTES, MAX_CONTROLLERS},
    schema::BoundedVec,
};

const CRYPTO_SUITE_RETIREMENT_ABORT_CANDIDATE_CODE: u16 = 1;
const CRYPTO_SUITE_RETIREMENT_RETIRE_PREVIOUS_CODE: u16 = 2;
const UPGRADE_COMPATIBILITY_OLD_CLIENTS_READ_ONLY_CODE: u16 = 1;

macro_rules! canonical_wire {
    ($type:ty, $resource:literal) => {
        impl CanonicalCodec for $type {
            const RESOURCE: &'static str = $resource;

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(self)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                decode_wire(bytes)
            }
        }
    };
    ($type:ty, $resource:literal, $maximum:expr) => {
        impl CanonicalCodec for $type {
            const RESOURCE: &'static str = $resource;
            const MAX_ENCODED_BYTES: usize = $maximum;

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(self)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                decode_wire(bytes)
            }
        }
    };
}

fn validate_nonzero_code(code: u16, resource: &'static str) -> Result<(), IdentityError> {
    if code == 0 {
        return Err(IdentityError::ZeroValue { resource });
    }
    Ok(())
}

/// A versioned, algorithm-tagged cryptographic suite descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CryptoSuiteDescriptor {
    version: ProtocolVersion,
    suite_code: u16,
    hash_algorithm_code: u16,
    signature_algorithm_code: u16,
    agreement_algorithm_code: u16,
    kdf_algorithm_code: u16,
    aead_algorithm_code: u16,
    extensions: Extensions,
}

impl CryptoSuiteDescriptor {
    /// Initial v1 suite: BLAKE3, Ed25519, X25519, BLAKE3 KDF, and XChaCha20-Poly1305.
    pub fn v1() -> Result<Self, IdentityError> {
        Self::try_new(
            ProtocolVersion::V1,
            1,
            HashAlgorithm::Blake3_256.code(),
            crate::SignatureAlgorithm::Ed25519.code(),
            AgreementAlgorithm::X25519.code(),
            KdfAlgorithm::Blake3DeriveKey.code(),
            AeadAlgorithm::XChaCha20Poly1305.code(),
            Extensions::default(),
        )
    }

    /// Construct a suite descriptor from nonzero registry codepoints.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        version: ProtocolVersion,
        suite_code: u16,
        hash_algorithm_code: u16,
        signature_algorithm_code: u16,
        agreement_algorithm_code: u16,
        kdf_algorithm_code: u16,
        aead_algorithm_code: u16,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(
            version,
            suite_code,
            hash_algorithm_code,
            signature_algorithm_code,
            agreement_algorithm_code,
            kdf_algorithm_code,
            aead_algorithm_code,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_canonical_wire(
        version: ProtocolVersion,
        suite_code: u16,
        hash_algorithm_code: u16,
        signature_algorithm_code: u16,
        agreement_algorithm_code: u16,
        kdf_algorithm_code: u16,
        aead_algorithm_code: u16,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_nonzero_code(suite_code, "cryptographic suite code")?;
        validate_nonzero_code(hash_algorithm_code, "hash algorithm code")?;
        validate_nonzero_code(signature_algorithm_code, "signature algorithm code")?;
        validate_nonzero_code(agreement_algorithm_code, "agreement algorithm code")?;
        validate_nonzero_code(kdf_algorithm_code, "key derivation algorithm code")?;
        validate_nonzero_code(
            aead_algorithm_code,
            "authenticated encryption algorithm code",
        )?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            version,
            suite_code,
            hash_algorithm_code,
            signature_algorithm_code,
            agreement_algorithm_code,
            kdf_algorithm_code,
            aead_algorithm_code,
            extensions,
        })
    }

    /// Schema version of this descriptor.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Stable cryptographic-suite registry code.
    pub const fn suite_code(&self) -> u16 {
        self.suite_code
    }

    /// Hash-algorithm registry code.
    pub const fn hash_algorithm_code(&self) -> u16 {
        self.hash_algorithm_code
    }

    /// Signature-algorithm registry code.
    pub const fn signature_algorithm_code(&self) -> u16 {
        self.signature_algorithm_code
    }

    /// Key-agreement-algorithm registry code.
    pub const fn agreement_algorithm_code(&self) -> u16 {
        self.agreement_algorithm_code
    }

    /// Key-derivation-algorithm registry code.
    pub const fn kdf_algorithm_code(&self) -> u16 {
        self.kdf_algorithm_code
    }

    /// Authenticated-encryption-algorithm registry code.
    pub const fn aead_algorithm_code(&self) -> u16 {
        self.aead_algorithm_code
    }

    /// Signed extension fields, which are the descriptor's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Derive the domain-separated identifier of this canonical descriptor.
    pub fn crypto_suite_id(&self) -> Result<CryptoSuiteId, IdentityError> {
        CryptoSuiteId::derive(self)
    }

    fn permits_v1_in_place_migration(&self) -> bool {
        self.hash_algorithm_code == HashAlgorithm::Blake3_256.code()
            && self.agreement_algorithm_code == AgreementAlgorithm::X25519.code()
            && self.kdf_algorithm_code == KdfAlgorithm::Blake3DeriveKey.code()
            && self.aead_algorithm_code == AeadAlgorithm::XChaCha20Poly1305.code()
    }
}

impl<'de> Deserialize<'de> for CryptoSuiteDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            version: ProtocolVersion,
            suite_code: u16,
            hash_algorithm_code: u16,
            signature_algorithm_code: u16,
            agreement_algorithm_code: u16,
            kdf_algorithm_code: u16,
            aead_algorithm_code: u16,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.version,
            wire.suite_code,
            wire.hash_algorithm_code,
            wire.signature_algorithm_code,
            wire.agreement_algorithm_code,
            wire.kdf_algorithm_code,
            wire.aead_algorithm_code,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(
    CryptoSuiteDescriptor,
    "cryptographic suite descriptor bytes"
);

/// One controller's old key identifier and bounded candidate signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControllerKeyBinding {
    controller_id: ControllerId,
    old_key_id: ControllerKeyId,
    new_signing_key: AlgorithmPublicKey,
    extensions: Extensions,
}

impl ControllerKeyBinding {
    /// Construct one controller key binding.
    pub fn try_new(
        controller_id: ControllerId,
        old_key_id: ControllerKeyId,
        new_signing_key: AlgorithmPublicKey,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(controller_id, old_key_id, new_signing_key, extensions)
    }

    fn from_canonical_wire(
        controller_id: ControllerId,
        old_key_id: ControllerKeyId,
        new_signing_key: AlgorithmPublicKey,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            controller_id,
            old_key_id,
            new_signing_key,
            extensions,
        })
    }

    /// Controller whose signing key is being migrated.
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Identifier of the controller's previously active key.
    pub const fn old_key_id(&self) -> ControllerKeyId {
        self.old_key_id
    }

    /// Candidate algorithm-tagged signing public key.
    pub const fn new_signing_key(&self) -> &AlgorithmPublicKey {
        &self.new_signing_key
    }

    /// Signed extension fields, which are the binding's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for ControllerKeyBinding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            controller_id: ControllerId,
            old_key_id: ControllerKeyId,
            new_signing_key: AlgorithmPublicKey,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.controller_id,
            wire.old_key_id,
            wire.new_signing_key,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(ControllerKeyBinding, "controller key binding bytes");

/// Canonical body describing a complete controller-signature-suite migration.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CryptoMigrationBody {
    version: ProtocolVersion,
    account_id: AccountId,
    from_suite_id: CryptoSuiteId,
    to_suite: CryptoSuiteDescriptor,
    bindings: BoundedVec<ControllerKeyBinding, MAX_CONTROLLERS>,
    successor_account_id: Option<AccountId>,
    nonce: [u8; 32],
    extensions: Extensions,
}

impl CryptoMigrationBody {
    /// Validate, sort, and construct a migration body.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        version: ProtocolVersion,
        account_id: AccountId,
        from_suite_id: CryptoSuiteId,
        to_suite: CryptoSuiteDescriptor,
        bindings: Vec<ControllerKeyBinding>,
        successor_account_id: Option<AccountId>,
        nonce: [u8; 32],
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let mut bindings = BoundedVec::<ControllerKeyBinding, MAX_CONTROLLERS>::new(
            "controller key bindings",
            bindings,
        )?
        .into_vec();
        bindings.sort_unstable_by_key(ControllerKeyBinding::controller_id);
        Self::from_canonical_wire(
            version,
            account_id,
            from_suite_id,
            to_suite,
            BoundedVec::new("controller key bindings", bindings)?,
            successor_account_id,
            nonce,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_canonical_wire(
        version: ProtocolVersion,
        account_id: AccountId,
        from_suite_id: CryptoSuiteId,
        to_suite: CryptoSuiteDescriptor,
        bindings: BoundedVec<ControllerKeyBinding, MAX_CONTROLLERS>,
        successor_account_id: Option<AccountId>,
        nonce: [u8; 32],
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let binding_slice = bindings.as_slice();
        if binding_slice.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "controller key bindings",
            });
        }
        for pair in binding_slice.windows(2) {
            if pair[0].controller_id() == pair[1].controller_id() {
                return Err(IdentityError::DuplicateElement {
                    resource: "controller key bindings",
                });
            }
            if pair[0].controller_id() > pair[1].controller_id() {
                return Err(IdentityError::NonCanonical);
            }
        }
        for (position, left) in binding_slice.iter().enumerate() {
            for right in binding_slice.iter().skip(position.saturating_add(1)) {
                if left.old_key_id() == right.old_key_id() {
                    return Err(IdentityError::DuplicateElement {
                        resource: "old controller key identifiers",
                    });
                }
                if left.new_signing_key() == right.new_signing_key() {
                    return Err(IdentityError::DuplicateSigningKey);
                }
            }
            if left.new_signing_key().algorithm_code() != to_suite.signature_algorithm_code() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "migration signing key algorithm",
                });
            }
        }
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(IdentityError::ZeroValue {
                resource: "cryptographic migration nonce",
            });
        }
        if successor_account_id.is_some_and(|successor| successor == account_id) {
            return Err(IdentityError::InvalidRelationship {
                resource: "migration successor account",
            });
        }
        if successor_account_id.is_none() && !to_suite.permits_v1_in_place_migration() {
            return Err(IdentityError::InvalidRelationship {
                resource: "in-place cryptographic migration suite",
            });
        }
        if from_suite_id == to_suite.crypto_suite_id()? {
            return Err(IdentityError::InvalidRelationship {
                resource: "cryptographic migration suites",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            version,
            account_id,
            from_suite_id,
            to_suite,
            bindings,
            successor_account_id,
            nonce,
            extensions,
        })
    }

    /// Schema version of this migration body.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Account whose controller suite is being migrated.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Identifier of the suite active before this migration.
    pub const fn from_suite_id(&self) -> CryptoSuiteId {
        self.from_suite_id
    }

    /// Candidate cryptographic suite descriptor.
    pub const fn to_suite(&self) -> &CryptoSuiteDescriptor {
        &self.to_suite
    }

    /// Canonically sorted controller key bindings.
    pub fn bindings(&self) -> &[ControllerKeyBinding] {
        self.bindings.as_slice()
    }

    /// Cross-certified successor account required by a digest-breaking migration.
    pub const fn successor_account_id(&self) -> Option<AccountId> {
        self.successor_account_id
    }

    /// Nonzero migration nonce.
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Signed extension fields, which are the migration body's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Derive the domain-separated identifier of this canonical migration body.
    pub fn crypto_migration_id(&self) -> Result<CryptoMigrationId, IdentityError> {
        CryptoMigrationId::derive(self)
    }
}

impl fmt::Debug for CryptoMigrationBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CryptoMigrationBody")
            .field("version", &self.version)
            .field("account_id", &self.account_id)
            .field("from_suite_id", &self.from_suite_id)
            .field("to_suite", &self.to_suite)
            .field("bindings", &self.bindings.as_slice())
            .field("successor_account_id", &self.successor_account_id)
            .field("nonce", &"<redacted nonce>")
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl<'de> Deserialize<'de> for CryptoMigrationBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            version: ProtocolVersion,
            account_id: AccountId,
            from_suite_id: CryptoSuiteId,
            to_suite: CryptoSuiteDescriptor,
            bindings: BoundedVec<ControllerKeyBinding, MAX_CONTROLLERS>,
            successor_account_id: Option<AccountId>,
            nonce: [u8; 32],
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.version,
            wire.account_id,
            wire.from_suite_id,
            wire.to_suite,
            wire.bindings,
            wire.successor_account_id,
            wire.nonce,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(
    CryptoMigrationBody,
    "cryptographic migration body bytes",
    MAX_ACCOUNT_EVENT_BYTES
);

/// Old/new cross-signature evidence for one controller binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControllerKeyBindingProof {
    migration_id: CryptoMigrationId,
    controller_id: ControllerId,
    old_key_signature: AlgorithmSignature,
    new_key_signature: AlgorithmSignature,
}

impl ControllerKeyBindingProof {
    /// Construct a controller's pair of migration cross-signatures.
    pub fn try_new(
        migration_id: CryptoMigrationId,
        controller_id: ControllerId,
        old_key_signature: AlgorithmSignature,
        new_key_signature: AlgorithmSignature,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(
            migration_id,
            controller_id,
            old_key_signature,
            new_key_signature,
        )
    }

    fn from_canonical_wire(
        migration_id: CryptoMigrationId,
        controller_id: ControllerId,
        old_key_signature: AlgorithmSignature,
        new_key_signature: AlgorithmSignature,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            migration_id,
            controller_id,
            old_key_signature,
            new_key_signature,
        })
    }

    /// Migration body authorized by this proof.
    pub const fn migration_id(&self) -> CryptoMigrationId {
        self.migration_id
    }

    /// Controller whose old and new keys produced the signatures.
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Signature produced by the previously active controller key.
    pub const fn old_key_signature(&self) -> &AlgorithmSignature {
        &self.old_key_signature
    }

    /// Signature produced by the candidate controller key.
    pub const fn new_key_signature(&self) -> &AlgorithmSignature {
        &self.new_key_signature
    }
}

impl<'de> Deserialize<'de> for ControllerKeyBindingProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            migration_id: CryptoMigrationId,
            controller_id: ControllerId,
            old_key_signature: AlgorithmSignature,
            new_key_signature: AlgorithmSignature,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.migration_id,
            wire.controller_id,
            wire.old_key_signature,
            wire.new_key_signature,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(
    ControllerKeyBindingProof,
    "controller key binding proof bytes"
);

/// A bounded proof set sorted uniquely by controller identifier.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ControllerKeyBindingProofSet(BoundedVec<ControllerKeyBindingProof, MAX_CONTROLLERS>);

impl ControllerKeyBindingProofSet {
    /// Validate, sort, and construct a complete-proof candidate set.
    pub fn try_new(proofs: Vec<ControllerKeyBindingProof>) -> Result<Self, IdentityError> {
        let mut proofs = BoundedVec::<ControllerKeyBindingProof, MAX_CONTROLLERS>::new(
            "controller key binding proofs",
            proofs,
        )?
        .into_vec();
        proofs.sort_unstable_by_key(ControllerKeyBindingProof::controller_id);
        Self::from_canonical_wire(BoundedVec::new("controller key binding proofs", proofs)?)
    }

    fn from_canonical_wire(
        proofs: BoundedVec<ControllerKeyBindingProof, MAX_CONTROLLERS>,
    ) -> Result<Self, IdentityError> {
        if proofs.as_slice().is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "controller key binding proofs",
            });
        }
        for pair in proofs.as_slice().windows(2) {
            if pair[0].controller_id() == pair[1].controller_id() {
                return Err(IdentityError::DuplicateElement {
                    resource: "controller key binding proofs",
                });
            }
            if pair[0].controller_id() > pair[1].controller_id() {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self(proofs))
    }

    /// Canonically sorted controller binding proofs.
    pub fn as_slice(&self) -> &[ControllerKeyBindingProof] {
        self.0.as_slice()
    }
}

impl fmt::Debug for ControllerKeyBindingProofSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ControllerKeyBindingProofSet")
            .field(&self.0.as_slice())
            .finish()
    }
}

impl<'de> Deserialize<'de> for ControllerKeyBindingProofSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let proofs =
            BoundedVec::<ControllerKeyBindingProof, MAX_CONTROLLERS>::deserialize(deserializer)?;
        Self::from_canonical_wire(proofs).map_err(de::Error::custom)
    }
}

canonical_wire!(
    ControllerKeyBindingProofSet,
    "controller key binding proof set bytes"
);

/// Code-18 payload that records a candidate migration and complete cross-bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BeginCryptoMigration {
    version: ProtocolVersion,
    migration: CryptoMigrationBody,
    proofs: ControllerKeyBindingProofSet,
    extensions: Extensions,
}

impl BeginCryptoMigration {
    /// Construct a begin payload with one matching proof for every controller binding.
    pub fn try_new(
        version: ProtocolVersion,
        migration: CryptoMigrationBody,
        proofs: ControllerKeyBindingProofSet,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(version, migration, proofs, extensions)
    }

    fn from_canonical_wire(
        version: ProtocolVersion,
        migration: CryptoMigrationBody,
        proofs: ControllerKeyBindingProofSet,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let migration_id = migration.crypto_migration_id()?;
        if migration.bindings().len() != proofs.as_slice().len() {
            return Err(IdentityError::InvalidRelationship {
                resource: "migration binding proof coverage",
            });
        }
        for (binding, proof) in migration.bindings().iter().zip(proofs.as_slice()) {
            if binding.controller_id() != proof.controller_id()
                || proof.migration_id() != migration_id
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "migration binding proof coverage",
                });
            }
            if proof.new_key_signature().algorithm_code()
                != migration.to_suite().signature_algorithm_code()
            {
                return Err(IdentityError::InvalidRelationship {
                    resource: "migration binding proof signature algorithm",
                });
            }
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            version,
            migration,
            proofs,
            extensions,
        })
    }

    /// Schema version of this begin payload.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Canonical migration body whose identifier is cross-signed.
    pub const fn migration(&self) -> &CryptoMigrationBody {
        &self.migration
    }

    /// Complete, sorted controller cross-binding proofs.
    pub const fn proofs(&self) -> &ControllerKeyBindingProofSet {
        &self.proofs
    }

    /// Signed extension fields, which are the payload's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for BeginCryptoMigration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            version: ProtocolVersion,
            migration: CryptoMigrationBody,
            proofs: ControllerKeyBindingProofSet,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(wire.version, wire.migration, wire.proofs, wire.extensions)
            .map_err(de::Error::custom)
    }
}

canonical_wire!(
    BeginCryptoMigration,
    "begin cryptographic migration payload bytes",
    MAX_ACCOUNT_EVENT_BYTES
);

/// Code-19 payload that activates the old/new dual-signature phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActivateCryptoMigration {
    version: ProtocolVersion,
    migration_id: CryptoMigrationId,
    begin_event_id: EventId,
    extensions: Extensions,
}

impl ActivateCryptoMigration {
    /// Construct a migration activation payload.
    pub fn try_new(
        version: ProtocolVersion,
        migration_id: CryptoMigrationId,
        begin_event_id: EventId,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(version, migration_id, begin_event_id, extensions)
    }

    fn from_canonical_wire(
        version: ProtocolVersion,
        migration_id: CryptoMigrationId,
        begin_event_id: EventId,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            version,
            migration_id,
            begin_event_id,
            extensions,
        })
    }

    /// Schema version of this activation payload.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Migration entering its dual-signature phase.
    pub const fn migration_id(&self) -> CryptoMigrationId {
        self.migration_id
    }

    /// Event that durably began this migration.
    pub const fn begin_event_id(&self) -> EventId {
        self.begin_event_id
    }

    /// Signed extension fields, which are the payload's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for ActivateCryptoMigration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            version: ProtocolVersion,
            migration_id: CryptoMigrationId,
            begin_event_id: EventId,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.version,
            wire.migration_id,
            wire.begin_event_id,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(
    ActivateCryptoMigration,
    "activate cryptographic migration payload bytes",
    MAX_ACCOUNT_EVENT_BYTES
);

/// Closed code-20 action selecting candidate abort or previous-suite retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum RetireCryptoSuiteMode {
    /// Abort an unactivated candidate and return the account to its prior active suite.
    AbortCandidate,
    /// Retire the previous suite after the dual-signature activation phase.
    RetirePrevious,
}

impl RetireCryptoSuiteMode {
    /// Stable v1 wire codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::AbortCandidate => CRYPTO_SUITE_RETIREMENT_ABORT_CANDIDATE_CODE,
            Self::RetirePrevious => CRYPTO_SUITE_RETIREMENT_RETIRE_PREVIOUS_CODE,
        }
    }

    /// Decode one closed v1 retirement-mode codepoint.
    pub const fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            CRYPTO_SUITE_RETIREMENT_ABORT_CANDIDATE_CODE => Ok(Self::AbortCandidate),
            CRYPTO_SUITE_RETIREMENT_RETIRE_PREVIOUS_CODE => Ok(Self::RetirePrevious),
            unsupported => Err(IdentityError::UnsupportedCodepoint {
                registry: "cryptographic suite retirement mode",
                code: unsupported,
            }),
        }
    }
}

impl Serialize for RetireCryptoSuiteMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RetireCryptoSuiteMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_code(u16::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

canonical_wire!(
    RetireCryptoSuiteMode,
    "cryptographic suite retirement mode bytes"
);

/// Code-20 payload that either recovers from a failed begin or completes migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireCryptoSuite {
    version: ProtocolVersion,
    migration_id: CryptoMigrationId,
    mode: RetireCryptoSuiteMode,
    phase_event_id: EventId,
    successor_account_id: Option<AccountId>,
    extensions: Extensions,
}

impl RetireCryptoSuite {
    /// Construct a recoverable code-20 migration payload.
    pub fn try_new(
        version: ProtocolVersion,
        migration_id: CryptoMigrationId,
        mode: RetireCryptoSuiteMode,
        phase_event_id: EventId,
        successor_account_id: Option<AccountId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(
            version,
            migration_id,
            mode,
            phase_event_id,
            successor_account_id,
            extensions,
        )
    }

    fn from_canonical_wire(
        version: ProtocolVersion,
        migration_id: CryptoMigrationId,
        mode: RetireCryptoSuiteMode,
        phase_event_id: EventId,
        successor_account_id: Option<AccountId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if mode == RetireCryptoSuiteMode::AbortCandidate && successor_account_id.is_some() {
            return Err(IdentityError::InvalidRelationship {
                resource: "aborted migration successor account",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            version,
            migration_id,
            mode,
            phase_event_id,
            successor_account_id,
            extensions,
        })
    }

    /// Schema version of this code-20 payload.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Migration being aborted or completed.
    pub const fn migration_id(&self) -> CryptoMigrationId {
        self.migration_id
    }

    /// Whether this payload aborts the candidate or retires the previous suite.
    pub const fn mode(&self) -> RetireCryptoSuiteMode {
        self.mode
    }

    /// Begin event for abort mode or activation event for retirement mode.
    pub const fn phase_event_id(&self) -> EventId {
        self.phase_event_id
    }

    /// Optional successor account published when completing a digest-breaking migration.
    pub const fn successor_account_id(&self) -> Option<AccountId> {
        self.successor_account_id
    }

    /// Signed extension fields, which are the payload's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for RetireCryptoSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            version: ProtocolVersion,
            migration_id: CryptoMigrationId,
            mode: RetireCryptoSuiteMode,
            phase_event_id: EventId,
            successor_account_id: Option<AccountId>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.version,
            wire.migration_id,
            wire.mode,
            wire.phase_event_id,
            wire.successor_account_id,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(
    RetireCryptoSuite,
    "retire cryptographic suite payload bytes",
    MAX_ACCOUNT_EVENT_BYTES
);

/// Compatibility behavior required after a v1 protocol-major upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum UpgradeCompatibility {
    /// Clients unable to validate the new major remain read-only.
    OldClientsReadOnly,
}

impl UpgradeCompatibility {
    /// Stable v1 wire codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::OldClientsReadOnly => UPGRADE_COMPATIBILITY_OLD_CLIENTS_READ_ONLY_CODE,
        }
    }

    /// Decode one closed v1 compatibility codepoint.
    pub const fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            UPGRADE_COMPATIBILITY_OLD_CLIENTS_READ_ONLY_CODE => Ok(Self::OldClientsReadOnly),
            unsupported => Err(IdentityError::UnsupportedCodepoint {
                registry: "protocol upgrade compatibility",
                code: unsupported,
            }),
        }
    }
}

impl Serialize for UpgradeCompatibility {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UpgradeCompatibility {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_code(u16::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

canonical_wire!(UpgradeCompatibility, "protocol upgrade compatibility bytes");

/// Code-21 payload that moves an account to a strictly newer protocol major.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolUpgrade {
    version: ProtocolVersion,
    from_major: ProtocolMajor,
    to_major: ProtocolMajor,
    specification_digest: Digest,
    compatibility: UpgradeCompatibility,
    successor_account_id: Option<AccountId>,
    extensions: Extensions,
}

impl ProtocolUpgrade {
    /// Construct an upgrade to a strictly greater nonzero protocol major.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        version: ProtocolVersion,
        from_major: ProtocolMajor,
        to_major: ProtocolMajor,
        specification_digest: Digest,
        compatibility: UpgradeCompatibility,
        successor_account_id: Option<AccountId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(
            version,
            from_major,
            to_major,
            specification_digest,
            compatibility,
            successor_account_id,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_canonical_wire(
        version: ProtocolVersion,
        from_major: ProtocolMajor,
        to_major: ProtocolMajor,
        specification_digest: Digest,
        compatibility: UpgradeCompatibility,
        successor_account_id: Option<AccountId>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if to_major <= from_major {
            return Err(IdentityError::InvalidRelationship {
                resource: "protocol upgrade major versions",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            version,
            from_major,
            to_major,
            specification_digest,
            compatibility,
            successor_account_id,
            extensions,
        })
    }

    /// Schema version of this upgrade payload.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Protocol major active before the upgrade.
    pub const fn from_major(&self) -> ProtocolMajor {
        self.from_major
    }

    /// Strictly newer target protocol major.
    pub const fn to_major(&self) -> ProtocolMajor {
        self.to_major
    }

    /// Digest of the target protocol specification.
    pub const fn specification_digest(&self) -> Digest {
        self.specification_digest
    }

    /// Required behavior for clients that cannot validate the target major.
    pub const fn compatibility(&self) -> UpgradeCompatibility {
        self.compatibility
    }

    /// Optional cross-certified account on the target protocol.
    pub const fn successor_account_id(&self) -> Option<AccountId> {
        self.successor_account_id
    }

    /// Signed extension fields, which are the payload's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for ProtocolUpgrade {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            version: ProtocolVersion,
            from_major: ProtocolMajor,
            to_major: ProtocolMajor,
            specification_digest: Digest,
            compatibility: UpgradeCompatibility,
            successor_account_id: Option<AccountId>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.version,
            wire.from_major,
            wire.to_major,
            wire.specification_digest,
            wire.compatibility,
            wire.successor_account_id,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(
    ProtocolUpgrade,
    "protocol upgrade payload bytes",
    MAX_ACCOUNT_EVENT_BYTES
);

/// Code-22 terminal account-retirement payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RetireAccount {
    version: ProtocolVersion,
    successor_account_id: Option<AccountId>,
    reason_code: Option<RevocationReasonCode>,
    extensions: Extensions,
}

impl RetireAccount {
    /// Construct terminal account retirement metadata.
    pub fn try_new(
        version: ProtocolVersion,
        successor_account_id: Option<AccountId>,
        reason_code: Option<RevocationReasonCode>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_canonical_wire(version, successor_account_id, reason_code, extensions)
    }

    fn from_canonical_wire(
        version: ProtocolVersion,
        successor_account_id: Option<AccountId>,
        reason_code: Option<RevocationReasonCode>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            version,
            successor_account_id,
            reason_code,
            extensions,
        })
    }

    /// Schema version of this retirement payload.
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    /// Optional successor account advertised by this terminal transition.
    pub const fn successor_account_id(&self) -> Option<AccountId> {
        self.successor_account_id
    }

    /// Optional nonzero public retirement reason code.
    pub const fn reason_code(&self) -> Option<RevocationReasonCode> {
        self.reason_code
    }

    /// Signed extension fields, which are the payload's final wire field.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for RetireAccount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            version: ProtocolVersion,
            successor_account_id: Option<AccountId>,
            reason_code: Option<RevocationReasonCode>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_canonical_wire(
            wire.version,
            wire.successor_account_id,
            wire.reason_code,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_wire!(
    RetireAccount,
    "retire account payload bytes",
    MAX_ACCOUNT_EVENT_BYTES
);
