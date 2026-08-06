//! Reusable bounded wire machinery and checked schema scalars.

use std::{fmt, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, de, ser::SerializeSeq};

use crate::{
    CanonicalWire, Digest, IdentityError, ProtocolSignature, SigningPublicKey,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_ALGORITHM_PUBLIC_KEY_BYTES, MAX_ALGORITHM_SIGNATURE_BYTES, MAX_DELEGATION_DEPTH},
    types::{HashDomain, hash_bytes},
};

macro_rules! digest_id {
    ($name:ident, $domain:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(Digest);

        impl $name {
            /// Borrow the algorithm-tagged digest.
            pub const fn as_digest(&self) -> &Digest {
                &self.0
            }

            #[allow(dead_code)] // Schema modules consume each derivation incrementally.
            pub(crate) fn derive<T: CanonicalWire>(body: &T) -> Result<Self, IdentityError> {
                let bytes = body.to_canonical_bytes()?;
                Ok(Self(hash_bytes(HashDomain::$domain, &bytes)))
            }

            #[allow(dead_code)] // Projection-only IDs need this in later planned tasks.
            pub(crate) const fn from_digest(digest: Digest) -> Self {
                Self(digest)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl CanonicalCodec for $name {
            const RESOURCE: &'static str = concat!(stringify!($name), " bytes");

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(self)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                decode_wire(bytes)
            }
        }
    };
}

digest_id!(
    GenesisAnchor,
    GenesisAnchor,
    "First-event predecessor derived from account genesis."
);
digest_id!(
    AccountId,
    AccountId,
    "Stable account identifier derived from canonical genesis."
);
digest_id!(
    ControllerId,
    ControllerDescriptor,
    "Stable account-controller identifier."
);
digest_id!(
    ControllerKeyId,
    ControllerKey,
    "Controller key binding identifier."
);
digest_id!(
    ControlPolicyId,
    ControlPolicy,
    "Canonical control-policy identifier."
);
digest_id!(
    RecoveryPolicyId,
    RecoveryPolicy,
    "Canonical recovery-policy identifier."
);
digest_id!(
    ProviderId,
    Provider,
    "Self-certifying transparency-provider identifier."
);
digest_id!(
    ProviderLogId,
    ProviderLog,
    "Transparency-provider log identifier."
);
digest_id!(
    ProviderPolicyId,
    ProviderPolicy,
    "Canonical account provider-policy identifier."
);
digest_id!(
    DeviceId,
    DeviceDescriptor,
    "Replaceable independently keyed device identifier."
);
digest_id!(
    CapabilityGrantId,
    CapabilityGrant,
    "Canonical capability-grant identifier."
);
digest_id!(
    DelegationId,
    CapabilityDelegation,
    "Canonical capability-delegation identifier."
);
digest_id!(
    ProposalId,
    AccountProposal,
    "Proposal-domain identifier of an account event body."
);
/// Authoritative identifier of an account event body and its exact admission evidence.
///
/// Unlike body-derived identifiers, this type deliberately has no generic `derive` helper. The
/// only v1 derivation is the acyclic admitted-event construction in `event`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventId(Digest);

impl EventId {
    /// Borrow the algorithm-tagged digest.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }

    pub(crate) const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("EventId").field(&self.0).finish()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl CanonicalCodec for EventId {
    const RESOURCE: &'static str = "EventId bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}
digest_id!(
    EventAuthorizationId,
    EventAuthorization,
    "Domain-separated identifier of a complete authorized-event envelope."
);
digest_id!(
    AdmissionEvidenceId,
    AdmissionEvidence,
    "Historical event-admission evidence identifier."
);
digest_id!(
    ControllerApprovalId,
    ControllerApproval,
    "Controller approval-body identifier."
);
digest_id!(
    EventIntentApprovalId,
    EventIntentApproval,
    "Controller proposal-intent approval-body identifier."
);
digest_id!(
    CheckpointId,
    AccountCheckpoint,
    "Canonical checkpoint-body identifier."
);
digest_id!(
    RecoveryId,
    Recovery,
    "Canonical recovery-proposal identifier."
);
digest_id!(
    GuardianGrantId,
    GuardianGrant,
    "Blinded recovery guardian-grant identifier."
);
digest_id!(
    ForkId,
    Fork,
    "Canonical complete fork descriptor identifier."
);
digest_id!(
    CryptoSuiteId,
    CryptoSuite,
    "Canonical cryptographic-suite identifier."
);
digest_id!(
    CryptoMigrationId,
    CryptoMigration,
    "Canonical cryptographic-migration identifier."
);
digest_id!(
    CryptoStateId,
    CryptoState,
    "Projected cryptographic-state identifier."
);
digest_id!(
    ApplicationId,
    ApplicationId,
    "Application-supplied typed identifier."
);
digest_id!(
    ApplicationEventId,
    ApplicationEvent,
    "Canonical signed application-event identifier."
);
digest_id!(GroupId, GroupId, "Application-supplied group identifier.");
digest_id!(
    GroupKeyWrapId,
    GroupKeyWrap,
    "Canonical wrapped group-key identifier."
);

impl ControllerKeyId {
    /// Derive the v1 key identifier used by approvals for an Ed25519 controller key.
    pub fn for_signing_key(key: &SigningPublicKey) -> Result<Self, IdentityError> {
        Self::derive(key)
    }

    /// Derive a migration-era key identifier from bounded algorithm-tagged key material.
    pub fn for_algorithm_key(key: &AlgorithmPublicKey) -> Result<Self, IdentityError> {
        Self::derive(key)
    }
}

impl ApplicationId {
    /// Construct an application-supplied v1 digest identifier.
    pub const fn new(digest: Digest) -> Self {
        Self::from_digest(digest)
    }
}

impl GroupId {
    /// Construct an application-supplied v1 digest identifier.
    pub const fn new(digest: Digest) -> Self {
        Self::from_digest(digest)
    }
}

/// A nonzero controller weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ControllerWeight(u32);

/// A nonzero authorization threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RequiredWeight(u32);

/// A nonzero number of transparency providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ProviderQuorum(u16);

/// A bounded, nonzero remaining capability-delegation depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct DelegationDepth(u8);

/// A nonzero public revocation reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RevocationReasonCode(u16);

/// A nonzero target protocol major, including locally unsupported future versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ProtocolMajor(u16);

macro_rules! nonzero_scalar {
    ($name:ident, $integer:ty, $resource:literal) => {
        impl $name {
            /// Construct a nonzero schema value.
            pub const fn new(value: $integer) -> Result<Self, IdentityError> {
                if value == 0 {
                    return Err(IdentityError::ZeroValue {
                        resource: $resource,
                    });
                }
                Ok(Self(value))
            }

            /// Return the exact wire value.
            pub const fn get(self) -> $integer {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = <$integer>::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }

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

nonzero_scalar!(ControllerWeight, u32, "controller weight");
nonzero_scalar!(RequiredWeight, u32, "required authorization weight");
nonzero_scalar!(ProviderQuorum, u16, "provider quorum");
nonzero_scalar!(RevocationReasonCode, u16, "revocation reason code");
nonzero_scalar!(ProtocolMajor, u16, "protocol major");

impl DelegationDepth {
    /// Construct a depth in the closed v1 range `1..=8`.
    pub const fn new(depth: u8) -> Result<Self, IdentityError> {
        if depth == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "delegation depth",
            });
        }
        if depth as usize > MAX_DELEGATION_DEPTH {
            return Err(IdentityError::LimitExceeded {
                resource: "delegation depth",
                actual: depth as usize,
                maximum: MAX_DELEGATION_DEPTH,
            });
        }
        Ok(Self(depth))
    }

    /// Remaining delegation depth.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for DelegationDepth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u8::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for DelegationDepth {
    const RESOURCE: &'static str = "delegation depth";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

macro_rules! checked_counter {
    ($name:ident, $zero:ident, $resource:literal) => {
        /// A checked monotonic schema counter.
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(u64);

        impl $name {
            /// Initial zero value.
            pub const $zero: Self = Self(0);

            /// Construct from the exact wire value.
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            /// Return the exact wire value.
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Advance exactly once, rejecting exhaustion.
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
                encode_wire(self)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                decode_wire(bytes)
            }
        }
    };
}

checked_counter!(ProviderPolicyVersion, GENESIS, "provider policy version");
checked_counter!(ProviderKeyVersion, GENESIS, "provider key version");
checked_counter!(GroupKeyEpoch, GENESIS, "group key epoch");

/// A length-bounded algorithm-tagged public signing key used during migration.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AlgorithmPublicKey {
    algorithm_code: u16,
    bytes: BoundedBytes<MAX_ALGORITHM_PUBLIC_KEY_BYTES>,
}

impl AlgorithmPublicKey {
    /// Construct bounded key material. Code `1` enforces the exact Ed25519 profile.
    pub fn new(algorithm_code: u16, bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if algorithm_code == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "signature algorithm code",
            });
        }
        if bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "algorithm public key bytes",
            });
        }
        let bytes = BoundedBytes::new("algorithm public key bytes", bytes)?;
        if algorithm_code == 1 {
            let key_bytes: [u8; 32] =
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityError::InvalidPublicKey {
                        kind: crate::AlgorithmKind::Signature,
                    })?;
            SigningPublicKey::ed25519(key_bytes)?;
        }
        Ok(Self {
            algorithm_code,
            bytes,
        })
    }

    /// Registry code for this key's signature algorithm.
    pub const fn algorithm_code(&self) -> u16 {
        self.algorithm_code
    }

    /// Exact public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for AlgorithmPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlgorithmPublicKey")
            .field("algorithm_code", &self.algorithm_code)
            .field(
                "bytes",
                &format_args!("<{} public bytes>", self.bytes.len()),
            )
            .finish()
    }
}

impl<'de> Deserialize<'de> for AlgorithmPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            algorithm_code: u16,
            bytes: BoundedBytes<MAX_ALGORITHM_PUBLIC_KEY_BYTES>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.algorithm_code, wire.bytes.into_vec()).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for AlgorithmPublicKey {
    const RESOURCE: &'static str = "algorithm public key bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// A length-bounded algorithm-tagged signature used during migration.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AlgorithmSignature {
    algorithm_code: u16,
    bytes: BoundedBytes<MAX_ALGORITHM_SIGNATURE_BYTES>,
}

impl AlgorithmSignature {
    /// Construct bounded signature material. Code `1` requires 64 Ed25519 bytes.
    pub fn new(algorithm_code: u16, bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if algorithm_code == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "signature algorithm code",
            });
        }
        if bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "algorithm signature bytes",
            });
        }
        let bytes = BoundedBytes::new("algorithm signature bytes", bytes)?;
        if algorithm_code == 1 {
            let signature_bytes: [u8; 64] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::InvalidEncoding)?;
            let _ = ProtocolSignature::ed25519(signature_bytes);
        }
        Ok(Self {
            algorithm_code,
            bytes,
        })
    }

    /// Registry code for this signature's algorithm.
    pub const fn algorithm_code(&self) -> u16 {
        self.algorithm_code
    }

    /// Exact signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for AlgorithmSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlgorithmSignature")
            .field("algorithm_code", &self.algorithm_code)
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for AlgorithmSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            algorithm_code: u16,
            bytes: BoundedBytes<MAX_ALGORITHM_SIGNATURE_BYTES>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.algorithm_code, wire.bytes.into_vec()).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for AlgorithmSignature {
    const RESOURCE: &'static str = "algorithm signature bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    pub(crate) fn new(resource: &'static str, bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.len() > MAX {
            return Err(IdentityError::limit(resource, bytes.len(), MAX));
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl<const MAX: usize> Serialize for BoundedBytes<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedBytes<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor<const MAX: usize>;

        impl<'de, const MAX: usize> de::Visitor<'de> for Visitor<MAX> {
            type Value = BoundedBytes<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "at most {MAX} bytes")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                if sequence.size_hint().is_some_and(|hint| hint > MAX) {
                    return Err(de::Error::invalid_length(MAX.saturating_add(1), &self));
                }
                let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
                while let Some(byte) = sequence.next_element()? {
                    if bytes.len() == MAX {
                        return Err(de::Error::invalid_length(MAX.saturating_add(1), &self));
                    }
                    bytes.push(byte);
                }
                Ok(BoundedBytes(bytes))
            }
        }

        deserializer.deserialize_seq(Visitor::<MAX>)
    }
}

#[allow(dead_code)] // Consumed by bounded Task 2 collection schemas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundedVec<T, const MAX: usize>(Vec<T>);

#[allow(dead_code)] // Consumed by bounded Task 2 collection schemas.
impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub(crate) fn new(resource: &'static str, values: Vec<T>) -> Result<Self, IdentityError> {
        if values.len() > MAX {
            return Err(IdentityError::limit(resource, values.len(), MAX));
        }
        Ok(Self(values))
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T: Serialize, const MAX: usize> Serialize for BoundedVec<T, MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for value in &self.0 {
            sequence.serialize_element(value)?;
        }
        sequence.end()
    }
}

impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor<T, const MAX: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const MAX: usize> de::Visitor<'de> for Visitor<T, MAX> {
            type Value = BoundedVec<T, MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "at most {MAX} sequence elements")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                if sequence.size_hint().is_some_and(|hint| hint > MAX) {
                    return Err(de::Error::invalid_length(MAX.saturating_add(1), &self));
                }
                let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
                while let Some(value) = sequence.next_element()? {
                    if values.len() == MAX {
                        return Err(de::Error::invalid_length(MAX.saturating_add(1), &self));
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(Visitor::<T, MAX>(PhantomData))
    }
}
