//! Canonical device authorization and lifecycle-operation schemas.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeTuple};

use crate::{
    CapabilityGrant, CapabilityGrantId, DeviceDescriptor, DeviceId, Epoch, Extensions,
    IdentityError, ProtocolVersion, RevocationReasonCode,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::MAX_CAPABILITIES_PER_DEVICE,
    schema::BoundedVec,
};

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

/// Closed v1 classification of an authorized application device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeviceClass {
    /// Ordinary user-operated device with capabilities selected by account policy.
    GeneralPurpose,
    /// Device whose private keys are protected by hardware-backed storage.
    HardwareBacked,
    /// Low-authority device intended only for explicitly granted applications.
    ApplicationOnly,
    /// Unattended service device with explicitly scoped capabilities.
    Service,
}

impl DeviceClass {
    /// Stable v1 codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::GeneralPurpose => 1,
            Self::HardwareBacked => 2,
            Self::ApplicationOnly => 3,
            Self::Service => 4,
        }
    }

    /// Parse a closed v1 codepoint.
    pub const fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::GeneralPurpose),
            2 => Ok(Self::HardwareBacked),
            3 => Ok(Self::ApplicationOnly),
            4 => Ok(Self::Service),
            unsupported => Err(IdentityError::UnsupportedCodepoint {
                registry: "device class",
                code: unsupported,
            }),
        }
    }
}

impl Serialize for DeviceClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_code(u16::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

canonical_schema!(DeviceClass, "device class bytes");

/// A structurally high-entropy-looking commitment to encrypted private device metadata.
///
/// The schema rejects zero, constant, and other visibly low-diversity values. It cannot prove
/// entropy or freshness: producers must blind each commitment with independently generated
/// randomness before hashing private metadata.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BlindedMetadataCommitment([u8; 32]);

impl BlindedMetadataCommitment {
    /// Construct a fixed-size commitment after the v1 structural entropy check.
    pub fn new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        let mut seen = [false; 256];
        let mut distinct = 0_u8;
        for byte in bytes {
            let index = usize::from(byte);
            if !seen[index] {
                seen[index] = true;
                distinct = distinct
                    .checked_add(1)
                    .ok_or(IdentityError::ArithmeticOverflow {
                        resource: "blinded metadata commitment byte diversity",
                    })?;
            }
        }
        if distinct < 8 {
            return Err(IdentityError::InvalidRelationship {
                resource: "blinded metadata commitment entropy profile",
            });
        }
        Ok(Self(bytes))
    }

    /// Exact commitment bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BlindedMetadataCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BlindedMetadataCommitment")
            .field(&"<redacted commitment>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for BlindedMetadataCommitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

canonical_schema!(
    BlindedMetadataCommitment,
    "blinded metadata commitment bytes"
);

fn validate_capabilities(
    capabilities: Vec<CapabilityGrant>,
    canonical_wire: bool,
) -> Result<BoundedVec<CapabilityGrant, MAX_CAPABILITIES_PER_DEVICE>, IdentityError> {
    if capabilities.len() > MAX_CAPABILITIES_PER_DEVICE {
        return Err(IdentityError::limit(
            "device capability grants",
            capabilities.len(),
            MAX_CAPABILITIES_PER_DEVICE,
        ));
    }

    let mut keyed = capabilities
        .into_iter()
        .map(|grant| Ok((grant.capability_grant_id()?, grant)))
        .collect::<Result<Vec<(CapabilityGrantId, CapabilityGrant)>, IdentityError>>()?;
    if !canonical_wire {
        keyed.sort_unstable_by_key(|(grant_id, _)| *grant_id);
    }
    for pair in keyed.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(IdentityError::DuplicateElement {
                resource: "device capability grants",
            });
        }
        if pair[0].0 > pair[1].0 {
            return Err(IdentityError::NonCanonical);
        }
    }
    BoundedVec::new(
        "device capability grants",
        keyed.into_iter().map(|(_, grant)| grant).collect(),
    )
}

/// Complete public authorization installed for one independently keyed device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceAuthorization {
    protocol_version: ProtocolVersion,
    device_id: DeviceId,
    descriptor: DeviceDescriptor,
    device_class: DeviceClass,
    metadata_commitment: Option<BlindedMetadataCommitment>,
    capabilities: BoundedVec<CapabilityGrant, MAX_CAPABILITIES_PER_DEVICE>,
    authorization_epoch: Epoch,
    extensions: Extensions,
}

impl DeviceAuthorization {
    /// Construct an authorization, sorting capabilities by their content identifier.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_id: DeviceId,
        descriptor: DeviceDescriptor,
        device_class: DeviceClass,
        metadata_commitment: Option<BlindedMetadataCommitment>,
        capabilities: Vec<CapabilityGrant>,
        authorization_epoch: Epoch,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_fields(
            device_id,
            descriptor,
            device_class,
            metadata_commitment,
            capabilities,
            authorization_epoch,
            extensions,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_fields(
        device_id: DeviceId,
        descriptor: DeviceDescriptor,
        device_class: DeviceClass,
        metadata_commitment: Option<BlindedMetadataCommitment>,
        capabilities: Vec<CapabilityGrant>,
        authorization_epoch: Epoch,
        extensions: Extensions,
        canonical_wire: bool,
    ) -> Result<Self, IdentityError> {
        if descriptor.id()? != device_id {
            return Err(IdentityError::InvalidIdentifier {
                resource: "device descriptor",
            });
        }
        let capabilities = validate_capabilities(capabilities, canonical_wire)?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            device_id,
            descriptor,
            device_class,
            metadata_commitment,
            capabilities,
            authorization_epoch,
            extensions,
        })
    }

    /// Device identifier derived from the exact descriptor.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Independently generated public key roles bound by this authorization.
    pub const fn descriptor(&self) -> &DeviceDescriptor {
        &self.descriptor
    }

    /// Public device class interpreted by account policy.
    pub const fn device_class(&self) -> DeviceClass {
        self.device_class
    }

    /// Optional blinded commitment to private metadata.
    pub const fn metadata_commitment(&self) -> Option<BlindedMetadataCommitment> {
        self.metadata_commitment
    }

    /// Canonically sorted, duplicate-free capability grants.
    pub fn capabilities(&self) -> &[CapabilityGrant] {
        self.capabilities.as_slice()
    }

    /// First account epoch at which this exact authorization is active.
    pub const fn authorization_epoch(&self) -> Epoch {
        self.authorization_epoch
    }

    /// Signed forward-compatible fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for DeviceAuthorization {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            device_id: DeviceId,
            descriptor: DeviceDescriptor,
            device_class: DeviceClass,
            metadata_commitment: Option<BlindedMetadataCommitment>,
            capabilities: BoundedVec<CapabilityGrant, MAX_CAPABILITIES_PER_DEVICE>,
            authorization_epoch: Epoch,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::from_fields(
            wire.device_id,
            wire.descriptor,
            wire.device_class,
            wire.metadata_commitment,
            wire.capabilities.into_vec(),
            wire.authorization_epoch,
            wire.extensions,
            true,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(DeviceAuthorization, "device authorization bytes");

/// Authorization-changing replacement for one device's class and capability set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceAuthorizationUpdate {
    protocol_version: ProtocolVersion,
    device_id: DeviceId,
    device_class: DeviceClass,
    capabilities: BoundedVec<CapabilityGrant, MAX_CAPABILITIES_PER_DEVICE>,
    authorization_epoch: Epoch,
    extensions: Extensions,
}

impl DeviceAuthorizationUpdate {
    /// Construct an authorization-changing update with canonical capability order.
    pub fn new(
        device_id: DeviceId,
        device_class: DeviceClass,
        capabilities: Vec<CapabilityGrant>,
        authorization_epoch: Epoch,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_fields(
            device_id,
            device_class,
            capabilities,
            authorization_epoch,
            extensions,
            false,
        )
    }

    fn from_fields(
        device_id: DeviceId,
        device_class: DeviceClass,
        capabilities: Vec<CapabilityGrant>,
        authorization_epoch: Epoch,
        extensions: Extensions,
        canonical_wire: bool,
    ) -> Result<Self, IdentityError> {
        let capabilities = validate_capabilities(capabilities, canonical_wire)?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            device_id,
            device_class,
            capabilities,
            authorization_epoch,
            extensions,
        })
    }

    /// Device whose authorization changes.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Replacement public class.
    pub const fn device_class(&self) -> DeviceClass {
        self.device_class
    }

    /// Complete replacement capability set.
    pub fn capabilities(&self) -> &[CapabilityGrant] {
        self.capabilities.as_slice()
    }

    /// First account epoch at which this replacement is active.
    pub const fn authorization_epoch(&self) -> Epoch {
        self.authorization_epoch
    }

    /// Signed forward-compatible fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for DeviceAuthorizationUpdate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            device_id: DeviceId,
            device_class: DeviceClass,
            capabilities: BoundedVec<CapabilityGrant, MAX_CAPABILITIES_PER_DEVICE>,
            authorization_epoch: Epoch,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::from_fields(
            wire.device_id,
            wire.device_class,
            wire.capabilities.into_vec(),
            wire.authorization_epoch,
            wire.extensions,
            true,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(
    DeviceAuthorizationUpdate,
    "device authorization update bytes"
);

/// Metadata-commitment-only update that does not change authorization authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceMetadataUpdate {
    protocol_version: ProtocolVersion,
    device_id: DeviceId,
    metadata_commitment: Option<BlindedMetadataCommitment>,
    extensions: Extensions,
}

impl DeviceMetadataUpdate {
    /// Construct a commitment-only update. `None` clears the prior public commitment.
    pub fn new(
        device_id: DeviceId,
        metadata_commitment: Option<BlindedMetadataCommitment>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            device_id,
            metadata_commitment,
            extensions,
        })
    }

    /// Device whose private-metadata commitment changes.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Replacement commitment, or `None` to clear it.
    pub const fn metadata_commitment(&self) -> Option<BlindedMetadataCommitment> {
        self.metadata_commitment
    }

    /// Signed forward-compatible fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for DeviceMetadataUpdate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            device_id: DeviceId,
            metadata_commitment: Option<BlindedMetadataCommitment>,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        Self::new(wire.device_id, wire.metadata_commitment, wire.extensions)
            .map_err(de::Error::custom)
    }
}

canonical_schema!(DeviceMetadataUpdate, "device metadata update bytes");

/// Closed v1 split between authority-changing and metadata-only device updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceUpdate {
    /// Changes device class and/or capabilities and therefore advances account epoch.
    Authorization(DeviceAuthorizationUpdate),
    /// Changes only the blinded metadata commitment and does not advance account epoch.
    Metadata(DeviceMetadataUpdate),
}

impl DeviceUpdate {
    /// Stable v1 update codepoint.
    pub const fn code(&self) -> u16 {
        match self {
            Self::Authorization(_) => 1,
            Self::Metadata(_) => 2,
        }
    }
}

impl Serialize for DeviceUpdate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.code())?;
        match self {
            Self::Authorization(update) => tuple.serialize_element(update)?,
            Self::Metadata(update) => tuple.serialize_element(update)?,
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for DeviceUpdate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = DeviceUpdate;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed v1 device update")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => Ok(DeviceUpdate::Authorization(
                        sequence
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    )),
                    2 => Ok(DeviceUpdate::Metadata(
                        sequence
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    )),
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "device update",
                        code: unsupported,
                    })),
                }
            }
        }

        deserializer.deserialize_tuple(2, Visitor)
    }
}

canonical_schema!(DeviceUpdate, "device update bytes");

macro_rules! simple_device_operation {
    ($name:ident, $resource:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        pub struct $name {
            protocol_version: ProtocolVersion,
            device_id: DeviceId,
            extensions: Extensions,
        }

        impl $name {
            /// Construct this exact device lifecycle operation.
            pub fn new(device_id: DeviceId, extensions: Extensions) -> Result<Self, IdentityError> {
                extensions.validate_critical(&[])?;
                Ok(Self {
                    protocol_version: ProtocolVersion::V1,
                    device_id,
                    extensions,
                })
            }

            /// Device affected by this operation.
            pub const fn device_id(&self) -> DeviceId {
                self.device_id
            }

            /// Signed forward-compatible fields.
            pub const fn extensions(&self) -> &Extensions {
                &self.extensions
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                #[derive(Deserialize)]
                struct Wire {
                    protocol_version: ProtocolVersion,
                    device_id: DeviceId,
                    extensions: Extensions,
                }
                let wire = Wire::deserialize(deserializer)?;
                let _ = wire.protocol_version;
                Self::new(wire.device_id, wire.extensions).map_err(de::Error::custom)
            }
        }

        canonical_schema!($name, $resource);
    };
}

simple_device_operation!(
    SuspendDevice,
    "suspend device operation bytes",
    "Temporarily disable one active device without erasing its authorization."
);
simple_device_operation!(
    ReinstateDevice,
    "reinstate device operation bytes",
    "Restore one suspended device's existing authorization."
);

/// Permanently revoke one device with an optional public reason category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevokeDevice {
    protocol_version: ProtocolVersion,
    device_id: DeviceId,
    reason_code: Option<RevocationReasonCode>,
    extensions: Extensions,
}

impl RevokeDevice {
    /// Construct a permanent device revocation payload.
    pub fn new(
        device_id: DeviceId,
        reason_code: Option<RevocationReasonCode>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            device_id,
            reason_code,
            extensions,
        })
    }

    /// Device permanently revoked.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Optional nonzero public reason category. Private detail remains encrypted metadata.
    pub const fn reason_code(&self) -> Option<RevocationReasonCode> {
        self.reason_code
    }

    /// Signed forward-compatible fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for RevokeDevice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            device_id: DeviceId,
            reason_code: Option<RevocationReasonCode>,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        Self::new(wire.device_id, wire.reason_code, wire.extensions).map_err(de::Error::custom)
    }
}

canonical_schema!(RevokeDevice, "revoke device operation bytes");

/// Atomic replacement of one old device identity with a complete new authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RotateDeviceKeys {
    protocol_version: ProtocolVersion,
    old_device_id: DeviceId,
    new_authorization: DeviceAuthorization,
    extensions: Extensions,
}

impl RotateDeviceKeys {
    /// Construct an atomic old-device revocation and new-device authorization.
    pub fn new(
        old_device_id: DeviceId,
        new_authorization: DeviceAuthorization,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if old_device_id == new_authorization.device_id() {
            return Err(IdentityError::InvalidRelationship {
                resource: "device key rotation identifiers",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            old_device_id,
            new_authorization,
            extensions,
        })
    }

    /// Previously active device identity revoked by the rotation.
    pub const fn old_device_id(&self) -> DeviceId {
        self.old_device_id
    }

    /// Complete replacement authorization installed atomically.
    pub const fn new_authorization(&self) -> &DeviceAuthorization {
        &self.new_authorization
    }

    /// Signed forward-compatible fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for RotateDeviceKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            old_device_id: DeviceId,
            new_authorization: DeviceAuthorization,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        Self::new(wire.old_device_id, wire.new_authorization, wire.extensions)
            .map_err(de::Error::custom)
    }
}

canonical_schema!(RotateDeviceKeys, "rotate device keys operation bytes");
