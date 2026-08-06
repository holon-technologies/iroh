//! Canonical controller, provider, and independently keyed device descriptors.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    AgreementPublicKey, ControllerId, ControllerWeight, DeviceId, Extensions, IdentityError,
    OperationKind, ProtocolVersion, ProviderId, SigningPublicKey,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::MAX_POLICY_RULES,
    schema::BoundedVec,
};

/// Stable v1 account-controller classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControllerClass {
    /// A controller kept on a trusted personal device.
    PersonalDevice,
    /// A dedicated hardware security key.
    HardwareSecurityKey,
    /// An offline recovery controller.
    OfflineRecovery,
    /// A controller operated by an explicit recovery guardian.
    GuardianAccount,
    /// An institutional or threshold-service controller.
    Institutional,
}

impl ControllerClass {
    /// Stable v1 wire codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::PersonalDevice => 1,
            Self::HardwareSecurityKey => 2,
            Self::OfflineRecovery => 3,
            Self::GuardianAccount => 4,
            Self::Institutional => 5,
        }
    }

    fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::PersonalDevice),
            2 => Ok(Self::HardwareSecurityKey),
            3 => Ok(Self::OfflineRecovery),
            4 => Ok(Self::GuardianAccount),
            5 => Ok(Self::Institutional),
            unsupported => Err(IdentityError::UnsupportedCodepoint {
                registry: "controller class",
                code: unsupported,
            }),
        }
    }
}

impl Serialize for ControllerClass {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.code().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ControllerClass {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_code(u16::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ControllerClass {
    const RESOURCE: &'static str = "controller class bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Immutable operation restrictions carried by one controller descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerScope {
    kind: ControllerScopeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ControllerScopeKind {
    AllV1Operations,
    Operations(Vec<OperationKind>),
}

impl ControllerScope {
    /// Construct the frozen all-v1-operations scope.
    pub const fn all_v1_operations() -> Self {
        Self {
            kind: ControllerScopeKind::AllV1Operations,
        }
    }

    /// Validate, sort, and construct an explicit operation set.
    pub fn operations(mut operations: Vec<OperationKind>) -> Result<Self, IdentityError> {
        operations.sort_unstable_by_key(|operation| operation.code());
        Self::from_sorted_operations(operations)
    }

    /// Borrow the explicit operation set, or `None` for all v1 operations.
    pub fn as_operations(&self) -> Option<&[OperationKind]> {
        match &self.kind {
            ControllerScopeKind::AllV1Operations => None,
            ControllerScopeKind::Operations(operations) => Some(operations),
        }
    }

    /// Whether this immutable scope permits the operation.
    pub fn allows(&self, operation: OperationKind) -> bool {
        match &self.kind {
            ControllerScopeKind::AllV1Operations => true,
            ControllerScopeKind::Operations(operations) => operations
                .binary_search_by_key(&operation.code(), |candidate| candidate.code())
                .is_ok(),
        }
    }

    fn from_sorted_operations(operations: Vec<OperationKind>) -> Result<Self, IdentityError> {
        if operations.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "controller operation scope",
            });
        }
        if operations.len() > MAX_POLICY_RULES {
            return Err(IdentityError::limit(
                "controller operation scope",
                operations.len(),
                MAX_POLICY_RULES,
            ));
        }
        for pair in operations.windows(2) {
            if pair[0].code() == pair[1].code() {
                return Err(IdentityError::DuplicateElement {
                    resource: "controller operation scope",
                });
            }
            if pair[0].code() > pair[1].code() {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self {
            kind: ControllerScopeKind::Operations(operations),
        })
    }
}

impl Serialize for ControllerScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.kind {
            ControllerScopeKind::AllV1Operations => {
                (1_u16, &[] as &[OperationKind]).serialize(serializer)
            }
            ControllerScopeKind::Operations(operations) => {
                (2_u16, operations.as_slice()).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for ControllerScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, operations) =
            <(u16, BoundedVec<OperationKind, MAX_POLICY_RULES>)>::deserialize(deserializer)?;
        let operations = operations.into_vec();
        match code {
            1 if operations.is_empty() => Ok(Self::all_v1_operations()),
            1 => Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "all-v1 controller scope payload",
            })),
            2 => Self::from_sorted_operations(operations).map_err(de::Error::custom),
            unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "controller scope",
                code: unsupported,
            })),
        }
    }
}

impl CanonicalCodec for ControllerScope {
    const RESOURCE: &'static str = "controller scope bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Versioned public descriptor for one weighted account controller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerDescriptor {
    protocol_version: ProtocolVersion,
    signing_key: SigningPublicKey,
    class: ControllerClass,
    weight: ControllerWeight,
    scope: ControllerScope,
    extensions: Extensions,
}

impl ControllerDescriptor {
    /// Construct a canonical v1 controller descriptor.
    pub fn new(
        signing_key: SigningPublicKey,
        class: ControllerClass,
        weight: ControllerWeight,
        scope: ControllerScope,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            signing_key,
            class,
            weight,
            scope,
            extensions,
        })
    }

    /// Derive the stable descriptor identifier.
    pub fn id(&self) -> Result<ControllerId, IdentityError> {
        ControllerId::derive(self)
    }

    /// Public signing key used for account-control approvals.
    pub const fn signing_key(&self) -> SigningPublicKey {
        self.signing_key
    }

    /// Controller class used by class selectors.
    pub const fn class(&self) -> ControllerClass {
        self.class
    }

    /// Nonzero controller weight.
    pub const fn weight(&self) -> ControllerWeight {
        self.weight
    }

    /// Immutable v1 operation scope.
    pub const fn scope(&self) -> &ControllerScope {
        &self.scope
    }

    /// Signed forward-compatible extensions.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Serialize for ControllerDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            self.protocol_version,
            self.signing_key,
            self.class,
            self.weight,
            &self.scope,
            &self.extensions,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ControllerDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (_version, signing_key, class, weight, scope, extensions) =
            <(
                ProtocolVersion,
                SigningPublicKey,
                ControllerClass,
                ControllerWeight,
                ControllerScope,
                Extensions,
            )>::deserialize(deserializer)?;
        Self::new(signing_key, class, weight, scope, extensions).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ControllerDescriptor {
    const RESOURCE: &'static str = "controller descriptor bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Versioned self-certifying transparency-provider descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDescriptor {
    protocol_version: ProtocolVersion,
    signing_key: SigningPublicKey,
    extensions: Extensions,
}

impl ProviderDescriptor {
    /// Construct a canonical v1 provider descriptor.
    pub fn new(
        signing_key: SigningPublicKey,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            signing_key,
            extensions,
        })
    }

    /// Derive the stable provider identifier.
    pub fn id(&self) -> Result<ProviderId, IdentityError> {
        ProviderId::derive(self)
    }

    /// Provider signing key.
    pub const fn signing_key(&self) -> SigningPublicKey {
        self.signing_key
    }

    /// Signed forward-compatible extensions.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Serialize for ProviderDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.protocol_version, self.signing_key, &self.extensions).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProviderDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (_version, signing_key, extensions) =
            <(ProtocolVersion, SigningPublicKey, Extensions)>::deserialize(deserializer)?;
        Self::new(signing_key, extensions).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ProviderDescriptor {
    const RESOURCE: &'static str = "provider descriptor bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Semantically distinct Ed25519 key used only for Krikos endpoint identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointPublicKey(SigningPublicKey);

impl EndpointPublicKey {
    /// Wrap a validated signing key in the endpoint-key role.
    pub const fn new(key: SigningPublicKey) -> Self {
        Self(key)
    }

    /// Exact endpoint public key.
    pub const fn as_signing_key(self) -> SigningPublicKey {
        self.0
    }
}

impl Serialize for EndpointPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for EndpointPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::new(SigningPublicKey::deserialize(deserializer)?))
    }
}

impl CanonicalCodec for EndpointPublicKey {
    const RESOURCE: &'static str = "endpoint public key bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Independently generated public key roles for one replaceable device identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDescriptor {
    protocol_version: ProtocolVersion,
    application_signing_key: SigningPublicKey,
    agreement_key: AgreementPublicKey,
    endpoint_key: EndpointPublicKey,
    extensions: Extensions,
}

impl DeviceDescriptor {
    /// Construct a device descriptor and enforce separation between all key roles.
    pub fn new(
        application_signing_key: SigningPublicKey,
        agreement_key: AgreementPublicKey,
        endpoint_key: EndpointPublicKey,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let application_bytes = application_signing_key.as_bytes();
        let agreement_bytes = agreement_key.as_bytes();
        let endpoint_signing_key = endpoint_key.as_signing_key();
        let endpoint_bytes = endpoint_signing_key.as_bytes();
        if application_bytes == endpoint_bytes
            || application_bytes == agreement_bytes
            || endpoint_bytes == agreement_bytes
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "device public-key role separation",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            application_signing_key,
            agreement_key,
            endpoint_key,
            extensions,
        })
    }

    /// Derive the stable device identifier from all public key roles.
    pub fn id(&self) -> Result<DeviceId, IdentityError> {
        DeviceId::derive(self)
    }

    /// Application-event signing key.
    pub const fn application_signing_key(&self) -> SigningPublicKey {
        self.application_signing_key
    }

    /// Group-key agreement key.
    pub const fn agreement_key(&self) -> AgreementPublicKey {
        self.agreement_key
    }

    /// Krikos transport endpoint key.
    pub const fn endpoint_key(&self) -> EndpointPublicKey {
        self.endpoint_key
    }

    /// Signed forward-compatible extensions.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Serialize for DeviceDescriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            self.protocol_version,
            self.application_signing_key,
            self.agreement_key,
            self.endpoint_key,
            &self.extensions,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (_version, signing_key, agreement_key, endpoint_key, extensions) =
            <(
                ProtocolVersion,
                SigningPublicKey,
                AgreementPublicKey,
                EndpointPublicKey,
                Extensions,
            )>::deserialize(deserializer)?;
        Self::new(signing_key, agreement_key, endpoint_key, extensions).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for DeviceDescriptor {
    const RESOURCE: &'static str = "device descriptor bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}
