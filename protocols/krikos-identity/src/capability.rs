//! Bounded capability grants and structurally validated delegation chains.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    AccountId, CapabilityGrantId, CheckpointId, DelegationDepth, DelegationId, DeviceId, Epoch,
    Extensions, IdentityError, ProtocolSignature, ProtocolVersion, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{
        MAX_CAPABILITY_NAME_BYTES, MAX_CONSTRAINTS_PER_CAPABILITY, MAX_DELEGATION_DEPTH,
        MAX_RESOURCE_SELECTOR_BYTES,
    },
    schema::{BoundedBytes, BoundedVec},
};

/// Maximum number of nonempty segments in one v1 resource path.
pub const MAX_RESOURCE_PATH_SEGMENTS: usize = 64;

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

macro_rules! bounded_capability_name {
    ($name:ident, $resource:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub struct $name(Box<str>);

        impl $name {
            /// Construct a nonempty, byte-for-byte v1 name.
            pub fn new(value: impl AsRef<str>) -> Result<Self, IdentityError> {
                let value = value.as_ref();
                if value.is_empty() {
                    return Err(IdentityError::EmptyCollection {
                        resource: $resource,
                    });
                }
                if value.len() > MAX_CAPABILITY_NAME_BYTES {
                    return Err(IdentityError::limit(
                        $resource,
                        value.len(),
                        MAX_CAPABILITY_NAME_BYTES,
                    ));
                }
                Ok(Self(Box::from(value)))
            }

            /// Borrow the exact UTF-8 name bytes as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct Visitor;

                impl<'de> de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "a nonempty UTF-8 name of at most {MAX_CAPABILITY_NAME_BYTES} bytes"
                        )
                    }

                    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::new(value).map_err(E::custom)
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::new(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }

        canonical_schema!($name, $resource);
    };
}

bounded_capability_name!(
    CapabilityNamespace,
    "capability namespace bytes",
    "An exact, nonempty UTF-8 capability namespace."
);
bounded_capability_name!(
    CapabilityAction,
    "capability action bytes",
    "An exact, nonempty UTF-8 capability action."
);

/// One nonempty opaque byte segment in a capability resource path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceSegment(BoundedBytes<MAX_RESOURCE_SELECTOR_BYTES>);

impl ResourceSegment {
    /// Construct one bounded, nonempty opaque segment.
    pub fn new(bytes: Vec<u8>) -> Result<Self, IdentityError> {
        if bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "resource path segment bytes",
            });
        }
        Ok(Self(BoundedBytes::new(
            "resource path segment bytes",
            bytes,
        )?))
    }

    /// Borrow the exact opaque segment bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<'de> Deserialize<'de> for ResourceSegment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = BoundedBytes::<MAX_RESOURCE_SELECTOR_BYTES>::deserialize(deserializer)?;
        Self::new(bytes.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(ResourceSegment, "resource path segment bytes");

/// A semantic-order sequence of nonempty opaque resource path segments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourcePath(Vec<ResourceSegment>);

impl ResourcePath {
    /// Construct a path from semantic-order opaque segment bytes.
    pub fn new(segments: Vec<Vec<u8>>) -> Result<Self, IdentityError> {
        if segments.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "resource path segments",
            });
        }
        if segments.len() > MAX_RESOURCE_PATH_SEGMENTS {
            return Err(IdentityError::limit(
                "resource path segments",
                segments.len(),
                MAX_RESOURCE_PATH_SEGMENTS,
            ));
        }
        let segments = segments
            .into_iter()
            .map(ResourceSegment::new)
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_segments(segments)
    }

    fn from_segments(segments: Vec<ResourceSegment>) -> Result<Self, IdentityError> {
        if segments.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "resource path segments",
            });
        }
        if segments.len() > MAX_RESOURCE_PATH_SEGMENTS {
            return Err(IdentityError::limit(
                "resource path segments",
                segments.len(),
                MAX_RESOURCE_PATH_SEGMENTS,
            ));
        }
        let path = Self(segments);
        path.validate_selector_size()?;
        Ok(path)
    }

    /// Borrow path segments in their semantic order.
    pub fn segments(&self) -> &[ResourceSegment] {
        &self.0
    }

    fn validate_selector_size(&self) -> Result<(), IdentityError> {
        let mut encoded_len = 1usize.checked_add(varint_len(self.0.len())).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "resource selector bytes",
            },
        )?;
        for segment in &self.0 {
            encoded_len = encoded_len
                .checked_add(varint_len(segment.as_bytes().len()))
                .and_then(|length| length.checked_add(segment.as_bytes().len()))
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "resource selector bytes",
                })?;
            if encoded_len > MAX_RESOURCE_SELECTOR_BYTES {
                return Err(IdentityError::limit(
                    "resource selector bytes",
                    encoded_len,
                    MAX_RESOURCE_SELECTOR_BYTES,
                ));
            }
        }
        Ok(())
    }

    fn starts_with(&self, prefix: &Self) -> bool {
        self.0.len() >= prefix.0.len()
            && self
                .0
                .iter()
                .zip(&prefix.0)
                .all(|(segment, prefix_segment)| segment == prefix_segment)
    }
}

impl<'de> Deserialize<'de> for ResourcePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let segments =
            BoundedVec::<ResourceSegment, MAX_RESOURCE_PATH_SEGMENTS>::deserialize(deserializer)?;
        Self::from_segments(segments.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(ResourcePath, "resource path bytes");

const fn varint_len(mut value: usize) -> usize {
    let mut length = 1;
    while value >= 128 {
        value >>= 7;
        length += 1;
    }
    length
}

/// A closed v1 exact or complete-segment-prefix resource selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceSelector {
    /// Select exactly one resource path.
    Exact(ResourcePath),
    /// Select every resource path beginning with these complete segments.
    Prefix(ResourcePath),
}

impl ResourceSelector {
    /// Construct an exact selector after rechecking its encoded size.
    pub fn exact(path: ResourcePath) -> Result<Self, IdentityError> {
        path.validate_selector_size()?;
        Ok(Self::Exact(path))
    }

    /// Construct a complete-segment-prefix selector after rechecking its encoded size.
    pub fn prefix(path: ResourcePath) -> Result<Self, IdentityError> {
        path.validate_selector_size()?;
        Ok(Self::Prefix(path))
    }

    /// Stable closed v1 selector codepoint.
    pub const fn code(&self) -> u16 {
        match self {
            Self::Exact(_) => 1,
            Self::Prefix(_) => 2,
        }
    }

    /// Borrow the selected path or prefix.
    pub const fn path(&self) -> &ResourcePath {
        match self {
            Self::Exact(path) | Self::Prefix(path) => path,
        }
    }
}

impl Serialize for ResourceSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.code(), self.path()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResourceSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, path) = <(u16, ResourcePath)>::deserialize(deserializer)?;
        match code {
            1 => Self::exact(path).map_err(de::Error::custom),
            2 => Self::prefix(path).map_err(de::Error::custom),
            unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "resource selector",
                code: unsupported,
            })),
        }
    }
}

impl CanonicalCodec for ResourceSelector {
    const RESOURCE: &'static str = "resource selector bytes";
    const MAX_ENCODED_BYTES: usize = MAX_RESOURCE_SELECTOR_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// A closed v1 conjunctive capability constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityConstraint {
    /// Require an authorization account epoch at least this value.
    AccountEpochAtLeast(Epoch),
    /// Require an authorization account epoch at most this value.
    AccountEpochAtMost(Epoch),
    /// Require use no earlier than this explicit timestamp.
    ValidFrom(Timestamp),
}

impl CapabilityConstraint {
    /// Stable closed v1 constraint codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::AccountEpochAtLeast(_) => 1,
            Self::AccountEpochAtMost(_) => 2,
            Self::ValidFrom(_) => 3,
        }
    }

    const fn value(self) -> u64 {
        match self {
            Self::AccountEpochAtLeast(epoch) | Self::AccountEpochAtMost(epoch) => epoch.get(),
            Self::ValidFrom(timestamp) => timestamp.as_unix_millis(),
        }
    }
}

impl Serialize for CapabilityConstraint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.code(), self.value()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CapabilityConstraint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, value) = <(u16, u64)>::deserialize(deserializer)?;
        match code {
            1 => Ok(Self::AccountEpochAtLeast(Epoch::new(value))),
            2 => Ok(Self::AccountEpochAtMost(Epoch::new(value))),
            3 => Ok(Self::ValidFrom(Timestamp::from_unix_millis(value))),
            unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "capability constraint",
                code: unsupported,
            })),
        }
    }
}

canonical_schema!(CapabilityConstraint, "capability constraint bytes");

/// Whether and how far a capability grant may be delegated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DelegationPermission {
    /// This grant cannot be delegated further.
    NotDelegable,
    /// This grant can be delegated with bounded remaining depth.
    Delegable {
        /// Maximum number of remaining delegation links.
        remaining: DelegationDepth,
    },
}

impl DelegationPermission {
    /// Construct a permission with a previously validated remaining depth.
    pub const fn delegable(remaining: DelegationDepth) -> Self {
        Self::Delegable { remaining }
    }

    /// Stable closed v1 delegation-permission codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::NotDelegable => 1,
            Self::Delegable { .. } => 2,
        }
    }

    /// Return the remaining depth, or `None` when delegation is forbidden.
    pub const fn remaining(self) -> Option<DelegationDepth> {
        match self {
            Self::NotDelegable => None,
            Self::Delegable { remaining } => Some(remaining),
        }
    }
}

impl Serialize for DelegationPermission {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let remaining = self.remaining().map_or(0, DelegationDepth::get);
        (self.code(), remaining).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DelegationPermission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, remaining) = <(u16, u8)>::deserialize(deserializer)?;
        match (code, remaining) {
            (1, 0) => Ok(Self::NotDelegable),
            (1, _) => Err(de::Error::custom(IdentityError::InvalidCapability {
                reason: "non-delegable permission has nonzero remaining depth",
            })),
            (2, remaining) => DelegationDepth::new(remaining)
                .map(Self::delegable)
                .map_err(de::Error::custom),
            (unsupported, _) => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "delegation permission",
                code: unsupported,
            })),
        }
    }
}

canonical_schema!(DelegationPermission, "delegation permission bytes");

/// A canonical, bounded v1 capability grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityGrant {
    protocol_version: ProtocolVersion,
    namespace: CapabilityNamespace,
    action: CapabilityAction,
    resource: ResourceSelector,
    constraints: Vec<CapabilityConstraint>,
    delegation: DelegationPermission,
    expires_at: Option<Timestamp>,
    extensions: Extensions,
}

impl CapabilityGrant {
    /// Validate, canonically sort, and construct a v1 capability grant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: CapabilityNamespace,
        action: CapabilityAction,
        resource: ResourceSelector,
        mut constraints: Vec<CapabilityConstraint>,
        delegation: DelegationPermission,
        expires_at: Option<Timestamp>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if constraints.len() > MAX_CONSTRAINTS_PER_CAPABILITY {
            return Err(IdentityError::limit(
                "capability constraints",
                constraints.len(),
                MAX_CONSTRAINTS_PER_CAPABILITY,
            ));
        }
        constraints.sort_unstable_by_key(|constraint| constraint.code());
        Self::from_sorted(
            namespace,
            action,
            resource,
            constraints,
            delegation,
            expires_at,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_sorted(
        namespace: CapabilityNamespace,
        action: CapabilityAction,
        resource: ResourceSelector,
        constraints: Vec<CapabilityConstraint>,
        delegation: DelegationPermission,
        expires_at: Option<Timestamp>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if constraints.len() > MAX_CONSTRAINTS_PER_CAPABILITY {
            return Err(IdentityError::limit(
                "capability constraints",
                constraints.len(),
                MAX_CONSTRAINTS_PER_CAPABILITY,
            ));
        }
        for pair in constraints.windows(2) {
            if pair[0].code() == pair[1].code() {
                return Err(IdentityError::DuplicateElement {
                    resource: "capability constraints",
                });
            }
            if pair[0].code() > pair[1].code() {
                return Err(IdentityError::NonCanonical);
            }
        }

        let minimum_epoch = constraints.iter().find_map(|constraint| match constraint {
            CapabilityConstraint::AccountEpochAtLeast(epoch) => Some(*epoch),
            _ => None,
        });
        let maximum_epoch = constraints.iter().find_map(|constraint| match constraint {
            CapabilityConstraint::AccountEpochAtMost(epoch) => Some(*epoch),
            _ => None,
        });
        if minimum_epoch
            .zip(maximum_epoch)
            .is_some_and(|(minimum, maximum)| minimum > maximum)
        {
            return Err(IdentityError::InvalidCapability {
                reason: "minimum account epoch exceeds maximum account epoch",
            });
        }
        if constraints.iter().any(|constraint| {
            matches!(
                (constraint, expires_at),
                (CapabilityConstraint::ValidFrom(valid_from), Some(expires_at))
                    if *valid_from > expires_at
            )
        }) {
            return Err(IdentityError::InvalidCapability {
                reason: "valid-from time exceeds expiration time",
            });
        }
        extensions.validate_critical(&[])?;

        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            namespace,
            action,
            resource,
            constraints,
            delegation,
            expires_at,
            extensions,
        })
    }

    /// Exact capability namespace.
    pub const fn namespace(&self) -> &CapabilityNamespace {
        &self.namespace
    }

    /// Exact capability action.
    pub const fn action(&self) -> &CapabilityAction {
        &self.action
    }

    /// Resource selector governed by this grant.
    pub const fn resource(&self) -> &ResourceSelector {
        &self.resource
    }

    /// Canonically sorted conjunctive constraints.
    pub fn constraints(&self) -> &[CapabilityConstraint] {
        &self.constraints
    }

    /// Remaining delegation permission.
    pub const fn delegation(&self) -> DelegationPermission {
        self.delegation
    }

    /// Optional exclusive upper time bound represented by the grant.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Preserved noncritical extension fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Derive the grant identifier from this exact canonical grant body.
    pub fn capability_grant_id(&self) -> Result<CapabilityGrantId, IdentityError> {
        CapabilityGrantId::derive(self)
    }
}

impl<'de> Deserialize<'de> for CapabilityGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            namespace: CapabilityNamespace,
            action: CapabilityAction,
            resource: ResourceSelector,
            constraints: BoundedVec<CapabilityConstraint, MAX_CONSTRAINTS_PER_CAPABILITY>,
            delegation: DelegationPermission,
            expires_at: Option<Timestamp>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::from_sorted(
            wire.namespace,
            wire.action,
            wire.resource,
            wire.constraints.into_vec(),
            wire.delegation,
            wire.expires_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(CapabilityGrant, "capability grant bytes");

/// Account checkpoint context against which an authorization is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuthorizationContext {
    account_id: AccountId,
    epoch: Epoch,
    checkpoint_id: CheckpointId,
}

impl AuthorizationContext {
    /// Construct an explicit account authorization context.
    pub const fn new(account_id: AccountId, epoch: Epoch, checkpoint_id: CheckpointId) -> Self {
        Self {
            account_id,
            epoch,
            checkpoint_id,
        }
    }

    /// Account whose projected state supplies the authorization context.
    pub const fn account_id(self) -> AccountId {
        self.account_id
    }

    /// Security-relevant account epoch at the referenced checkpoint.
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }

    /// Exact checkpoint supplying projected authorization state.
    pub const fn checkpoint_id(self) -> CheckpointId {
        self.checkpoint_id
    }
}

impl<'de> Deserialize<'de> for AuthorizationContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            account_id: AccountId,
            epoch: Epoch,
            checkpoint_id: CheckpointId,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self::new(wire.account_id, wire.epoch, wire.checkpoint_id))
    }
}

canonical_schema!(AuthorizationContext, "authorization context bytes");

/// Root authority and holder from which a delegation chain begins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityRoot {
    authorization_context: AuthorizationContext,
    holder: DeviceId,
    grant: CapabilityGrant,
    extensions: Extensions,
}

impl CapabilityRoot {
    /// Construct a v1 capability root with understood critical extensions only.
    pub fn new(
        authorization_context: AuthorizationContext,
        holder: DeviceId,
        grant: CapabilityGrant,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            authorization_context,
            holder,
            grant,
            extensions,
        })
    }

    /// Account checkpoint context authorizing this root.
    pub const fn authorization_context(&self) -> AuthorizationContext {
        self.authorization_context
    }

    /// Device initially holding this capability.
    pub const fn holder(&self) -> DeviceId {
        self.holder
    }

    /// Root capability grant.
    pub const fn grant(&self) -> &CapabilityGrant {
        &self.grant
    }

    /// Preserved noncritical extension fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for CapabilityRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            authorization_context: AuthorizationContext,
            holder: DeviceId,
            grant: CapabilityGrant,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.authorization_context,
            wire.holder,
            wire.grant,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(CapabilityRoot, "capability root bytes");

/// Canonical signed body for one semantic delegation edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DelegationBody {
    protocol_version: ProtocolVersion,
    parent_grant_id: CapabilityGrantId,
    child_grant: CapabilityGrant,
    issuer: DeviceId,
    subject: DeviceId,
    authorization_context: AuthorizationContext,
    issued_at: Timestamp,
    nonce: [u8; 16],
    extensions: Extensions,
}

impl DelegationBody {
    /// Construct one v1 delegation edge.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_grant_id: CapabilityGrantId,
        child_grant: CapabilityGrant,
        issuer: DeviceId,
        subject: DeviceId,
        authorization_context: AuthorizationContext,
        issued_at: Timestamp,
        nonce: [u8; 16],
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if issuer == subject {
            return Err(IdentityError::InvalidDelegation {
                reason: "delegation issuer and subject are identical",
            });
        }
        if parent_grant_id == child_grant.capability_grant_id()? {
            return Err(IdentityError::InvalidDelegation {
                reason: "delegation child repeats its parent grant",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            parent_grant_id,
            child_grant,
            issuer,
            subject,
            authorization_context,
            issued_at,
            nonce,
            extensions,
        })
    }

    /// Grant identifier that this edge narrows.
    pub const fn parent_grant_id(&self) -> CapabilityGrantId {
        self.parent_grant_id
    }

    /// Narrowed grant assigned by this edge.
    pub const fn child_grant(&self) -> &CapabilityGrant {
        &self.child_grant
    }

    /// Device signing and issuing this edge.
    pub const fn issuer(&self) -> DeviceId {
        self.issuer
    }

    /// Device receiving the child grant.
    pub const fn subject(&self) -> DeviceId {
        self.subject
    }

    /// Account checkpoint context authorizing issuance.
    pub const fn authorization_context(&self) -> AuthorizationContext {
        self.authorization_context
    }

    /// Explicit issuance time.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Caller-supplied uniqueness nonce.
    pub const fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    /// Preserved noncritical extension fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Derive the delegation identifier from this exact canonical body.
    pub fn delegation_id(&self) -> Result<DelegationId, IdentityError> {
        DelegationId::derive(self)
    }
}

impl<'de> Deserialize<'de> for DelegationBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            parent_grant_id: CapabilityGrantId,
            child_grant: CapabilityGrant,
            issuer: DeviceId,
            subject: DeviceId,
            authorization_context: AuthorizationContext,
            issued_at: Timestamp,
            nonce: [u8; 16],
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::new(
            wire.parent_grant_id,
            wire.child_grant,
            wire.issuer,
            wire.subject,
            wire.authorization_context,
            wire.issued_at,
            wire.nonce,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(DelegationBody, "capability delegation body bytes");

/// One signed capability-delegation edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDelegation {
    body: DelegationBody,
    signature: ProtocolSignature,
}

impl SignedDelegation {
    /// Pair a validated delegation body with its protocol signature.
    pub const fn new(body: DelegationBody, signature: ProtocolSignature) -> Self {
        Self { body, signature }
    }

    /// Signed delegation body.
    pub const fn body(&self) -> &DelegationBody {
        &self.body
    }

    /// Protocol signature over the canonical body.
    pub const fn signature(&self) -> ProtocolSignature {
        self.signature
    }

    /// Derive the delegation identifier from the signed body.
    pub fn delegation_id(&self) -> Result<DelegationId, IdentityError> {
        self.body.delegation_id()
    }
}

canonical_schema!(SignedDelegation, "signed capability delegation bytes");

/// A bounded, semantic-order, same-account delegation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DelegationChain {
    root: CapabilityRoot,
    links: Vec<SignedDelegation>,
}

impl DelegationChain {
    /// Validate and construct a semantic-order chain of one to eight links.
    pub fn new(root: CapabilityRoot, links: Vec<SignedDelegation>) -> Result<Self, IdentityError> {
        if links.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "delegation chain links",
            });
        }
        if links.len() > MAX_DELEGATION_DEPTH {
            return Err(IdentityError::limit(
                "delegation chain links",
                links.len(),
                MAX_DELEGATION_DEPTH,
            ));
        }
        let chain = Self { root, links };
        chain.validate()?;
        Ok(chain)
    }

    /// Root authority and initial holder.
    pub const fn root(&self) -> &CapabilityRoot {
        &self.root
    }

    /// Delegation edges in parent-to-child semantic order.
    pub fn links(&self) -> &[SignedDelegation] {
        &self.links
    }

    /// Grant assigned by the final delegation edge.
    pub fn leaf_grant(&self) -> &CapabilityGrant {
        match self.links.last() {
            Some(link) => link.body().child_grant(),
            None => self.root.grant(),
        }
    }

    /// Device receiving the final delegation edge.
    pub fn leaf_holder(&self) -> DeviceId {
        match self.links.last() {
            Some(link) => link.body().subject(),
            None => self.root.holder(),
        }
    }

    fn validate(&self) -> Result<(), IdentityError> {
        let root_account = self.root.authorization_context().account_id();
        let mut current_holder = self.root.holder();
        let mut current_grant = self.root.grant();
        let mut current_grant_id = current_grant.capability_grant_id()?;

        let mut seen_devices = Vec::with_capacity(self.links.len().saturating_add(1));
        let mut seen_grants = Vec::with_capacity(self.links.len().saturating_add(1));
        let mut seen_delegations = Vec::with_capacity(self.links.len());
        seen_devices.push(current_holder);
        seen_grants.push(current_grant_id);

        for link in &self.links {
            let body = link.body();
            if body.authorization_context().account_id() != root_account {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation chain crosses account contexts",
                });
            }
            if body.issuer() != current_holder {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation issuer does not hold the parent grant",
                });
            }
            if body.parent_grant_id() != current_grant_id {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation parent grant is out of semantic order",
                });
            }
            if seen_devices.contains(&body.subject()) {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation chain contains a device cycle",
                });
            }

            let child_grant = body.child_grant();
            validate_narrowing(current_grant, child_grant)?;
            let child_grant_id = child_grant.capability_grant_id()?;
            if seen_grants.contains(&child_grant_id) {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation chain repeats a grant identifier",
                });
            }
            let delegation_id = link.delegation_id()?;
            if seen_delegations.contains(&delegation_id) {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation chain repeats a delegation identifier",
                });
            }

            seen_devices.push(body.subject());
            seen_grants.push(child_grant_id);
            seen_delegations.push(delegation_id);
            current_holder = body.subject();
            current_grant = child_grant;
            current_grant_id = child_grant_id;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for DelegationChain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            root: CapabilityRoot,
            links: BoundedVec<SignedDelegation, MAX_DELEGATION_DEPTH>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.root, wire.links.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(DelegationChain, "delegation chain bytes");

fn validate_narrowing(
    parent: &CapabilityGrant,
    child: &CapabilityGrant,
) -> Result<(), IdentityError> {
    if parent.namespace() != child.namespace() || parent.action() != child.action() {
        return Err(IdentityError::InvalidDelegation {
            reason: "delegation changes capability namespace or action",
        });
    }

    let mut strict = validate_resource_narrowing(parent.resource(), child.resource())?;
    strict |= validate_constraint_narrowing(parent.constraints(), child.constraints())?;
    strict |= validate_expiration_narrowing(parent.expires_at(), child.expires_at())?;
    strict |= validate_permission_narrowing(parent.delegation(), child.delegation())?;

    if !strict {
        return Err(IdentityError::InvalidDelegation {
            reason: "delegation child does not strictly narrow its parent",
        });
    }
    Ok(())
}

fn validate_resource_narrowing(
    parent: &ResourceSelector,
    child: &ResourceSelector,
) -> Result<bool, IdentityError> {
    match (parent, child) {
        (ResourceSelector::Exact(parent), ResourceSelector::Exact(child)) if parent == child => {
            Ok(false)
        }
        (ResourceSelector::Prefix(parent), ResourceSelector::Prefix(child))
            if child.starts_with(parent) =>
        {
            Ok(parent != child)
        }
        (ResourceSelector::Prefix(parent), ResourceSelector::Exact(child))
            if child.starts_with(parent) =>
        {
            Ok(true)
        }
        _ => Err(IdentityError::InvalidDelegation {
            reason: "delegation broadens its resource selector",
        }),
    }
}

fn validate_constraint_narrowing(
    parent: &[CapabilityConstraint],
    child: &[CapabilityConstraint],
) -> Result<bool, IdentityError> {
    let mut strict = false;
    for code in 1..=3 {
        let parent_value = parent
            .iter()
            .find(|constraint| constraint.code() == code)
            .map(|constraint| constraint.value());
        let child_value = child
            .iter()
            .find(|constraint| constraint.code() == code)
            .map(|constraint| constraint.value());

        match (code, parent_value, child_value) {
            (_, Some(_), None) => {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation removes a parent constraint",
                });
            }
            (1 | 3, Some(parent_value), Some(child_value)) => {
                if child_value < parent_value {
                    return Err(IdentityError::InvalidDelegation {
                        reason: "delegation weakens a lower-bound constraint",
                    });
                }
                strict |= child_value > parent_value;
            }
            (2, Some(parent_value), Some(child_value)) => {
                if child_value > parent_value {
                    return Err(IdentityError::InvalidDelegation {
                        reason: "delegation weakens an upper-bound constraint",
                    });
                }
                strict |= child_value < parent_value;
            }
            (_, None, Some(_)) => strict = true,
            (_, None, None) => {}
            _ => {
                return Err(IdentityError::InvalidDelegation {
                    reason: "delegation has an invalid constraint relationship",
                });
            }
        }
    }
    Ok(strict)
}

fn validate_expiration_narrowing(
    parent: Option<Timestamp>,
    child: Option<Timestamp>,
) -> Result<bool, IdentityError> {
    match (parent, child) {
        (None, None) => Ok(false),
        (None, Some(_)) => Ok(true),
        (Some(_), None) => Err(IdentityError::InvalidDelegation {
            reason: "delegation removes parent expiration",
        }),
        (Some(parent), Some(child)) if child <= parent => Ok(child < parent),
        (Some(_), Some(_)) => Err(IdentityError::InvalidDelegation {
            reason: "delegation extends parent expiration",
        }),
    }
}

fn validate_permission_narrowing(
    parent: DelegationPermission,
    child: DelegationPermission,
) -> Result<bool, IdentityError> {
    match (parent, child) {
        (DelegationPermission::NotDelegable, _) => Err(IdentityError::InvalidDelegation {
            reason: "parent grant is not delegable",
        }),
        (DelegationPermission::Delegable { .. }, DelegationPermission::NotDelegable) => Ok(true),
        (
            DelegationPermission::Delegable { remaining: parent },
            DelegationPermission::Delegable { remaining: child },
        ) if child.get() < parent.get() => Ok(true),
        (DelegationPermission::Delegable { .. }, DelegationPermission::Delegable { .. }) => {
            Err(IdentityError::InvalidDelegation {
                reason: "delegation remaining depth does not decrease",
            })
        }
    }
}
