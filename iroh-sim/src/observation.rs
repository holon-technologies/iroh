//! Immutable production/environment observations consumed by reference models and invariants.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::ResourceKind;

/// Current observation schema.
pub const OBSERVATION_SCHEMA_VERSION: u16 = 1;

macro_rules! entity_id {
    ($name:ident, $label:literal) => {
        #[doc = concat!("Stable ", $label, " identity within one run.")]
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ObservationError> {
                let value = value.into();
                validate_id($label, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

entity_id!(OperationId, "operation");
entity_id!(EndpointId, "endpoint");
entity_id!(ConnectionId, "connection");
entity_id!(StreamId, "stream");
entity_id!(PacketId, "packet");
entity_id!(PathId, "path");

/// Blake3 application-payload identity; payload bytes never enter observations.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PayloadDigest(String);

impl PayloadDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }

    pub fn from_hex(value: impl Into<String>) -> Result<Self, ObservationError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ObservationError::InvalidPayloadDigest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Monotonic endpoint lifecycle states visible to scenarios.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointState {
    Created,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// Monotonic connection lifecycle states visible to scenarios.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Created,
    Dialing,
    Connected,
    Closing,
    Closed,
    Failed,
}

/// One immutable observation with a run-local sequence and virtual timestamp.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema_version: u16,
    pub sequence: u64,
    pub virtual_time_nanos: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caused_by: Option<OperationId>,
    pub kind: ObservationKind,
}

impl Observation {
    pub const fn new(sequence: u64, virtual_time_nanos: u64, kind: ObservationKind) -> Self {
        Self {
            schema_version: OBSERVATION_SCHEMA_VERSION,
            sequence,
            virtual_time_nanos,
            caused_by: None,
            kind,
        }
    }

    pub fn caused_by(mut self, operation: OperationId) -> Self {
        self.caused_by = Some(operation);
        self
    }

    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.schema_version != OBSERVATION_SCHEMA_VERSION {
            return Err(ObservationError::UnsupportedSchema(self.schema_version));
        }
        if self.sequence == 0 {
            return Err(ObservationError::ZeroSequence);
        }
        match &self.kind {
            ObservationKind::ConnectionState {
                peer_identity: Some(identity),
                ..
            } if identity.is_empty() || identity.len() > 256 => {
                Err(ObservationError::InvalidIdentity)
            }
            ObservationKind::Marker { name, fields } => {
                validate_id("marker", name)?;
                if fields.len() > 256 {
                    return Err(ObservationError::TooManyFields);
                }
                for (key, value) in fields {
                    validate_id("field", key)?;
                    if value.len() > 1_024 {
                        return Err(ObservationError::FieldTooLong);
                    }
                }
                Ok(())
            }
            ObservationKind::RelayState { relay, .. }
            | ObservationKind::RelayCoverage { relay, .. } => validate_id("relay", relay),
            _ => Ok(()),
        }
    }
}

/// Observation vocabulary shared by runners, models, and invariants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "observation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationKind {
    OperationStarted {
        operation: OperationId,
    },
    OperationCompleted {
        operation: OperationId,
        outcome: String,
    },
    EndpointState {
        endpoint: EndpointId,
        from: EndpointState,
        to: EndpointState,
    },
    ConnectionState {
        connection: ConnectionId,
        owner: EndpointId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_identity: Option<String>,
        from: ConnectionState,
        to: ConnectionState,
    },
    Delivery {
        connection: ConnectionId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stream: Option<StreamId>,
        sequence: u64,
        source: EndpointId,
        destination: EndpointId,
        intended_destination: EndpointId,
        expected: PayloadDigest,
        actual: PayloadDigest,
    },
    Resource {
        kind: ResourceKind,
        current: u64,
        limit: u64,
    },
    InterfaceState {
        host: String,
        interface: String,
        up: bool,
    },
    InterfaceAddress {
        host: String,
        interface: String,
        address: String,
        present: bool,
    },
    HostPower {
        host: String,
        sleeping: bool,
    },
    RouteState {
        host: String,
        route: String,
        active: bool,
    },
    PortMappingState {
        endpoint: EndpointId,
        active: bool,
        external: Option<String>,
    },
    DiscoveryRecordState {
        provider: String,
        record: String,
        endpoint: EndpointId,
        state: String,
        addresses: Vec<String>,
        available_nanos: u64,
        expires_nanos: u64,
    },
    RelayState {
        relay: String,
        online: bool,
        generation: u64,
        sessions: u64,
    },
    /// Monotonic proof that the production relay admission, authentication, and routing handlers
    /// executed during this run.
    RelayCoverage {
        relay: String,
        connect_attempts: u64,
        authenticated_sessions: u64,
        forwarded_packets: u64,
        dropped_packets: u64,
    },
    PathState {
        connection: ConnectionId,
        path: PathId,
        active: bool,
    },
    Marker {
        name: String,
        fields: BTreeMap<String, String>,
    },
}

/// Malformed observation identity or payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservationError {
    UnsupportedSchema(u16),
    ZeroSequence,
    InvalidId { kind: &'static str, value: String },
    InvalidPayloadDigest,
    InvalidIdentity,
    TooManyFields,
    FieldTooLong,
}

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(version) => {
                write!(f, "unsupported observation schema {version}")
            }
            Self::ZeroSequence => f.write_str("observation sequence must be nonzero"),
            Self::InvalidId { kind, value } => write!(f, "invalid {kind} identity {value:?}"),
            Self::InvalidPayloadDigest => f.write_str("invalid payload digest"),
            Self::InvalidIdentity => f.write_str("invalid authenticated peer identity"),
            Self::TooManyFields => f.write_str("marker field limit exceeded"),
            Self::FieldTooLong => f.write_str("marker field value limit exceeded"),
        }
    }
}

impl std::error::Error for ObservationError {}

fn validate_id(kind: &'static str, value: &str) -> Result<(), ObservationError> {
    if value.is_empty()
        || value.len() > 128
        || value.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        Err(ObservationError::InvalidId {
            kind,
            value: value.to_owned(),
        })
    } else {
        Ok(())
    }
}
