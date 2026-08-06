//! Bounded signed application-event envelopes.

use krikos_base::{PublicKey, Signature};
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountId, ApplicationEventId, ApplicationId, AuthorizationContext, CheckpointId,
    DeviceAuthorization, DeviceId, Epoch, Extensions, IdentityError, ProtocolSignature,
    ProtocolVersion,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_APPLICATION_EVENT_BYTES, MAX_APPLICATION_PAYLOAD_BYTES},
    schema::BoundedBytes,
};

const APPLICATION_EVENT_SIGNATURE_DOMAIN: &[u8] = b"KRIKOS-ID/application-event-signature/v1";

/// Checked device-local application-event counter.
///
/// This counter orders events emitted by one device for one application. It deliberately makes no
/// claim about global ordering across devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ApplicationEventCounter(u64);

impl ApplicationEventCounter {
    /// Initial device-local counter.
    pub const GENESIS: Self = Self(0);

    /// Construct from the exact wire value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Exact counter value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance exactly once, rejecting exhaustion.
    pub fn checked_next(self) -> Result<Self, IdentityError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "application event counter",
            })
    }
}

impl CanonicalCodec for ApplicationEventCounter {
    const RESOURCE: &'static str = "application event counter bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Canonical application payload and exact account authorization context signed by one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplicationEventBody {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    application_id: ApplicationId,
    device_id: DeviceId,
    account_epoch: Epoch,
    checkpoint_id: CheckpointId,
    local_counter: ApplicationEventCounter,
    payload: BoundedBytes<MAX_APPLICATION_PAYLOAD_BYTES>,
    extensions: Extensions,
}

impl ApplicationEventBody {
    /// Construct a bounded v1 application event body.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        application_id: ApplicationId,
        device_id: DeviceId,
        account_epoch: Epoch,
        checkpoint_id: CheckpointId,
        local_counter: ApplicationEventCounter,
        payload: Vec<u8>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let payload = BoundedBytes::new("application event payload bytes", payload)?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            application_id,
            device_id,
            account_epoch,
            checkpoint_id,
            local_counter,
            payload,
            extensions,
        })
    }

    /// Account whose checkpoint supplies authorization state.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Application namespace interpreting the opaque payload.
    pub const fn application_id(&self) -> ApplicationId {
        self.application_id
    }

    /// Device signing the event.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Account epoch at the referenced authorization checkpoint.
    pub const fn account_epoch(&self) -> Epoch {
        self.account_epoch
    }

    /// Exact account checkpoint against which authorization is evaluated.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Device-local, application-local sequence counter.
    pub const fn local_counter(&self) -> ApplicationEventCounter {
        self.local_counter
    }

    /// Opaque bounded application payload.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Signed forward-compatible fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Build the exact domain-separated byte string signed by the device application key.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let canonical_body = encode_wire(self)?;
        let capacity = APPLICATION_EVENT_SIGNATURE_DOMAIN
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(canonical_body.len()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "application event signing message bytes",
            })?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(APPLICATION_EVENT_SIGNATURE_DOMAIN);
        message.push(0);
        message.extend_from_slice(&canonical_body);
        Ok(message)
    }
}

impl<'de> Deserialize<'de> for ApplicationEventBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            application_id: ApplicationId,
            device_id: DeviceId,
            account_epoch: Epoch,
            checkpoint_id: CheckpointId,
            local_counter: ApplicationEventCounter,
            payload: BoundedBytes<MAX_APPLICATION_PAYLOAD_BYTES>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::new(
            wire.account_id,
            wire.application_id,
            wire.device_id,
            wire.account_epoch,
            wire.checkpoint_id,
            wire.local_counter,
            wire.payload.into_vec(),
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ApplicationEventBody {
    const RESOURCE: &'static str = "application event body bytes";
    const MAX_ENCODED_BYTES: usize = MAX_APPLICATION_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Complete application event with one exact device-protocol signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedApplicationEvent {
    body: ApplicationEventBody,
    signature: ProtocolSignature,
}

/// Lifecycle result supplied by a trusted account projection for application verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplicationDeviceStatus {
    /// No authorization for the named device exists at the supplied context.
    Unknown,
    /// The device may exercise capabilities installed at the supplied context.
    Active,
    /// The device is temporarily unable to exercise application authority.
    Suspended,
    /// The device is permanently unable to exercise application authority.
    Revoked,
}

/// Exact, read-only authorization facts used to verify an application envelope.
///
/// Implementations represent an already authenticated account checkpoint. This interface performs
/// no network or wall-clock access and deliberately does not claim that the checkpoint is globally
/// fresh. A caller that requires freshness must establish it before constructing the view.
pub trait ApplicationAuthorizationView {
    /// Exact account, epoch, and checkpoint represented by this view.
    fn authorization_context(&self) -> AuthorizationContext;

    /// Lifecycle of the named device at the exact authorization context.
    fn device_status(&self, device_id: DeviceId) -> ApplicationDeviceStatus;

    /// Device authorization installed at the exact context, if one exists.
    fn device_authorization(&self, device_id: DeviceId) -> Option<&DeviceAuthorization>;
}

/// Verify an application event under its exact device key and authorization context.
///
/// The returned identifier commits to the complete signed envelope. This check establishes local
/// cryptographic authenticity and known-checkpoint authorization only; it does not establish
/// global event order, reachability, presence, or checkpoint freshness.
pub fn verify_application_event(
    event: &SignedApplicationEvent,
    view: &impl ApplicationAuthorizationView,
) -> Result<ApplicationEventId, IdentityError> {
    let body = event.body();
    let context = view.authorization_context();
    if body.account_id() != context.account_id() {
        return Err(IdentityError::AccountMismatch);
    }
    if body.account_epoch() != context.epoch() {
        return Err(IdentityError::InvalidEpoch);
    }
    if body.checkpoint_id() != context.checkpoint_id() {
        return Err(IdentityError::InvalidRelationship {
            resource: "application event authorization checkpoint",
        });
    }

    match view.device_status(body.device_id()) {
        ApplicationDeviceStatus::Unknown => return Err(IdentityError::DeviceNotAuthorized),
        ApplicationDeviceStatus::Active => {}
        ApplicationDeviceStatus::Suspended => return Err(IdentityError::DeviceSuspended),
        ApplicationDeviceStatus::Revoked => return Err(IdentityError::DeviceRevoked),
    }
    let authorization = view
        .device_authorization(body.device_id())
        .ok_or(IdentityError::DeviceNotAuthorized)?;
    if authorization.authorization_epoch() > context.epoch() {
        return Err(IdentityError::InvalidEpoch);
    }
    event.validate_authorization(authorization)?;

    let signing_key = authorization.descriptor().application_signing_key();
    let public_key = PublicKey::from_bytes(signing_key.as_bytes())
        .map_err(|_| IdentityError::InvalidSignature)?;
    let signature = Signature::try_from(event.signature().as_bytes().as_slice())
        .map_err(|_| IdentityError::InvalidSignature)?;
    public_key
        .verify(&body.signing_bytes()?, &signature)
        .map_err(|_| IdentityError::InvalidSignature)?;
    event.application_event_id()
}

impl SignedApplicationEvent {
    /// Construct a complete event and enforce the one-mebibyte envelope limit.
    pub fn new(
        body: ApplicationEventBody,
        signature: ProtocolSignature,
    ) -> Result<Self, IdentityError> {
        let event = Self { body, signature };
        let encoded_len = encode_wire(&event)?.len();
        if encoded_len > MAX_APPLICATION_EVENT_BYTES {
            return Err(IdentityError::limit(
                "signed application event bytes",
                encoded_len,
                MAX_APPLICATION_EVENT_BYTES,
            ));
        }
        Ok(event)
    }

    /// Exact signed body.
    pub const fn body(&self) -> &ApplicationEventBody {
        &self.body
    }

    /// Exact fixed-profile signature. Cryptographic verification is performed by Task 4.
    pub const fn signature(&self) -> ProtocolSignature {
        self.signature
    }

    /// Validate the state-dependent device identifier and authorization-epoch relationship.
    pub fn validate_authorization(
        &self,
        authorization: &DeviceAuthorization,
    ) -> Result<(), IdentityError> {
        if self.body.device_id != authorization.device_id() {
            return Err(IdentityError::InvalidRelationship {
                resource: "application event signer device",
            });
        }
        if self.body.account_epoch < authorization.authorization_epoch() {
            return Err(IdentityError::InvalidRelationship {
                resource: "application event authorization epoch",
            });
        }
        Ok(())
    }

    /// Derive the identifier of the complete canonical signed envelope.
    pub fn application_event_id(&self) -> Result<ApplicationEventId, IdentityError> {
        ApplicationEventId::derive(self)
    }
}

impl<'de> Deserialize<'de> for SignedApplicationEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            body: ApplicationEventBody,
            signature: ProtocolSignature,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.body, wire.signature).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for SignedApplicationEvent {
    const RESOURCE: &'static str = "signed application event bytes";
    const MAX_ENCODED_BYTES: usize = MAX_APPLICATION_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}
