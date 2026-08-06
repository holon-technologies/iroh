//! Pure, bounded device-pairing ceremony schemas and state transitions.

use std::fmt;

mod nonce_store;

pub use nonce_store::MemoryPairingNonceStore;
#[cfg(feature = "fs-store")]
pub use nonce_store::RedbPairingNonceStore;

use krikos_base::{PublicKey as Ed25519PublicKey, Signature as Ed25519Signature};
use rand_core::TryCryptoRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeTuple};
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    AccountId, AgreementPublicKey, AgreementSecretKey, CanonicalWire, DeviceAuthorizationProposal,
    DeviceDescriptor, DeviceId, Digest, EndpointPublicKey, Extensions, HashAlgorithm,
    IdentityError, ProtocolSignature, ProtocolVersion, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{
        MAX_ACCOUNT_EVENT_BYTES, MAX_FUTURE_CLOCK_SKEW, MAX_PAIRING_LIFETIME,
        MAX_PAIRING_TICKET_BYTES,
    },
    schema::BoundedBytes,
};

/// Maximum opaque transport-discovery bytes retained in a pairing ticket.
pub const MAX_PAIRING_ENDPOINT_HINT_BYTES: usize = 1_024;

const PAIRING_SECRET_COMMITMENT_CONTEXT: &str = "KRIKOS-ID/pairing-secret-commitment/v1";
const PAIRING_TICKET_ID_CONTEXT: &str = "KRIKOS-ID/pairing-ticket-id/v1";
const PAIRING_TRANSCRIPT_ID_CONTEXT: &str = "KRIKOS-ID/pairing-transcript-id/v1";
const PAIRING_PROOF_ID_CONTEXT: &str = "KRIKOS-ID/pairing-possession-proof-id/v1";
#[cfg(any(test, feature = "net"))]
const PAIRING_TRANSPORT_EXPORTER_CONTEXT: &str = "KRIKOS-ID/pairing-transport-exporter/v1";
const APPLICATION_POSSESSION_DOMAIN: &[u8] = b"KRIKOS-ID/pairing-application-possession/v1";
const ENDPOINT_POSSESSION_DOMAIN: &[u8] = b"KRIKOS-ID/pairing-endpoint-possession/v1";
const AGREEMENT_POSSESSION_DOMAIN: &[u8] = b"KRIKOS-ID/pairing-agreement-possession/v1";
const EPHEMERAL_POSSESSION_DOMAIN: &[u8] = b"KRIKOS-ID/pairing-ephemeral-possession/v1";
const PAIRING_CONFIRMATION_DOMAIN: &[u8] = b"KRIKOS-ID/pairing-confirmation/v1";
const AGREEMENT_PROOF_KEY_CONTEXT: &str = "KRIKOS-ID/pairing-agreement-proof-key/v1";
const EPHEMERAL_PROOF_KEY_CONTEXT: &str = "KRIKOS-ID/pairing-ephemeral-proof-key/v1";

fn derive_digest(context: &'static str, bytes: &[u8]) -> Digest {
    Digest::new(
        HashAlgorithm::Blake3_256,
        blake3::derive_key(context, bytes),
    )
}

fn validate_ticket_times(issued_at: Timestamp, expires_at: Timestamp) -> Result<(), IdentityError> {
    let lifetime = expires_at
        .as_unix_millis()
        .checked_sub(issued_at.as_unix_millis())
        .ok_or(IdentityError::InvalidRelationship {
            resource: "pairing ticket validity interval",
        })?;
    if lifetime == 0 {
        return Err(IdentityError::ZeroValue {
            resource: "pairing ticket lifetime",
        });
    }
    if u128::from(lifetime) > MAX_PAIRING_LIFETIME.as_millis() {
        return Err(IdentityError::LimitExceeded {
            resource: "pairing ticket lifetime milliseconds",
            actual: usize::try_from(lifetime).unwrap_or(usize::MAX),
            maximum: usize::try_from(MAX_PAIRING_LIFETIME.as_millis()).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

/// Nonzero one-time pairing-ticket nonce.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PairingNonce([u8; 32]);

impl PairingNonce {
    /// Validate an exact 256-bit nonce.
    pub fn new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        if bytes == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "pairing ticket nonce",
            });
        }
        Ok(Self(bytes))
    }

    /// Exact nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PairingNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingNonce(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for PairingNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for PairingNonce {
    const RESOURCE: &'static str = "pairing nonce bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Domain-separated identifier of a complete canonical pairing ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PairingTicketId(Digest);

impl PairingTicketId {
    /// Borrow the tagged digest.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl CanonicalCodec for PairingTicketId {
    const RESOURCE: &'static str = "pairing ticket identifier bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Validated public inputs used to issue a pairing ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTicketRequest {
    account_id: AccountId,
    proposed_device: DeviceDescriptor,
    endpoint_hint: BoundedBytes<MAX_PAIRING_ENDPOINT_HINT_BYTES>,
    issued_at: Timestamp,
    expires_at: Timestamp,
    extensions: Extensions,
}

impl PairingTicketRequest {
    /// Construct a request with an explicit validity interval and bounded opaque endpoint hint.
    pub fn new(
        account_id: AccountId,
        proposed_device: DeviceDescriptor,
        endpoint_hint: Vec<u8>,
        issued_at: Timestamp,
        expires_at: Timestamp,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_ticket_times(issued_at, expires_at)?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            account_id,
            proposed_device,
            endpoint_hint: BoundedBytes::new("pairing endpoint hint bytes", endpoint_hint)?,
            issued_at,
            expires_at,
            extensions,
        })
    }
}

/// Complete bounded QR/local-code ticket for one proposed device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairingTicket {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    proposed_device: DeviceDescriptor,
    proposed_device_id: DeviceId,
    ephemeral_public_key: AgreementPublicKey,
    proposed_endpoint: EndpointPublicKey,
    endpoint_hint: BoundedBytes<MAX_PAIRING_ENDPOINT_HINT_BYTES>,
    random_secret_commitment: Digest,
    issued_at: Timestamp,
    expires_at: Timestamp,
    nonce: PairingNonce,
    extensions: Extensions,
}

impl PairingTicket {
    /// Issue a ticket using fallible operating-system cryptographic entropy.
    #[cfg(feature = "os-rng")]
    #[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
    pub fn issue(
        request: PairingTicketRequest,
    ) -> Result<(Self, PairingTicketSecrets), IdentityError> {
        let mut random_secret = Zeroizing::new([0_u8; 32]);
        let mut ephemeral_secret = Zeroizing::new([0_u8; 32]);
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut random_secret[..]).map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(&mut ephemeral_secret[..])
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        getrandom::fill(&mut nonce).map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::issue_with_material(request, random_secret, ephemeral_secret, nonce)
    }

    /// Issue a deterministic ticket using an explicit cryptographic RNG.
    pub fn issue_with_rng(
        request: PairingTicketRequest,
        rng: &mut impl TryCryptoRng,
    ) -> Result<(Self, PairingTicketSecrets), IdentityError> {
        let mut random_secret = Zeroizing::new([0_u8; 32]);
        let mut ephemeral_secret = Zeroizing::new([0_u8; 32]);
        let mut nonce = [0_u8; 32];
        rng.try_fill_bytes(&mut random_secret[..])
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(&mut ephemeral_secret[..])
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::issue_with_material(request, random_secret, ephemeral_secret, nonce)
    }

    fn issue_with_material(
        request: PairingTicketRequest,
        random_secret: Zeroizing<[u8; 32]>,
        ephemeral_secret: Zeroizing<[u8; 32]>,
        nonce: [u8; 32],
    ) -> Result<(Self, PairingTicketSecrets), IdentityError> {
        if *random_secret == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "pairing random secret",
            });
        }
        if *ephemeral_secret == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "pairing ephemeral secret",
            });
        }
        let nonce = PairingNonce::new(nonce)?;
        let pairing_secret = PairingRandomSecret(random_secret);
        let ephemeral_secret = PairingEphemeralSecret(StaticSecret::from(*ephemeral_secret));
        let ephemeral_public_key = ephemeral_secret.public_key()?;
        let proposed_device_id = request.proposed_device.id()?;
        let proposed_endpoint = request.proposed_device.endpoint_key();
        let random_secret_commitment = pairing_secret.commitment();
        let ticket = Self::new(
            request.account_id,
            request.proposed_device,
            proposed_device_id,
            ephemeral_public_key,
            proposed_endpoint,
            request.endpoint_hint.into_vec(),
            random_secret_commitment,
            request.issued_at,
            request.expires_at,
            nonce,
            request.extensions,
        )?;
        let ticket_id = ticket.ticket_id()?;
        Ok((
            ticket,
            PairingTicketSecrets {
                ticket_id,
                random_secret: pairing_secret,
                ephemeral_secret,
            },
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        account_id: AccountId,
        proposed_device: DeviceDescriptor,
        proposed_device_id: DeviceId,
        ephemeral_public_key: AgreementPublicKey,
        proposed_endpoint: EndpointPublicKey,
        endpoint_hint: Vec<u8>,
        random_secret_commitment: Digest,
        issued_at: Timestamp,
        expires_at: Timestamp,
        nonce: PairingNonce,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_ticket_times(issued_at, expires_at)?;
        let derived_device_id = proposed_device.id()?;
        if proposed_device_id != derived_device_id {
            return Err(IdentityError::InvalidIdentifier {
                resource: "pairing proposed device",
            });
        }
        if proposed_endpoint != proposed_device.endpoint_key() {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing proposed endpoint binding",
            });
        }
        extensions.validate_critical(&[])?;
        let ticket = Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            proposed_device,
            proposed_device_id,
            ephemeral_public_key,
            proposed_endpoint,
            endpoint_hint: BoundedBytes::new("pairing endpoint hint bytes", endpoint_hint)?,
            random_secret_commitment,
            issued_at,
            expires_at,
            nonce,
            extensions,
        };
        let encoded_len = encode_wire(&ticket)?.len();
        if encoded_len > MAX_PAIRING_TICKET_BYTES {
            return Err(IdentityError::limit(
                "pairing ticket bytes",
                encoded_len,
                MAX_PAIRING_TICKET_BYTES,
            ));
        }
        Ok(ticket)
    }

    /// Derive the identifier of the complete canonical ticket.
    pub fn ticket_id(&self) -> Result<PairingTicketId, IdentityError> {
        Ok(PairingTicketId(derive_digest(
            PAIRING_TICKET_ID_CONTEXT,
            &self.to_canonical_bytes()?,
        )))
    }

    /// Stable account being extended.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Complete proposed public device descriptor.
    pub const fn proposed_device(&self) -> &DeviceDescriptor {
        &self.proposed_device
    }

    /// Exact identifier derived from the proposed descriptor.
    pub const fn proposed_device_id(&self) -> DeviceId {
        self.proposed_device_id
    }

    /// Fresh X25519 key dedicated to this pairing ceremony.
    pub const fn ephemeral_public_key(&self) -> AgreementPublicKey {
        self.ephemeral_public_key
    }

    /// Endpoint identity expected on the authenticated connection.
    pub const fn proposed_endpoint(&self) -> EndpointPublicKey {
        self.proposed_endpoint
    }

    /// Opaque bounded discovery hint; never treated as transport authentication.
    pub fn endpoint_hint(&self) -> &[u8] {
        self.endpoint_hint.as_slice()
    }

    /// Commitment to the separately retained fresh random secret.
    pub const fn random_secret_commitment(&self) -> Digest {
        self.random_secret_commitment
    }

    /// Explicit ticket issue time.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Explicit ticket expiry time.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Durable one-time-use nonce.
    pub const fn nonce(&self) -> PairingNonce {
        self.nonce
    }

    /// Signed forward-compatible fields.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl<'de> Deserialize<'de> for PairingTicket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            proposed_device: DeviceDescriptor,
            proposed_device_id: DeviceId,
            ephemeral_public_key: AgreementPublicKey,
            proposed_endpoint: EndpointPublicKey,
            endpoint_hint: BoundedBytes<MAX_PAIRING_ENDPOINT_HINT_BYTES>,
            random_secret_commitment: Digest,
            issued_at: Timestamp,
            expires_at: Timestamp,
            nonce: PairingNonce,
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
            wire.proposed_device,
            wire.proposed_device_id,
            wire.ephemeral_public_key,
            wire.proposed_endpoint,
            wire.endpoint_hint.into_vec(),
            wire.random_secret_commitment,
            wire.issued_at,
            wire.expires_at,
            wire.nonce,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for PairingTicket {
    const RESOURCE: &'static str = "pairing ticket bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PAIRING_TICKET_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Ticket-side fresh secret material, retained only on the proposed device.
///
/// This type is intentionally neither `Copy` nor `Clone` and redacts its debug output.
pub struct PairingTicketSecrets {
    ticket_id: PairingTicketId,
    random_secret: PairingRandomSecret,
    ephemeral_secret: PairingEphemeralSecret,
}

impl fmt::Debug for PairingTicketSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingTicketSecrets(<redacted>)")
    }
}

struct PairingRandomSecret(Zeroizing<[u8; 32]>);

impl PairingRandomSecret {
    fn commitment(&self) -> Digest {
        derive_digest(PAIRING_SECRET_COMMITMENT_CONTEXT, &self.0[..])
    }
}

struct PairingEphemeralSecret(StaticSecret);

impl PairingEphemeralSecret {
    fn public_key(&self) -> Result<AgreementPublicKey, IdentityError> {
        AgreementPublicKey::x25519(X25519PublicKey::from(&self.0).to_bytes())
    }
}

#[cfg(test)]
mod tests;

macro_rules! nonzero_bytes {
    ($name:ident, $resource:literal, $debug:literal) => {
        #[doc = $resource]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Validate exact nonzero bytes.
            pub fn new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
                if bytes == [0; 32] {
                    return Err(IdentityError::ZeroValue {
                        resource: $resource,
                    });
                }
                Ok(Self(bytes))
            }

            /// Borrow the exact bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($debug)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(de::Error::custom)
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

nonzero_bytes!(
    PairingSessionId,
    "pairing session identifier",
    "PairingSessionId(<redacted>)"
);
nonzero_bytes!(
    PairingChallenge,
    "pairing verifier challenge",
    "PairingChallenge(<redacted>)"
);
/// Secret authenticated-transport exporter supplied by the effect boundary.
///
/// The raw value is non-`Copy`, non-`Clone`, redacted, and erased on drop. Only its
/// domain-separated binding is retained in the protocol transcript.
#[cfg(any(test, feature = "net"))]
pub(crate) struct TransportExporterValue(Zeroizing<[u8; 32]>);

#[cfg(any(test, feature = "net"))]
impl TransportExporterValue {
    /// Take ownership of an exact nonzero exporter value at a trusted adapter boundary.
    pub(crate) fn new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        if bytes == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "authenticated transport exporter",
            });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn into_binding(self) -> Digest {
        derive_digest(PAIRING_TRANSPORT_EXPORTER_CONTEXT, &self.0[..])
    }
}

/// Complete authenticated facts returned by a crate-owned transport adapter.
#[cfg(any(test, feature = "net"))]
pub(crate) struct AuthenticatedTransportFacts {
    /// Unique authenticated transport session.
    pub(crate) session_id: PairingSessionId,
    /// Locally authenticated controller endpoint.
    pub(crate) controller_endpoint: EndpointPublicKey,
    /// Remotely authenticated proposed-device endpoint.
    pub(crate) proposed_endpoint: EndpointPublicKey,
    /// Secret exporter extracted from the same authenticated connection.
    pub(crate) exporter: TransportExporterValue,
}

/// Sealed crate boundary that may attest authenticated pairing-transport facts.
///
/// The optional network adapter and the private deterministic test adapter are the only intended
/// implementations. Public callers can carry a resulting binding but cannot implement this trait
/// or mint its facts.
#[cfg(any(test, feature = "net"))]
pub(crate) trait AuthenticatedTransportAdapter {
    /// Consume the adapter and return facts obtained from one authenticated connection.
    fn into_authenticated_transport_facts(self) -> AuthenticatedTransportFacts;
}

#[cfg(any(test, feature = "net"))]
impl fmt::Debug for TransportExporterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransportExporterValue(<redacted>)")
    }
}

/// Explicit evidence supplied by an authenticated Krikos transport adapter.
///
/// Construction does not perform transport authentication. Task 6 transport code may construct
/// this capability only after authentication and exporter extraction succeed. Endpoint hints are
/// deliberately absent because they are discovery metadata, not authentication evidence.
///
/// Public callers cannot mint raw transport evidence:
///
/// ```compile_fail
/// use krikos_identity::TransportExporterValue;
///
/// let _forged = TransportExporterValue::new([7_u8; 32]);
/// ```
///
/// Public callers also cannot invoke the authenticated adapter factory directly:
///
/// ```compile_fail
/// use krikos_identity::AuthenticatedTransportBinding;
///
/// let _forged = AuthenticatedTransportBinding::new(todo!(), todo!(), todo!(), todo!());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedTransportBinding {
    session_id: PairingSessionId,
    controller_endpoint: EndpointPublicKey,
    proposed_endpoint: EndpointPublicKey,
    exporter_binding: Digest,
}

impl AuthenticatedTransportBinding {
    /// Bind facts supplied by a crate-owned authenticated transport adapter.
    #[cfg(any(test, feature = "net"))]
    pub(crate) fn from_authenticated_adapter(
        adapter: impl AuthenticatedTransportAdapter,
    ) -> Result<Self, IdentityError> {
        let facts = adapter.into_authenticated_transport_facts();
        Self::new(
            facts.session_id,
            facts.controller_endpoint,
            facts.proposed_endpoint,
            facts.exporter,
        )
    }

    #[cfg(any(test, feature = "net"))]
    fn new(
        session_id: PairingSessionId,
        controller_endpoint: EndpointPublicKey,
        proposed_endpoint: EndpointPublicKey,
        exporter: TransportExporterValue,
    ) -> Result<Self, IdentityError> {
        if controller_endpoint == proposed_endpoint {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing authenticated endpoint separation",
            });
        }
        Ok(Self {
            session_id,
            controller_endpoint,
            proposed_endpoint,
            exporter_binding: exporter.into_binding(),
        })
    }

    /// Authenticated transport session identifier.
    pub const fn session_id(self) -> PairingSessionId {
        self.session_id
    }

    /// Authenticated existing-controller endpoint.
    pub const fn controller_endpoint(self) -> EndpointPublicKey {
        self.controller_endpoint
    }

    /// Authenticated proposed-device endpoint.
    pub const fn proposed_endpoint(self) -> EndpointPublicKey {
        self.proposed_endpoint
    }

    /// Domain-separated binding of the channel exporter unique to this connection.
    pub const fn exporter_binding(self) -> Digest {
        self.exporter_binding
    }
}

/// Verifier-side X25519 secret dedicated to one authenticated pairing connection.
///
/// This type is intentionally neither `Copy` nor `Clone` and zeroizes on drop.
pub struct ConnectionEphemeralSecret(StaticSecret);

impl ConnectionEphemeralSecret {
    /// Take ownership of exact X25519 secret-key material.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// Generate using fallible operating-system entropy.
    #[cfg(feature = "os-rng")]
    #[cfg_attr(krikos_docsrs, doc(cfg(feature = "os-rng")))]
    pub fn generate() -> Result<Self, IdentityError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut bytes[..]).map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::from_generated_material(bytes)
    }

    /// Generate using an explicit deterministic cryptographic RNG.
    pub fn generate_with_rng(rng: &mut impl TryCryptoRng) -> Result<Self, IdentityError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        rng.try_fill_bytes(&mut bytes[..])
            .map_err(|_| IdentityError::EntropyUnavailable)?;
        Self::from_generated_material(bytes)
    }

    fn from_generated_material(bytes: Zeroizing<[u8; 32]>) -> Result<Self, IdentityError> {
        if *bytes == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "pairing connection ephemeral secret",
            });
        }
        Ok(Self::from_bytes(*bytes))
    }

    /// Corresponding contributory X25519 public key.
    pub fn public_key(&self) -> Result<AgreementPublicKey, IdentityError> {
        AgreementPublicKey::x25519(X25519PublicKey::from(&self.0).to_bytes())
    }

    fn diffie_hellman(
        &self,
        public_key: AgreementPublicKey,
    ) -> Result<SharedSecret, IdentityError> {
        let public_key = X25519PublicKey::from(*public_key.as_bytes());
        let shared_secret = self.0.diffie_hellman(&public_key);
        validate_contributory(&shared_secret)?;
        Ok(shared_secret)
    }
}

impl fmt::Debug for ConnectionEphemeralSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionEphemeralSecret(<redacted>)")
    }
}

/// Domain-separated identifier of a complete pairing transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PairingTranscriptId(Digest);

impl PairingTranscriptId {
    /// Borrow the tagged digest.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl CanonicalCodec for PairingTranscriptId {
    const RESOURCE: &'static str = "pairing transcript identifier bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Complete immutable context signed and MACed by the proposed device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingTranscript {
    protocol_version: ProtocolVersion,
    ticket_id: PairingTicketId,
    random_secret_commitment: Digest,
    account_id: AccountId,
    proposed_device: DeviceDescriptor,
    proposed_device_id: DeviceId,
    controller_device: DeviceDescriptor,
    controller_device_id: DeviceId,
    proposed_endpoint: EndpointPublicKey,
    controller_endpoint: EndpointPublicKey,
    verifier_challenge: PairingChallenge,
    session_id: PairingSessionId,
    transport_exporter_binding: Digest,
    pairing_ephemeral_public_key: AgreementPublicKey,
    connection_ephemeral_public_key: AgreementPublicKey,
}

impl PairingTranscript {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ticket: &PairingTicket,
        controller_device: DeviceDescriptor,
        transport: AuthenticatedTransportBinding,
        verifier_challenge: PairingChallenge,
        connection_ephemeral_public_key: AgreementPublicKey,
    ) -> Result<Self, IdentityError> {
        validate_pairing_public_key_separation(
            &ticket.proposed_device,
            &controller_device,
            ticket.ephemeral_public_key,
            connection_ephemeral_public_key,
        )?;
        let controller_device_id = controller_device.id()?;
        if controller_device_id == ticket.proposed_device_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing controller and proposed device separation",
            });
        }
        if transport.controller_endpoint != controller_device.endpoint_key()
            || transport.proposed_endpoint != ticket.proposed_endpoint
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing authenticated transport endpoints",
            });
        }
        let transcript = Self {
            protocol_version: ProtocolVersion::V1,
            ticket_id: ticket.ticket_id()?,
            random_secret_commitment: ticket.random_secret_commitment,
            account_id: ticket.account_id,
            proposed_device: ticket.proposed_device.clone(),
            proposed_device_id: ticket.proposed_device_id,
            controller_device,
            controller_device_id,
            proposed_endpoint: transport.proposed_endpoint,
            controller_endpoint: transport.controller_endpoint,
            verifier_challenge,
            session_id: transport.session_id,
            transport_exporter_binding: transport.exporter_binding,
            pairing_ephemeral_public_key: ticket.ephemeral_public_key,
            connection_ephemeral_public_key,
        };
        let encoded_len = encode_wire(&transcript)?.len();
        if encoded_len > MAX_ACCOUNT_EVENT_BYTES {
            return Err(IdentityError::limit(
                "pairing transcript bytes",
                encoded_len,
                MAX_ACCOUNT_EVENT_BYTES,
            ));
        }
        Ok(transcript)
    }

    /// Derive the identifier of the complete transcript.
    pub fn transcript_id(&self) -> Result<PairingTranscriptId, IdentityError> {
        Ok(PairingTranscriptId(derive_digest(
            PAIRING_TRANSCRIPT_ID_CONTEXT,
            &self.to_canonical_bytes()?,
        )))
    }

    /// Exact domain-separated application-key possession message.
    pub fn application_possession_signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        domain_message(APPLICATION_POSSESSION_DOMAIN, &self.to_canonical_bytes()?)
    }

    /// Exact domain-separated endpoint-key possession message.
    pub fn endpoint_possession_signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        domain_message(ENDPOINT_POSSESSION_DOMAIN, &self.to_canonical_bytes()?)
    }

    /// Exact participant- and transcript-bound bytes signed after independent SAS confirmation.
    pub fn confirmation_signing_bytes(
        &self,
        participant: ConfirmationParticipant,
        observed_short_auth: ShortAuthString,
        confirmed_at: Timestamp,
    ) -> Result<Vec<u8>, IdentityError> {
        pairing_confirmation_signing_bytes(
            participant,
            self.transcript_id()?,
            observed_short_auth,
            confirmed_at,
        )
    }

    /// Construct one endpoint-signed participant confirmation for this exact transcript.
    pub fn signed_confirmation(
        &self,
        participant: ConfirmationParticipant,
        observed_short_auth: ShortAuthString,
        confirmed_at: Timestamp,
        endpoint_signature: ProtocolSignature,
    ) -> Result<PairingConfirmation, IdentityError> {
        Ok(PairingConfirmation {
            participant,
            transcript_id: self.transcript_id()?,
            observed_short_auth,
            confirmed_at,
            endpoint_signature,
        })
    }

    /// Account being extended.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Proposed complete public device descriptor.
    pub const fn proposed_device(&self) -> &DeviceDescriptor {
        &self.proposed_device
    }

    /// Existing controller's complete public device descriptor.
    pub const fn controller_device(&self) -> &DeviceDescriptor {
        &self.controller_device
    }

    /// Ticket identifier bound into this transcript.
    pub const fn ticket_id(&self) -> PairingTicketId {
        self.ticket_id
    }

    /// Verifier challenge bound into this transcript.
    pub const fn verifier_challenge(&self) -> PairingChallenge {
        self.verifier_challenge
    }

    /// Authenticated session bound into this transcript.
    pub const fn session_id(&self) -> PairingSessionId {
        self.session_id
    }

    /// Domain-separated authenticated transport exporter binding in this transcript.
    pub const fn transport_exporter_binding(&self) -> Digest {
        self.transport_exporter_binding
    }

    /// Proposed-device pairing-ephemeral public key committed by this transcript.
    pub const fn pairing_ephemeral_public_key(&self) -> AgreementPublicKey {
        self.pairing_ephemeral_public_key
    }

    /// Controller connection-ephemeral public key committed by this transcript.
    pub const fn connection_ephemeral_public_key(&self) -> AgreementPublicKey {
        self.connection_ephemeral_public_key
    }
}

impl CanonicalCodec for PairingTranscript {
    const RESOURCE: &'static str = "pairing transcript bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let transcript: Self = decode_wire(bytes)?;
        if transcript.proposed_device.id()? != transcript.proposed_device_id
            || transcript.controller_device.id()? != transcript.controller_device_id
            || transcript.proposed_endpoint != transcript.proposed_device.endpoint_key()
            || transcript.controller_endpoint != transcript.controller_device.endpoint_key()
            || transcript.proposed_device_id == transcript.controller_device_id
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing transcript device bindings",
            });
        }
        validate_pairing_public_key_separation(
            &transcript.proposed_device,
            &transcript.controller_device,
            transcript.pairing_ephemeral_public_key,
            transcript.connection_ephemeral_public_key,
        )?;
        Ok(transcript)
    }
}

fn validate_pairing_public_key_separation(
    proposed_device: &DeviceDescriptor,
    controller_device: &DeviceDescriptor,
    pairing_ephemeral_public_key: AgreementPublicKey,
    connection_ephemeral_public_key: AgreementPublicKey,
) -> Result<(), IdentityError> {
    let proposed_application = proposed_device.application_signing_key();
    let proposed_agreement = proposed_device.agreement_key();
    let proposed_endpoint = proposed_device.endpoint_key().as_signing_key();
    let controller_application = controller_device.application_signing_key();
    let controller_agreement = controller_device.agreement_key();
    let controller_endpoint = controller_device.endpoint_key().as_signing_key();
    let public_keys = [
        proposed_application.as_bytes(),
        proposed_agreement.as_bytes(),
        proposed_endpoint.as_bytes(),
        controller_application.as_bytes(),
        controller_agreement.as_bytes(),
        controller_endpoint.as_bytes(),
        pairing_ephemeral_public_key.as_bytes(),
        connection_ephemeral_public_key.as_bytes(),
    ];
    let mut remaining = public_keys.as_slice();
    while let Some((public_key, tail)) = remaining.split_first() {
        if tail.contains(public_key) {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing transcript public-key separation",
            });
        }
        remaining = tail;
    }
    Ok(())
}

/// Domain-separated identifier of a complete possession proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PairingProofId(Digest);

impl PairingProofId {
    /// Borrow the tagged digest.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl CanonicalCodec for PairingProofId {
    const RESOURCE: &'static str = "pairing possession proof identifier bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

struct PairingSecretReveal(Zeroizing<[u8; 32]>);

impl PairingSecretReveal {
    fn commitment(&self) -> Digest {
        derive_digest(PAIRING_SECRET_COMMITMENT_CONTEXT, &self.0[..])
    }
}

impl fmt::Debug for PairingSecretReveal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSecretReveal(<redacted>)")
    }
}

impl Serialize for PairingSecretReveal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (*self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PairingSecretReveal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(Zeroizing::new(<[u8; 32]>::deserialize(deserializer)?)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PairingProofMac([u8; 32]);

/// Complete proof of every proposed-device private key role and ticket secret.
///
/// The revealed committed secret is transient protocol material. It and its containing proof are
/// intentionally not `Copy` or `Clone`, and the bytes are erased when dropped.
pub struct PairingPossessionProof {
    protocol_version: ProtocolVersion,
    transcript_id: PairingTranscriptId,
    random_secret: PairingSecretReveal,
    application_signature: ProtocolSignature,
    endpoint_signature: ProtocolSignature,
    agreement_mac: PairingProofMac,
    pairing_ephemeral_mac: PairingProofMac,
    extensions: Extensions,
}

impl PairingPossessionProof {
    /// Build all possession responses for one exact transcript.
    pub fn create(
        transcript: &PairingTranscript,
        ticket_secrets: &PairingTicketSecrets,
        agreement_secret: &AgreementSecretKey,
        application_signature: ProtocolSignature,
        endpoint_signature: ProtocolSignature,
    ) -> Result<Self, IdentityError> {
        if ticket_secrets.ticket_id != transcript.ticket_id
            || ticket_secrets.random_secret.commitment() != transcript.random_secret_commitment
            || ticket_secrets.ephemeral_secret.public_key()?
                != transcript.pairing_ephemeral_public_key
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing ticket secret proof subjects",
            });
        }
        if agreement_secret.public_key()? != transcript.proposed_device.agreement_key() {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing agreement secret proof subject",
            });
        }
        let agreement_shared =
            agreement_secret.diffie_hellman(transcript.connection_ephemeral_public_key)?;
        let ephemeral_shared = ticket_secrets
            .ephemeral_secret
            .diffie_hellman(transcript.connection_ephemeral_public_key)?;
        let transcript_bytes = transcript.to_canonical_bytes()?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            transcript_id: transcript.transcript_id()?,
            random_secret: PairingSecretReveal(Zeroizing::new(*ticket_secrets.random_secret.0)),
            application_signature,
            endpoint_signature,
            agreement_mac: PairingProofMac(derive_possession_mac(
                &agreement_shared,
                AGREEMENT_PROOF_KEY_CONTEXT,
                AGREEMENT_POSSESSION_DOMAIN,
                transcript.proposed_device.agreement_key(),
                transcript.connection_ephemeral_public_key,
                &transcript_bytes,
            )?),
            pairing_ephemeral_mac: PairingProofMac(derive_possession_mac(
                &ephemeral_shared,
                EPHEMERAL_PROOF_KEY_CONTEXT,
                EPHEMERAL_POSSESSION_DOMAIN,
                transcript.pairing_ephemeral_public_key,
                transcript.connection_ephemeral_public_key,
                &transcript_bytes,
            )?),
            extensions: Extensions::default(),
        })
    }

    /// Identifier of the complete proof, including all four role responses.
    pub fn proof_id(&self) -> Result<PairingProofId, IdentityError> {
        Ok(PairingProofId(derive_digest(
            PAIRING_PROOF_ID_CONTEXT,
            &self.to_canonical_bytes()?,
        )))
    }

    /// Exact transcript identifier bound by all four possession responses.
    pub const fn transcript_id(&self) -> PairingTranscriptId {
        self.transcript_id
    }

    /// Proposed-device application-key signature response.
    pub const fn application_signature(&self) -> ProtocolSignature {
        self.application_signature
    }

    /// Proposed-device endpoint-key signature response.
    pub const fn endpoint_signature(&self) -> ProtocolSignature {
        self.endpoint_signature
    }

    /// Proposed-device long-term agreement-key MAC response.
    pub const fn agreement_mac(&self) -> &[u8; 32] {
        &self.agreement_mac.0
    }

    /// Ticket-ephemeral agreement-key MAC response.
    pub const fn pairing_ephemeral_mac(&self) -> &[u8; 32] {
        &self.pairing_ephemeral_mac.0
    }
}

impl fmt::Debug for PairingPossessionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingPossessionProof")
            .field("transcript_id", &self.transcript_id)
            .field("responses", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Serialize for PairingPossessionProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(8)?;
        tuple.serialize_element(&self.protocol_version)?;
        tuple.serialize_element(&self.transcript_id)?;
        tuple.serialize_element(&self.random_secret)?;
        tuple.serialize_element(&self.application_signature)?;
        tuple.serialize_element(&self.endpoint_signature)?;
        tuple.serialize_element(&self.agreement_mac)?;
        tuple.serialize_element(&self.pairing_ephemeral_mac)?;
        tuple.serialize_element(&self.extensions)?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for PairingPossessionProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (
            protocol_version,
            transcript_id,
            random_secret,
            application_signature,
            endpoint_signature,
            agreement_mac,
            pairing_ephemeral_mac,
            extensions,
        ) = <(
            ProtocolVersion,
            PairingTranscriptId,
            PairingSecretReveal,
            ProtocolSignature,
            ProtocolSignature,
            PairingProofMac,
            PairingProofMac,
            Extensions,
        )>::deserialize(deserializer)?;
        if protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: protocol_version.get(),
            }));
        }
        extensions
            .validate_critical(&[])
            .map_err(de::Error::custom)?;
        if !extensions.as_slice().is_empty() {
            return Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "pairing possession proof extensions",
            }));
        }
        Ok(Self {
            protocol_version,
            transcript_id,
            random_secret,
            application_signature,
            endpoint_signature,
            agreement_mac,
            pairing_ephemeral_mac,
            extensions,
        })
    }
}

impl CanonicalCodec for PairingPossessionProof {
    const RESOURCE: &'static str = "pairing possession proof bytes";
    const MAX_ENCODED_BYTES: usize = MAX_PAIRING_TICKET_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Six decimal digits derived from one complete transcript identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct ShortAuthString([u8; 6]);

impl ShortAuthString {
    /// Validate six exact ASCII decimal digits.
    pub fn new(digits: [u8; 6]) -> Result<Self, IdentityError> {
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(IdentityError::InvalidEncoding);
        }
        Ok(Self(digits))
    }

    fn derive(transcript_id: PairingTranscriptId) -> Result<Self, IdentityError> {
        let bytes = transcript_id.0.as_bytes();
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
        let mut remainder = value;
        let mut digits = [b'0'; 6];
        for index in (0..digits.len()).rev() {
            let digit =
                u8::try_from(remainder % 10).map_err(|_| IdentityError::ArithmeticOverflow {
                    resource: "pairing short-auth digit",
                })?;
            digits[index] = b'0' + digit;
            remainder /= 10;
        }
        Ok(Self(digits))
    }

    /// Exact six ASCII decimal digits.
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Debug for ShortAuthString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ShortAuthString({self})")
    }
}

impl fmt::Display for ShortAuthString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for digit in self.0 {
            fmt::Write::write_char(formatter, char::from(digit))?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ShortAuthString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 6]>::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ShortAuthString {
    const RESOURCE: &'static str = "pairing short-auth string bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Side providing one independently observed short-auth value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfirmationParticipant {
    /// Existing account controller.
    Controller,
    /// Proposed device.
    ProposedDevice,
}

/// Exact transcript-bound confirmation observation from one participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingConfirmation {
    participant: ConfirmationParticipant,
    transcript_id: PairingTranscriptId,
    observed_short_auth: ShortAuthString,
    confirmed_at: Timestamp,
    endpoint_signature: ProtocolSignature,
}

/// Immutable context retained in the resulting non-authoritative proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PairingConfirmationContext {
    transcript_id: PairingTranscriptId,
    short_auth: ShortAuthString,
    controller_confirmed_at: Timestamp,
    proposed_device_confirmed_at: Timestamp,
}

impl PairingConfirmationContext {
    /// Exact transcript confirmed on both devices.
    pub const fn transcript_id(self) -> PairingTranscriptId {
        self.transcript_id
    }

    /// Transcript-derived value observed on both devices.
    pub const fn short_auth(self) -> ShortAuthString {
        self.short_auth
    }

    fn validate(self) -> Result<Self, IdentityError> {
        if self.short_auth != ShortAuthString::derive(self.transcript_id)? {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing confirmation short-auth transcript",
            });
        }
        Ok(self)
    }
}

impl<'de> Deserialize<'de> for PairingConfirmationContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (transcript_id, short_auth, controller_confirmed_at, proposed_device_confirmed_at) =
            <(PairingTranscriptId, ShortAuthString, Timestamp, Timestamp)>::deserialize(
                deserializer,
            )?;
        Self {
            transcript_id,
            short_auth,
            controller_confirmed_at,
            proposed_device_confirmed_at,
        }
        .validate()
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for PairingConfirmationContext {
    const RESOURCE: &'static str = "pairing confirmation context bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Typestate for an accepted but not connected ticket.
#[derive(Debug)]
pub struct Issued;

/// Typestate for an authenticated transport connection with a frozen transcript.
#[derive(Debug)]
pub struct Connected {
    transcript: PairingTranscript,
    connection_secret: ConnectionEphemeralSecret,
}

/// Typestate after every proposed-device key role has been proven.
#[derive(Debug)]
pub struct Proven {
    transcript: PairingTranscript,
    transcript_id: PairingTranscriptId,
    proof_id: PairingProofId,
    short_auth: ShortAuthString,
}

/// Typestate after exact two-sided transcript confirmation.
#[derive(Debug)]
pub struct Confirmed {
    transcript: PairingTranscript,
    proof_id: PairingProofId,
    confirmation: PairingConfirmationContext,
}

/// Terminal typestate after durable one-time consumption and proposal construction.
#[derive(Debug)]
pub struct Consumed {
    proposal: DeviceAuthorizationProposal,
}

/// Terminal typestate for an expired ticket. It exposes no proposal transition.
#[derive(Debug)]
pub struct Expired;

/// Terminal typestate for an explicitly cancelled or mismatched ceremony.
#[derive(Debug)]
pub struct Cancelled;

/// Pairing ceremony whose available transitions are controlled by `State`.
///
/// A proposal cannot be extracted before durable consumption:
///
/// ```compile_fail
/// use krikos_identity::{Confirmed, PairingCeremony};
///
/// fn proposal_too_early(confirmed: PairingCeremony<Confirmed>) {
///     let _proposal = confirmed.into_proposal();
/// }
/// ```
#[derive(Debug)]
pub struct PairingCeremony<State> {
    ticket: PairingTicket,
    state: State,
}

/// Result of classifying one accepted ticket at an explicit time.
#[derive(Debug)]
pub enum PairingAdmission {
    /// Ticket is within its validity interval.
    Issued(PairingCeremony<Issued>),
    /// Ticket is already expired and terminal.
    Expired(PairingCeremony<Expired>),
}

impl PairingCeremony<Issued> {
    /// Validate explicit acceptance time and durable replay state.
    ///
    /// Observing an expired ticket durably consumes it before returning [`PairingAdmission::Expired`].
    /// Callers must use the same durable store across process restarts.
    pub fn accept<S: PairingNonceStore>(
        ticket: PairingTicket,
        store: &mut S,
        now: Timestamp,
    ) -> Result<PairingAdmission, PairingConsumeError<S::Error>> {
        let future_skew = u64::try_from(MAX_FUTURE_CLOCK_SKEW.as_millis()).map_err(|_| {
            PairingConsumeError::Protocol(IdentityError::ArithmeticOverflow {
                resource: "pairing future clock skew milliseconds",
            })
        })?;
        let maximum_issue_time = now
            .checked_add(crate::DurationMillis::new(future_skew))
            .map_err(PairingConsumeError::Protocol)?;
        if ticket.issued_at > maximum_issue_time {
            return Err(PairingConsumeError::Protocol(
                IdentityError::InvalidRelationship {
                    resource: "pairing ticket future issue time",
                },
            ));
        }
        let ticket_id = ticket.ticket_id().map_err(PairingConsumeError::Protocol)?;
        let key = PairingNonceKey {
            account_id: ticket.account_id,
            ticket_id,
            nonce: ticket.nonce,
        };
        if store.is_consumed(key).map_err(PairingConsumeError::Store)? {
            return Err(PairingConsumeError::AlreadyConsumed);
        }
        if now > ticket.expires_at {
            match store
                .consume_atomically(key, ticket.expires_at)
                .map_err(PairingConsumeError::Store)?
            {
                NonceConsumeResult::Consumed => {}
                NonceConsumeResult::AlreadyConsumed => {
                    return Err(PairingConsumeError::AlreadyConsumed);
                }
            }
            return Ok(PairingAdmission::Expired(PairingCeremony {
                ticket,
                state: Expired,
            }));
        }
        Ok(PairingAdmission::Issued(Self {
            ticket,
            state: Issued,
        }))
    }

    /// Bind an explicit authenticated transport and verifier ephemeral secret.
    pub fn connect(
        self,
        controller_device: DeviceDescriptor,
        transport: AuthenticatedTransportBinding,
        verifier_challenge: PairingChallenge,
        connection_secret: ConnectionEphemeralSecret,
    ) -> Result<PairingCeremony<Connected>, IdentityError> {
        let connection_public = connection_secret.public_key()?;
        let transcript = PairingTranscript::new(
            &self.ticket,
            controller_device,
            transport,
            verifier_challenge,
            connection_public,
        )?;
        Ok(PairingCeremony {
            ticket: self.ticket,
            state: Connected {
                transcript,
                connection_secret,
            },
        })
    }

    /// Explicitly cancel before connection.
    pub fn cancel(self) -> PairingCeremony<Cancelled> {
        self.into_cancelled()
    }
}

impl PairingCeremony<Connected> {
    /// Complete transcript supplied to the proposed device for proof construction.
    pub const fn transcript(&self) -> &PairingTranscript {
        &self.state.transcript
    }

    /// Verify all four possession subjects and enter proven state.
    pub fn verify_possession(
        self,
        proof: PairingPossessionProof,
    ) -> Result<PairingCeremony<Proven>, IdentityError> {
        let expected_transcript_id = self.state.transcript.transcript_id()?;
        if proof.transcript_id != expected_transcript_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "pairing possession transcript",
            });
        }
        if proof.random_secret.commitment() != self.state.transcript.random_secret_commitment {
            return Err(IdentityError::InvalidProof);
        }
        verify_signature(
            self.state
                .transcript
                .proposed_device
                .application_signing_key(),
            &self
                .state
                .transcript
                .application_possession_signing_bytes()?,
            proof.application_signature,
        )?;
        verify_signature(
            self.state
                .transcript
                .proposed_device
                .endpoint_key()
                .as_signing_key(),
            &self.state.transcript.endpoint_possession_signing_bytes()?,
            proof.endpoint_signature,
        )?;
        let transcript_bytes = self.state.transcript.to_canonical_bytes()?;
        let agreement_shared = self
            .state
            .connection_secret
            .diffie_hellman(self.state.transcript.proposed_device.agreement_key())?;
        let expected_agreement_mac = derive_possession_mac(
            &agreement_shared,
            AGREEMENT_PROOF_KEY_CONTEXT,
            AGREEMENT_POSSESSION_DOMAIN,
            self.state.transcript.proposed_device.agreement_key(),
            self.state.transcript.connection_ephemeral_public_key,
            &transcript_bytes,
        )?;
        verify_mac(proof.agreement_mac.0, expected_agreement_mac)?;
        let ephemeral_shared = self
            .state
            .connection_secret
            .diffie_hellman(self.state.transcript.pairing_ephemeral_public_key)?;
        let expected_ephemeral_mac = derive_possession_mac(
            &ephemeral_shared,
            EPHEMERAL_PROOF_KEY_CONTEXT,
            EPHEMERAL_POSSESSION_DOMAIN,
            self.state.transcript.pairing_ephemeral_public_key,
            self.state.transcript.connection_ephemeral_public_key,
            &transcript_bytes,
        )?;
        verify_mac(proof.pairing_ephemeral_mac.0, expected_ephemeral_mac)?;
        let proof_id = proof.proof_id()?;
        let short_auth = ShortAuthString::derive(expected_transcript_id)?;
        Ok(PairingCeremony {
            ticket: self.ticket,
            state: Proven {
                transcript: self.state.transcript,
                transcript_id: expected_transcript_id,
                proof_id,
                short_auth,
            },
        })
    }

    /// Explicitly cancel after connection.
    pub fn cancel(self) -> PairingCeremony<Cancelled> {
        self.into_cancelled()
    }
}

/// Result of exact short-auth confirmation.
#[derive(Debug)]
pub enum PairingConfirmationOutcome {
    /// Both participant observations match the transcript-derived value.
    Confirmed(Box<PairingCeremony<Confirmed>>),
    /// A mismatch or invalid confirmation context terminally cancelled the ceremony.
    Cancelled(Box<PairingCeremony<Cancelled>>),
}

impl PairingCeremony<Proven> {
    /// Transcript-derived short authentication string displayed on both devices.
    pub const fn short_auth_string(&self) -> ShortAuthString {
        self.state.short_auth
    }

    /// Exact bytes one participant's endpoint key signs after independent SAS confirmation.
    pub fn confirmation_signing_bytes(
        &self,
        participant: ConfirmationParticipant,
        observed_short_auth: ShortAuthString,
        confirmed_at: Timestamp,
    ) -> Result<Vec<u8>, IdentityError> {
        pairing_confirmation_signing_bytes(
            participant,
            self.state.transcript_id,
            observed_short_auth,
            confirmed_at,
        )
    }

    /// Attach one participant's endpoint-key signature to an exact SAS observation.
    pub const fn signed_confirmation(
        &self,
        participant: ConfirmationParticipant,
        observed_short_auth: ShortAuthString,
        confirmed_at: Timestamp,
        endpoint_signature: ProtocolSignature,
    ) -> PairingConfirmation {
        PairingConfirmation {
            participant,
            transcript_id: self.state.transcript_id,
            observed_short_auth,
            confirmed_at,
            endpoint_signature,
        }
    }

    /// Compare two exact side-specific confirmations and enter confirmed or cancelled state.
    pub fn confirm(
        self,
        controller: PairingConfirmation,
        proposed_device: PairingConfirmation,
    ) -> PairingConfirmationOutcome {
        let transcript_id = self.state.transcript_id;
        let context_valid = controller.participant == ConfirmationParticipant::Controller
            && proposed_device.participant == ConfirmationParticipant::ProposedDevice
            && controller.transcript_id == transcript_id
            && proposed_device.transcript_id == transcript_id
            && controller.observed_short_auth == self.state.short_auth
            && proposed_device.observed_short_auth == self.state.short_auth
            && controller.confirmed_at >= self.ticket.issued_at
            && proposed_device.confirmed_at >= self.ticket.issued_at
            && controller.confirmed_at <= self.ticket.expires_at
            && proposed_device.confirmed_at <= self.ticket.expires_at;
        if !context_valid
            || !confirmation_signature_is_valid(
                &controller,
                self.state
                    .transcript
                    .controller_device
                    .endpoint_key()
                    .as_signing_key(),
            )
            || !confirmation_signature_is_valid(
                &proposed_device,
                self.state
                    .transcript
                    .proposed_device
                    .endpoint_key()
                    .as_signing_key(),
            )
        {
            return PairingConfirmationOutcome::Cancelled(Box::new(self.into_cancelled()));
        }
        PairingConfirmationOutcome::Confirmed(Box::new(PairingCeremony {
            ticket: self.ticket,
            state: Confirmed {
                transcript: self.state.transcript,
                proof_id: self.state.proof_id,
                confirmation: PairingConfirmationContext {
                    transcript_id,
                    short_auth: self.state.short_auth,
                    controller_confirmed_at: controller.confirmed_at,
                    proposed_device_confirmed_at: proposed_device.confirmed_at,
                },
            },
        }))
    }

    /// Explicitly cancel after possession proof.
    pub fn cancel(self) -> PairingCeremony<Cancelled> {
        self.into_cancelled()
    }
}

/// Immutable nonce-store key durably tombstoned before proposal construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PairingNonceKey {
    account_id: AccountId,
    ticket_id: PairingTicketId,
    nonce: PairingNonce,
}

impl PairingNonceKey {
    /// Derive the complete durable tombstone key from one validated ticket.
    pub fn for_ticket(ticket: &PairingTicket) -> Result<Self, IdentityError> {
        Ok(Self {
            account_id: ticket.account_id,
            ticket_id: ticket.ticket_id()?,
            nonce: ticket.nonce,
        })
    }

    /// Account whose durable nonce namespace is used.
    pub const fn account_id(self) -> AccountId {
        self.account_id
    }

    /// Exact consumed ticket identifier.
    pub const fn ticket_id(self) -> PairingTicketId {
        self.ticket_id
    }

    /// Exact ticket nonce.
    pub const fn nonce(self) -> PairingNonce {
        self.nonce
    }
}

/// Outcome of one atomic durable nonce insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceConsumeResult {
    /// This call durably inserted the one-time tombstone.
    Consumed,
    /// A durable tombstone already exists, including after process restart.
    AlreadyConsumed,
}

/// Durable one-time pairing nonce boundary.
///
/// Implementations must atomically check and durably insert the complete record before returning
/// [`NonceConsumeResult::Consumed`]. A crash or error may not report success. Tombstones must
/// remain effective after restart; `expires_at` is compaction metadata and must never enable a
/// previously observed ticket again.
pub trait PairingNonceStore {
    /// Storage-specific error.
    type Error;

    /// Check whether one exact ticket key already has a durable tombstone.
    fn is_consumed(&mut self, key: PairingNonceKey) -> Result<bool, Self::Error>;

    /// Atomically check and durably consume one exact ticket key.
    ///
    /// `expires_at` is explicit retention/compaction metadata, not part of the equality key.
    fn consume_atomically(
        &mut self,
        key: PairingNonceKey,
        expires_at: Timestamp,
    ) -> Result<NonceConsumeResult, Self::Error>;
}

/// Failure before a proposal can be returned from durable consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingConsumeError<E> {
    /// Atomic persistence failed; no proposal was constructed or returned.
    Store(E),
    /// Durable state proves the ticket was already consumed or expired.
    AlreadyConsumed,
    /// Proposal construction failed after safe nonce consumption.
    Protocol(IdentityError),
}

/// Successful durable consumption outcome.
#[derive(Debug)]
pub enum PairingConsumeOutcome {
    /// Ticket was live and produced a non-authoritative authorization proposal.
    Consumed(Box<PairingCeremony<Consumed>>),
    /// Ticket was expired; the durable nonce tombstone was still written first.
    Expired(Box<PairingCeremony<Expired>>),
}

impl PairingCeremony<Confirmed> {
    /// Durably consume first, then and only then construct an authorization proposal.
    pub fn consume<S: PairingNonceStore>(
        self,
        store: &mut S,
        now: Timestamp,
    ) -> Result<PairingConsumeOutcome, PairingConsumeError<S::Error>> {
        let ticket_id = self
            .ticket
            .ticket_id()
            .map_err(PairingConsumeError::Protocol)?;
        let key = PairingNonceKey {
            account_id: self.ticket.account_id,
            ticket_id,
            nonce: self.ticket.nonce,
        };
        match store
            .consume_atomically(key, self.ticket.expires_at)
            .map_err(PairingConsumeError::Store)?
        {
            NonceConsumeResult::AlreadyConsumed => {
                return Err(PairingConsumeError::AlreadyConsumed);
            }
            NonceConsumeResult::Consumed => {}
        }
        if now > self.ticket.expires_at {
            return Ok(PairingConsumeOutcome::Expired(Box::new(PairingCeremony {
                ticket: self.ticket,
                state: Expired,
            })));
        }
        let transcript_id = self
            .state
            .transcript
            .transcript_id()
            .map_err(PairingConsumeError::Protocol)?;
        let proposal = DeviceAuthorizationProposal::from_confirmed_pairing(
            self.ticket.account_id,
            self.ticket.proposed_device.clone(),
            self.ticket.proposed_device_id,
            ticket_id,
            transcript_id,
            self.state.proof_id,
            self.state.confirmation,
        )
        .map_err(PairingConsumeError::Protocol)?;
        Ok(PairingConsumeOutcome::Consumed(Box::new(PairingCeremony {
            ticket: self.ticket,
            state: Consumed { proposal },
        })))
    }

    /// Explicitly cancel after confirmation and before durable consumption.
    pub fn cancel(self) -> PairingCeremony<Cancelled> {
        self.into_cancelled()
    }
}

impl PairingCeremony<Consumed> {
    /// Consume the terminal ceremony and return its non-authoritative proposal.
    pub fn into_proposal(self) -> DeviceAuthorizationProposal {
        self.state.proposal
    }
}

impl<State> PairingCeremony<State> {
    /// Exact ticket carried through every typestate.
    pub const fn ticket(&self) -> &PairingTicket {
        &self.ticket
    }

    fn into_cancelled(self) -> PairingCeremony<Cancelled> {
        PairingCeremony {
            ticket: self.ticket,
            state: Cancelled,
        }
    }
}

fn domain_message(domain: &[u8], body: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let capacity = domain
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(body.len()))
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "pairing domain-separated message bytes",
        })?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(body);
    Ok(message)
}

fn pairing_confirmation_signing_bytes(
    participant: ConfirmationParticipant,
    transcript_id: PairingTranscriptId,
    observed_short_auth: ShortAuthString,
    confirmed_at: Timestamp,
) -> Result<Vec<u8>, IdentityError> {
    let body = encode_wire(&(
        ProtocolVersion::V1,
        participant,
        transcript_id,
        observed_short_auth,
        confirmed_at,
    ))?;
    domain_message(PAIRING_CONFIRMATION_DOMAIN, &body)
}

fn confirmation_signature_is_valid(
    confirmation: &PairingConfirmation,
    public_key: crate::SigningPublicKey,
) -> bool {
    let Ok(message) = pairing_confirmation_signing_bytes(
        confirmation.participant,
        confirmation.transcript_id,
        confirmation.observed_short_auth,
        confirmation.confirmed_at,
    ) else {
        return false;
    };
    verify_signature(public_key, &message, confirmation.endpoint_signature).is_ok()
}

fn derive_possession_mac(
    shared_secret: &SharedSecret,
    key_context: &'static str,
    message_domain: &[u8],
    subject_public_key: AgreementPublicKey,
    connection_public_key: AgreementPublicKey,
    transcript_bytes: &[u8],
) -> Result<[u8; 32], IdentityError> {
    validate_contributory(shared_secret)?;
    let mut material = Zeroizing::new([0_u8; 96]);
    material[..32].copy_from_slice(shared_secret.as_bytes());
    material[32..64].copy_from_slice(subject_public_key.as_bytes());
    material[64..].copy_from_slice(connection_public_key.as_bytes());
    let key = Zeroizing::new(blake3::derive_key(key_context, &material[..]));
    let message = domain_message(message_domain, transcript_bytes)?;
    Ok(*blake3::keyed_hash(&key, &message).as_bytes())
}

fn verify_signature(
    public_key: crate::SigningPublicKey,
    message: &[u8],
    signature: ProtocolSignature,
) -> Result<(), IdentityError> {
    let public_key = Ed25519PublicKey::from_bytes(public_key.as_bytes())
        .map_err(|_| IdentityError::InvalidSignature)?;
    let signature = Ed25519Signature::try_from(signature.as_bytes().as_slice())
        .map_err(|_| IdentityError::InvalidSignature)?;
    public_key
        .verify(message, &signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

fn verify_mac(actual: [u8; 32], expected: [u8; 32]) -> Result<(), IdentityError> {
    if blake3::Hash::from_bytes(actual) != blake3::Hash::from_bytes(expected) {
        return Err(IdentityError::InvalidProof);
    }
    Ok(())
}

fn validate_contributory(shared_secret: &SharedSecret) -> Result<(), IdentityError> {
    if !shared_secret.was_contributory() {
        return Err(IdentityError::InvalidPublicKey {
            kind: crate::AlgorithmKind::Agreement,
        });
    }
    Ok(())
}

impl PairingEphemeralSecret {
    fn diffie_hellman(
        &self,
        public_key: AgreementPublicKey,
    ) -> Result<SharedSecret, IdentityError> {
        let public_key = X25519PublicKey::from(*public_key.as_bytes());
        let shared_secret = self.0.diffie_hellman(&public_key);
        validate_contributory(&shared_secret)?;
        Ok(shared_secret)
    }
}
