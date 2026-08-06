//! Short-lived, exact-context device-presence challenge responses.

use std::fmt;

use krikos_base::{PublicKey as Ed25519PublicKey, Signature as Ed25519Signature};
use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountId, ApplicationAuthorizationView, ApplicationDeviceStatus, CanonicalWire, CheckpointId,
    DeviceId, Digest, Extensions, HashAlgorithm, IdentityError, ProtocolSignature, ProtocolVersion,
    SigningPublicKey, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_ACCOUNT_EVENT_BYTES, MAX_FUTURE_CLOCK_SKEW, MAX_PRESENCE_LIFETIME},
};

const PRESENCE_SIGNATURE_DOMAIN: &[u8] = b"KRIKOS-ID/device-presence-signature/v1";
const PRESENCE_PROOF_ID_CONTEXT: &str = "KRIKOS-ID/device-presence-proof-id/v1";

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
    PresenceVerifierChallenge,
    "presence verifier challenge",
    "PresenceVerifierChallenge(<redacted>)"
);
nonzero_bytes!(
    PresenceSessionId,
    "presence session identifier",
    "PresenceSessionId(<redacted>)"
);

fn validate_lifetime(issued_at: Timestamp, expires_at: Timestamp) -> Result<(), IdentityError> {
    let lifetime = expires_at
        .as_unix_millis()
        .checked_sub(issued_at.as_unix_millis())
        .ok_or(IdentityError::InvalidRelationship {
            resource: "presence proof validity interval",
        })?;
    if lifetime == 0 {
        return Err(IdentityError::ZeroValue {
            resource: "presence proof lifetime",
        });
    }
    if u128::from(lifetime) > MAX_PRESENCE_LIFETIME.as_millis() {
        return Err(IdentityError::LimitExceeded {
            resource: "presence proof lifetime milliseconds",
            actual: usize::try_from(lifetime).unwrap_or(usize::MAX),
            maximum: usize::try_from(MAX_PRESENCE_LIFETIME.as_millis()).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

/// Verifier-generated complete context to be signed by one exact device key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DevicePresenceChallenge {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    device_id: DeviceId,
    verifier_challenge: PresenceVerifierChallenge,
    session_id: PresenceSessionId,
    transcript_binding: Digest,
    checkpoint_id: CheckpointId,
    issued_at: Timestamp,
    expires_at: Timestamp,
    signing_key: SigningPublicKey,
    extensions: Extensions,
}

impl DevicePresenceChallenge {
    /// Construct a complete presence challenge with at most five minutes of validity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        device_id: DeviceId,
        verifier_challenge: PresenceVerifierChallenge,
        session_id: PresenceSessionId,
        transcript_binding: Digest,
        checkpoint_id: CheckpointId,
        issued_at: Timestamp,
        expires_at: Timestamp,
        signing_key: SigningPublicKey,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_lifetime(issued_at, expires_at)?;
        if transcript_binding.as_bytes() == &[0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "presence transcript binding",
            });
        }
        extensions.validate_critical(&[])?;
        let challenge = Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            device_id,
            verifier_challenge,
            session_id,
            transcript_binding,
            checkpoint_id,
            issued_at,
            expires_at,
            signing_key,
            extensions,
        };
        let encoded_len = encode_wire(&challenge)?.len();
        if encoded_len > MAX_ACCOUNT_EVENT_BYTES {
            return Err(IdentityError::limit(
                "device presence challenge bytes",
                encoded_len,
                MAX_ACCOUNT_EVENT_BYTES,
            ));
        }
        Ok(challenge)
    }

    /// Exact domain-separated bytes signed by the named device key.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let body = self.to_canonical_bytes()?;
        let capacity = PRESENCE_SIGNATURE_DOMAIN
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(body.len()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "presence signature message bytes",
            })?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(PRESENCE_SIGNATURE_DOMAIN);
        message.push(0);
        message.extend_from_slice(&body);
        Ok(message)
    }

    /// Account whose known checkpoint supplies authorization.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Device expected to sign.
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Fresh verifier challenge.
    pub const fn verifier_challenge(&self) -> PresenceVerifierChallenge {
        self.verifier_challenge
    }

    /// Single authenticated session identifier.
    pub const fn session_id(&self) -> PresenceSessionId {
        self.session_id
    }

    /// Exact higher-level connection transcript binding.
    pub const fn transcript_binding(&self) -> Digest {
        self.transcript_binding
    }

    /// Exact locally known authorization checkpoint.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Explicit challenge issue time.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Explicit proof expiry time.
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Exact authorized application-signing key expected to respond.
    pub const fn signing_key(&self) -> SigningPublicKey {
        self.signing_key
    }
}

impl<'de> Deserialize<'de> for DevicePresenceChallenge {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (
            protocol_version,
            account_id,
            device_id,
            verifier_challenge,
            session_id,
            transcript_binding,
            checkpoint_id,
            issued_at,
            expires_at,
            signing_key,
            extensions,
        ) = <(
            ProtocolVersion,
            AccountId,
            DeviceId,
            PresenceVerifierChallenge,
            PresenceSessionId,
            Digest,
            CheckpointId,
            Timestamp,
            Timestamp,
            SigningPublicKey,
            Extensions,
        )>::deserialize(deserializer)?;
        if protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: protocol_version.get(),
            }));
        }
        Self::new(
            account_id,
            device_id,
            verifier_challenge,
            session_id,
            transcript_binding,
            checkpoint_id,
            issued_at,
            expires_at,
            signing_key,
            extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for DevicePresenceChallenge {
    const RESOURCE: &'static str = "device presence challenge bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Complete signed response to one exact presence challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceProof {
    challenge: DevicePresenceChallenge,
    signature: ProtocolSignature,
}

impl PresenceProof {
    /// Construct a signed response. Cryptographic and state checks occur during verification.
    pub fn new(
        challenge: DevicePresenceChallenge,
        signature: ProtocolSignature,
    ) -> Result<Self, IdentityError> {
        let proof = Self {
            challenge,
            signature,
        };
        let encoded_len = encode_wire(&proof)?.len();
        if encoded_len > MAX_ACCOUNT_EVENT_BYTES {
            return Err(IdentityError::limit(
                "device presence proof bytes",
                encoded_len,
                MAX_ACCOUNT_EVENT_BYTES,
            ));
        }
        Ok(proof)
    }

    /// Exact challenge that was signed.
    pub const fn challenge(&self) -> &DevicePresenceChallenge {
        &self.challenge
    }

    /// Exact Ed25519 response signature.
    pub const fn signature(&self) -> ProtocolSignature {
        self.signature
    }

    /// Domain-separated identifier of the complete proof.
    pub fn proof_id(&self) -> Result<PresenceProofId, IdentityError> {
        Ok(PresenceProofId(Digest::new(
            HashAlgorithm::Blake3_256,
            blake3::derive_key(PRESENCE_PROOF_ID_CONTEXT, &self.to_canonical_bytes()?),
        )))
    }
}

impl CanonicalCodec for PresenceProof {
    const RESOURCE: &'static str = "device presence proof bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Domain-separated identifier of a complete signed presence proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PresenceProofId(Digest);

impl PresenceProofId {
    /// Borrow the tagged digest.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl CanonicalCodec for PresenceProofId {
    const RESOURCE: &'static str = "device presence proof identifier bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Verify exact-session liveness under one already-authenticated known checkpoint.
///
/// Success proves possession of the exact active device key in the caller-supplied checkpoint
/// view. It does not establish that checkpoint's global freshness, network reachability outside
/// this session, or continued authorization after the proof expires.
pub fn verify_presence_proof(
    proof: &PresenceProof,
    expected_challenge: &DevicePresenceChallenge,
    now: Timestamp,
    view: &impl ApplicationAuthorizationView,
) -> Result<PresenceProofId, IdentityError> {
    if proof.challenge != *expected_challenge {
        return Err(IdentityError::InvalidRelationship {
            resource: "presence expected challenge context",
        });
    }
    let future_skew = u64::try_from(MAX_FUTURE_CLOCK_SKEW.as_millis()).map_err(|_| {
        IdentityError::ArithmeticOverflow {
            resource: "presence future clock skew milliseconds",
        }
    })?;
    let maximum_issue_time = now.checked_add(crate::DurationMillis::new(future_skew))?;
    if proof.challenge.issued_at > maximum_issue_time {
        return Err(IdentityError::InvalidRelationship {
            resource: "presence proof future issue time",
        });
    }
    if now > proof.challenge.expires_at {
        return Err(IdentityError::StaleEvidence);
    }

    let context = view.authorization_context();
    if proof.challenge.account_id != context.account_id() {
        return Err(IdentityError::AccountMismatch);
    }
    if proof.challenge.checkpoint_id != context.checkpoint_id() {
        return Err(IdentityError::InvalidRelationship {
            resource: "presence authorization checkpoint",
        });
    }
    match view.device_status(proof.challenge.device_id) {
        ApplicationDeviceStatus::Unknown => return Err(IdentityError::DeviceNotAuthorized),
        ApplicationDeviceStatus::Active => {}
        ApplicationDeviceStatus::Suspended => return Err(IdentityError::DeviceSuspended),
        ApplicationDeviceStatus::Revoked => return Err(IdentityError::DeviceRevoked),
    }
    let authorization = view
        .device_authorization(proof.challenge.device_id)
        .ok_or(IdentityError::DeviceNotAuthorized)?;
    if authorization.device_id() != proof.challenge.device_id {
        return Err(IdentityError::InvalidIdentifier {
            resource: "presence authorized device",
        });
    }
    if authorization.authorization_epoch() > context.epoch() {
        return Err(IdentityError::InvalidEpoch);
    }
    if authorization.descriptor().application_signing_key() != proof.challenge.signing_key {
        return Err(IdentityError::InvalidRelationship {
            resource: "presence exact device signing key",
        });
    }

    let public_key = Ed25519PublicKey::from_bytes(proof.challenge.signing_key.as_bytes())
        .map_err(|_| IdentityError::InvalidSignature)?;
    let signature = Ed25519Signature::try_from(proof.signature.as_bytes().as_slice())
        .map_err(|_| IdentityError::InvalidSignature)?;
    public_key
        .verify(&proof.challenge.signing_bytes()?, &signature)
        .map_err(|_| IdentityError::InvalidSignature)?;
    proof.proof_id()
}
