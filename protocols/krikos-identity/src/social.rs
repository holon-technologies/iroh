//! Signed, non-authoritative social attestations and explicitly bounded trust hints.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountId, AlgorithmSignature, CheckpointId, Digest, Extensions, IdentityError,
    ProtocolVersion, SigningPublicKey, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_SOCIAL_ATTESTATION_BYTES, MAX_SOCIAL_TRANSITIVITY_DEPTH},
};

const SOCIAL_ATTESTATION_SIGNING_DOMAIN: &[u8] = b"KRIKOS-ID/social-attestation/v1";

/// Exact subject and issuer facts covered by one social statement.
///
/// A social attestation is only a hint or trust input. It never grants account,
/// recovery, storage, provider, or device authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocialAttestationBody {
    protocol_version: ProtocolVersion,
    issuer_account_id: AccountId,
    issuer_checkpoint_id: CheckpointId,
    issuer_signing_key: SigningPublicKey,
    subject_account_id: AccountId,
    subject_checkpoint_id: CheckpointId,
    subject_signing_key: SigningPublicKey,
    claim_digest: Digest,
    issued_at: Timestamp,
    expires_at: Option<Timestamp>,
    extensions: Extensions,
}

impl SocialAttestationBody {
    /// Construct one exact, optionally expiring social statement.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        issuer_account_id: AccountId,
        issuer_checkpoint_id: CheckpointId,
        issuer_signing_key: SigningPublicKey,
        subject_account_id: AccountId,
        subject_checkpoint_id: CheckpointId,
        subject_signing_key: SigningPublicKey,
        claim_digest: Digest,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_parts(
            issuer_account_id,
            issuer_checkpoint_id,
            issuer_signing_key,
            subject_account_id,
            subject_checkpoint_id,
            subject_signing_key,
            claim_digest,
            issued_at,
            expires_at,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        issuer_account_id: AccountId,
        issuer_checkpoint_id: CheckpointId,
        issuer_signing_key: SigningPublicKey,
        subject_account_id: AccountId,
        subject_checkpoint_id: CheckpointId,
        subject_signing_key: SigningPublicKey,
        claim_digest: Digest,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if issuer_account_id == subject_account_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "social attestation issuer and subject",
            });
        }
        if expires_at.is_some_and(|expiry| expiry <= issued_at) {
            return Err(IdentityError::InvalidRelationship {
                resource: "social attestation validity interval",
            });
        }
        extensions.validate_critical(&[])?;
        let body = Self {
            protocol_version: ProtocolVersion::V1,
            issuer_account_id,
            issuer_checkpoint_id,
            issuer_signing_key,
            subject_account_id,
            subject_checkpoint_id,
            subject_signing_key,
            claim_digest,
            issued_at,
            expires_at,
            extensions,
        };
        let encoded_len = encode_wire(&body)?.len();
        if encoded_len > MAX_SOCIAL_ATTESTATION_BYTES {
            return Err(IdentityError::limit(
                "social attestation body bytes",
                encoded_len,
                MAX_SOCIAL_ATTESTATION_BYTES,
            ));
        }
        Ok(body)
    }

    /// Domain-separated canonical bytes signed by the issuer.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        domain_message(SOCIAL_ATTESTATION_SIGNING_DOMAIN, &encode_wire(self)?)
    }

    /// Issuer account authenticated by the caller's verification context.
    pub const fn issuer_account_id(&self) -> AccountId {
        self.issuer_account_id
    }

    /// Exact issuer checkpoint authenticated by the caller.
    pub const fn issuer_checkpoint_id(&self) -> CheckpointId {
        self.issuer_checkpoint_id
    }

    /// Exact issuer key which signs this statement.
    pub const fn issuer_signing_key(&self) -> SigningPublicKey {
        self.issuer_signing_key
    }

    /// Subject account named by this statement.
    pub const fn subject_account_id(&self) -> AccountId {
        self.subject_account_id
    }

    /// Exact subject checkpoint named by this statement.
    pub const fn subject_checkpoint_id(&self) -> CheckpointId {
        self.subject_checkpoint_id
    }

    /// Exact subject key named by this statement.
    pub const fn subject_signing_key(&self) -> SigningPublicKey {
        self.subject_signing_key
    }

    /// Digest of the private or selectively disclosed claim.
    pub const fn claim_digest(&self) -> Digest {
        self.claim_digest
    }

    /// Explicit statement issuance time.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Optional exclusive statement expiry.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }
}

impl<'de> Deserialize<'de> for SocialAttestationBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            issuer_account_id: AccountId,
            issuer_checkpoint_id: CheckpointId,
            issuer_signing_key: SigningPublicKey,
            subject_account_id: AccountId,
            subject_checkpoint_id: CheckpointId,
            subject_signing_key: SigningPublicKey,
            claim_digest: Digest,
            issued_at: Timestamp,
            expires_at: Option<Timestamp>,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        Self::from_parts(
            wire.issuer_account_id,
            wire.issuer_checkpoint_id,
            wire.issuer_signing_key,
            wire.subject_account_id,
            wire.subject_checkpoint_id,
            wire.subject_signing_key,
            wire.claim_digest,
            wire.issued_at,
            wire.expires_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for SocialAttestationBody {
    const RESOURCE: &'static str = "social attestation body bytes";
    const MAX_ENCODED_BYTES: usize = MAX_SOCIAL_ATTESTATION_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// One issuer-signed social statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedSocialAttestation {
    body: SocialAttestationBody,
    issuer_signature: AlgorithmSignature,
}

impl SignedSocialAttestation {
    /// Verify and retain the exact issuer signature.
    pub fn try_new(
        body: SocialAttestationBody,
        issuer_signature: AlgorithmSignature,
    ) -> Result<Self, IdentityError> {
        verify_signature(
            body.issuer_signing_key,
            &issuer_signature,
            &body.signing_bytes()?,
        )?;
        let signed = Self {
            body,
            issuer_signature,
        };
        let encoded_len = encode_wire(&signed)?.len();
        if encoded_len > MAX_SOCIAL_ATTESTATION_BYTES {
            return Err(IdentityError::limit(
                "signed social attestation bytes",
                encoded_len,
                MAX_SOCIAL_ATTESTATION_BYTES,
            ));
        }
        Ok(signed)
    }

    /// Exact signed statement body.
    pub const fn body(&self) -> &SocialAttestationBody {
        &self.body
    }

    /// Typed issuer signature.
    pub const fn issuer_signature(&self) -> &AlgorithmSignature {
        &self.issuer_signature
    }
}

impl<'de> Deserialize<'de> for SignedSocialAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (body, issuer_signature) =
            <(SocialAttestationBody, AlgorithmSignature)>::deserialize(deserializer)?;
        Self::try_new(body, issuer_signature).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for SignedSocialAttestation {
    const RESOURCE: &'static str = "signed social attestation bytes";
    const MAX_ENCODED_BYTES: usize = MAX_SOCIAL_ATTESTATION_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Caller-supplied authoritative facts expected when checking an attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocialAttestationVerificationContext {
    issuer_account_id: AccountId,
    issuer_checkpoint_id: CheckpointId,
    issuer_signing_key: SigningPublicKey,
    subject_account_id: AccountId,
    subject_checkpoint_id: CheckpointId,
    subject_signing_key: SigningPublicKey,
    claim_digest: Digest,
    authority_time: Timestamp,
}

impl SocialAttestationVerificationContext {
    /// Construct exact caller-authenticated issuer, subject, claim, and time facts.
    #[allow(clippy::too_many_arguments)]
    pub const fn try_new(
        issuer_account_id: AccountId,
        issuer_checkpoint_id: CheckpointId,
        issuer_signing_key: SigningPublicKey,
        subject_account_id: AccountId,
        subject_checkpoint_id: CheckpointId,
        subject_signing_key: SigningPublicKey,
        claim_digest: Digest,
        authority_time: Timestamp,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            issuer_account_id,
            issuer_checkpoint_id,
            issuer_signing_key,
            subject_account_id,
            subject_checkpoint_id,
            subject_signing_key,
            claim_digest,
            authority_time,
        })
    }
}

/// A cryptographically checked social statement that grants no authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSocialAttestation {
    body: SocialAttestationBody,
    authority_time: Timestamp,
}

impl VerifiedSocialAttestation {
    /// Issuer account at the authenticated checkpoint and key.
    pub const fn issuer_account_id(&self) -> AccountId {
        self.body.issuer_account_id
    }

    /// Exact issuer checkpoint.
    pub const fn issuer_checkpoint_id(&self) -> CheckpointId {
        self.body.issuer_checkpoint_id
    }

    /// Exact issuer signing key.
    pub const fn issuer_signing_key(&self) -> SigningPublicKey {
        self.body.issuer_signing_key
    }

    /// Subject account named by the checked statement.
    pub const fn subject_account_id(&self) -> AccountId {
        self.body.subject_account_id
    }

    /// Exact subject checkpoint.
    pub const fn subject_checkpoint_id(&self) -> CheckpointId {
        self.body.subject_checkpoint_id
    }

    /// Exact subject signing key.
    pub const fn subject_signing_key(&self) -> SigningPublicKey {
        self.body.subject_signing_key
    }

    /// Claim digest shared by a valid trust chain.
    pub const fn claim_digest(&self) -> Digest {
        self.body.claim_digest
    }

    /// Exact caller-authenticated time basis at which this fact was verified.
    pub const fn authority_time(&self) -> Timestamp {
        self.authority_time
    }

    /// Inclusive start of the signed validity interval.
    pub const fn issued_at(&self) -> Timestamp {
        self.body.issued_at
    }

    /// Optional exclusive end of the signed validity interval.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.body.expires_at
    }

    fn valid_at(&self, authority_time: Timestamp) -> bool {
        authority_time >= self.issued_at()
            && self
                .expires_at()
                .is_none_or(|expiry| authority_time < expiry)
    }
}

/// Verify one social statement against caller-authenticated exact facts and explicit time.
pub fn verify_social_attestation(
    attestation: &SignedSocialAttestation,
    context: &SocialAttestationVerificationContext,
) -> Result<VerifiedSocialAttestation, IdentityError> {
    let body = attestation.body();
    if body.issuer_account_id != context.issuer_account_id
        || body.issuer_checkpoint_id != context.issuer_checkpoint_id
        || body.issuer_signing_key != context.issuer_signing_key
        || body.subject_account_id != context.subject_account_id
        || body.subject_checkpoint_id != context.subject_checkpoint_id
        || body.subject_signing_key != context.subject_signing_key
        || body.claim_digest != context.claim_digest
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "social attestation verification context",
        });
    }
    if context.authority_time < body.issued_at
        || body
            .expires_at
            .is_some_and(|expiry| context.authority_time >= expiry)
    {
        return Err(IdentityError::StaleEvidence);
    }
    verify_signature(
        body.issuer_signing_key,
        attestation.issuer_signature(),
        &body.signing_bytes()?,
    )?;
    Ok(VerifiedSocialAttestation {
        body: body.clone(),
        authority_time: context.authority_time,
    })
}

/// Explicit policy for following social-attestation chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SocialTransitivityPolicy {
    mode: TransitivityMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum TransitivityMode {
    #[default]
    Disabled,
    Bounded {
        max_depth: u8,
    },
}

impl SocialTransitivityPolicy {
    /// Enable transitivity with a nonzero protocol-bounded maximum depth.
    pub fn bounded(max_depth: u8) -> Result<Self, IdentityError> {
        if max_depth == 0 || usize::from(max_depth) > MAX_SOCIAL_TRANSITIVITY_DEPTH {
            return Err(IdentityError::limit(
                "social transitivity depth",
                usize::from(max_depth),
                MAX_SOCIAL_TRANSITIVITY_DEPTH,
            ));
        }
        Ok(Self {
            mode: TransitivityMode::Bounded { max_depth },
        })
    }
}

/// Non-authoritative result of explicitly following a checked social chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocialTrustHint {
    issuer_account_id: AccountId,
    subject_account_id: AccountId,
    claim_digest: Digest,
    depth: u8,
    authority_time: Timestamp,
}

impl SocialTrustHint {
    /// First issuer in the checked chain.
    pub const fn issuer_account_id(self) -> AccountId {
        self.issuer_account_id
    }

    /// Final subject reached by the checked chain.
    pub const fn subject_account_id(self) -> AccountId {
        self.subject_account_id
    }

    /// Exact claim digest shared by every edge.
    pub const fn claim_digest(self) -> Digest {
        self.claim_digest
    }

    /// Number of signed edges followed.
    pub const fn depth(self) -> u8 {
        self.depth
    }

    /// Exact common authority-time basis shared by every edge in this hint.
    pub const fn authority_time(self) -> Timestamp {
        self.authority_time
    }
}

/// Follow an ordered social chain verified at one explicit common authority time.
pub fn evaluate_social_trust(
    attestations: &[VerifiedSocialAttestation],
    policy: SocialTransitivityPolicy,
    authority_time: Timestamp,
) -> Result<SocialTrustHint, IdentityError> {
    let first = attestations.first().ok_or(IdentityError::EmptyCollection {
        resource: "social attestation chain",
    })?;
    let depth = u8::try_from(attestations.len()).map_err(|_| {
        IdentityError::limit(
            "social transitivity depth",
            attestations.len(),
            MAX_SOCIAL_TRANSITIVITY_DEPTH,
        )
    })?;
    let permitted_depth = match policy.mode {
        TransitivityMode::Disabled => 1,
        TransitivityMode::Bounded { max_depth } => max_depth,
    };
    if depth > permitted_depth || usize::from(depth) > MAX_SOCIAL_TRANSITIVITY_DEPTH {
        return Err(IdentityError::limit(
            "social transitivity depth",
            usize::from(depth),
            usize::from(permitted_depth).min(MAX_SOCIAL_TRANSITIVITY_DEPTH),
        ));
    }

    for attestation in attestations {
        if !attestation.valid_at(authority_time) {
            return Err(IdentityError::StaleEvidence);
        }
        if attestation.authority_time() != authority_time {
            return Err(IdentityError::InvalidRelationship {
                resource: "social attestation common authority time",
            });
        }
    }

    let mut visited_accounts = BTreeSet::new();
    visited_accounts.insert(first.issuer_account_id());
    let mut prior = first;
    if !visited_accounts.insert(first.subject_account_id()) {
        return Err(IdentityError::InvalidRelationship {
            resource: "cyclic social attestation chain",
        });
    }
    for attestation in &attestations[1..] {
        if prior.subject_account_id() != attestation.issuer_account_id()
            || prior.subject_checkpoint_id() != attestation.issuer_checkpoint_id()
            || prior.subject_signing_key() != attestation.issuer_signing_key()
            || first.claim_digest() != attestation.claim_digest()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "social attestation chain",
            });
        }
        if !visited_accounts.insert(attestation.subject_account_id()) {
            return Err(IdentityError::InvalidRelationship {
                resource: "cyclic social attestation chain",
            });
        }
        prior = attestation;
    }

    Ok(SocialTrustHint {
        issuer_account_id: first.issuer_account_id(),
        subject_account_id: prior.subject_account_id(),
        claim_digest: first.claim_digest(),
        depth,
        authority_time,
    })
}

fn verify_signature(
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

fn domain_message(domain: &[u8], body: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let capacity = domain
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(body.len()))
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "social attestation signing bytes",
        })?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(body);
    Ok(message)
}
