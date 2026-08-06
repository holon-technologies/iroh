//! Untrusted name-resolution candidates, signed claims, and pure TOFU decisions.

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountId, AlgorithmSignature, CheckpointId, Extensions, IdentityError, ProtocolVersion,
    SigningPublicKey, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_NAME_CLAIM_BYTES, MAX_NAME_CLAIMS, MAX_NORMALIZED_NAME_BYTES},
    schema::BoundedVec,
};

const NAME_CLAIM_SIGNING_DOMAIN: &[u8] = b"KRIKOS-ID/name-claim/v1";

/// A bounded lowercase ASCII DNS-style name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct NormalizedName(String);

impl NormalizedName {
    /// Normalize and validate a name without ambiguous Unicode processing.
    pub fn try_new(value: &str) -> Result<Self, IdentityError> {
        if value.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "normalized name",
            });
        }
        if !value.is_ascii() || value.len() > MAX_NORMALIZED_NAME_BYTES {
            return Err(IdentityError::limit(
                "normalized name",
                value.len(),
                MAX_NORMALIZED_NAME_BYTES,
            ));
        }
        let normalized = value.to_ascii_lowercase();
        for label in normalized.split('.') {
            if label.is_empty()
                || label.len() > 63
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(IdentityError::InvalidEncoding);
            }
        }
        Ok(Self(normalized))
    }

    /// Canonical lowercase name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NormalizedName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_new(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for NormalizedName {
    const RESOURCE: &'static str = "normalized name bytes";
    const MAX_ENCODED_BYTES: usize = MAX_NORMALIZED_NAME_BYTES + 4;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Exact self-signed claim binding a normalized name to account authority facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NameClaimBody {
    protocol_version: ProtocolVersion,
    name: NormalizedName,
    subject_account_id: AccountId,
    subject_checkpoint_id: CheckpointId,
    subject_signing_key: SigningPublicKey,
    issued_at: Timestamp,
    expires_at: Option<Timestamp>,
    extensions: Extensions,
}

impl NameClaimBody {
    /// Construct an exact, optionally expiring name claim.
    pub fn try_new(
        name: NormalizedName,
        subject_account_id: AccountId,
        subject_checkpoint_id: CheckpointId,
        subject_signing_key: SigningPublicKey,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_parts(
            name,
            subject_account_id,
            subject_checkpoint_id,
            subject_signing_key,
            issued_at,
            expires_at,
            extensions,
        )
    }

    fn from_parts(
        name: NormalizedName,
        subject_account_id: AccountId,
        subject_checkpoint_id: CheckpointId,
        subject_signing_key: SigningPublicKey,
        issued_at: Timestamp,
        expires_at: Option<Timestamp>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if expires_at.is_some_and(|expiry| expiry <= issued_at) {
            return Err(IdentityError::InvalidRelationship {
                resource: "name claim validity interval",
            });
        }
        extensions.validate_critical(&[])?;
        let body = Self {
            protocol_version: ProtocolVersion::V1,
            name,
            subject_account_id,
            subject_checkpoint_id,
            subject_signing_key,
            issued_at,
            expires_at,
            extensions,
        };
        let encoded_len = encode_wire(&body)?.len();
        if encoded_len > MAX_NAME_CLAIM_BYTES {
            return Err(IdentityError::limit(
                "name claim body bytes",
                encoded_len,
                MAX_NAME_CLAIM_BYTES,
            ));
        }
        Ok(body)
    }

    /// Domain-separated canonical bytes signed by the subject key.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        domain_message(NAME_CLAIM_SIGNING_DOMAIN, &encode_wire(self)?)
    }

    /// Claimed canonical name.
    pub const fn name(&self) -> &NormalizedName {
        &self.name
    }

    /// Subject account bound to the name.
    pub const fn subject_account_id(&self) -> AccountId {
        self.subject_account_id
    }

    /// Exact subject checkpoint bound to the name.
    pub const fn subject_checkpoint_id(&self) -> CheckpointId {
        self.subject_checkpoint_id
    }

    /// Exact subject key which self-signs the claim.
    pub const fn subject_signing_key(&self) -> SigningPublicKey {
        self.subject_signing_key
    }

    /// Explicit claim issuance time.
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// Optional exclusive claim expiry.
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }
}

impl<'de> Deserialize<'de> for NameClaimBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            name: NormalizedName,
            subject_account_id: AccountId,
            subject_checkpoint_id: CheckpointId,
            subject_signing_key: SigningPublicKey,
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
            wire.name,
            wire.subject_account_id,
            wire.subject_checkpoint_id,
            wire.subject_signing_key,
            wire.issued_at,
            wire.expires_at,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for NameClaimBody {
    const RESOURCE: &'static str = "name claim body bytes";
    const MAX_ENCODED_BYTES: usize = MAX_NAME_CLAIM_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// A subject-signed name claim returned as untrusted resolver data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedNameClaim {
    body: NameClaimBody,
    subject_signature: AlgorithmSignature,
}

impl SignedNameClaim {
    /// Verify and retain one exact subject signature.
    pub fn try_new(
        body: NameClaimBody,
        subject_signature: AlgorithmSignature,
    ) -> Result<Self, IdentityError> {
        verify_signature(
            body.subject_signing_key,
            &subject_signature,
            &body.signing_bytes()?,
        )?;
        let claim = Self {
            body,
            subject_signature,
        };
        let encoded_len = encode_wire(&claim)?.len();
        if encoded_len > MAX_NAME_CLAIM_BYTES {
            return Err(IdentityError::limit(
                "signed name claim bytes",
                encoded_len,
                MAX_NAME_CLAIM_BYTES,
            ));
        }
        Ok(claim)
    }

    /// Exact signed claim body.
    pub const fn body(&self) -> &NameClaimBody {
        &self.body
    }

    /// Typed subject signature.
    pub const fn subject_signature(&self) -> &AlgorithmSignature {
        &self.subject_signature
    }
}

impl<'de> Deserialize<'de> for SignedNameClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (body, subject_signature) =
            <(NameClaimBody, AlgorithmSignature)>::deserialize(deserializer)?;
        Self::try_new(body, subject_signature).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for SignedNameClaim {
    const RESOURCE: &'static str = "signed name claim bytes";
    const MAX_ENCODED_BYTES: usize = MAX_NAME_CLAIM_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Bounded untrusted candidate set returned by a name resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameCandidateSet {
    candidates: BoundedVec<SignedNameClaim, MAX_NAME_CLAIMS>,
}

impl NameCandidateSet {
    /// Bound an untrusted resolver result before cryptographic processing.
    pub fn try_new(candidates: Vec<SignedNameClaim>) -> Result<Self, IdentityError> {
        Ok(Self {
            candidates: BoundedVec::new("name resolver candidates", candidates)?,
        })
    }

    /// Untrusted signed candidates awaiting caller-authoritative verification.
    pub fn as_slice(&self) -> &[SignedNameClaim] {
        self.candidates.as_slice()
    }
}

/// Synchronous untrusted name-resolution boundary.
pub trait NameResolver {
    /// Return candidate records only, respecting the supplied protocol maximum.
    ///
    /// Callers still enforce the bound because an untrusted implementation may ignore it.
    fn resolve(
        &self,
        name: &NormalizedName,
        maximum_candidates: usize,
    ) -> Result<Vec<SignedNameClaim>, IdentityError>;
}

/// Query an untrusted resolver and enforce the protocol candidate bound.
pub fn resolve_name_candidates<R: NameResolver + ?Sized>(
    resolver: &R,
    name: &NormalizedName,
) -> Result<NameCandidateSet, IdentityError> {
    NameCandidateSet::try_new(resolver.resolve(name, MAX_NAME_CLAIMS)?)
}

/// Caller-supplied authoritative account/checkpoint/key facts for one name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAuthorityContext {
    name: NormalizedName,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    signing_key: SigningPublicKey,
    authority_time: Timestamp,
}

impl NameAuthorityContext {
    /// Construct exact caller-authenticated facts without ambient lookup or time.
    pub const fn try_new(
        name: NormalizedName,
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        signing_key: SigningPublicKey,
        authority_time: Timestamp,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            name,
            account_id,
            checkpoint_id,
            signing_key,
            authority_time,
        })
    }
}

/// A name candidate verified against caller-authoritative exact facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNameClaim {
    body: NameClaimBody,
}

impl VerifiedNameClaim {
    /// Canonical verified name.
    pub const fn name(&self) -> &NormalizedName {
        &self.body.name
    }

    /// Verified subject account.
    pub const fn account_id(&self) -> AccountId {
        self.body.subject_account_id
    }

    /// Exact verified subject checkpoint.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.body.subject_checkpoint_id
    }

    /// Exact verified subject signing key.
    pub const fn signing_key(&self) -> SigningPublicKey {
        self.body.subject_signing_key
    }
}

/// Bounded list of candidates which matched caller-authoritative facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNameCandidates {
    candidates: BoundedVec<VerifiedNameClaim, MAX_NAME_CLAIMS>,
}

impl VerifiedNameCandidates {
    /// Verified candidates; this list grants no account authority.
    pub fn as_slice(&self) -> &[VerifiedNameClaim] {
        self.candidates.as_slice()
    }
}

/// Verify one candidate against exact caller-authenticated name and authority facts.
pub fn verify_name_claim(
    claim: &SignedNameClaim,
    context: &NameAuthorityContext,
) -> Result<VerifiedNameClaim, IdentityError> {
    let body = claim.body();
    if body.name != context.name
        || body.subject_account_id != context.account_id
        || body.subject_checkpoint_id != context.checkpoint_id
        || body.subject_signing_key != context.signing_key
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "name claim verification context",
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
        body.subject_signing_key,
        claim.subject_signature(),
        &body.signing_bytes()?,
    )?;
    Ok(VerifiedNameClaim { body: body.clone() })
}

/// Filter an untrusted candidate set through bounded caller-authoritative facts.
pub fn verify_name_candidates(
    candidates: &NameCandidateSet,
    contexts: &[NameAuthorityContext],
) -> Result<VerifiedNameCandidates, IdentityError> {
    if contexts.len() > MAX_NAME_CLAIMS {
        return Err(IdentityError::limit(
            "name authority contexts",
            contexts.len(),
            MAX_NAME_CLAIMS,
        ));
    }
    let verified = candidates
        .as_slice()
        .iter()
        .filter_map(|candidate| {
            contexts
                .iter()
                .find_map(|context| verify_name_claim(candidate, context).ok())
        })
        .collect();
    Ok(VerifiedNameCandidates {
        candidates: BoundedVec::new("verified name candidates", verified)?,
    })
}

/// Immutable trust-on-first-use observation selected by an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TofuObservation {
    name: NormalizedName,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    signing_key: SigningPublicKey,
}

impl TofuObservation {
    /// Canonical observed name.
    pub const fn name(&self) -> &NormalizedName {
        &self.name
    }

    /// Observed subject account.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact observed checkpoint.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Exact observed signing key.
    pub const fn signing_key(&self) -> SigningPublicKey {
        self.signing_key
    }
}

/// Pure TOFU comparison result; evaluating it never updates storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuDecision {
    /// No prior observation was supplied.
    FirstUse {
        /// Current verified observation for an application to accept or reject.
        observation: TofuObservation,
    },
    /// Account, key, and exact checkpoint match the prior observation.
    Unchanged {
        /// Current verified observation.
        observation: TofuObservation,
    },
    /// Account and key match, but the opaque checkpoint identifier changed.
    ///
    /// `CheckpointId` has no ordering semantics. The application must authenticate checkpoint
    /// lineage before accepting `current` as an advancement over `previous`.
    CheckpointChanged {
        /// Prior application-supplied observation.
        previous: TofuObservation,
        /// Current verified observation whose lineage is not established by TOFU comparison.
        current: TofuObservation,
    },
    /// Account or key differs from the prior observation and requires explicit handling.
    KeyChanged {
        /// Prior application-supplied observation.
        previous: TofuObservation,
        /// Current verified but not automatically trusted observation.
        current: TofuObservation,
    },
}

/// Compare one verified claim to optional prior TOFU data without mutating a trust store.
pub fn evaluate_name_tofu(
    previous: Option<&TofuObservation>,
    current: &VerifiedNameClaim,
) -> Result<TofuDecision, IdentityError> {
    let current = TofuObservation {
        name: current.name().clone(),
        account_id: current.account_id(),
        checkpoint_id: current.checkpoint_id(),
        signing_key: current.signing_key(),
    };
    let Some(previous) = previous else {
        return Ok(TofuDecision::FirstUse {
            observation: current,
        });
    };
    if previous.name != current.name {
        return Err(IdentityError::InvalidRelationship {
            resource: "TOFU name observation",
        });
    }
    if previous.account_id != current.account_id || previous.signing_key != current.signing_key {
        Ok(TofuDecision::KeyChanged {
            previous: previous.clone(),
            current,
        })
    } else if previous.checkpoint_id == current.checkpoint_id {
        Ok(TofuDecision::Unchanged {
            observation: current,
        })
    } else {
        Ok(TofuDecision::CheckpointChanged {
            previous: previous.clone(),
            current,
        })
    }
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
            resource: "name claim signing bytes",
        })?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(domain);
    message.push(0);
    message.extend_from_slice(body);
    Ok(message)
}
