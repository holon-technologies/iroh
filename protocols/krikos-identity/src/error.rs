//! Stable identity-protocol error classes.

use std::fmt;

/// Kind of algorithm registry entry that failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlgorithmKind {
    /// Cryptographic hash algorithm.
    Hash,
    /// Digital-signature algorithm.
    Signature,
    /// Key-agreement algorithm.
    Agreement,
    /// Key-derivation algorithm.
    Kdf,
    /// Authenticated-encryption algorithm.
    Aead,
}

impl fmt::Display for AlgorithmKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Hash => "hash",
            Self::Signature => "signature",
            Self::Agreement => "agreement",
            Self::Kdf => "key derivation",
            Self::Aead => "authenticated encryption",
        };
        formatter.write_str(name)
    }
}

/// Error returned by identity protocol validation and foundational codecs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// Bytes are not a well-formed v1 protocol object.
    #[error("invalid canonical protocol encoding")]
    InvalidEncoding,
    /// The encoded object uses a protocol version this implementation cannot verify.
    #[error("unsupported protocol version {version}")]
    UnsupportedVersion {
        /// Unsupported wire version.
        version: u16,
    },
    /// The encoded object uses an unknown cryptographic algorithm codepoint.
    #[error("unsupported {kind} algorithm codepoint {code}")]
    UnsupportedAlgorithm {
        /// Registry containing the codepoint.
        kind: AlgorithmKind,
        /// Unsupported wire codepoint.
        code: u16,
    },
    /// A wire codepoint is intentionally reserved and cannot be accepted as state.
    #[error("reserved {registry} codepoint {code}")]
    ReservedCodepoint {
        /// Registry containing the reserved value.
        registry: &'static str,
        /// Reserved codepoint encountered on the wire.
        code: u16,
    },
    /// A wire codepoint is unknown in a closed v1 registry.
    #[error("unsupported {registry} codepoint {code}")]
    UnsupportedCodepoint {
        /// Registry containing the unknown value.
        registry: &'static str,
        /// Unknown codepoint encountered on the wire.
        code: u16,
    },
    /// A public key is malformed or forbidden by its algorithm profile.
    #[error("invalid {kind} public key")]
    InvalidPublicKey {
        /// Registry containing the key algorithm.
        kind: AlgorithmKind,
    },
    /// Extension code zero is reserved for the absence of an extension.
    #[error("invalid extension code {code}")]
    InvalidExtensionCode {
        /// Invalid extension code.
        code: u32,
    },
    /// An extension code appears more than once in one object.
    #[error("duplicate extension code {code}")]
    DuplicateExtension {
        /// Repeated extension code.
        code: u32,
    },
    /// A critical extension is not understood by the validating object.
    #[error("unknown critical extension code {code}")]
    UnknownCriticalExtension {
        /// Unknown critical extension code.
        code: u32,
    },
    /// Bytes decode but are not the unique canonical representation.
    #[error("non-canonical protocol encoding")]
    NonCanonical,
    /// A named input or collection exceeds a protocol resource bound.
    #[error("{resource} contains {actual} items or bytes, maximum is {maximum}")]
    LimitExceeded {
        /// Name of the bounded resource.
        resource: &'static str,
        /// Observed item or byte count.
        actual: usize,
        /// Maximum accepted item or byte count.
        maximum: usize,
    },
    /// A collection required by the schema is empty.
    #[error("{resource} must not be empty")]
    EmptyCollection {
        /// Name of the empty resource.
        resource: &'static str,
    },
    /// A set-like collection contains the same semantic element more than once.
    #[error("{resource} contains a duplicate element")]
    DuplicateElement {
        /// Name of the duplicate-bearing resource.
        resource: &'static str,
    },
    /// A typed content identifier is malformed or inconsistent with its body.
    #[error("invalid {resource} identifier")]
    InvalidIdentifier {
        /// Identifier class.
        resource: &'static str,
    },
    /// Two otherwise valid fields have a forbidden relationship.
    #[error("invalid {resource} relationship")]
    InvalidRelationship {
        /// Relationship class.
        resource: &'static str,
    },
    /// A schema field that must be nonzero was zero.
    #[error("{resource} must be nonzero")]
    ZeroValue {
        /// Nonzero field class.
        resource: &'static str,
    },
    /// A threshold cannot be met by its eligible authority set.
    #[error("authorization threshold is not satisfiable")]
    UnsatisfiableThreshold,
    /// One public signing key was assigned to multiple active authorities.
    #[error("duplicate active signing key")]
    DuplicateSigningKey,
    /// A control, recovery, or provider policy is structurally invalid.
    #[error("invalid {resource} policy")]
    InvalidPolicy {
        /// Policy class.
        resource: &'static str,
    },
    /// A capability grant is structurally invalid.
    #[error("invalid capability: {reason}")]
    InvalidCapability {
        /// Stable validation reason.
        reason: &'static str,
    },
    /// A capability delegation is structurally invalid.
    #[error("invalid delegation: {reason}")]
    InvalidDelegation {
        /// Stable validation reason.
        reason: &'static str,
    },
    /// A protocol feature is intentionally not accepted by v1 policy semantics.
    #[error("unsupported v1 policy feature: {feature}")]
    UnsupportedPolicyFeature {
        /// Feature deliberately unavailable in v1.
        feature: &'static str,
    },
    /// A cryptographic signature did not verify under its declared key and suite.
    #[error("invalid protocol signature")]
    InvalidSignature,
    /// A group-key wrap names a suite other than the fixed v1 KEM/KDF/AEAD profile.
    #[error("unsupported group-key wrap cryptographic suite")]
    UnsupportedKeyWrapSuite,
    /// Group-key unwrap failed authentication.
    ///
    /// This deliberately does not distinguish a wrong key, modified ciphertext, or
    /// modified associated data. Retrying the same inputs cannot succeed.
    #[error("group-key wrap authentication failed")]
    KeyWrapAuthenticationFailed,
    /// Private artifact authentication failed.
    ///
    /// This deliberately does not distinguish a wrong key or passphrase, modified ciphertext,
    /// modified parameters, or modified associated context.
    #[error("private artifact authentication failed")]
    PrivateArtifactAuthenticationFailed,
    /// The operating system could not provide cryptographic entropy.
    ///
    /// A caller may retry after the platform entropy source becomes available.
    #[error("operating-system cryptographic entropy is unavailable")]
    EntropyUnavailable,
    /// An approval names no controller in the relevant pre-state.
    #[error("unknown account controller")]
    UnknownController,
    /// A known controller is outside the operation rule's selector or immutable scope.
    #[error("controller is ineligible for this operation")]
    IneligibleController,
    /// A terminally removed controller attempted to authorize a later transition.
    #[error("controller has been revoked")]
    RevokedController,
    /// The same authority was counted more than once in one authorization set.
    #[error("duplicate authorization signer")]
    DuplicateSigner,
    /// Valid eligible signatures do not meet the active policy threshold.
    #[error("account authorization denied")]
    AuthorizationDenied,
    /// An event sequence does not advance from its predecessor exactly once.
    #[error("invalid account event sequence")]
    InvalidSequence,
    /// A possible branch predates the bounded in-memory lineage cache and needs durable replay.
    #[error("historical account state is required for event sequence {sequence}")]
    HistoricalStateRequired {
        /// Sequence whose authenticated pre-state must be loaded from durable lineage.
        sequence: u64,
    },
    /// An event or application envelope names the wrong security epoch.
    #[error("invalid account epoch")]
    InvalidEpoch,
    /// An event's predecessor reference does not match the complete current head set.
    #[error("invalid account event predecessor")]
    InvalidPredecessor,
    /// A nested object belongs to a different stable account.
    #[error("account identifier mismatch")]
    AccountMismatch,
    /// Conflicting valid account-control bodies were retained as a fork.
    #[error("account fork detected")]
    ForkDetected,
    /// The requested transition is forbidden while the account remains forked.
    #[error("account is forked")]
    AccountForked,
    /// The requested transition conflicts with an authoritative pending recovery.
    #[error("account recovery is pending")]
    RecoveryPending,
    /// The account is terminally retired.
    #[error("account is retired")]
    AccountRetired,
    /// A newer protocol major is authoritative, so this v1 client is read-only.
    #[error("account is read-only after a protocol-major upgrade")]
    ProtocolUpgradeReadOnly,
    /// A rule requires signed provider freshness that is not available.
    #[error("required freshness evidence is unavailable")]
    FreshnessUnavailable,
    /// Signed provider evidence is older than the applicable freshness bound.
    #[error("freshness evidence is stale")]
    StaleEvidence,
    /// A delayed transition has not reached its signed provider-observed deadline.
    #[error("required authorization delay has not elapsed")]
    DelayNotElapsed,
    /// Historical evidence names a policy revision other than the applicable pre-state revision.
    #[error("policy version mismatch")]
    PolicyVersionMismatch,
    /// A device has no authorization in the supplied account state.
    #[error("device is not authorized")]
    DeviceNotAuthorized,
    /// A temporarily suspended device attempted an authorized action.
    #[error("device is suspended")]
    DeviceSuspended,
    /// A terminally revoked device attempted an authorized action.
    #[error("device is revoked")]
    DeviceRevoked,
    /// An atomic state write raced with a different account revision.
    #[error("stale account-store revision")]
    StaleRevision,
    /// Durable bytes or indices are inconsistent with their authenticated state.
    #[error("identity store corruption")]
    StorageCorruption,
    /// An owned operation was explicitly cancelled before completion.
    #[error("identity operation cancelled")]
    Cancelled,
    /// A bounded retry policy exhausted all permitted attempts.
    #[error("identity operation exhausted its retry budget")]
    RetryExhausted,
    /// Bounded concurrency or queue capacity is currently exhausted.
    #[error("identity resource is busy")]
    ResourceBusy,
    /// A configured transparency provider could not be reached.
    #[error("transparency provider is unavailable")]
    ProviderUnavailable,
    /// A configured transparency-provider request exceeded its bounded deadline.
    #[error("transparency provider request timed out")]
    ProviderTimeout,
    /// A transparency provider rejected work because its abuse-control limit was reached.
    #[error("transparency provider rate limit exceeded")]
    ProviderRateLimited,
    /// A sealed provider generation released the requested payload to its verified archive.
    #[error("provider archive is required for this released history")]
    ProviderArchiveRequired,
    /// Protected application writes are blocked pending mandatory key rotation.
    #[error("protected writes are blocked pending group-key rotation")]
    ProtectedWritesBlocked,
    /// A Merkle, consistency, non-membership, or lineage proof is invalid.
    #[error("invalid transparency proof")]
    InvalidProof,
    /// Two signed provider heads prove inconsistent statements for one tree size.
    #[error("transparency provider equivocation")]
    ProviderEquivocation,
    /// A provider returned an older tree size or observation than a previously verified head.
    #[error("transparency provider rollback")]
    ProviderRollback,
    /// A protocol counter or time calculation overflowed.
    #[error("{resource} arithmetic overflow")]
    ArithmeticOverflow {
        /// Counter or unit that overflowed.
        resource: &'static str,
    },
}

impl IdentityError {
    pub(crate) const fn unsupported_algorithm(kind: AlgorithmKind, code: u16) -> Self {
        Self::UnsupportedAlgorithm { kind, code }
    }

    pub(crate) const fn limit(resource: &'static str, actual: usize, maximum: usize) -> Self {
        Self::LimitExceeded {
            resource,
            actual,
            maximum,
        }
    }
}
