//! Account-event admission and mergeable controller approval schemas.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeTuple};

use crate::{
    AccountId, ActivateCryptoMigration, AdmissionEvidenceId, AlgorithmSignature,
    BeginCryptoMigration, BeginRecovery, CancelRecovery, CheckpointId, ControlPolicy,
    ControllerApprovalId, ControllerDescriptor, ControllerId, ControllerKeyId, CryptoSuiteId,
    DeviceAuthorization, DeviceAuthorizationUpdate, DeviceMetadataUpdate, Epoch,
    EventAuthorizationId, EventId, EventIntentApprovalId, Extensions, FinalizeRecovery,
    GenesisAnchor, IdentityError, OperationKind, ProposalId, ProtocolUpgrade, ProtocolVersion,
    ProviderLogSubject, ProviderPolicy, ProviderPolicyId, ProviderReceipts, RecoveryPolicy,
    ReinstateDevice, ResolveFork, RetireAccount, RetireCryptoSuite, RevokeDevice, RotateDeviceKeys,
    Sequence, SuspendDevice, Timestamp, VetoRecovery,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{
        MAX_ACCOUNT_EVENT_BYTES, MAX_ACTIVE_CRYPTO_SUITES, MAX_AUTHORIZATION_SIGNATURES,
        MAX_FORK_HEADS,
    },
    schema::BoundedVec,
    types::{HashDomain, hash_bytes},
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum EventPredecessorsKind {
    Genesis(GenesisAnchor),
    Events(BoundedVec<EventId, MAX_FORK_HEADS>),
}

/// Complete predecessor reference for one account event.
///
/// The first event names the genesis anchor. Linear events name one event ID, while
/// fork resolution names the complete bounded, sorted set of current branch heads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPredecessors(EventPredecessorsKind);

impl EventPredecessors {
    /// Construct the predecessor of the first account event.
    pub const fn genesis(anchor: GenesisAnchor) -> Self {
        Self(EventPredecessorsKind::Genesis(anchor))
    }

    /// Sort and construct a nonempty, duplicate-free event-head set.
    pub fn events(mut event_ids: Vec<EventId>) -> Result<Self, IdentityError> {
        event_ids.sort_unstable();
        Self::events_from_sorted(event_ids)
    }

    fn events_from_sorted(event_ids: Vec<EventId>) -> Result<Self, IdentityError> {
        if event_ids.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "event predecessors",
            });
        }
        let event_ids = BoundedVec::new("event predecessors", event_ids)?;
        for pair in event_ids.as_slice().windows(2) {
            if pair[0] == pair[1] {
                return Err(IdentityError::DuplicateElement {
                    resource: "event predecessors",
                });
            }
            if pair[0] > pair[1] {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self(EventPredecessorsKind::Events(event_ids)))
    }

    /// Genesis anchor when this is the first-event predecessor.
    pub const fn genesis_anchor(&self) -> Option<GenesisAnchor> {
        match &self.0 {
            EventPredecessorsKind::Genesis(anchor) => Some(*anchor),
            EventPredecessorsKind::Events(_) => None,
        }
    }

    /// Complete event-head set when this names existing events.
    pub fn event_heads(&self) -> Option<&[EventId]> {
        match &self.0 {
            EventPredecessorsKind::Genesis(_) => None,
            EventPredecessorsKind::Events(event_ids) => Some(event_ids.as_slice()),
        }
    }
}

impl Serialize for EventPredecessors {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            EventPredecessorsKind::Genesis(anchor) => (1u16, anchor).serialize(serializer),
            EventPredecessorsKind::Events(event_ids) => (2u16, event_ids).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for EventPredecessors {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = EventPredecessors;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a v1 event predecessor reference")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => Ok(EventPredecessors::genesis(
                        sequence
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    )),
                    2 => {
                        let values = sequence
                            .next_element::<BoundedVec<EventId, MAX_FORK_HEADS>>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        EventPredecessors::events_from_sorted(values.into_vec())
                            .map_err(de::Error::custom)
                    }
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "event predecessors",
                        code: unsupported,
                    })),
                }
            }
        }

        deserializer.deserialize_tuple(2, Visitor)
    }
}

impl CanonicalCodec for EventPredecessors {
    const RESOURCE: &'static str = "event predecessor bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (code, _) =
            postcard::take_from_bytes::<u16>(bytes).map_err(|_| IdentityError::InvalidEncoding)?;
        match code {
            1 => {
                let (_, anchor): (u16, GenesisAnchor) = decode_wire(bytes)?;
                Ok(Self::genesis(anchor))
            }
            2 => {
                let (_, values): (u16, BoundedVec<EventId, MAX_FORK_HEADS>) = decode_wire(bytes)?;
                Self::events_from_sorted(values.into_vec())
            }
            unsupported => Err(IdentityError::UnsupportedCodepoint {
                registry: "event predecessors",
                code: unsupported,
            }),
        }
    }
}

/// Complete closed v1 account-control operation registry with typed payloads.
#[allow(clippy::large_enum_variant)] // Exact typed wire payloads avoid hidden heap indirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountOperation {
    /// Authorize a new independently keyed device.
    AuthorizeDevice(DeviceAuthorization),
    /// Replace a device's class or capability authorization.
    UpdateDeviceAuthorization(DeviceAuthorizationUpdate),
    /// Replace only a device's blinded private-metadata commitment.
    UpdateDeviceMetadata(DeviceMetadataUpdate),
    /// Temporarily disable a device.
    SuspendDevice(SuspendDevice),
    /// Restore a suspended device.
    ReinstateDevice(ReinstateDevice),
    /// Permanently revoke a device identifier.
    RevokeDevice(RevokeDevice),
    /// Atomically replace a device with newly generated keys.
    RotateDeviceKeys(RotateDeviceKeys),
    /// Add one independently keyed account controller.
    AddController(ControllerDescriptor),
    /// Permanently remove one controller identifier.
    RemoveController(ControllerId),
    /// Replace the weighted account-control policy.
    ChangeControlPolicy(ControlPolicy),
    /// Replace the explicit recovery policy.
    ChangeRecoveryPolicy(RecoveryPolicy),
    /// Replace the minimum transparency-provider policy.
    ChangeProviderPolicy(ProviderPolicy),
    /// Install one authoritative pending recovery.
    BeginRecovery(BeginRecovery),
    /// Veto the exact pending recovery under the pre-recovery control policy.
    VetoRecovery(VetoRecovery),
    /// Cancel the exact pending recovery under its pre-state recovery policy.
    CancelRecovery(CancelRecovery),
    /// Finalize a sufficiently authorized and delayed recovery.
    FinalizeRecovery(FinalizeRecovery),
    /// Select one existing branch and add only monotonic revocations.
    ResolveFork(ResolveFork),
    /// Begin a cross-signed controller signature-suite migration.
    BeginCryptoMigration(BeginCryptoMigration),
    /// Activate the dual-signature migration phase.
    ActivateCryptoMigration(ActivateCryptoMigration),
    /// Abort a candidate or retire the previous cryptographic suite.
    RetireCryptoSuite(RetireCryptoSuite),
    /// Adopt a future account protocol major under explicit compatibility rules.
    UpgradeProtocol(ProtocolUpgrade),
    /// Terminally retire the account.
    RetireAccount(RetireAccount),
}

impl AccountOperation {
    /// Stable operation class used for policy selection and wire codepoints.
    pub const fn kind(&self) -> OperationKind {
        match self {
            Self::AuthorizeDevice(_) => OperationKind::AuthorizeDevice,
            Self::UpdateDeviceAuthorization(_) => OperationKind::UpdateDeviceAuthorization,
            Self::UpdateDeviceMetadata(_) => OperationKind::UpdateDeviceMetadata,
            Self::SuspendDevice(_) => OperationKind::SuspendDevice,
            Self::ReinstateDevice(_) => OperationKind::ReinstateDevice,
            Self::RevokeDevice(_) => OperationKind::RevokeDevice,
            Self::RotateDeviceKeys(_) => OperationKind::RotateDeviceKeys,
            Self::AddController(_) => OperationKind::AddController,
            Self::RemoveController(_) => OperationKind::RemoveController,
            Self::ChangeControlPolicy(_) => OperationKind::ChangeControlPolicy,
            Self::ChangeRecoveryPolicy(_) => OperationKind::ChangeRecoveryPolicy,
            Self::ChangeProviderPolicy(_) => OperationKind::ChangeProviderPolicy,
            Self::BeginRecovery(_) => OperationKind::BeginRecovery,
            Self::VetoRecovery(_) => OperationKind::VetoRecovery,
            Self::CancelRecovery(_) => OperationKind::CancelRecovery,
            Self::FinalizeRecovery(_) => OperationKind::FinalizeRecovery,
            Self::ResolveFork(_) => OperationKind::ResolveFork,
            Self::BeginCryptoMigration(_) => OperationKind::BeginCryptoMigration,
            Self::ActivateCryptoMigration(_) => OperationKind::ActivateCryptoMigration,
            Self::RetireCryptoSuite(_) => OperationKind::RetireCryptoSuite,
            Self::UpgradeProtocol(_) => OperationKind::UpgradeProtocol,
            Self::RetireAccount(_) => OperationKind::RetireAccount,
        }
    }
}

impl Serialize for AccountOperation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tuple = serializer.serialize_tuple(2)?;
        tuple.serialize_element(&self.kind().code())?;
        match self {
            Self::AuthorizeDevice(payload) => tuple.serialize_element(payload)?,
            Self::UpdateDeviceAuthorization(payload) => tuple.serialize_element(payload)?,
            Self::UpdateDeviceMetadata(payload) => tuple.serialize_element(payload)?,
            Self::SuspendDevice(payload) => tuple.serialize_element(payload)?,
            Self::ReinstateDevice(payload) => tuple.serialize_element(payload)?,
            Self::RevokeDevice(payload) => tuple.serialize_element(payload)?,
            Self::RotateDeviceKeys(payload) => tuple.serialize_element(payload)?,
            Self::AddController(payload) => tuple.serialize_element(payload)?,
            Self::RemoveController(payload) => tuple.serialize_element(payload)?,
            Self::ChangeControlPolicy(payload) => tuple.serialize_element(payload)?,
            Self::ChangeRecoveryPolicy(payload) => tuple.serialize_element(payload)?,
            Self::ChangeProviderPolicy(payload) => tuple.serialize_element(payload)?,
            Self::BeginRecovery(payload) => tuple.serialize_element(payload)?,
            Self::VetoRecovery(payload) => tuple.serialize_element(payload)?,
            Self::CancelRecovery(payload) => tuple.serialize_element(payload)?,
            Self::FinalizeRecovery(payload) => tuple.serialize_element(payload)?,
            Self::ResolveFork(payload) => tuple.serialize_element(payload)?,
            Self::BeginCryptoMigration(payload) => tuple.serialize_element(payload)?,
            Self::ActivateCryptoMigration(payload) => tuple.serialize_element(payload)?,
            Self::RetireCryptoSuite(payload) => tuple.serialize_element(payload)?,
            Self::UpgradeProtocol(payload) => tuple.serialize_element(payload)?,
            Self::RetireAccount(payload) => tuple.serialize_element(payload)?,
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for AccountOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = AccountOperation;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a closed typed v1 account operation")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let kind = OperationKind::from_code(code).map_err(de::Error::custom)?;
                macro_rules! payload {
                    ($variant:ident, $type:ty) => {
                        AccountOperation::$variant(
                            sequence
                                .next_element::<$type>()?
                                .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                        )
                    };
                }
                Ok(match kind {
                    OperationKind::AuthorizeDevice => {
                        payload!(AuthorizeDevice, DeviceAuthorization)
                    }
                    OperationKind::UpdateDeviceAuthorization => {
                        payload!(UpdateDeviceAuthorization, DeviceAuthorizationUpdate)
                    }
                    OperationKind::UpdateDeviceMetadata => {
                        payload!(UpdateDeviceMetadata, DeviceMetadataUpdate)
                    }
                    OperationKind::SuspendDevice => payload!(SuspendDevice, SuspendDevice),
                    OperationKind::ReinstateDevice => payload!(ReinstateDevice, ReinstateDevice),
                    OperationKind::RevokeDevice => payload!(RevokeDevice, RevokeDevice),
                    OperationKind::RotateDeviceKeys => payload!(RotateDeviceKeys, RotateDeviceKeys),
                    OperationKind::AddController => payload!(AddController, ControllerDescriptor),
                    OperationKind::RemoveController => payload!(RemoveController, ControllerId),
                    OperationKind::ChangeControlPolicy => {
                        payload!(ChangeControlPolicy, ControlPolicy)
                    }
                    OperationKind::ChangeRecoveryPolicy => {
                        payload!(ChangeRecoveryPolicy, RecoveryPolicy)
                    }
                    OperationKind::ChangeProviderPolicy => {
                        payload!(ChangeProviderPolicy, ProviderPolicy)
                    }
                    OperationKind::BeginRecovery => payload!(BeginRecovery, BeginRecovery),
                    OperationKind::VetoRecovery => payload!(VetoRecovery, VetoRecovery),
                    OperationKind::CancelRecovery => payload!(CancelRecovery, CancelRecovery),
                    OperationKind::FinalizeRecovery => payload!(FinalizeRecovery, FinalizeRecovery),
                    OperationKind::ResolveFork => payload!(ResolveFork, ResolveFork),
                    OperationKind::BeginCryptoMigration => {
                        payload!(BeginCryptoMigration, BeginCryptoMigration)
                    }
                    OperationKind::ActivateCryptoMigration => {
                        payload!(ActivateCryptoMigration, ActivateCryptoMigration)
                    }
                    OperationKind::RetireCryptoSuite => {
                        payload!(RetireCryptoSuite, RetireCryptoSuite)
                    }
                    OperationKind::UpgradeProtocol => payload!(UpgradeProtocol, ProtocolUpgrade),
                    OperationKind::RetireAccount => payload!(RetireAccount, RetireAccount),
                })
            }
        }

        deserializer.deserialize_tuple(2, Visitor)
    }
}

impl CanonicalCodec for AccountOperation {
    const RESOURCE: &'static str = "account operation bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let (code, _) =
            postcard::take_from_bytes::<u16>(bytes).map_err(|_| IdentityError::InvalidEncoding)?;
        let _ = OperationKind::from_code(code)?;
        decode_wire(bytes)
    }
}

/// Canonical unsigned account-event body used by both proposal and event ID domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventBody {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    sequence: Sequence,
    resulting_epoch: Epoch,
    predecessors: EventPredecessors,
    operation: AccountOperation,
    created_at: Timestamp,
    nonce: [u8; 16],
    extensions: Extensions,
}

/// Circularity-free material naming one admitted event history.
#[derive(Serialize)]
struct AdmittedEventIdentity<'a> {
    body: &'a EventBody,
    admission_evidence_id: AdmissionEvidenceId,
}

impl EventBody {
    /// Construct a structurally valid v1 body; state-dependent checks happen in projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        sequence: Sequence,
        resulting_epoch: Epoch,
        predecessors: EventPredecessors,
        operation: AccountOperation,
        created_at: Timestamp,
        nonce: [u8; 16],
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if sequence == Sequence::GENESIS {
            return Err(IdentityError::InvalidSequence);
        }
        if nonce == [0; 16] {
            return Err(IdentityError::ZeroValue {
                resource: "account event nonce",
            });
        }
        if sequence.get() == 1 {
            if predecessors.genesis_anchor().is_none() {
                return Err(IdentityError::InvalidPredecessor);
            }
        } else if predecessors.event_heads().is_none() {
            return Err(IdentityError::InvalidPredecessor);
        }

        match &operation {
            AccountOperation::ResolveFork(resolution) => {
                if resolution.fork().account_id() != account_id
                    || predecessors.event_heads() != Some(resolution.fork().heads())
                {
                    return Err(IdentityError::InvalidPredecessor);
                }
            }
            AccountOperation::BeginRecovery(begin) => {
                if begin.proposal().plan().account_id() != account_id {
                    return Err(IdentityError::AccountMismatch);
                }
                let prior_event_head = begin.proposal().plan().prior_event_head();
                if sequence.get() == 1
                    || predecessors.event_heads() != Some(std::slice::from_ref(&prior_event_head))
                {
                    return Err(IdentityError::InvalidPredecessor);
                }
            }
            AccountOperation::BeginCryptoMigration(begin) => {
                if begin.migration().account_id() != account_id {
                    return Err(IdentityError::AccountMismatch);
                }
                if predecessors
                    .event_heads()
                    .is_some_and(|heads| heads.len() != 1)
                {
                    return Err(IdentityError::InvalidPredecessor);
                }
            }
            _ => {
                if predecessors
                    .event_heads()
                    .is_some_and(|heads| heads.len() != 1)
                {
                    return Err(IdentityError::InvalidPredecessor);
                }
            }
        }
        extensions.validate_critical(&[])?;
        let body = Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            sequence,
            resulting_epoch,
            predecessors,
            operation,
            created_at,
            nonce,
            extensions,
        };
        let encoded_len = encode_wire(&body)?.len();
        if encoded_len > MAX_ACCOUNT_EVENT_BYTES {
            return Err(IdentityError::limit(
                "account event body bytes",
                encoded_len,
                MAX_ACCOUNT_EVENT_BYTES,
            ));
        }
        Ok(body)
    }

    /// Stable account whose authority log contains this body.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact account sequence proposed by this body.
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Account security epoch after this operation is applied.
    pub const fn resulting_epoch(&self) -> Epoch {
        self.resulting_epoch
    }

    /// Complete predecessor reference used for fork detection and resolution.
    pub const fn predecessors(&self) -> &EventPredecessors {
        &self.predecessors
    }

    /// Typed authoritative operation.
    pub const fn operation(&self) -> &AccountOperation {
        &self.operation
    }

    /// Metadata timestamp; never ordering or authority input.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Proposal-domain body identifier signed before provider delay observation.
    pub fn proposal_id(&self) -> Result<ProposalId, IdentityError> {
        ProposalId::derive(self)
    }

    /// Final event identifier for this body under one exact admission history.
    pub fn admitted_event_id(
        &self,
        admission_evidence_id: AdmissionEvidenceId,
    ) -> Result<EventId, IdentityError> {
        let material = AdmittedEventIdentity {
            body: self,
            admission_evidence_id,
        };
        let bytes = encode_wire(&material)?;
        Ok(EventId::from_digest(hash_bytes(
            HashDomain::AccountEvent,
            &bytes,
        )))
    }
}

impl<'de> Deserialize<'de> for EventBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            sequence: Sequence,
            resulting_epoch: Epoch,
            predecessors: EventPredecessors,
            operation: AccountOperation,
            created_at: Timestamp,
            nonce: [u8; 16],
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        Self::new(
            wire.account_id,
            wire.sequence,
            wire.resulting_epoch,
            wire.predecessors,
            wire.operation,
            wire.created_at,
            wire.nonce,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for EventBody {
    const RESOURCE: &'static str = "account event body bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// One signature tied to an exact controller key and crypto suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyedSignature {
    crypto_suite_id: CryptoSuiteId,
    controller_key_id: ControllerKeyId,
    signature: AlgorithmSignature,
}

impl KeyedSignature {
    /// Construct a keyed controller signature.
    pub const fn new(
        crypto_suite_id: CryptoSuiteId,
        controller_key_id: ControllerKeyId,
        signature: AlgorithmSignature,
    ) -> Self {
        Self {
            crypto_suite_id,
            controller_key_id,
            signature,
        }
    }

    /// Cryptographic suite under which this signature must verify.
    pub const fn crypto_suite_id(&self) -> CryptoSuiteId {
        self.crypto_suite_id
    }

    /// Exact controller key expected to verify this signature.
    pub const fn controller_key_id(&self) -> ControllerKeyId {
        self.controller_key_id
    }

    /// Algorithm-tagged signature bytes.
    pub const fn signature(&self) -> &AlgorithmSignature {
        &self.signature
    }

    const fn sort_key(&self) -> (CryptoSuiteId, ControllerKeyId) {
        (self.crypto_suite_id, self.controller_key_id)
    }
}

canonical_schema!(KeyedSignature, "keyed controller signature bytes");

/// Body signed before providers observe a delayed proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventIntentApprovalBody {
    protocol_version: ProtocolVersion,
    controller_id: ControllerId,
    proposal_id: ProposalId,
    extensions: Extensions,
}

impl EventIntentApprovalBody {
    /// Construct one exact proposal-intent approval body.
    pub fn new(
        controller_id: ControllerId,
        proposal_id: ProposalId,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            controller_id,
            proposal_id,
            extensions,
        })
    }

    /// Controller making this approval.
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Proposal whose delay is being started.
    pub const fn proposal_id(&self) -> ProposalId {
        self.proposal_id
    }

    /// Derive the exact signed approval-body identifier.
    pub fn event_intent_approval_id(&self) -> Result<EventIntentApprovalId, IdentityError> {
        EventIntentApprovalId::derive(self)
    }
}

impl<'de> Deserialize<'de> for EventIntentApprovalBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            controller_id: ControllerId,
            proposal_id: ProposalId,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        Self::new(wire.controller_id, wire.proposal_id, wire.extensions).map_err(de::Error::custom)
    }
}

canonical_schema!(EventIntentApprovalBody, "event intent approval body bytes");

/// Mergeable signatures from one controller over one proposal intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedEventIntentApproval {
    body: EventIntentApprovalBody,
    signatures: BoundedVec<KeyedSignature, MAX_ACTIVE_CRYPTO_SUITES>,
}

impl SignedEventIntentApproval {
    /// Construct sorted, duplicate-free suite signatures for one controller.
    pub fn new(
        body: EventIntentApprovalBody,
        mut signatures: Vec<KeyedSignature>,
    ) -> Result<Self, IdentityError> {
        signatures.sort_unstable_by_key(KeyedSignature::sort_key);
        Self::from_sorted(body, signatures)
    }

    fn from_sorted(
        body: EventIntentApprovalBody,
        signatures: Vec<KeyedSignature>,
    ) -> Result<Self, IdentityError> {
        if signatures.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "event intent signatures",
            });
        }
        let signatures = BoundedVec::new("event intent signatures", signatures)?;
        for pair in signatures.as_slice().windows(2) {
            if pair[0].sort_key() == pair[1].sort_key() {
                return Err(IdentityError::DuplicateElement {
                    resource: "event intent signatures",
                });
            }
            if pair[0].sort_key() > pair[1].sort_key() {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self { body, signatures })
    }

    /// Signed intent body.
    pub const fn body(&self) -> &EventIntentApprovalBody {
        &self.body
    }

    /// Sorted suite signatures over the canonical intent body.
    pub fn signatures(&self) -> &[KeyedSignature] {
        self.signatures.as_slice()
    }
}

impl<'de> Deserialize<'de> for SignedEventIntentApproval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            body: EventIntentApprovalBody,
            signatures: BoundedVec<KeyedSignature, MAX_ACTIVE_CRYPTO_SUITES>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_sorted(wire.body, wire.signatures.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(
    SignedEventIntentApproval,
    "signed event intent approval bytes"
);

/// Sorted controller approvals proving a threshold-approved proposal intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventIntentApprovals(
    BoundedVec<SignedEventIntentApproval, MAX_AUTHORIZATION_SIGNATURES>,
);

impl EventIntentApprovals {
    /// Sort and construct a duplicate-free controller intent set.
    pub fn new(mut approvals: Vec<SignedEventIntentApproval>) -> Result<Self, IdentityError> {
        approvals.sort_unstable_by_key(|approval| approval.body().controller_id());
        Self::from_sorted(approvals)
    }

    fn from_sorted(approvals: Vec<SignedEventIntentApproval>) -> Result<Self, IdentityError> {
        if approvals.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "event intent approvals",
            });
        }
        let approvals = BoundedVec::new("event intent approvals", approvals)?;
        for pair in approvals.as_slice().windows(2) {
            let left = pair[0].body().controller_id();
            let right = pair[1].body().controller_id();
            if left == right {
                return Err(IdentityError::DuplicateElement {
                    resource: "event intent controllers",
                });
            }
            if left > right {
                return Err(IdentityError::NonCanonical);
            }
        }
        let proposal = approvals.as_slice()[0].body().proposal_id();
        if approvals
            .as_slice()
            .iter()
            .any(|approval| approval.body().proposal_id() != proposal)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "event intent proposal set",
            });
        }
        Ok(Self(approvals))
    }

    /// Canonically ordered controller intent approvals.
    pub fn as_slice(&self) -> &[SignedEventIntentApproval] {
        self.0.as_slice()
    }

    /// Proposal shared by every approval.
    pub fn proposal_id(&self) -> ProposalId {
        self.0.as_slice()[0].body().proposal_id()
    }
}

impl<'de> Deserialize<'de> for EventIntentApprovals {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values =
            BoundedVec::<SignedEventIntentApproval, MAX_AUTHORIZATION_SIGNATURES>::deserialize(
                deserializer,
            )?;
        Self::from_sorted(values.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(EventIntentApprovals, "event intent approval set bytes");

#[derive(Debug, Clone, PartialEq, Eq)]
enum FreshnessEvidenceKind {
    LocalKnown(CheckpointId),
    ProviderQuorum {
        checkpoint_id: CheckpointId,
        provider_policy_id: ProviderPolicyId,
        receipts: ProviderReceipts,
    },
}

/// Historical checkpoint freshness evidence used when admitting an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshnessEvidence(FreshnessEvidenceKind);

impl FreshnessEvidence {
    /// Use the locally trusted checkpoint without claiming provider freshness.
    pub const fn local_known(checkpoint_id: CheckpointId) -> Self {
        Self(FreshnessEvidenceKind::LocalKnown(checkpoint_id))
    }

    /// Construct provider-quorum evidence for one checkpoint.
    pub fn provider_quorum(
        checkpoint_id: CheckpointId,
        provider_policy_id: ProviderPolicyId,
        receipts: ProviderReceipts,
    ) -> Result<Self, IdentityError> {
        if receipts.as_slice().is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "freshness provider receipts",
            });
        }
        if receipts.as_slice().iter().any(|receipt| {
            receipt.entry().subject() != ProviderLogSubject::Checkpoint(checkpoint_id)
        }) {
            return Err(IdentityError::InvalidRelationship {
                resource: "freshness checkpoint receipts",
            });
        }
        Ok(Self(FreshnessEvidenceKind::ProviderQuorum {
            checkpoint_id,
            provider_policy_id,
            receipts,
        }))
    }

    /// Checkpoint whose freshness is evidenced.
    pub const fn checkpoint_id(&self) -> CheckpointId {
        match &self.0 {
            FreshnessEvidenceKind::LocalKnown(id)
            | FreshnessEvidenceKind::ProviderQuorum {
                checkpoint_id: id, ..
            } => *id,
        }
    }

    /// Account provider-policy identifier committed by replicated evidence.
    pub const fn provider_policy_id(&self) -> Option<ProviderPolicyId> {
        match &self.0 {
            FreshnessEvidenceKind::LocalKnown(_) => None,
            FreshnessEvidenceKind::ProviderQuorum {
                provider_policy_id, ..
            } => Some(*provider_policy_id),
        }
    }

    /// Signed provider receipts, absent for local-known evidence.
    pub const fn provider_receipts(&self) -> Option<&ProviderReceipts> {
        match &self.0 {
            FreshnessEvidenceKind::LocalKnown(_) => None,
            FreshnessEvidenceKind::ProviderQuorum { receipts, .. } => Some(receipts),
        }
    }
}

impl Serialize for FreshnessEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            FreshnessEvidenceKind::LocalKnown(checkpoint_id) => {
                (1u16, checkpoint_id).serialize(serializer)
            }
            FreshnessEvidenceKind::ProviderQuorum {
                checkpoint_id,
                provider_policy_id,
                receipts,
            } => (2u16, (checkpoint_id, provider_policy_id, receipts)).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FreshnessEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = FreshnessEvidence;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("v1 freshness evidence")
            }
            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => Ok(FreshnessEvidence::local_known(
                        sequence
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    )),
                    2 => {
                        let (checkpoint_id, provider_policy_id, receipts) = sequence
                            .next_element::<(CheckpointId, ProviderPolicyId, ProviderReceipts)>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        FreshnessEvidence::provider_quorum(
                            checkpoint_id,
                            provider_policy_id,
                            receipts,
                        )
                        .map_err(de::Error::custom)
                    }
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "freshness evidence",
                        code: unsupported,
                    })),
                }
            }
        }
        deserializer.deserialize_tuple(2, Visitor)
    }
}

canonical_schema!(FreshnessEvidence, "freshness evidence bytes");

#[derive(Debug, Clone, PartialEq, Eq)]
enum DelayEvidenceKind {
    None,
    ProviderQuorum {
        provider_policy_id: ProviderPolicyId,
        required_quorum: crate::ProviderQuorum,
        observed_at: Timestamp,
        intent_approvals: EventIntentApprovals,
        receipts: ProviderReceipts,
    },
    GuardianRecovery {
        provider_policy_id: ProviderPolicyId,
        required_quorum: crate::ProviderQuorum,
        observed_at: Timestamp,
        proposal_id: ProposalId,
        receipts: ProviderReceipts,
    },
}

/// Provider-observed proposal intent proving an elapsed policy delay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayEvidence(DelayEvidenceKind);

impl DelayEvidence {
    /// No delay evidence, valid only for a no-delay policy rule.
    pub const fn none() -> Self {
        Self(DelayEvidenceKind::None)
    }

    /// Construct provider-observed evidence for one threshold-approved intent.
    pub fn provider_quorum(
        provider_policy_id: ProviderPolicyId,
        required_quorum: crate::ProviderQuorum,
        intent_approvals: EventIntentApprovals,
        receipts: ProviderReceipts,
    ) -> Result<Self, IdentityError> {
        if receipts.as_slice().is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "delay provider receipts",
            });
        }
        let proposal_id = intent_approvals.proposal_id();
        if receipts.as_slice().iter().any(|receipt| {
            receipt.entry().subject() != ProviderLogSubject::EventIntent(proposal_id)
        }) {
            return Err(IdentityError::InvalidRelationship {
                resource: "delay proposal intent receipts",
            });
        }
        let quorum = usize::from(required_quorum.get());
        if receipts.as_slice().len() < quorum {
            return Err(IdentityError::UnsatisfiableThreshold);
        }
        let mut observations = receipts
            .as_slice()
            .iter()
            .map(|receipt| receipt.entry().observed_at())
            .collect::<Vec<_>>();
        observations.sort_unstable();
        let observed_at = observations[quorum - 1];
        Ok(Self(DelayEvidenceKind::ProviderQuorum {
            provider_policy_id,
            required_quorum,
            observed_at,
            intent_approvals,
            receipts,
        }))
    }

    /// Construct provider-observed evidence for guardian authority embedded in a recovery intent.
    ///
    /// No controller intent approvals are accepted by this shape. The exact guardian approval set
    /// is already committed by the provider-receipted proposal body and is reverified against the
    /// authenticated provider authority time when the event is applied.
    pub fn guardian_recovery(
        provider_policy_id: ProviderPolicyId,
        required_quorum: crate::ProviderQuorum,
        receipts: ProviderReceipts,
    ) -> Result<Self, IdentityError> {
        let first = receipts
            .as_slice()
            .first()
            .ok_or(IdentityError::EmptyCollection {
                resource: "guardian recovery delay provider receipts",
            })?;
        let ProviderLogSubject::EventIntent(proposal_id) = first.entry().subject() else {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian recovery delay receipt subject",
            });
        };
        if receipts.as_slice().iter().any(|receipt| {
            receipt.entry().subject() != ProviderLogSubject::EventIntent(proposal_id)
        }) {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian recovery delay proposal receipts",
            });
        }
        let quorum = usize::from(required_quorum.get());
        if receipts.as_slice().len() < quorum {
            return Err(IdentityError::UnsatisfiableThreshold);
        }
        let mut observations = receipts
            .as_slice()
            .iter()
            .map(|receipt| receipt.entry().observed_at())
            .collect::<Vec<_>>();
        observations.sort_unstable();
        let observed_at = observations[quorum - 1];
        Ok(Self(DelayEvidenceKind::GuardianRecovery {
            provider_policy_id,
            required_quorum,
            observed_at,
            proposal_id,
            receipts,
        }))
    }

    fn proposal_id(&self) -> Option<ProposalId> {
        match &self.0 {
            DelayEvidenceKind::None => None,
            DelayEvidenceKind::ProviderQuorum {
                intent_approvals, ..
            } => Some(intent_approvals.proposal_id()),
            DelayEvidenceKind::GuardianRecovery { proposal_id, .. } => Some(*proposal_id),
        }
    }

    /// Account provider-policy identifier committed by delayed evidence.
    pub const fn provider_policy_id(&self) -> Option<ProviderPolicyId> {
        match &self.0 {
            DelayEvidenceKind::None => None,
            DelayEvidenceKind::ProviderQuorum {
                provider_policy_id, ..
            }
            | DelayEvidenceKind::GuardianRecovery {
                provider_policy_id, ..
            } => Some(*provider_policy_id),
        }
    }

    /// Deterministic quorum-th earliest distinct-provider observation.
    pub const fn observed_at(&self) -> Option<Timestamp> {
        match &self.0 {
            DelayEvidenceKind::None => None,
            DelayEvidenceKind::ProviderQuorum { observed_at, .. }
            | DelayEvidenceKind::GuardianRecovery { observed_at, .. } => Some(*observed_at),
        }
    }

    /// Quorum used to derive the signed observation anchor.
    pub const fn required_quorum(&self) -> Option<crate::ProviderQuorum> {
        match &self.0 {
            DelayEvidenceKind::None => None,
            DelayEvidenceKind::ProviderQuorum {
                required_quorum, ..
            }
            | DelayEvidenceKind::GuardianRecovery {
                required_quorum, ..
            } => Some(*required_quorum),
        }
    }

    /// Threshold-approved intent carried by provider-quorum delay evidence.
    pub const fn intent_approvals(&self) -> Option<&EventIntentApprovals> {
        match &self.0 {
            DelayEvidenceKind::None => None,
            DelayEvidenceKind::ProviderQuorum {
                intent_approvals, ..
            } => Some(intent_approvals),
            DelayEvidenceKind::GuardianRecovery { .. } => None,
        }
    }

    /// Whether the delayed intent carries embedded guardian recovery authority rather than
    /// unrelated controller-intent approvals.
    pub const fn is_guardian_recovery(&self) -> bool {
        matches!(self.0, DelayEvidenceKind::GuardianRecovery { .. })
    }

    /// Signed distinct-provider receipts carried by delayed evidence.
    pub const fn provider_receipts(&self) -> Option<&ProviderReceipts> {
        match &self.0 {
            DelayEvidenceKind::None => None,
            DelayEvidenceKind::ProviderQuorum { receipts, .. }
            | DelayEvidenceKind::GuardianRecovery { receipts, .. } => Some(receipts),
        }
    }
}

impl Serialize for DelayEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.0 {
            DelayEvidenceKind::None => (0u16, ()).serialize(serializer),
            DelayEvidenceKind::ProviderQuorum {
                provider_policy_id,
                required_quorum,
                observed_at,
                intent_approvals,
                receipts,
            } => (
                1u16,
                (
                    provider_policy_id,
                    required_quorum,
                    observed_at,
                    intent_approvals,
                    receipts,
                ),
            )
                .serialize(serializer),
            DelayEvidenceKind::GuardianRecovery {
                provider_policy_id,
                required_quorum,
                observed_at,
                receipts,
                ..
            } => (
                2u16,
                (provider_policy_id, required_quorum, observed_at, receipts),
            )
                .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for DelayEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = DelayEvidence;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("v1 delay evidence")
            }
            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    0 => {
                        sequence
                            .next_element::<()>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        Ok(DelayEvidence::none())
                    }
                    1 => {
                        let (
                            provider_policy_id,
                            required_quorum,
                            observed_at,
                            intent_approvals,
                            receipts,
                        ) = sequence
                            .next_element::<(
                                ProviderPolicyId,
                                crate::ProviderQuorum,
                                Timestamp,
                                EventIntentApprovals,
                                ProviderReceipts,
                            )>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let evidence = DelayEvidence::provider_quorum(
                            provider_policy_id,
                            required_quorum,
                            intent_approvals,
                            receipts,
                        )
                        .map_err(de::Error::custom)?;
                        if evidence.observed_at() != Some(observed_at) {
                            return Err(de::Error::custom(IdentityError::InvalidRelationship {
                                resource: "delay evidence observation anchor",
                            }));
                        }
                        Ok(evidence)
                    }
                    2 => {
                        let (provider_policy_id, required_quorum, observed_at, receipts) = sequence
                            .next_element::<(
                                ProviderPolicyId,
                                crate::ProviderQuorum,
                                Timestamp,
                                ProviderReceipts,
                            )>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let evidence = DelayEvidence::guardian_recovery(
                            provider_policy_id,
                            required_quorum,
                            receipts,
                        )
                        .map_err(de::Error::custom)?;
                        if evidence.observed_at() != Some(observed_at) {
                            return Err(de::Error::custom(IdentityError::InvalidRelationship {
                                resource: "guardian recovery delay evidence observation anchor",
                            }));
                        }
                        Ok(evidence)
                    }
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "delay evidence",
                        code: unsupported,
                    })),
                }
            }
        }
        deserializer.deserialize_tuple(2, Visitor)
    }
}

canonical_schema!(DelayEvidence, "delay evidence bytes");

/// Signed historical evidence used to admit one exact account event body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmissionEvidence {
    protocol_version: ProtocolVersion,
    proposal_id: ProposalId,
    preceding_checkpoint: CheckpointId,
    provider_policy_id: ProviderPolicyId,
    freshness: FreshnessEvidence,
    delay: DelayEvidence,
    extensions: Extensions,
}

impl AdmissionEvidence {
    /// Construct internally consistent event admission evidence.
    pub fn new(
        proposal_id: ProposalId,
        preceding_checkpoint: CheckpointId,
        provider_policy_id: ProviderPolicyId,
        freshness: FreshnessEvidence,
        delay: DelayEvidence,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if freshness.checkpoint_id() != preceding_checkpoint {
            return Err(IdentityError::InvalidRelationship {
                resource: "admission preceding/freshness checkpoint",
            });
        }
        if delay
            .proposal_id()
            .is_some_and(|delayed_proposal| delayed_proposal != proposal_id)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "admission delayed proposal",
            });
        }
        if freshness
            .provider_policy_id()
            .is_some_and(|evidence_policy| evidence_policy != provider_policy_id)
            || delay
                .provider_policy_id()
                .is_some_and(|evidence_policy| evidence_policy != provider_policy_id)
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "admission provider policy",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            proposal_id,
            preceding_checkpoint,
            provider_policy_id,
            freshness,
            delay,
            extensions,
        })
    }

    /// Derive the exact historical admission evidence identifier.
    pub fn admission_evidence_id(&self) -> Result<AdmissionEvidenceId, IdentityError> {
        AdmissionEvidenceId::derive(self)
    }

    /// Derive the final history identifier for the exact body this evidence admits.
    pub fn event_id_for_body(&self, body: &EventBody) -> Result<EventId, IdentityError> {
        if self.proposal_id != body.proposal_id()? {
            return Err(IdentityError::InvalidRelationship {
                resource: "authorized event admission subject",
            });
        }
        body.admitted_event_id(self.admission_evidence_id()?)
    }

    /// Proposal admitted by this evidence.
    pub const fn proposal_id(&self) -> ProposalId {
        self.proposal_id
    }

    /// Prior checkpoint used as the historical admission basis.
    pub const fn preceding_checkpoint(&self) -> CheckpointId {
        self.preceding_checkpoint
    }

    /// Exact pre-state account provider-policy identifier.
    pub const fn provider_policy_id(&self) -> ProviderPolicyId {
        self.provider_policy_id
    }

    /// Historical freshness basis.
    pub const fn freshness(&self) -> &FreshnessEvidence {
        &self.freshness
    }

    /// Historical policy-delay basis.
    pub const fn delay(&self) -> &DelayEvidence {
        &self.delay
    }
}

impl<'de> Deserialize<'de> for AdmissionEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            proposal_id: ProposalId,
            preceding_checkpoint: CheckpointId,
            provider_policy_id: ProviderPolicyId,
            freshness: FreshnessEvidence,
            delay: DelayEvidence,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        Self::new(
            wire.proposal_id,
            wire.preceding_checkpoint,
            wire.provider_policy_id,
            wire.freshness,
            wire.delay,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

canonical_schema!(AdmissionEvidence, "admission evidence bytes");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControllerApprovalSubject {
    Event {
        event_id: EventId,
        admission_evidence_id: AdmissionEvidenceId,
    },
    Checkpoint(CheckpointId),
}

impl Serialize for ControllerApprovalSubject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Event {
                event_id,
                admission_evidence_id,
            } => (1u16, (event_id, admission_evidence_id)).serialize(serializer),
            Self::Checkpoint(checkpoint_id) => (2u16, checkpoint_id).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ControllerApprovalSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ControllerApprovalSubject;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("v1 controller approval subject")
            }
            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let code = sequence
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                match code {
                    1 => {
                        let (event_id, admission_evidence_id) = sequence
                            .next_element::<(EventId, AdmissionEvidenceId)>()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        Ok(ControllerApprovalSubject::Event {
                            event_id,
                            admission_evidence_id,
                        })
                    }
                    2 => Ok(ControllerApprovalSubject::Checkpoint(
                        sequence
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    )),
                    unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                        registry: "controller approval subject",
                        code: unsupported,
                    })),
                }
            }
        }
        deserializer.deserialize_tuple(2, Visitor)
    }
}

/// Exact controller approval body; signatures form an outer mergeable set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControllerApprovalBody {
    protocol_version: ProtocolVersion,
    controller_id: ControllerId,
    subject: ControllerApprovalSubject,
    extensions: Extensions,
}

impl ControllerApprovalBody {
    /// Construct a final account-event approval body.
    pub fn event(
        controller_id: ControllerId,
        event_id: EventId,
        admission_evidence_id: AdmissionEvidenceId,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            controller_id,
            subject: ControllerApprovalSubject::Event {
                event_id,
                admission_evidence_id,
            },
            extensions,
        })
    }

    /// Construct a checkpoint approval body.
    pub fn checkpoint(
        controller_id: ControllerId,
        checkpoint_id: CheckpointId,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            controller_id,
            subject: ControllerApprovalSubject::Checkpoint(checkpoint_id),
            extensions,
        })
    }

    /// Approving controller.
    pub const fn controller_id(&self) -> ControllerId {
        self.controller_id
    }

    /// Approved checkpoint, when this body is a checkpoint approval.
    pub const fn checkpoint_id(&self) -> Option<CheckpointId> {
        match self.subject {
            ControllerApprovalSubject::Checkpoint(id) => Some(id),
            ControllerApprovalSubject::Event { .. } => None,
        }
    }

    /// Approved event and evidence IDs, when this is an event approval.
    pub const fn event_subject(&self) -> Option<(EventId, AdmissionEvidenceId)> {
        match self.subject {
            ControllerApprovalSubject::Event {
                event_id,
                admission_evidence_id,
            } => Some((event_id, admission_evidence_id)),
            ControllerApprovalSubject::Checkpoint(_) => None,
        }
    }

    /// Derive the exact signed approval-body identifier.
    pub fn controller_approval_id(&self) -> Result<ControllerApprovalId, IdentityError> {
        ControllerApprovalId::derive(self)
    }
}

impl<'de> Deserialize<'de> for ControllerApprovalBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            controller_id: ControllerId,
            subject: ControllerApprovalSubject,
            extensions: Extensions,
        }
        let wire = Wire::deserialize(deserializer)?;
        let _ = wire.protocol_version;
        match wire.subject {
            ControllerApprovalSubject::Event {
                event_id,
                admission_evidence_id,
            } => Self::event(
                wire.controller_id,
                event_id,
                admission_evidence_id,
                wire.extensions,
            ),
            ControllerApprovalSubject::Checkpoint(checkpoint_id) => {
                Self::checkpoint(wire.controller_id, checkpoint_id, wire.extensions)
            }
        }
        .map_err(de::Error::custom)
    }
}

canonical_schema!(ControllerApprovalBody, "controller approval body bytes");

/// Mergeable suite signatures from one controller over one approval body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignedControllerApproval {
    body: ControllerApprovalBody,
    signatures: BoundedVec<KeyedSignature, MAX_ACTIVE_CRYPTO_SUITES>,
}

impl SignedControllerApproval {
    /// Sort and construct duplicate-free suite signatures.
    pub fn new(
        body: ControllerApprovalBody,
        mut signatures: Vec<KeyedSignature>,
    ) -> Result<Self, IdentityError> {
        signatures.sort_unstable_by_key(KeyedSignature::sort_key);
        Self::from_sorted(body, signatures)
    }

    fn from_sorted(
        body: ControllerApprovalBody,
        signatures: Vec<KeyedSignature>,
    ) -> Result<Self, IdentityError> {
        if signatures.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "controller approval signatures",
            });
        }
        let signatures = BoundedVec::new("controller approval signatures", signatures)?;
        for pair in signatures.as_slice().windows(2) {
            if pair[0].sort_key() == pair[1].sort_key() {
                return Err(IdentityError::DuplicateElement {
                    resource: "controller approval signatures",
                });
            }
            if pair[0].sort_key() > pair[1].sort_key() {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self { body, signatures })
    }

    /// Signed approval body.
    pub const fn body(&self) -> &ControllerApprovalBody {
        &self.body
    }

    /// Sorted suite signatures over the canonical approval body.
    pub fn signatures(&self) -> &[KeyedSignature] {
        self.signatures.as_slice()
    }

    /// Merge canonical suite signatures for the same exact controller approval body.
    ///
    /// Repeating an identical signature is idempotent. Two different signatures claiming the
    /// same suite/key slot are rejected instead of selecting one by arrival order.
    pub fn merge(&self, other: &Self) -> Result<Self, IdentityError> {
        if self.body != other.body {
            return Err(IdentityError::InvalidRelationship {
                resource: "merged controller approval body",
            });
        }
        let mut signatures = self.signatures.as_slice().to_vec();
        signatures.extend_from_slice(other.signatures.as_slice());
        signatures.sort_unstable_by_key(KeyedSignature::sort_key);
        let mut merged: Vec<KeyedSignature> = Vec::with_capacity(signatures.len());
        for signature in signatures {
            if let Some(previous) = merged.last()
                && previous.sort_key() == signature.sort_key()
            {
                if previous != &signature {
                    return Err(IdentityError::InvalidSignature);
                }
                continue;
            }
            merged.push(signature);
        }
        Self::from_sorted(self.body.clone(), merged)
    }
}

impl<'de> Deserialize<'de> for SignedControllerApproval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            body: ControllerApprovalBody,
            signatures: BoundedVec<KeyedSignature, MAX_ACTIVE_CRYPTO_SUITES>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::from_sorted(wire.body, wire.signatures.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(SignedControllerApproval, "signed controller approval bytes");

/// Sorted, duplicate-free final controller approvals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControllerApprovals(BoundedVec<SignedControllerApproval, MAX_AUTHORIZATION_SIGNATURES>);

impl ControllerApprovals {
    /// Sort approvals by controller identifier.
    pub fn new(mut approvals: Vec<SignedControllerApproval>) -> Result<Self, IdentityError> {
        approvals.sort_unstable_by_key(|approval| approval.body().controller_id());
        Self::from_sorted(approvals)
    }

    fn from_sorted(approvals: Vec<SignedControllerApproval>) -> Result<Self, IdentityError> {
        let approvals = BoundedVec::new("controller approvals", approvals)?;
        for pair in approvals.as_slice().windows(2) {
            let left = pair[0].body().controller_id();
            let right = pair[1].body().controller_id();
            if left == right {
                return Err(IdentityError::DuplicateElement {
                    resource: "controller approvals",
                });
            }
            if left > right {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self(approvals))
    }

    /// Canonically ordered controller approvals.
    ///
    /// An empty set is only valid when the containing [`AuthorizedEvent`] operation carries its
    /// complete authority elsewhere. [`AuthorizedEvent::new`] enforces that contextual rule.
    pub fn as_slice(&self) -> &[SignedControllerApproval] {
        self.0.as_slice()
    }

    /// Merge controller evidence as a canonical signer/signature union.
    ///
    /// The operation is commutative and idempotent for identical valid evidence. Approvals from
    /// the same controller must bind the same exact approval body.
    pub fn merge(&self, other: &Self) -> Result<Self, IdentityError> {
        let mut merged = self.0.as_slice().to_vec();
        for incoming in other.0.as_slice() {
            let controller_id = incoming.body().controller_id();
            match merged
                .binary_search_by_key(&controller_id, |approval| approval.body().controller_id())
            {
                Ok(index) => merged[index] = merged[index].merge(incoming)?,
                Err(index) => merged.insert(index, incoming.clone()),
            }
        }
        Self::from_sorted(merged)
    }
}

impl<'de> Deserialize<'de> for ControllerApprovals {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values =
            BoundedVec::<SignedControllerApproval, MAX_AUTHORIZATION_SIGNATURES>::deserialize(
                deserializer,
            )?;
        Self::from_sorted(values.into_vec()).map_err(de::Error::custom)
    }
}

canonical_schema!(ControllerApprovals, "controller approval set bytes");

/// Complete admitted account event with mergeable final controller approvals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizedEvent {
    body: EventBody,
    admission_evidence: AdmissionEvidence,
    approvals: ControllerApprovals,
}

impl AuthorizedEvent {
    /// Construct an event whose evidence and every approval bind the same body IDs.
    pub fn new(
        body: EventBody,
        admission_evidence: AdmissionEvidence,
        approvals: ControllerApprovals,
    ) -> Result<Self, IdentityError> {
        let event_id = admission_evidence.event_id_for_body(&body)?;
        if let AccountOperation::BeginRecovery(begin) = body.operation()
            && admission_evidence.preceding_checkpoint()
                != begin.proposal().plan().prior_checkpoint_id()
        {
            return Err(IdentityError::InvalidRelationship {
                resource: "begin recovery admission checkpoint",
            });
        }
        let requires_empty_controller_approvals = match body.operation() {
            AccountOperation::BeginRecovery(begin) => {
                begin.threshold_evidence().as_guardian_approvals().is_some()
            }
            AccountOperation::CancelRecovery(cancel) => cancel
                .threshold_evidence()
                .as_guardian_approvals()
                .is_some(),
            AccountOperation::FinalizeRecovery(_) => true,
            _ => false,
        };
        if approvals.as_slice().is_empty() != requires_empty_controller_approvals {
            return Err(IdentityError::InvalidRelationship {
                resource: "authorized event controller approval cardinality",
            });
        }
        let admission_evidence_id = admission_evidence.admission_evidence_id()?;
        if approvals.as_slice().iter().any(|approval| {
            approval.body().event_subject() != Some((event_id, admission_evidence_id))
        }) {
            return Err(IdentityError::InvalidRelationship {
                resource: "authorized event approval subject",
            });
        }
        let event = Self {
            body,
            admission_evidence,
            approvals,
        };
        let encoded_len = encode_wire(&event)?.len();
        if encoded_len > MAX_ACCOUNT_EVENT_BYTES {
            return Err(IdentityError::limit(
                "authorized account event bytes",
                encoded_len,
                MAX_ACCOUNT_EVENT_BYTES,
            ));
        }
        Ok(event)
    }

    /// Canonical body whose intent ID is committed by the stable event identifier.
    pub const fn body(&self) -> &EventBody {
        &self.body
    }

    /// Historical freshness and delay basis bound by final approvals.
    pub const fn admission_evidence(&self) -> &AdmissionEvidence {
        &self.admission_evidence
    }

    /// Sorted final controller approvals, mergeable without changing the event ID.
    pub const fn approvals(&self) -> &ControllerApprovals {
        &self.approvals
    }

    /// Stable event identifier committing the body and exact admission evidence.
    pub fn event_id(&self) -> Result<EventId, IdentityError> {
        self.admission_evidence.event_id_for_body(&self.body)
    }

    /// Domain-separated identifier of this exact evidence-and-approval envelope.
    ///
    /// Unlike [`EventId`], this identifier changes when valid late approvals are merged. It is
    /// used only when a checkpoint explicitly refers to the retained complete proof.
    pub fn event_authorization_id(&self) -> Result<EventAuthorizationId, IdentityError> {
        EventAuthorizationId::derive(self)
    }
}

impl<'de> Deserialize<'de> for AuthorizedEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            body: EventBody,
            admission_evidence: AdmissionEvidence,
            approvals: ControllerApprovals,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.body, wire.admission_evidence, wire.approvals).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for AuthorizedEvent {
    const RESOURCE: &'static str = "authorized account event bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}
