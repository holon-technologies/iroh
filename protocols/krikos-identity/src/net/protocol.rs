//! Concrete one-request-per-connection handlers for the six identity v1 ALPNs.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use krikos::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::{
    AccountId, AccountStore, AuthenticatedTransportBinding, CanonicalWire, CheckpointId, CursorKey,
    DeviceAuthorizationProposal, DeviceId, Digest, HashAlgorithm, IdentityError, PairingTicket,
    ProtocolVersion, RecoveryProposal, SignedCheckpoint, SignedProviderHead, StoreFuture,
    SyncRequest, SyncResponse, SyncSessionBudget,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{
        IDENTITY_QUEUE_CAPACITY, MAX_ACCOUNT_EVENT_BYTES, MAX_CONCURRENT_IDENTITY_TASKS,
        MAX_ENCODED_OBJECT_BYTES, MAX_PAIRING_TICKET_BYTES, MAX_SYNC_FRAME_BYTES,
    },
    sync::serve_sync_request_with_meter,
    transport::{
        AuthorizedEndpointStream, CHECKPOINT_ALPN, PAIRING_ALPN, PROPOSAL_ALPN, RECOVERY_ALPN,
        SYNC_ALPN, TRANSPARENCY_GOSSIP_ALPN, VerifiedCheckpointView, authorize_endpoint_stream,
    },
};

use super::{
    PairingEndpointRole, framed_network_bytes, pairing_binding_from_connection, read_bounded_frame,
    write_bounded_frame,
};

const REQUEST_COMMITMENT_CONTEXT: &str = "KRIKOS-ID/network-request-commitment/v1";
const REPLY_ACK_CODE: u16 = 1;
const REPLY_SYNC_CODE: u16 = 2;

macro_rules! canonical_schema {
    ($name:ty, $resource:literal, $maximum:expr) => {
        impl CanonicalCodec for $name {
            const RESOURCE: &'static str = $resource;
            const MAX_ENCODED_BYTES: usize = $maximum;

            fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
                encode_wire(self)
            }

            fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
                decode_wire(bytes)
            }
        }
    };
}

/// Frozen identity protocol discriminator and its exact negotiated ALPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityProtocolKind {
    /// Authenticated device pairing.
    Pairing,
    /// Frozen-revision account synchronization.
    Sync,
    /// Device authorization proposal delivery.
    Proposal,
    /// Signed checkpoint delivery.
    Checkpoint,
    /// Signed transparency-head gossip.
    TransparencyGossip,
    /// Guardian recovery proposal delivery.
    Recovery,
}

impl IdentityProtocolKind {
    /// Stable v1 network response codepoint.
    pub const fn code(self) -> u16 {
        match self {
            Self::Pairing => 1,
            Self::Sync => 2,
            Self::Proposal => 3,
            Self::Checkpoint => 4,
            Self::TransparencyGossip => 5,
            Self::Recovery => 6,
        }
    }

    /// Exact ALPN that must have completed negotiation for this handler.
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Pairing => PAIRING_ALPN,
            Self::Sync => SYNC_ALPN,
            Self::Proposal => PROPOSAL_ALPN,
            Self::Checkpoint => CHECKPOINT_ALPN,
            Self::TransparencyGossip => TRANSPARENCY_GOSSIP_ALPN,
            Self::Recovery => RECOVERY_ALPN,
        }
    }

    fn from_code(code: u16) -> Result<Self, IdentityError> {
        match code {
            1 => Ok(Self::Pairing),
            2 => Ok(Self::Sync),
            3 => Ok(Self::Proposal),
            4 => Ok(Self::Checkpoint),
            5 => Ok(Self::TransparencyGossip),
            6 => Ok(Self::Recovery),
            _ => Err(IdentityError::UnsupportedCodepoint {
                registry: "identity network protocol",
                code,
            }),
        }
    }

    const fn maximum_request_bytes(self) -> usize {
        match self {
            Self::Pairing => MAX_PAIRING_TICKET_BYTES,
            Self::Proposal | Self::Recovery => MAX_ACCOUNT_EVENT_BYTES,
            Self::Sync => MAX_SYNC_FRAME_BYTES,
            Self::Checkpoint | Self::TransparencyGossip => MAX_ENCODED_OBJECT_BYTES,
        }
    }
}

/// Exact account-device authorization coordinates carried by device-authorized requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EndpointAuthorizationRequest {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    device_id: DeviceId,
}

impl EndpointAuthorizationRequest {
    /// Bind a request to one exact verified checkpoint and active device.
    pub const fn new(
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        device_id: DeviceId,
    ) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            checkpoint_id,
            device_id,
        }
    }

    /// Requested account.
    pub const fn account_id(self) -> AccountId {
        self.account_id
    }

    /// Exact verified checkpoint used for endpoint authorization.
    pub const fn checkpoint_id(self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Device expected to own the authenticated remote endpoint.
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }
}

impl<'de> Deserialize<'de> for EndpointAuthorizationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            checkpoint_id: CheckpointId,
            device_id: DeviceId,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(serde::de::Error::custom(
                IdentityError::UnsupportedVersion {
                    version: wire.protocol_version.get(),
                },
            ));
        }
        Ok(Self::new(
            wire.account_id,
            wire.checkpoint_id,
            wire.device_id,
        ))
    }
}

impl CanonicalCodec for EndpointAuthorizationRequest {
    const RESOURCE: &'static str = "endpoint authorization request bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ENCODED_OBJECT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        #[derive(Deserialize, Serialize)]
        struct Wire {
            protocol_version: u16,
            account_id: AccountId,
            checkpoint_id: CheckpointId,
            device_id: DeviceId,
        }

        let wire: Wire = decode_wire(bytes)?;
        ProtocolVersion::new(wire.protocol_version)?;
        Ok(Self::new(
            wire.account_id,
            wire.checkpoint_id,
            wire.device_id,
        ))
    }
}

/// Checkpoint-authorized synchronization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizedSyncRequest {
    authorization: EndpointAuthorizationRequest,
    request: SyncRequest,
}

impl AuthorizedSyncRequest {
    /// Construct a request whose account matches the authorization coordinates.
    pub fn new(
        authorization: EndpointAuthorizationRequest,
        request: SyncRequest,
    ) -> Result<Self, IdentityError> {
        if authorization.account_id != request.account_id() {
            return Err(IdentityError::AccountMismatch);
        }
        Ok(Self {
            authorization,
            request,
        })
    }

    /// Unverified authorization coordinates.
    pub const fn authorization(&self) -> EndpointAuthorizationRequest {
        self.authorization
    }

    /// Bounded synchronization request.
    pub const fn request(&self) -> &SyncRequest {
        &self.request
    }
}

impl<'de> Deserialize<'de> for AuthorizedSyncRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            authorization: EndpointAuthorizationRequest,
            request: SyncRequest,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.authorization, wire.request).map_err(serde::de::Error::custom)
    }
}

canonical_schema!(
    AuthorizedSyncRequest,
    "authorized sync request bytes",
    MAX_SYNC_FRAME_BYTES
);

/// Checkpoint-authorized device proposal request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizedProposalRequest {
    authorization: EndpointAuthorizationRequest,
    proposal: DeviceAuthorizationProposal,
}

impl AuthorizedProposalRequest {
    /// Construct a request whose account matches the proposal.
    pub fn new(
        authorization: EndpointAuthorizationRequest,
        proposal: DeviceAuthorizationProposal,
    ) -> Result<Self, IdentityError> {
        if authorization.account_id != proposal.account_id() {
            return Err(IdentityError::AccountMismatch);
        }
        Ok(Self {
            authorization,
            proposal,
        })
    }

    /// Unverified authorization coordinates.
    pub const fn authorization(&self) -> EndpointAuthorizationRequest {
        self.authorization
    }

    /// Bounded pairing-derived proposal.
    pub const fn proposal(&self) -> &DeviceAuthorizationProposal {
        &self.proposal
    }
}

impl<'de> Deserialize<'de> for AuthorizedProposalRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            authorization: EndpointAuthorizationRequest,
            proposal: DeviceAuthorizationProposal,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.authorization, wire.proposal).map_err(serde::de::Error::custom)
    }
}

canonical_schema!(
    AuthorizedProposalRequest,
    "authorized proposal request bytes",
    MAX_ACCOUNT_EVENT_BYTES
);

/// Checkpoint-authorized signed-checkpoint request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizedCheckpointRequest {
    authorization: EndpointAuthorizationRequest,
    checkpoint: SignedCheckpoint,
}

impl AuthorizedCheckpointRequest {
    /// Construct a request whose account matches the checkpoint body.
    pub fn new(
        authorization: EndpointAuthorizationRequest,
        checkpoint: SignedCheckpoint,
    ) -> Result<Self, IdentityError> {
        if authorization.account_id != checkpoint.body().account_id() {
            return Err(IdentityError::AccountMismatch);
        }
        Ok(Self {
            authorization,
            checkpoint,
        })
    }

    /// Unverified authorization coordinates.
    pub const fn authorization(&self) -> EndpointAuthorizationRequest {
        self.authorization
    }

    /// Bounded signed checkpoint.
    pub const fn checkpoint(&self) -> &SignedCheckpoint {
        &self.checkpoint
    }
}

impl<'de> Deserialize<'de> for AuthorizedCheckpointRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            authorization: EndpointAuthorizationRequest,
            checkpoint: SignedCheckpoint,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.authorization, wire.checkpoint).map_err(serde::de::Error::custom)
    }
}

canonical_schema!(
    AuthorizedCheckpointRequest,
    "authorized checkpoint request bytes",
    MAX_ENCODED_OBJECT_BYTES
);

/// Validated nonzero application rejection code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRejectionCode(u16);

impl ServiceRejectionCode {
    /// Stable default-deny code used when a service method is not implemented.
    pub const UNAVAILABLE: Self = Self(1);

    /// Validate a caller-owned nonzero rejection code.
    pub fn new(code: u16) -> Result<Self, IdentityError> {
        if code == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "identity service rejection code",
            });
        }
        Ok(Self(code))
    }

    /// Stable caller-defined code.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Observable caller-owned decision for one fully decoded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityServiceOutcome {
    /// The caller accepted the request and permits the handler response.
    Accepted,
    /// The caller rejected the request under a stable nonzero application code.
    Rejected(ServiceRejectionCode),
}

fn default_rejection<'a>() -> StoreFuture<'a, IdentityServiceOutcome> {
    Box::pin(async {
        Ok(IdentityServiceOutcome::Rejected(
            ServiceRejectionCode::UNAVAILABLE,
        ))
    })
}

/// Caller-owned deterministic service boundary for all six decoded v1 request classes.
///
/// Every method defaults to deny. Implementations receive authenticated endpoint capabilities,
/// never raw endpoint hints, for protocols that require account-device authority.
pub trait IdentityProtocolService: fmt::Debug + Send + Sync + 'static {
    /// Process one pairing ticket bound to the completed transport handshake.
    fn pairing(
        &self,
        _transport: AuthenticatedTransportBinding,
        _ticket: PairingTicket,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        default_rejection()
    }

    /// Observe one store-derived synchronization result before it is returned.
    fn sync(
        &self,
        _authorized: AuthorizedEndpointStream,
        _request: SyncRequest,
        _response: SyncResponse,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        default_rejection()
    }

    /// Process one checkpoint-authorized device proposal.
    fn proposal(
        &self,
        _authorized: AuthorizedEndpointStream,
        _proposal: DeviceAuthorizationProposal,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        default_rejection()
    }

    /// Process one checkpoint-authorized signed checkpoint.
    fn checkpoint(
        &self,
        _authorized: AuthorizedEndpointStream,
        _checkpoint: SignedCheckpoint,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        default_rejection()
    }

    /// Process one signed transparency head from its authenticated transport peer.
    fn transparency_gossip(
        &self,
        _remote_endpoint: crate::EndpointPublicKey,
        _head: SignedProviderHead,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        default_rejection()
    }

    /// Process one guardian recovery proposal from its authenticated transport peer.
    fn recovery(
        &self,
        _remote_endpoint: crate::EndpointPublicKey,
        _proposal: RecoveryProposal,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        default_rejection()
    }
}

/// Default-deny service useful while individual operational integrations are installed.
#[derive(Debug, Default)]
pub struct DenyIdentityProtocolService;

impl IdentityProtocolService for DenyIdentityProtocolService {}

/// Canonical acknowledgement of a caller-owned service decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityProtocolAck {
    protocol_version: ProtocolVersion,
    protocol_code: u16,
    request_commitment: Digest,
    decision_code: u16,
}

impl IdentityProtocolAck {
    /// Commit one exact canonical request and caller-owned service outcome.
    pub fn for_canonical_request(
        kind: IdentityProtocolKind,
        canonical_request: &[u8],
        outcome: IdentityServiceOutcome,
    ) -> Self {
        let mut commitment_hasher = blake3::Hasher::new_derive_key(REQUEST_COMMITMENT_CONTEXT);
        commitment_hasher.update(&kind.code().to_be_bytes());
        commitment_hasher.update(canonical_request);
        let request_commitment = Digest::new(
            HashAlgorithm::Blake3_256,
            *commitment_hasher.finalize().as_bytes(),
        );
        let decision_code = match outcome {
            IdentityServiceOutcome::Accepted => 0,
            IdentityServiceOutcome::Rejected(code) => code.get(),
        };
        Self {
            protocol_version: ProtocolVersion::V1,
            protocol_code: kind.code(),
            request_commitment,
            decision_code,
        }
    }

    /// Protocol whose request was processed.
    pub fn protocol(&self) -> Result<IdentityProtocolKind, IdentityError> {
        IdentityProtocolKind::from_code(self.protocol_code)
    }

    /// Domain-separated commitment to the exact canonical request bytes.
    pub const fn request_commitment(&self) -> Digest {
        self.request_commitment
    }

    /// Whether the caller-owned service accepted the request.
    pub const fn accepted(&self) -> bool {
        self.decision_code == 0
    }

    /// Caller-owned rejection code, or `None` for acceptance.
    pub fn rejection_code(&self) -> Result<Option<ServiceRejectionCode>, IdentityError> {
        if self.decision_code == 0 {
            Ok(None)
        } else {
            ServiceRejectionCode::new(self.decision_code).map(Some)
        }
    }
}

impl<'de> Deserialize<'de> for IdentityProtocolAck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            protocol_code: u16,
            request_commitment: Digest,
            decision_code: u16,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(serde::de::Error::custom(
                IdentityError::UnsupportedVersion {
                    version: wire.protocol_version.get(),
                },
            ));
        }
        IdentityProtocolKind::from_code(wire.protocol_code).map_err(serde::de::Error::custom)?;
        Ok(Self {
            protocol_version: wire.protocol_version,
            protocol_code: wire.protocol_code,
            request_commitment: wire.request_commitment,
            decision_code: wire.decision_code,
        })
    }
}

canonical_schema!(
    IdentityProtocolAck,
    "identity protocol acknowledgement bytes",
    MAX_ENCODED_OBJECT_BYTES
);

/// One bounded response from a concrete identity protocol handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityProtocolReply {
    protocol_version: ProtocolVersion,
    reply_code: u16,
    ack: Option<IdentityProtocolAck>,
    sync: Option<SyncResponse>,
}

impl IdentityProtocolReply {
    /// Wrap one canonical service acknowledgement.
    pub const fn acknowledgement(ack: IdentityProtocolAck) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            reply_code: REPLY_ACK_CODE,
            ack: Some(ack),
            sync: None,
        }
    }

    /// Wrap one accepted synchronization page.
    pub const fn synchronization(response: SyncResponse) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            reply_code: REPLY_SYNC_CODE,
            ack: None,
            sync: Some(response),
        }
    }

    /// Service acknowledgement, when the reply is not a successful sync data page.
    pub const fn as_ack(&self) -> Option<&IdentityProtocolAck> {
        self.ack.as_ref()
    }

    /// Store-derived synchronization response, when accepted by the service.
    pub const fn as_sync(&self) -> Option<&SyncResponse> {
        self.sync.as_ref()
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.protocol_version.get(),
            });
        }
        match (self.reply_code, &self.ack, &self.sync) {
            (REPLY_ACK_CODE, Some(_), None) | (REPLY_SYNC_CODE, None, Some(_)) => Ok(()),
            (REPLY_ACK_CODE | REPLY_SYNC_CODE, _, _) => Err(IdentityError::InvalidRelationship {
                resource: "identity protocol reply payload",
            }),
            (code, _, _) => Err(IdentityError::UnsupportedCodepoint {
                registry: "identity protocol reply",
                code,
            }),
        }
    }
}

impl<'de> Deserialize<'de> for IdentityProtocolReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            reply_code: u16,
            ack: Option<IdentityProtocolAck>,
            sync: Option<SyncResponse>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let reply = Self {
            protocol_version: wire.protocol_version,
            reply_code: wire.reply_code,
            ack: wire.ack,
            sync: wire.sync,
        };
        reply.validate().map_err(serde::de::Error::custom)?;
        Ok(reply)
    }
}

canonical_schema!(
    IdentityProtocolReply,
    "identity protocol reply bytes",
    MAX_SYNC_FRAME_BYTES
);

#[derive(Debug)]
struct IdentityHandlerSupervisor {
    cancellation: CancellationToken,
    permits: Arc<Semaphore>,
    reservations: AtomicUsize,
}

impl IdentityHandlerSupervisor {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancellation: CancellationToken::new(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_IDENTITY_TASKS)),
            reservations: AtomicUsize::new(0),
        })
    }

    fn reserve(self: &Arc<Self>) -> Result<IdentityHandlerReservation, IdentityError> {
        if self.cancellation.is_cancelled() {
            return Err(IdentityError::Cancelled);
        }
        self.reservations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                if current < IDENTITY_QUEUE_CAPACITY {
                    current.checked_add(1)
                } else {
                    None
                }
            })
            .map_err(|_| IdentityError::ResourceBusy)?;
        Ok(IdentityHandlerReservation {
            supervisor: self.clone(),
            permit: None,
        })
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }
}

#[derive(Debug)]
struct IdentityHandlerReservation {
    supervisor: Arc<IdentityHandlerSupervisor>,
    permit: Option<OwnedSemaphorePermit>,
}

impl IdentityHandlerReservation {
    async fn activate(mut self) -> Result<Self, IdentityError> {
        let permit = tokio::select! {
            () = self.supervisor.cancellation.cancelled() => {
                return Err(IdentityError::Cancelled);
            }
            permit = self.supervisor.permits.clone().acquire_owned() => {
                permit.map_err(|_| IdentityError::Cancelled)?
            }
        };
        self.permit = Some(permit);
        Ok(self)
    }
}

impl Drop for IdentityHandlerReservation {
    fn drop(&mut self) {
        let previous = self.supervisor.reservations.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "identity handler reservation underflow");
    }
}

/// Factory sharing bounded services, authorization, source history, and cancellation.
#[derive(Clone)]
pub struct IdentityProtocolHandlers {
    service: Arc<dyn IdentityProtocolService>,
    checkpoints: Arc<dyn VerifiedCheckpointView>,
    store: Arc<dyn AccountStore>,
    cursor_key: Arc<CursorKey>,
    supervisor: Arc<IdentityHandlerSupervisor>,
}

impl fmt::Debug for IdentityProtocolHandlers {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityProtocolHandlers")
            .finish_non_exhaustive()
    }
}

impl IdentityProtocolHandlers {
    /// Construct all six handlers around one shared service, store, and supervisor.
    pub fn new(
        service: Arc<dyn IdentityProtocolService>,
        checkpoints: Arc<dyn VerifiedCheckpointView>,
        store: Arc<dyn AccountStore>,
        cursor_key: CursorKey,
    ) -> Self {
        Self {
            service,
            checkpoints,
            store,
            cursor_key: Arc::new(cursor_key),
            supervisor: IdentityHandlerSupervisor::new(),
        }
    }

    /// Build one concrete handler for an exact ALPN registration.
    pub fn handler(&self, kind: IdentityProtocolKind) -> IdentityProtocolHandler {
        IdentityProtocolHandler {
            kind,
            shared: self.clone(),
        }
    }
}

/// Bounded supervised handler for one exact identity protocol ALPN.
#[derive(Clone)]
pub struct IdentityProtocolHandler {
    kind: IdentityProtocolKind,
    shared: IdentityProtocolHandlers,
}

impl fmt::Debug for IdentityProtocolHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityProtocolHandler")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl ProtocolHandler for IdentityProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        self.accept_owned(connection)
            .await
            .map_err(AcceptError::from_err)
    }

    async fn shutdown(&self) {
        self.shared.supervisor.cancel();
    }
}

impl IdentityProtocolHandler {
    async fn accept_owned(&self, connection: Connection) -> Result<(), IdentityError> {
        if connection.alpn() != self.kind.alpn() {
            return Err(IdentityError::InvalidRelationship {
                resource: "identity handler negotiated ALPN",
            });
        }
        let reservation = self.shared.supervisor.reserve()?;
        let _active = reservation.activate().await?;
        let outcome = self.process_one_stream(connection.clone()).await;
        if outcome.is_err() {
            connection.close(0_u32.into(), b"identity request rejected");
        }
        outcome
    }

    async fn process_one_stream(&self, connection: Connection) -> Result<(), IdentityError> {
        let (mut send, mut receive) = tokio::select! {
            () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
            streams = connection.accept_bi() => streams.map_err(|_| IdentityError::InvalidEncoding)?,
        };
        let mut budget = SyncSessionBudget::new();
        let request_bytes = tokio::select! {
            () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
            bytes = read_bounded_frame(
                &mut receive,
                &mut budget,
                self.kind.maximum_request_bytes(),
            ) => bytes?,
        };
        let reply = self.dispatch(&connection, &request_bytes).await?;
        let reply_bytes = reply.to_canonical_bytes()?;
        budget.charge_bytes(framed_network_bytes(reply_bytes.len())?)?;
        tokio::select! {
            () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
            result = write_bounded_frame(&mut send, &reply_bytes, MAX_SYNC_FRAME_BYTES) => result?,
        }
        send.finish().map_err(|_| IdentityError::Cancelled)?;
        tokio::select! {
            () = self.shared.supervisor.cancellation.cancelled() => {
                return Err(IdentityError::Cancelled);
            }
            _ = connection.closed() => {}
        }
        Ok(())
    }

    async fn dispatch(
        &self,
        connection: &Connection,
        request_bytes: &[u8],
    ) -> Result<IdentityProtocolReply, IdentityError> {
        let remote_endpoint = super::endpoint_key_from_krikos(connection.remote_id())?;
        match self.kind {
            IdentityProtocolKind::Pairing => {
                let ticket = PairingTicket::from_canonical_bytes(request_bytes)?;
                let binding =
                    pairing_binding_from_connection(connection, PairingEndpointRole::Controller)?;
                if ticket.proposed_endpoint() != binding.proposed_endpoint() {
                    return Err(IdentityError::DeviceNotAuthorized);
                }
                let outcome = tokio::select! {
                    () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
                    outcome = self.shared.service.pairing(binding, ticket) => outcome?,
                };
                Ok(IdentityProtocolReply::acknowledgement(
                    IdentityProtocolAck::for_canonical_request(self.kind, request_bytes, outcome),
                ))
            }
            IdentityProtocolKind::Sync => {
                let request = AuthorizedSyncRequest::from_canonical_bytes(request_bytes)?;
                let authorized = self.authorize(request.authorization, remote_endpoint)?;
                let sync_request = request.request;
                let response = serve_sync_request_with_meter(
                    self.shared.store.as_ref(),
                    self.shared.cursor_key.as_ref(),
                    &sync_request,
                    framed_network_bytes(request_bytes.len())?,
                    sync_reply_framed_bytes,
                )
                .await?;
                let outcome = tokio::select! {
                    () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
                    outcome = self.shared.service.sync(authorized, sync_request, response.clone()) => outcome?,
                };
                match outcome {
                    IdentityServiceOutcome::Accepted => {
                        Ok(IdentityProtocolReply::synchronization(response))
                    }
                    IdentityServiceOutcome::Rejected(_) => {
                        Ok(IdentityProtocolReply::acknowledgement(
                            IdentityProtocolAck::for_canonical_request(
                                self.kind,
                                request_bytes,
                                outcome,
                            ),
                        ))
                    }
                }
            }
            IdentityProtocolKind::Proposal => {
                let request = AuthorizedProposalRequest::from_canonical_bytes(request_bytes)?;
                let authorized = self.authorize(request.authorization, remote_endpoint)?;
                let outcome = tokio::select! {
                    () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
                    outcome = self.shared.service.proposal(authorized, request.proposal) => outcome?,
                };
                Ok(IdentityProtocolReply::acknowledgement(
                    IdentityProtocolAck::for_canonical_request(self.kind, request_bytes, outcome),
                ))
            }
            IdentityProtocolKind::Checkpoint => {
                let request = AuthorizedCheckpointRequest::from_canonical_bytes(request_bytes)?;
                let authorized = self.authorize(request.authorization, remote_endpoint)?;
                let outcome = tokio::select! {
                    () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
                    outcome = self.shared.service.checkpoint(authorized, request.checkpoint) => outcome?,
                };
                Ok(IdentityProtocolReply::acknowledgement(
                    IdentityProtocolAck::for_canonical_request(self.kind, request_bytes, outcome),
                ))
            }
            IdentityProtocolKind::TransparencyGossip => {
                let head = SignedProviderHead::from_canonical_bytes(request_bytes)?;
                let outcome = tokio::select! {
                    () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
                    outcome = self.shared.service.transparency_gossip(remote_endpoint, head) => outcome?,
                };
                Ok(IdentityProtocolReply::acknowledgement(
                    IdentityProtocolAck::for_canonical_request(self.kind, request_bytes, outcome),
                ))
            }
            IdentityProtocolKind::Recovery => {
                let proposal = RecoveryProposal::from_canonical_bytes(request_bytes)?;
                let outcome = tokio::select! {
                    () = self.shared.supervisor.cancellation.cancelled() => return Err(IdentityError::Cancelled),
                    outcome = self.shared.service.recovery(remote_endpoint, proposal) => outcome?,
                };
                Ok(IdentityProtocolReply::acknowledgement(
                    IdentityProtocolAck::for_canonical_request(self.kind, request_bytes, outcome),
                ))
            }
        }
    }

    fn authorize(
        &self,
        request: EndpointAuthorizationRequest,
        remote_endpoint: crate::EndpointPublicKey,
    ) -> Result<AuthorizedEndpointStream, IdentityError> {
        authorize_endpoint_stream(
            self.shared.checkpoints.as_ref(),
            request.account_id,
            request.checkpoint_id,
            request.device_id,
            remote_endpoint,
        )
    }
}

fn sync_reply_framed_bytes(response: &SyncResponse) -> Result<usize, IdentityError> {
    let reply = IdentityProtocolReply::synchronization(response.clone());
    framed_network_bytes(reply.to_canonical_bytes()?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ack_streaming_commitment_matches_protocol_formula() {
        let kind = IdentityProtocolKind::Proposal;
        let request = b"canonical request";
        let ack = IdentityProtocolAck::for_canonical_request(
            kind,
            request,
            IdentityServiceOutcome::Accepted,
        );
        let mut committed = kind.code().to_be_bytes().to_vec();
        committed.extend_from_slice(request);
        assert_eq!(
            ack.request_commitment(),
            Digest::new(
                HashAlgorithm::Blake3_256,
                blake3::derive_key(REQUEST_COMMITMENT_CONTEXT, &committed),
            )
        );
    }

    #[tokio::test]
    async fn shared_handler_supervisor_bounds_total_and_active_reservations() {
        let supervisor = IdentityHandlerSupervisor::new();
        let mut reservations = Vec::with_capacity(IDENTITY_QUEUE_CAPACITY);
        for _ in 0..IDENTITY_QUEUE_CAPACITY {
            reservations.push(supervisor.reserve().unwrap());
        }
        assert!(matches!(
            supervisor.reserve(),
            Err(IdentityError::ResourceBusy)
        ));

        let mut active = Vec::with_capacity(MAX_CONCURRENT_IDENTITY_TASKS);
        for reservation in reservations.drain(..MAX_CONCURRENT_IDENTITY_TASKS) {
            active.push(reservation.activate().await.unwrap());
        }
        let queued = reservations.pop().unwrap();
        supervisor.cancel();
        assert!(matches!(
            queued.activate().await,
            Err(IdentityError::Cancelled)
        ));
        drop(active);
        drop(reservations);
        assert_eq!(supervisor.reservations.load(Ordering::Acquire), 0);
    }
}
