//! Runtime-independent identity transport contracts.

use crate::{
    AccountId, CheckpointId, DeviceId, EndpointPublicKey, IdentityError, ProjectedDeviceLifecycle,
    StoreFuture,
};

/// Pairing protocol v1 ALPN.
pub const PAIRING_ALPN: &[u8] = b"krikos-identity/pairing/1";
/// Account synchronization protocol v1 ALPN.
pub const SYNC_ALPN: &[u8] = b"krikos-identity/sync/1";
/// Authorization-proposal protocol v1 ALPN.
pub const PROPOSAL_ALPN: &[u8] = b"krikos-identity/proposal/1";
/// Account-checkpoint protocol v1 ALPN.
pub const CHECKPOINT_ALPN: &[u8] = b"krikos-identity/checkpoint/1";
/// Transparency-gossip protocol v1 ALPN.
pub const TRANSPARENCY_GOSSIP_ALPN: &[u8] = b"krikos-identity/transparency-gossip/1";
/// Recovery protocol v1 ALPN.
pub const RECOVERY_ALPN: &[u8] = b"krikos-identity/recovery/1";

/// Device endpoint record resolved only after checkpoint verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointDeviceEndpoint {
    endpoint_key: EndpointPublicKey,
    lifecycle: ProjectedDeviceLifecycle,
}

impl CheckpointDeviceEndpoint {
    /// Construct a record at a verified-checkpoint implementation boundary.
    pub fn new(endpoint_key: EndpointPublicKey, lifecycle: ProjectedDeviceLifecycle) -> Self {
        Self {
            endpoint_key,
            lifecycle,
        }
    }

    /// Endpoint key committed by the verified checkpoint projection.
    pub const fn endpoint_key(self) -> EndpointPublicKey {
        self.endpoint_key
    }

    /// Device lifecycle committed by the verified checkpoint projection.
    pub const fn lifecycle(self) -> ProjectedDeviceLifecycle {
        self.lifecycle
    }
}

/// Trusted lookup boundary for an already cryptographically verified checkpoint.
pub trait VerifiedCheckpointView: Send + Sync {
    /// Resolve one device from the exact verified checkpoint, or `None` when absent.
    fn device_endpoint(
        &self,
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        device_id: DeviceId,
    ) -> Result<Option<CheckpointDeviceEndpoint>, IdentityError>;
}

/// Capability proving an authenticated stream endpoint is active at one verified checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedEndpointStream {
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    device_id: DeviceId,
    endpoint_key: EndpointPublicKey,
}

impl AuthorizedEndpointStream {
    /// Authorized account.
    pub const fn account_id(self) -> AccountId {
        self.account_id
    }

    /// Verified checkpoint used for authorization.
    pub const fn checkpoint_id(self) -> CheckpointId {
        self.checkpoint_id
    }

    /// Active device bound to the endpoint.
    pub const fn device_id(self) -> DeviceId {
        self.device_id
    }

    /// Exact authenticated remote endpoint key.
    pub const fn endpoint_key(self) -> EndpointPublicKey {
        self.endpoint_key
    }
}

/// Authorize an authenticated remote endpoint before any protocol dispatch.
pub fn authorize_endpoint_stream(
    view: &(impl VerifiedCheckpointView + ?Sized),
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    device_id: DeviceId,
    remote_endpoint_key: EndpointPublicKey,
) -> Result<AuthorizedEndpointStream, IdentityError> {
    let record = view
        .device_endpoint(account_id, checkpoint_id, device_id)?
        .ok_or(IdentityError::DeviceNotAuthorized)?;
    match record.lifecycle() {
        ProjectedDeviceLifecycle::Active => {}
        ProjectedDeviceLifecycle::Suspended => return Err(IdentityError::DeviceSuspended),
        ProjectedDeviceLifecycle::Revoked => return Err(IdentityError::DeviceRevoked),
    }
    if record.endpoint_key() != remote_endpoint_key {
        return Err(IdentityError::DeviceNotAuthorized);
    }
    Ok(AuthorizedEndpointStream {
        account_id,
        checkpoint_id,
        device_id,
        endpoint_key: remote_endpoint_key,
    })
}

/// Runtime-independent bidirectional length-delimited stream.
pub trait IdentityStream: Send {
    /// Send one already bounded canonical frame.
    fn send_frame(&mut self, frame: Vec<u8>) -> StoreFuture<'_, ()>;

    /// Receive one frame after length validation and before protocol dispatch.
    fn receive_frame(&mut self) -> StoreFuture<'_, Option<Vec<u8>>>;
}

/// Authenticated endpoint transport capable of opening one exact ALPN stream.
pub trait IdentityTransport: Send + Sync {
    /// Concrete owned stream.
    type Stream: IdentityStream;

    /// Open a stream to an authenticated endpoint under an exact supported ALPN.
    fn open_stream(
        &self,
        endpoint_key: EndpointPublicKey,
        alpn: &'static [u8],
    ) -> StoreFuture<'_, Self::Stream>;
}

/// Explicit endpoint discovery boundary.
pub trait IdentityDiscovery: Send + Sync {
    /// Resolve bounded opaque endpoint-address records for one endpoint key.
    fn resolve_endpoint(&self, endpoint_key: EndpointPublicKey) -> StoreFuture<'_, Vec<Vec<u8>>>;
}

/// Explicit bounded transparency-gossip boundary.
pub trait IdentityGossip: Send + Sync {
    /// Publish one bounded canonical gossip record.
    fn publish(&self, topic: Vec<u8>, record: Vec<u8>) -> StoreFuture<'_, ()>;
}

/// Explicit content-addressed blob boundary used by identity integrations.
pub trait IdentityBlobStore: Send + Sync {
    /// Store one bounded blob and return its exact content digest.
    fn put(&self, bytes: Vec<u8>) -> StoreFuture<'_, [u8; 32]>;

    /// Load a blob, distinguishing absence from transport or storage failure.
    fn get(&self, digest: [u8; 32]) -> StoreFuture<'_, Option<Vec<u8>>>;
}
