//! Optional Tokio/Krikos adapters for bounded identity streams.

mod protocol;

use std::{future::Future, sync::Arc};

use krikos::endpoint::Connection;
pub use protocol::{
    AuthorizedCheckpointRequest, AuthorizedProposalRequest, AuthorizedSyncRequest,
    DenyIdentityProtocolService, EndpointAuthorizationRequest, IdentityProtocolAck,
    IdentityProtocolHandler, IdentityProtocolHandlers, IdentityProtocolKind, IdentityProtocolReply,
    IdentityProtocolService, IdentityServiceOutcome, ServiceRejectionCode,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    AuthenticatedTransportBinding, CanonicalWire, EndpointPublicKey, IdentityError,
    PairingSessionId, SigningPublicKey, SyncFrame, SyncSessionBudget,
    limits::{
        IDENTITY_QUEUE_CAPACITY, MAX_CONCURRENT_IDENTITY_TASKS, MAX_SYNC_FRAME_BYTES,
        SHUTDOWN_TIMEOUT,
    },
    pairing::{AuthenticatedTransportAdapter, AuthenticatedTransportFacts, TransportExporterValue},
    transport::PAIRING_ALPN,
};

const PAIRING_EXPORTER_LABEL: &[u8] = b"KRIKOS-ID/pairing-exporter/v1";
const PAIRING_EXPORTER_CONTEXT_DOMAIN: &[u8] = b"KRIKOS-ID/pairing-exporter-context/v1";
const PAIRING_SESSION_ID_CONTEXT: &str = "KRIKOS-ID/pairing-session-id/v1";
const NETWORK_FRAME_PREFIX_BYTES: usize = size_of::<u32>();

/// Local role on one authenticated pairing connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairingEndpointRole {
    /// The local endpoint is the already-authorized controller device.
    Controller,
    /// The local endpoint is the proposed device being paired.
    #[cfg(test)]
    ProposedDevice,
}

struct KrikosPairingAdapter {
    facts: AuthenticatedTransportFacts,
}

impl AuthenticatedTransportAdapter for KrikosPairingAdapter {
    fn into_authenticated_transport_facts(self) -> AuthenticatedTransportFacts {
        self.facts
    }
}

/// Derive an unforgeable pairing binding from one completed Krikos handshake.
///
/// Both endpoint identities are derived from the completed connection rather than accepted as
/// freely substitutable hints.
pub(crate) fn pairing_binding_from_connection(
    connection: &Connection,
    local_role: PairingEndpointRole,
) -> Result<AuthenticatedTransportBinding, IdentityError> {
    if connection.alpn() != PAIRING_ALPN {
        return Err(IdentityError::InvalidRelationship {
            resource: "pairing negotiated ALPN",
        });
    }
    let local_endpoint_id = connection.local_id();
    let remote_endpoint_id = connection.remote_id();
    if local_endpoint_id == remote_endpoint_id {
        return Err(IdentityError::InvalidRelationship {
            resource: "pairing authenticated endpoint separation",
        });
    }

    let context = pairing_exporter_context(local_endpoint_id, remote_endpoint_id)?;
    let mut exporter = Zeroizing::new([0_u8; 32]);
    connection
        .export_keying_material(&mut exporter[..], PAIRING_EXPORTER_LABEL, &context)
        .map_err(|_| IdentityError::InvalidProof)?;
    let session_id = PairingSessionId::new(blake3::derive_key(
        PAIRING_SESSION_ID_CONTEXT,
        &exporter[..],
    ))?;
    let exporter = TransportExporterValue::new(*exporter)?;
    let local_endpoint = endpoint_key_from_krikos(local_endpoint_id)?;
    let remote_endpoint = endpoint_key_from_krikos(remote_endpoint_id)?;
    let (controller_endpoint, proposed_endpoint) = match local_role {
        PairingEndpointRole::Controller => (local_endpoint, remote_endpoint),
        #[cfg(test)]
        PairingEndpointRole::ProposedDevice => (remote_endpoint, local_endpoint),
    };
    AuthenticatedTransportBinding::from_authenticated_adapter(KrikosPairingAdapter {
        facts: AuthenticatedTransportFacts {
            session_id,
            controller_endpoint,
            proposed_endpoint,
            exporter,
        },
    })
}

fn pairing_exporter_context(
    first: krikos::EndpointId,
    second: krikos::EndpointId,
) -> Result<Vec<u8>, IdentityError> {
    let alpn_length =
        u16::try_from(PAIRING_ALPN.len()).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "pairing exporter ALPN length",
        })?;
    let (lower, upper) = if first <= second {
        (first, second)
    } else {
        (second, first)
    };
    let capacity = PAIRING_EXPORTER_CONTEXT_DOMAIN
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(PAIRING_ALPN.len()))
        .and_then(|value| value.checked_add(64))
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "pairing exporter context length",
        })?;
    let mut context = Vec::with_capacity(capacity);
    context.extend_from_slice(PAIRING_EXPORTER_CONTEXT_DOMAIN);
    context.extend_from_slice(&alpn_length.to_be_bytes());
    context.extend_from_slice(PAIRING_ALPN);
    context.extend_from_slice(lower.as_bytes());
    context.extend_from_slice(upper.as_bytes());
    Ok(context)
}

/// Convert an authenticated Krikos endpoint ID into the identity endpoint-key role.
pub fn endpoint_key_from_krikos(
    endpoint_id: krikos::EndpointId,
) -> Result<EndpointPublicKey, IdentityError> {
    Ok(EndpointPublicKey::new(SigningPublicKey::ed25519(
        *endpoint_id.as_bytes(),
    )?))
}

/// Read one big-endian length-delimited frame after checking all limits before allocation.
pub async fn read_bounded_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    session_budget: &mut SyncSessionBudget,
    maximum_bytes: usize,
) -> Result<Vec<u8>, IdentityError> {
    if maximum_bytes == 0 || maximum_bytes > MAX_SYNC_FRAME_BYTES {
        return Err(IdentityError::limit(
            "network frame configured bytes",
            maximum_bytes,
            MAX_SYNC_FRAME_BYTES,
        ));
    }
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .await
        .map_err(|_| IdentityError::InvalidEncoding)?;
    let declared = u32::from_be_bytes(prefix);
    let declared = usize::try_from(declared).map_err(|_| IdentityError::ArithmeticOverflow {
        resource: "network frame length",
    })?;
    if declared > maximum_bytes {
        return Err(IdentityError::limit(
            "network frame bytes",
            declared,
            maximum_bytes,
        ));
    }
    session_budget.charge_bytes(framed_network_bytes(declared)?)?;
    let mut bytes = vec![0_u8; declared];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|_| IdentityError::InvalidEncoding)?;
    Ok(bytes)
}

pub(crate) fn framed_network_bytes(payload_bytes: usize) -> Result<usize, IdentityError> {
    payload_bytes
        .checked_add(NETWORK_FRAME_PREFIX_BYTES)
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "network framed bytes",
        })
}

/// Write one bounded frame with a checked big-endian length prefix.
pub async fn write_bounded_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<(), IdentityError> {
    if maximum_bytes == 0 || bytes.len() > maximum_bytes || maximum_bytes > MAX_SYNC_FRAME_BYTES {
        return Err(IdentityError::limit(
            "network frame bytes",
            bytes.len(),
            maximum_bytes.min(MAX_SYNC_FRAME_BYTES),
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| IdentityError::ArithmeticOverflow {
        resource: "network frame length",
    })?;
    writer
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|_| IdentityError::Cancelled)?;
    writer
        .write_all(bytes)
        .await
        .map_err(|_| IdentityError::Cancelled)?;
    writer.flush().await.map_err(|_| IdentityError::Cancelled)
}

/// Decode one bounded canonical synchronization frame from a stream.
pub async fn read_sync_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    session_budget: &mut SyncSessionBudget,
) -> Result<SyncFrame, IdentityError> {
    let bytes = read_bounded_frame(reader, session_budget, MAX_SYNC_FRAME_BYTES).await?;
    SyncFrame::from_canonical_bytes(&bytes)
}

/// Owned bounded supervisor for identity protocol child tasks.
#[derive(Debug)]
pub struct IdentityTaskSupervisor {
    cancellation: CancellationToken,
    permits: Arc<Semaphore>,
    tasks: JoinSet<Result<(), IdentityError>>,
}

impl IdentityTaskSupervisor {
    /// Create an empty supervisor with the frozen queue and concurrency bounds.
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_IDENTITY_TASKS)),
            tasks: JoinSet::new(),
        }
    }

    /// Submit owned work, rejecting submissions beyond the bounded pending queue.
    pub fn submit<F>(&mut self, task: F) -> Result<(), IdentityError>
    where
        F: Future<Output = Result<(), IdentityError>> + Send + 'static,
    {
        if self.cancellation.is_cancelled() {
            return Err(IdentityError::Cancelled);
        }
        if self.tasks.len() >= IDENTITY_QUEUE_CAPACITY {
            return Err(IdentityError::ResourceBusy);
        }
        let cancellation = self.cancellation.clone();
        let permits = self.permits.clone();
        self.tasks.spawn(async move {
            let permit = tokio::select! {
                () = cancellation.cancelled() => return Err(IdentityError::Cancelled),
                permit = permits.acquire_owned() => {
                    permit.map_err(|_| IdentityError::Cancelled)?
                }
            };
            run_owned_task(cancellation, permit, task).await
        });
        Ok(())
    }

    /// Cancel every child task without detaching it.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Await the next observable child outcome.
    pub async fn join_next(&mut self) -> Option<Result<(), IdentityError>> {
        self.tasks
            .join_next()
            .await
            .map(|result| result.unwrap_or(Err(IdentityError::Cancelled)))
    }

    /// Cancel and drain all tasks within the frozen ten-second shutdown deadline.
    pub async fn shutdown(mut self) -> Result<(), IdentityError> {
        self.cancellation.cancel();
        let drain = async {
            let mut first_error = None;
            while let Some(result) = self.join_next().await {
                if let Err(error) = result
                    && first_error.is_none()
                {
                    first_error = Some(error);
                }
            }
            first_error.map_or(Ok(()), Err)
        };
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, drain).await {
            Ok(result) => result,
            Err(_) => {
                self.tasks.abort_all();
                while self.tasks.join_next().await.is_some() {}
                Err(IdentityError::Cancelled)
            }
        }
    }
}

impl Default for IdentityTaskSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IdentityTaskSupervisor {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.abort_all();
    }
}

async fn run_owned_task<F>(
    cancellation: CancellationToken,
    _permit: OwnedSemaphorePermit,
    task: F,
) -> Result<(), IdentityError>
where
    F: Future<Output = Result<(), IdentityError>>,
{
    tokio::select! {
        () = cancellation.cancelled() => Err(IdentityError::Cancelled),
        result = task => result,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use krikos::{
        Endpoint, RelayMode,
        endpoint::presets,
        protocol::{AcceptError, ProtocolHandler, Router},
    };
    use tokio::sync::oneshot;

    use super::*;

    #[derive(Debug)]
    struct PairingBindingCapture {
        binding: Mutex<Option<oneshot::Sender<AuthenticatedTransportBinding>>>,
    }

    impl ProtocolHandler for PairingBindingCapture {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let binding =
                pairing_binding_from_connection(&connection, PairingEndpointRole::Controller)
                    .map_err(AcceptError::from_err)?;
            let sender = self
                .binding
                .lock()
                .map_err(|_| AcceptError::from_err(std::io::Error::other("capture lock poisoned")))?
                .take()
                .ok_or_else(|| {
                    AcceptError::from_err(std::io::Error::other("binding already captured"))
                })?;
            sender.send(binding).map_err(|_| {
                AcceptError::from_err(std::io::Error::other("capture receiver closed"))
            })?;
            connection.closed().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn completed_pairing_connection_derives_direction_independent_binding() {
        let controller = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let proposed = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let (binding_tx, binding_rx) = oneshot::channel();
        let capture = Arc::new(PairingBindingCapture {
            binding: Mutex::new(Some(binding_tx)),
        });
        let router = Router::builder(controller.clone())
            .accept(PAIRING_ALPN, capture)
            .spawn();

        let connection = proposed
            .connect(controller.addr(), PAIRING_ALPN)
            .await
            .unwrap();
        let client_binding =
            pairing_binding_from_connection(&connection, PairingEndpointRole::ProposedDevice)
                .unwrap();
        let server_binding = binding_rx.await.unwrap();
        assert_eq!(client_binding, server_binding);
        assert_eq!(
            client_binding.controller_endpoint(),
            endpoint_key_from_krikos(controller.id()).unwrap()
        );
        assert_eq!(
            client_binding.proposed_endpoint(),
            endpoint_key_from_krikos(proposed.id()).unwrap()
        );

        connection.close(0_u32.into(), b"test complete");
        router.shutdown().await.unwrap();
        proposed.close().await;
    }
}
