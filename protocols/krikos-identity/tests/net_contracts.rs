#![cfg(feature = "net")]

use std::{
    convert::Infallible,
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use krikos::{
    Endpoint, RelayMode,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use krikos_base::SecretKey;
use krikos_identity::{
    AccountGenesis, AccountId, AccountOperation, AccountState, AccountStore, AdmissionEvidence,
    AgreementSecretKey, AlgorithmSignature, AuthorizedEvent, CanonicalWire, CheckpointId,
    ControllerApprovalBody, ControllerApprovals, ControllerClass, ControllerDescriptor,
    ControllerKeyId, ControllerScope, CryptoSuiteDescriptor, CursorKey, DelayEvidence,
    DeviceAuthorizationProposal, DeviceDescriptor, DeviceId, Digest, EndpointPublicKey, EventBody,
    EventPredecessors, Extensions, FreshnessEvidence, HashAlgorithm, IdentityError, KeyedSignature,
    MemoryAccountStore, PairingTicket, PairingTicketRequest, ProjectedDeviceLifecycle,
    RecoveryProposal, SignedCheckpoint, SignedControllerApproval, SignedProviderHead,
    SigningPublicKey, StoreFuture, SyncRequest, SyncResponse, SyncSessionBudget, Timestamp,
    net::{
        AuthorizedCheckpointRequest, AuthorizedProposalRequest, AuthorizedSyncRequest,
        EndpointAuthorizationRequest, IdentityProtocolAck, IdentityProtocolHandlers,
        IdentityProtocolKind, IdentityProtocolReply, IdentityProtocolService,
        IdentityServiceOutcome, IdentityTaskSupervisor, read_bounded_frame, write_bounded_frame,
    },
    transport::{CheckpointDeviceEndpoint, VerifiedCheckpointView, authorize_endpoint_stream},
};
use rand_core::{TryCryptoRng, TryRng};
use tokio::{
    io::{AsyncWriteExt, duplex, sink},
    sync::{Notify, Semaphore, oneshot},
    task::JoinSet,
};

struct RepeatingRng(u8);

impl TryRng for RepeatingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from(self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from(self.0))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        destination.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for RepeatingRng {}

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn endpoint(fill: u8) -> EndpointPublicKey {
    let secret = SecretKey::from_bytes(&[fill; 32]);
    EndpointPublicKey::new(SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap())
}

fn controller_descriptor(secret: &SecretKey) -> ControllerDescriptor {
    ControllerDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        ControllerClass::PersonalDevice,
        krikos_identity::ControllerWeight::new(1).unwrap(),
        ControllerScope::all_v1_operations(),
        Extensions::default(),
    )
    .unwrap()
}

fn followup_event(state: &AccountState) -> AuthorizedEvent {
    let signer = SecretKey::from_bytes(&[0x11; 32]);
    let operation =
        AccountOperation::AddController(controller_descriptor(&SecretKey::from_bytes(&[0x15; 32])));
    let body = EventBody::new(
        state.account_id(),
        state.sequence().checked_next().unwrap(),
        state.expected_epoch_for(&operation).unwrap(),
        EventPredecessors::events(state.heads().to_vec()).unwrap(),
        operation,
        Timestamp::from_unix_millis(3),
        [0x16; 16],
        Extensions::default(),
    )
    .unwrap();
    let checkpoint_id = typed_id::<CheckpointId>(0x22);
    let evidence = AdmissionEvidence::new(
        body.proposal_id().unwrap(),
        checkpoint_id,
        state.provider_policy_id(),
        FreshnessEvidence::local_known(checkpoint_id),
        DelayEvidence::none(),
        Extensions::default(),
    )
    .unwrap();
    let signing_key = SigningPublicKey::ed25519(*signer.public().as_bytes()).unwrap();
    let controller_id = state
        .active_controllers()
        .iter()
        .find(|controller| controller.signing_key() == signing_key)
        .unwrap()
        .id();
    let approval_body = ControllerApprovalBody::event(
        controller_id,
        evidence.event_id_for_body(&body).unwrap(),
        evidence.admission_evidence_id().unwrap(),
        Extensions::default(),
    )
    .unwrap();
    let signature = signer.sign(&approval_body.to_canonical_bytes().unwrap());
    let approval = SignedControllerApproval::new(
        approval_body,
        vec![KeyedSignature::new(
            CryptoSuiteDescriptor::v1()
                .unwrap()
                .crypto_suite_id()
                .unwrap(),
            ControllerKeyId::for_signing_key(&signing_key).unwrap(),
            AlgorithmSignature::new(1, signature.to_bytes().to_vec()).unwrap(),
        )],
    )
    .unwrap();
    AuthorizedEvent::new(
        body,
        evidence,
        ControllerApprovals::new(vec![approval]).unwrap(),
    )
    .unwrap()
}

#[derive(Debug, Default)]
struct AcceptPairingService {
    pairing_calls: AtomicUsize,
    sync_calls: AtomicUsize,
    proposal_calls: AtomicUsize,
    checkpoint_calls: AtomicUsize,
    gossip_calls: AtomicUsize,
    recovery_calls: AtomicUsize,
}

impl IdentityProtocolService for AcceptPairingService {
    fn pairing(
        &self,
        _transport: krikos_identity::AuthenticatedTransportBinding,
        _ticket: PairingTicket,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.pairing_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(IdentityServiceOutcome::Accepted) })
    }

    fn sync(
        &self,
        _authorized: krikos_identity::transport::AuthorizedEndpointStream,
        _request: SyncRequest,
        _response: SyncResponse,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.sync_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(IdentityServiceOutcome::Accepted) })
    }

    fn proposal(
        &self,
        _authorized: krikos_identity::transport::AuthorizedEndpointStream,
        _proposal: DeviceAuthorizationProposal,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.proposal_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(IdentityServiceOutcome::Accepted) })
    }

    fn checkpoint(
        &self,
        _authorized: krikos_identity::transport::AuthorizedEndpointStream,
        _checkpoint: SignedCheckpoint,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.checkpoint_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(IdentityServiceOutcome::Accepted) })
    }

    fn transparency_gossip(
        &self,
        _remote_endpoint: EndpointPublicKey,
        _head: SignedProviderHead,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.gossip_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(IdentityServiceOutcome::Accepted) })
    }

    fn recovery(
        &self,
        _remote_endpoint: EndpointPublicKey,
        _proposal: RecoveryProposal,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.recovery_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(IdentityServiceOutcome::Accepted) })
    }
}

#[derive(Debug, Default)]
struct BlockingPairingService {
    entered: Arc<Notify>,
}

#[derive(Debug)]
struct ConcurrencyBoundPairingService {
    calls: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    gate: Arc<Semaphore>,
}

impl Default for ConcurrencyBoundPairingService {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            gate: Arc::new(Semaphore::new(0)),
        }
    }
}

impl IdentityProtocolService for ConcurrencyBoundPairingService {
    fn pairing(
        &self,
        _transport: krikos_identity::AuthenticatedTransportBinding,
        _ticket: PairingTicket,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        let gate = self.gate.clone();
        Box::pin(async move {
            let permit = gate
                .acquire_owned()
                .await
                .map_err(|_| IdentityError::Cancelled)?;
            permit.forget();
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(IdentityServiceOutcome::Accepted)
        })
    }
}

#[derive(Debug)]
struct ConnectionCapture {
    sender: std::sync::Mutex<Option<oneshot::Sender<Connection>>>,
}

impl ProtocolHandler for ConnectionCapture {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let sender = self
            .sender
            .lock()
            .map_err(|_| AcceptError::from_err(std::io::Error::other("capture lock poisoned")))?
            .take()
            .ok_or_else(|| {
                AcceptError::from_err(std::io::Error::other("connection already captured"))
            })?;
        sender
            .send(connection.clone())
            .map_err(|_| AcceptError::from_err(std::io::Error::other("capture receiver closed")))?;
        connection.closed().await;
        Ok(())
    }
}

#[cfg(feature = "fs-store")]
#[derive(Debug)]
struct ReopeningNonceService {
    path: std::path::PathBuf,
}

#[cfg(feature = "fs-store")]
impl IdentityProtocolService for ReopeningNonceService {
    fn pairing(
        &self,
        _transport: krikos_identity::AuthenticatedTransportBinding,
        ticket: PairingTicket,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        let result = (|| {
            use krikos_identity::{PairingNonceKey, PairingNonceStore, RedbPairingNonceStore};

            let mut store = RedbPairingNonceStore::open(&self.path)?;
            let key = PairingNonceKey::for_ticket(&ticket)?;
            store.consume_atomically(key, ticket.expires_at())
        })();
        Box::pin(async move {
            match result? {
                krikos_identity::NonceConsumeResult::Consumed => {
                    Ok(IdentityServiceOutcome::Accepted)
                }
                krikos_identity::NonceConsumeResult::AlreadyConsumed => {
                    Ok(IdentityServiceOutcome::Rejected(
                        krikos_identity::net::ServiceRejectionCode::new(2)?,
                    ))
                }
            }
        })
    }
}

impl IdentityProtocolService for BlockingPairingService {
    fn pairing(
        &self,
        _transport: krikos_identity::AuthenticatedTransportBinding,
        _ticket: PairingTicket,
    ) -> StoreFuture<'_, IdentityServiceOutcome> {
        self.entered.notify_one();
        Box::pin(pending())
    }
}

fn endpoint_key(endpoint_id: krikos::EndpointId) -> EndpointPublicKey {
    EndpointPublicKey::new(SigningPublicKey::ed25519(*endpoint_id.as_bytes()).unwrap())
}

fn pairing_ticket(proposed_endpoint: krikos::EndpointId) -> PairingTicket {
    let application = SecretKey::from_bytes(&[0x81; 32]);
    let agreement = AgreementSecretKey::from_bytes([0x82; 32]);
    let descriptor = DeviceDescriptor::new(
        SigningPublicKey::ed25519(*application.public().as_bytes()).unwrap(),
        agreement.public_key().unwrap(),
        endpoint_key(proposed_endpoint),
        Extensions::default(),
    )
    .unwrap();
    let request = PairingTicketRequest::new(
        typed_id(0x83),
        descriptor,
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(601_000),
        Extensions::default(),
    )
    .unwrap();
    PairingTicket::issue_with_rng(request, &mut RepeatingRng(0x84))
        .unwrap()
        .0
}

#[tokio::test]
async fn pairing_handler_dispatches_typed_request_and_rejects_endpoint_substitution() {
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
    let service = Arc::new(AcceptPairingService::default());
    let handlers = IdentityProtocolHandlers::new(
        service.clone(),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(proposed.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        Arc::new(MemoryAccountStore::new()),
        CursorKey::new([0x91; 32]).unwrap(),
    );
    let router = Router::builder(controller.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            handlers.handler(IdentityProtocolKind::Pairing),
        )
        .spawn();

    let connection = proposed
        .connect(controller.addr(), krikos_identity::transport::PAIRING_ALPN)
        .await
        .unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    let request = pairing_ticket(proposed.id()).to_canonical_bytes().unwrap();
    write_bounded_frame(&mut send, &request, 16 * 1024)
        .await
        .unwrap();
    let mut budget = SyncSessionBudget::new();
    let response = read_bounded_frame(&mut receive, &mut budget, 4 * 1024 * 1024)
        .await
        .unwrap();
    let reply = IdentityProtocolReply::from_canonical_bytes(&response).unwrap();
    let ack = reply.as_ack().unwrap();
    assert!(ack.accepted());
    assert_eq!(ack.protocol().unwrap(), IdentityProtocolKind::Pairing);
    let ack_bytes = ack.to_canonical_bytes().unwrap();
    assert_eq!(
        IdentityProtocolAck::from_canonical_bytes(&ack_bytes).unwrap(),
        *ack,
    );
    assert_eq!(service.pairing_calls.load(Ordering::SeqCst), 1);

    let connection = proposed
        .connect(controller.addr(), krikos_identity::transport::PAIRING_ALPN)
        .await
        .unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    let wrong_endpoint = SecretKey::from_bytes(&[0x92; 32]).public();
    let request = pairing_ticket(wrong_endpoint).to_canonical_bytes().unwrap();
    write_bounded_frame(&mut send, &request, 16 * 1024)
        .await
        .unwrap();
    let mut budget = SyncSessionBudget::new();
    assert!(
        read_bounded_frame(&mut receive, &mut budget, 4 * 1024 * 1024)
            .await
            .is_err()
    );
    assert_eq!(service.pairing_calls.load(Ordering::SeqCst), 1);

    router.shutdown().await.unwrap();
    proposed.close().await;
}

#[derive(Debug)]
struct ExactCheckpointView {
    account_id: AccountId,
    checkpoint_id: CheckpointId,
    device_id: DeviceId,
    endpoint: EndpointPublicKey,
}

impl VerifiedCheckpointView for ExactCheckpointView {
    fn device_endpoint(
        &self,
        account_id: AccountId,
        checkpoint_id: CheckpointId,
        device_id: DeviceId,
    ) -> Result<Option<CheckpointDeviceEndpoint>, IdentityError> {
        if account_id != self.account_id
            || checkpoint_id != self.checkpoint_id
            || device_id != self.device_id
        {
            return Ok(None);
        }
        Ok(Some(CheckpointDeviceEndpoint::new(
            self.endpoint,
            ProjectedDeviceLifecycle::Active,
        )))
    }
}

async fn identity_round_trip(
    client: &Endpoint,
    server: krikos::EndpointAddr,
    kind: IdentityProtocolKind,
    request: &[u8],
) -> Result<IdentityProtocolReply, IdentityError> {
    let connection = client
        .connect(server, kind.alpn())
        .await
        .map_err(|_| IdentityError::Cancelled)?;
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .map_err(|_| IdentityError::Cancelled)?;
    write_bounded_frame(&mut send, request, 4 * 1024 * 1024).await?;
    let mut budget = SyncSessionBudget::new();
    let response = read_bounded_frame(&mut receive, &mut budget, 4 * 1024 * 1024).await?;
    IdentityProtocolReply::from_canonical_bytes(&response)
}

fn exact_handlers(
    _server: &Endpoint,
    client: &Endpoint,
    service: Arc<AcceptPairingService>,
    store: Arc<MemoryAccountStore>,
    authorization: EndpointAuthorizationRequest,
) -> IdentityProtocolHandlers {
    IdentityProtocolHandlers::new(
        service,
        Arc::new(ExactCheckpointView {
            account_id: authorization.account_id(),
            checkpoint_id: authorization.checkpoint_id(),
            device_id: authorization.device_id(),
            endpoint: endpoint_key(client.id()),
        }),
        store,
        CursorKey::new([0xa1; 32]).unwrap(),
    )
}

#[test]
fn endpoint_authorization_is_explicitly_versioned_and_rejects_legacy_bytes() {
    let account_id = typed_id(0xca);
    let checkpoint_id = typed_id(0xcb);
    let device_id = typed_id(0xcc);
    let request = EndpointAuthorizationRequest::new(account_id, checkpoint_id, device_id);
    let encoded = request.to_canonical_bytes().unwrap();
    assert_eq!(encoded.first(), Some(&1));
    assert_eq!(
        EndpointAuthorizationRequest::from_canonical_bytes(&encoded).unwrap(),
        request
    );

    let legacy = postcard::to_stdvec(&(account_id, checkpoint_id, device_id)).unwrap();
    assert!(EndpointAuthorizationRequest::from_canonical_bytes(&legacy).is_err());
    let unsupported = postcard::to_stdvec(&(2_u16, account_id, checkpoint_id, device_id)).unwrap();
    assert!(matches!(
        EndpointAuthorizationRequest::from_canonical_bytes(&unsupported),
        Err(IdentityError::UnsupportedVersion { version: 2 })
    ));
}

#[tokio::test]
async fn authorized_envelopes_reject_cross_account_canonical_bytes_before_dispatch() {
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let service = Arc::new(AcceptPairingService::default());
    let store = Arc::new(MemoryAccountStore::new());
    let genesis =
        AccountGenesis::from_canonical_bytes(include_bytes!("vectors/account-genesis.bin"))
            .unwrap();
    let sync_account_id = genesis.account_id().unwrap();
    store.create_account(genesis).await.unwrap();

    let sync_authorization =
        EndpointAuthorizationRequest::new(typed_id(0xd1), typed_id(0xd2), typed_id(0xd3));
    assert_ne!(sync_authorization.account_id(), sync_account_id);
    let sync_request =
        SyncRequest::new(sync_account_id, Vec::new(), None, 1, 4 * 1024 * 1024).unwrap();
    let sync_bytes = postcard::to_stdvec(&(sync_authorization, &sync_request)).unwrap();
    assert!(AuthorizedSyncRequest::from_canonical_bytes(&sync_bytes).is_err());

    let proposal = DeviceAuthorizationProposal::from_canonical_bytes(include_bytes!(
        "vectors/device-authorization-proposal.bin"
    ))
    .unwrap();
    let proposal_authorization =
        EndpointAuthorizationRequest::new(typed_id(0xd4), typed_id(0xd5), typed_id(0xd6));
    assert_ne!(proposal_authorization.account_id(), proposal.account_id());
    let proposal_bytes = postcard::to_stdvec(&(proposal_authorization, &proposal)).unwrap();
    assert!(AuthorizedProposalRequest::from_canonical_bytes(&proposal_bytes).is_err());

    let checkpoint =
        SignedCheckpoint::from_canonical_bytes(include_bytes!("vectors/checkpoint-direct.bin"))
            .unwrap();
    let checkpoint_authorization =
        EndpointAuthorizationRequest::new(typed_id(0xd7), typed_id(0xd8), typed_id(0xd9));
    assert_ne!(
        checkpoint_authorization.account_id(),
        checkpoint.body().account_id()
    );
    let checkpoint_bytes = postcard::to_stdvec(&(checkpoint_authorization, &checkpoint)).unwrap();
    assert!(AuthorizedCheckpointRequest::from_canonical_bytes(&checkpoint_bytes).is_err());

    let sync_handlers = exact_handlers(
        &server,
        &client,
        service.clone(),
        store.clone(),
        sync_authorization,
    );
    let proposal_handlers = exact_handlers(
        &server,
        &client,
        service.clone(),
        store.clone(),
        proposal_authorization,
    );
    let checkpoint_handlers = exact_handlers(
        &server,
        &client,
        service.clone(),
        store,
        checkpoint_authorization,
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::SYNC_ALPN,
            sync_handlers.handler(IdentityProtocolKind::Sync),
        )
        .accept(
            krikos_identity::transport::PROPOSAL_ALPN,
            proposal_handlers.handler(IdentityProtocolKind::Proposal),
        )
        .accept(
            krikos_identity::transport::CHECKPOINT_ALPN,
            checkpoint_handlers.handler(IdentityProtocolKind::Checkpoint),
        )
        .spawn();

    for (kind, bytes) in [
        (IdentityProtocolKind::Sync, sync_bytes),
        (IdentityProtocolKind::Proposal, proposal_bytes),
        (IdentityProtocolKind::Checkpoint, checkpoint_bytes),
    ] {
        assert!(
            identity_round_trip(&client, server.addr(), kind, &bytes)
                .await
                .is_err()
        );
    }
    assert_eq!(service.sync_calls.load(Ordering::SeqCst), 0);
    assert_eq!(service.proposal_calls.load(Ordering::SeqCst), 0);
    assert_eq!(service.checkpoint_calls.load(Ordering::SeqCst), 0);

    router.shutdown().await.unwrap();
    client.close().await;
}

#[tokio::test]
async fn all_six_handlers_dispatch_bounded_canonical_requests_and_exact_authority() {
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let service = Arc::new(AcceptPairingService::default());
    let store = Arc::new(MemoryAccountStore::new());
    let genesis =
        AccountGenesis::from_canonical_bytes(include_bytes!("vectors/account-genesis.bin"))
            .unwrap();
    let account_id = genesis.account_id().unwrap();
    let snapshot = store.create_account(genesis).await.unwrap();
    let event =
        AuthorizedEvent::from_canonical_bytes(include_bytes!("vectors/authorized-event.bin"))
            .unwrap();
    let first_commit = store
        .commit_event(snapshot.revision().clone(), event)
        .await
        .unwrap();
    let second = followup_event(first_commit.snapshot().state());
    store
        .commit_event(first_commit.snapshot().revision().clone(), second)
        .await
        .unwrap();

    let sync_authorization =
        EndpointAuthorizationRequest::new(account_id, typed_id(0xa2), typed_id(0xa3));
    let authorization_bytes = sync_authorization.to_canonical_bytes().unwrap();
    assert_eq!(
        EndpointAuthorizationRequest::from_canonical_bytes(&authorization_bytes).unwrap(),
        sync_authorization,
    );
    let sync_handlers = exact_handlers(
        &server,
        &client,
        service.clone(),
        store.clone(),
        sync_authorization,
    );
    let proposal = DeviceAuthorizationProposal::from_canonical_bytes(include_bytes!(
        "vectors/device-authorization-proposal.bin"
    ))
    .unwrap();
    let proposal_authorization =
        EndpointAuthorizationRequest::new(proposal.account_id(), typed_id(0xa4), typed_id(0xa5));
    let proposal_handlers = exact_handlers(
        &server,
        &client,
        service.clone(),
        store.clone(),
        proposal_authorization,
    );
    let checkpoint =
        SignedCheckpoint::from_canonical_bytes(include_bytes!("vectors/checkpoint-direct.bin"))
            .unwrap();
    let checkpoint_authorization = EndpointAuthorizationRequest::new(
        checkpoint.body().account_id(),
        typed_id(0xa6),
        typed_id(0xa7),
    );
    let checkpoint_handlers = exact_handlers(
        &server,
        &client,
        service.clone(),
        store.clone(),
        checkpoint_authorization,
    );
    let open_handlers = exact_handlers(
        &server,
        &client,
        service.clone(),
        store.clone(),
        sync_authorization,
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            open_handlers.handler(IdentityProtocolKind::Pairing),
        )
        .accept(
            krikos_identity::transport::SYNC_ALPN,
            sync_handlers.handler(IdentityProtocolKind::Sync),
        )
        .accept(
            krikos_identity::transport::PROPOSAL_ALPN,
            proposal_handlers.handler(IdentityProtocolKind::Proposal),
        )
        .accept(
            krikos_identity::transport::CHECKPOINT_ALPN,
            checkpoint_handlers.handler(IdentityProtocolKind::Checkpoint),
        )
        .accept(
            krikos_identity::transport::TRANSPARENCY_GOSSIP_ALPN,
            open_handlers.handler(IdentityProtocolKind::TransparencyGossip),
        )
        .accept(
            krikos_identity::transport::RECOVERY_ALPN,
            open_handlers.handler(IdentityProtocolKind::Recovery),
        )
        .spawn();

    let pairing = pairing_ticket(client.id()).to_canonical_bytes().unwrap();
    let reply = identity_round_trip(
        &client,
        server.addr(),
        IdentityProtocolKind::Pairing,
        &pairing,
    )
    .await
    .unwrap();
    assert!(reply.as_ack().unwrap().accepted());

    let request = SyncRequest::new(account_id, Vec::new(), None, 1, 4 * 1024 * 1024).unwrap();
    let sync = AuthorizedSyncRequest::new(sync_authorization, request)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    let reply = identity_round_trip(&client, server.addr(), IdentityProtocolKind::Sync, &sync)
        .await
        .unwrap();
    let first_exchange_bytes = sync
        .len()
        .checked_add(4)
        .and_then(|bytes| bytes.checked_add(reply.to_canonical_bytes().unwrap().len()))
        .and_then(|bytes| bytes.checked_add(4))
        .unwrap();
    let first_sync = reply.as_sync().unwrap();
    let continuation = first_sync
        .as_frame()
        .unwrap()
        .continuation()
        .unwrap()
        .clone();
    assert_eq!(
        usize::try_from(continuation.delivered_bytes()).unwrap(),
        first_exchange_bytes
    );
    assert_eq!(first_sync.as_frame().unwrap().events().len(), 1);
    let resumed = AuthorizedSyncRequest::new(
        sync_authorization,
        SyncRequest::new(
            account_id,
            Vec::new(),
            Some(continuation),
            1,
            4 * 1024 * 1024,
        )
        .unwrap(),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    let resumed = identity_round_trip(&client, server.addr(), IdentityProtocolKind::Sync, &resumed)
        .await
        .unwrap();
    assert_eq!(
        resumed
            .as_sync()
            .unwrap()
            .as_frame()
            .unwrap()
            .events()
            .len(),
        1
    );
    assert!(
        resumed
            .as_sync()
            .unwrap()
            .as_frame()
            .unwrap()
            .continuation()
            .is_none()
    );

    let proposal = AuthorizedProposalRequest::new(proposal_authorization, proposal)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    let reply = identity_round_trip(
        &client,
        server.addr(),
        IdentityProtocolKind::Proposal,
        &proposal,
    )
    .await
    .unwrap();
    assert!(reply.as_ack().unwrap().accepted());

    let checkpoint = AuthorizedCheckpointRequest::new(checkpoint_authorization, checkpoint)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    let reply = identity_round_trip(
        &client,
        server.addr(),
        IdentityProtocolKind::Checkpoint,
        &checkpoint,
    )
    .await
    .unwrap();
    assert!(reply.as_ack().unwrap().accepted());

    let head = SignedProviderHead::from_canonical_bytes(include_bytes!(
        "vectors/signed-provider-head.bin"
    ))
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    let reply = identity_round_trip(
        &client,
        server.addr(),
        IdentityProtocolKind::TransparencyGossip,
        &head,
    )
    .await
    .unwrap();
    assert!(reply.as_ack().unwrap().accepted());

    let recovery =
        RecoveryProposal::from_canonical_bytes(include_bytes!("vectors/recovery-proposal.bin"))
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
    let reply = identity_round_trip(
        &client,
        server.addr(),
        IdentityProtocolKind::Recovery,
        &recovery,
    )
    .await
    .unwrap();
    assert!(reply.as_ack().unwrap().accepted());

    let wrong_sync = AuthorizedSyncRequest::new(
        EndpointAuthorizationRequest::new(account_id, typed_id(0xff), typed_id(0xa3)),
        SyncRequest::new(account_id, Vec::new(), None, 1, 4 * 1024 * 1024).unwrap(),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    assert!(
        identity_round_trip(
            &client,
            server.addr(),
            IdentityProtocolKind::Sync,
            &wrong_sync,
        )
        .await
        .is_err()
    );

    let wrong_device = AuthorizedSyncRequest::new(
        EndpointAuthorizationRequest::new(
            account_id,
            sync_authorization.checkpoint_id(),
            typed_id(0xfe),
        ),
        SyncRequest::new(account_id, Vec::new(), None, 1, 4 * 1024 * 1024).unwrap(),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    assert!(
        identity_round_trip(
            &client,
            server.addr(),
            IdentityProtocolKind::Sync,
            &wrong_device,
        )
        .await
        .is_err()
    );

    assert_eq!(service.pairing_calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.sync_calls.load(Ordering::SeqCst), 2);
    assert_eq!(service.proposal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.checkpoint_calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.gossip_calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.recovery_calls.load(Ordering::SeqCst), 1);

    router.shutdown().await.unwrap();
    client.close().await;
}

#[tokio::test]
async fn pairing_proposal_and_sync_use_repository_local_relay_only_addresses() {
    let (relay_map, _relay_url, _relay_guard) =
        krikos::test_utils::run_relay_server().await.unwrap();
    let controller = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map.clone()))
        .ca_tls_config(krikos::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .unwrap();
    let proposed = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(relay_map))
        .ca_tls_config(krikos::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), controller.online())
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), proposed.online())
        .await
        .unwrap();

    let service = Arc::new(AcceptPairingService::default());
    let store = Arc::new(MemoryAccountStore::new());
    let genesis =
        AccountGenesis::from_canonical_bytes(include_bytes!("vectors/account-genesis.bin"))
            .unwrap();
    let account_id = genesis.account_id().unwrap();
    store.create_account(genesis).await.unwrap();
    let handlers = IdentityProtocolHandlers::new(
        service.clone(),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(proposed.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        store,
        CursorKey::new([0xb1; 32]).unwrap(),
    );
    let router = Router::builder(controller.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            handlers.handler(IdentityProtocolKind::Pairing),
        )
        .accept(
            krikos_identity::transport::SYNC_ALPN,
            handlers.handler(IdentityProtocolKind::Sync),
        )
        .accept(
            krikos_identity::transport::PROPOSAL_ALPN,
            handlers.handler(IdentityProtocolKind::Proposal),
        )
        .spawn();
    let mut relay_only = controller.addr();
    relay_only.addrs.retain(krikos::TransportAddr::is_relay);
    assert!(!relay_only.addrs.is_empty());

    let request = pairing_ticket(proposed.id()).to_canonical_bytes().unwrap();
    let reply = identity_round_trip(
        &proposed,
        relay_only.clone(),
        IdentityProtocolKind::Pairing,
        &request,
    )
    .await
    .unwrap();
    assert!(reply.as_ack().unwrap().accepted());
    assert_eq!(service.pairing_calls.load(Ordering::SeqCst), 1);

    let authorization =
        EndpointAuthorizationRequest::new(account_id, typed_id(0xb2), typed_id(0xb3));
    let sync = AuthorizedSyncRequest::new(
        authorization,
        SyncRequest::new(account_id, Vec::new(), None, 1, 4 * 1024 * 1024).unwrap(),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    let reply = identity_round_trip(
        &proposed,
        relay_only.clone(),
        IdentityProtocolKind::Sync,
        &sync,
    )
    .await
    .unwrap();
    assert!(reply.as_sync().is_some());

    let proposal = DeviceAuthorizationProposal::from_canonical_bytes(include_bytes!(
        "vectors/device-authorization-proposal.bin"
    ))
    .unwrap();
    let proposal = AuthorizedProposalRequest::new(
        EndpointAuthorizationRequest::new(proposal.account_id(), typed_id(0xb4), typed_id(0xb5)),
        proposal,
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();
    let reply = identity_round_trip(
        &proposed,
        relay_only,
        IdentityProtocolKind::Proposal,
        &proposal,
    )
    .await
    .unwrap();
    assert!(reply.as_ack().unwrap().accepted());
    assert_eq!(service.sync_calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.proposal_calls.load(Ordering::SeqCst), 1);

    router.shutdown().await.unwrap();
    proposed.close().await;
}

#[tokio::test]
async fn router_shutdown_cancels_pending_read_and_pending_service_without_detaching() {
    async fn endpoints() -> (Endpoint, Endpoint) {
        let server = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        (server, client)
    }

    let (server, client) = endpoints().await;
    let service = Arc::new(BlockingPairingService::default());
    let handlers = IdentityProtocolHandlers::new(
        service.clone(),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(client.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        Arc::new(MemoryAccountStore::new()),
        CursorKey::new([0xc1; 32]).unwrap(),
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            handlers.handler(IdentityProtocolKind::Pairing),
        )
        .spawn();
    let connection = client
        .connect(server.addr(), krikos_identity::transport::PAIRING_ALPN)
        .await
        .unwrap();
    let (mut send, _receive) = connection.open_bi().await.unwrap();
    let request = pairing_ticket(client.id()).to_canonical_bytes().unwrap();
    write_bounded_frame(&mut send, &request, 16 * 1024)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        service.entered.notified(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), router.shutdown())
        .await
        .unwrap()
        .unwrap();
    client.close().await;

    let (server, client) = endpoints().await;
    let handlers = IdentityProtocolHandlers::new(
        Arc::new(AcceptPairingService::default()),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(client.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        Arc::new(MemoryAccountStore::new()),
        CursorKey::new([0xc2; 32]).unwrap(),
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            handlers.handler(IdentityProtocolKind::Pairing),
        )
        .spawn();
    let connection = client
        .connect(server.addr(), krikos_identity::transport::PAIRING_ALPN)
        .await
        .unwrap();
    let (mut send, _receive) = connection.open_bi().await.unwrap();
    send.write_all(&64_u32.to_be_bytes()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), router.shutdown())
        .await
        .unwrap()
        .unwrap();
    client.close().await;
}

#[cfg(feature = "fs-store")]
#[tokio::test]
async fn pairing_nonce_replay_is_rejected_after_redb_reopen_between_connections() {
    let directory = tempfile::tempdir().unwrap();
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let handlers = IdentityProtocolHandlers::new(
        Arc::new(ReopeningNonceService {
            path: directory.path().join("pairing-nonces.redb"),
        }),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(client.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        Arc::new(MemoryAccountStore::new()),
        CursorKey::new([0xd1; 32]).unwrap(),
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            handlers.handler(IdentityProtocolKind::Pairing),
        )
        .spawn();
    let request = pairing_ticket(client.id()).to_canonical_bytes().unwrap();

    let first = identity_round_trip(
        &client,
        server.addr(),
        IdentityProtocolKind::Pairing,
        &request,
    )
    .await
    .unwrap();
    assert!(first.as_ack().unwrap().accepted());

    let replay = identity_round_trip(
        &client,
        server.addr(),
        IdentityProtocolKind::Pairing,
        &request,
    )
    .await
    .unwrap();
    let replay_ack = replay.as_ack().unwrap();
    assert!(!replay_ack.accepted());
    assert_eq!(replay_ack.rejection_code().unwrap().unwrap().get(), 2);

    router.shutdown().await.unwrap();
    client.close().await;
}

#[test]
fn concrete_protocol_kinds_commit_all_six_exact_alpns() {
    assert_eq!(
        IdentityProtocolKind::Pairing.alpn(),
        krikos_identity::transport::PAIRING_ALPN
    );
    assert_eq!(
        IdentityProtocolKind::Sync.alpn(),
        krikos_identity::transport::SYNC_ALPN
    );
    assert_eq!(
        IdentityProtocolKind::Proposal.alpn(),
        krikos_identity::transport::PROPOSAL_ALPN
    );
    assert_eq!(
        IdentityProtocolKind::Checkpoint.alpn(),
        krikos_identity::transport::CHECKPOINT_ALPN
    );
    assert_eq!(
        IdentityProtocolKind::TransparencyGossip.alpn(),
        krikos_identity::transport::TRANSPARENCY_GOSSIP_ALPN,
    );
    assert_eq!(
        IdentityProtocolKind::Recovery.alpn(),
        krikos_identity::transport::RECOVERY_ALPN
    );
}

#[tokio::test]
async fn pairing_router_rejects_wrong_alpn_during_handshake() {
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let handlers = IdentityProtocolHandlers::new(
        Arc::new(AcceptPairingService::default()),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(client.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        Arc::new(MemoryAccountStore::new()),
        CursorKey::new([0xe1; 32]).unwrap(),
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            handlers.handler(IdentityProtocolKind::Pairing),
        )
        .spawn();

    assert!(
        client
            .connect(server.addr(), krikos_identity::transport::SYNC_ALPN)
            .await
            .is_err()
    );
    router.shutdown().await.unwrap();
    client.close().await;
}

#[tokio::test]
async fn concrete_handler_rejects_a_completed_connection_with_another_alpn() {
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let (sender, receiver) = oneshot::channel();
    let capture = ConnectionCapture {
        sender: std::sync::Mutex::new(Some(sender)),
    };
    let router = Router::builder(server.clone())
        .accept(krikos_identity::transport::PAIRING_ALPN, capture)
        .spawn();
    let client_connection = client
        .connect(server.addr(), krikos_identity::transport::PAIRING_ALPN)
        .await
        .unwrap();
    let server_connection = receiver.await.unwrap();
    let handlers = IdentityProtocolHandlers::new(
        Arc::new(AcceptPairingService::default()),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(client.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        Arc::new(MemoryAccountStore::new()),
        CursorKey::new([0xe2; 32]).unwrap(),
    );

    assert!(
        handlers
            .handler(IdentityProtocolKind::Sync)
            .accept(server_connection)
            .await
            .is_err()
    );

    client_connection.close(0_u32.into(), b"mismatch observed");
    router.shutdown().await.unwrap();
    client.close().await;
}

#[tokio::test]
async fn shared_handler_admission_caps_aggregate_network_service_concurrency() {
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let service = Arc::new(ConcurrencyBoundPairingService::default());
    let handlers = IdentityProtocolHandlers::new(
        service.clone(),
        Arc::new(CheckpointView {
            endpoint: endpoint_key(client.id()),
            lifecycle: ProjectedDeviceLifecycle::Active,
        }),
        Arc::new(MemoryAccountStore::new()),
        CursorKey::new([0xe3; 32]).unwrap(),
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::PAIRING_ALPN,
            handlers.handler(IdentityProtocolKind::Pairing),
        )
        .spawn();
    let request = Arc::new(pairing_ticket(client.id()).to_canonical_bytes().unwrap());
    let mut tasks = JoinSet::new();
    for _ in 0..=krikos_identity::limits::MAX_CONCURRENT_IDENTITY_TASKS {
        let client = client.clone();
        let server = server.addr();
        let request = request.clone();
        tasks.spawn(async move {
            identity_round_trip(
                &client,
                server,
                IdentityProtocolKind::Pairing,
                request.as_slice(),
            )
            .await
        });
    }

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while service.calls.load(Ordering::SeqCst)
            < krikos_identity::limits::MAX_CONCURRENT_IDENTITY_TASKS
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        service.calls.load(Ordering::SeqCst),
        krikos_identity::limits::MAX_CONCURRENT_IDENTITY_TASKS
    );
    assert_eq!(
        service.peak.load(Ordering::SeqCst),
        krikos_identity::limits::MAX_CONCURRENT_IDENTITY_TASKS
    );

    service.gate.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while service.calls.load(Ordering::SeqCst)
            <= krikos_identity::limits::MAX_CONCURRENT_IDENTITY_TASKS
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    service
        .gate
        .add_permits(krikos_identity::limits::MAX_CONCURRENT_IDENTITY_TASKS);
    while let Some(result) = tasks.join_next().await {
        assert!(result.unwrap().unwrap().as_ack().unwrap().accepted());
    }
    assert_eq!(
        service.peak.load(Ordering::SeqCst),
        krikos_identity::limits::MAX_CONCURRENT_IDENTITY_TASKS
    );

    router.shutdown().await.unwrap();
    client.close().await;
}

#[tokio::test]
async fn network_sync_session_rejects_cumulative_request_and_framing_overflow() {
    let server = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .unwrap();
    let service = Arc::new(AcceptPairingService::default());
    let store = Arc::new(MemoryAccountStore::new());
    let genesis =
        AccountGenesis::from_canonical_bytes(include_bytes!("vectors/account-genesis.bin"))
            .unwrap();
    let account_id = genesis.account_id().unwrap();
    let snapshot = store.create_account(genesis).await.unwrap();
    let authorization =
        EndpointAuthorizationRequest::new(account_id, typed_id(0xe4), typed_id(0xe5));
    let key = CursorKey::new([0xe6; 32]).unwrap();
    let continuation = krikos_identity::SyncCursor::issue(
        &key,
        account_id,
        snapshot.revision().heads().to_vec(),
        0,
        krikos_identity::limits::MAX_SYNC_SESSION_BYTES - 1,
    )
    .unwrap();
    let handlers = IdentityProtocolHandlers::new(
        service.clone(),
        Arc::new(ExactCheckpointView {
            account_id,
            checkpoint_id: authorization.checkpoint_id(),
            device_id: authorization.device_id(),
            endpoint: endpoint_key(client.id()),
        }),
        store,
        CursorKey::new([0xe6; 32]).unwrap(),
    );
    let router = Router::builder(server.clone())
        .accept(
            krikos_identity::transport::SYNC_ALPN,
            handlers.handler(IdentityProtocolKind::Sync),
        )
        .spawn();
    let request = AuthorizedSyncRequest::new(
        authorization,
        SyncRequest::new(
            account_id,
            Vec::new(),
            Some(continuation),
            1,
            4 * 1024 * 1024,
        )
        .unwrap(),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap();

    assert!(
        identity_round_trip(&client, server.addr(), IdentityProtocolKind::Sync, &request)
            .await
            .is_err()
    );
    assert_eq!(service.sync_calls.load(Ordering::SeqCst), 0);

    router.shutdown().await.unwrap();
    client.close().await;
}

#[tokio::test]
async fn network_length_prefix_is_rejected_before_payload_allocation() {
    let (mut sender, mut receiver) = duplex(16);
    sender.write_all(&65_u32.to_be_bytes()).await.unwrap();
    drop(sender);

    let mut budget = SyncSessionBudget::new();
    assert!(matches!(
        read_bounded_frame(&mut receiver, &mut budget, 64).await,
        Err(IdentityError::LimitExceeded { .. })
    ));
    assert_eq!(budget.consumed_bytes(), 0);
}

#[tokio::test]
async fn bounded_frame_round_trip_charges_exact_payload_and_rejects_zero_limit() {
    let payload = b"bounded identity frame";
    let (mut sender, mut receiver) = duplex(128);
    write_bounded_frame(&mut sender, payload, 64).await.unwrap();
    let mut budget = SyncSessionBudget::new();
    assert_eq!(
        read_bounded_frame(&mut receiver, &mut budget, 64)
            .await
            .unwrap(),
        payload
    );
    assert_eq!(budget.consumed_bytes(), payload.len() + 4);

    assert!(matches!(
        write_bounded_frame(&mut sink(), &[], 0).await,
        Err(IdentityError::LimitExceeded { .. })
    ));
}

#[tokio::test]
async fn supervisor_enforces_queue_bound_and_observable_cancellation() {
    let mut supervisor = IdentityTaskSupervisor::new();
    for _ in 0..256 {
        supervisor
            .submit(async { pending::<Result<(), IdentityError>>().await })
            .unwrap();
    }
    assert_eq!(
        supervisor.submit(async { Ok(()) }),
        Err(IdentityError::ResourceBusy)
    );
    assert_eq!(supervisor.shutdown().await, Err(IdentityError::Cancelled));
}

#[tokio::test]
async fn supervisor_reports_child_failure_before_shutdown() {
    let mut supervisor = IdentityTaskSupervisor::new();
    supervisor
        .submit(async { Err(IdentityError::InvalidProof) })
        .unwrap();
    assert_eq!(
        supervisor.join_next().await,
        Some(Err(IdentityError::InvalidProof))
    );
    assert_eq!(supervisor.shutdown().await, Ok(()));
}

struct CheckpointView {
    endpoint: EndpointPublicKey,
    lifecycle: ProjectedDeviceLifecycle,
}

impl VerifiedCheckpointView for CheckpointView {
    fn device_endpoint(
        &self,
        _account_id: AccountId,
        _checkpoint_id: CheckpointId,
        _device_id: DeviceId,
    ) -> Result<Option<CheckpointDeviceEndpoint>, IdentityError> {
        Ok(Some(CheckpointDeviceEndpoint::new(
            self.endpoint,
            self.lifecycle,
        )))
    }
}

#[test]
fn endpoint_dispatch_requires_exact_key_and_active_checkpoint_device() {
    let account_id = typed_id(1);
    let checkpoint_id = typed_id(2);
    let device_id = typed_id(3);
    let expected = endpoint(4);
    let active = CheckpointView {
        endpoint: expected,
        lifecycle: ProjectedDeviceLifecycle::Active,
    };
    let authorized =
        authorize_endpoint_stream(&active, account_id, checkpoint_id, device_id, expected).unwrap();
    assert_eq!(authorized.endpoint_key(), expected);
    assert_eq!(
        authorize_endpoint_stream(&active, account_id, checkpoint_id, device_id, endpoint(5),),
        Err(IdentityError::DeviceNotAuthorized)
    );

    for lifecycle in [
        ProjectedDeviceLifecycle::Suspended,
        ProjectedDeviceLifecycle::Revoked,
    ] {
        let inactive = CheckpointView {
            endpoint: expected,
            lifecycle,
        };
        assert!(
            authorize_endpoint_stream(&inactive, account_id, checkpoint_id, device_id, expected,)
                .is_err()
        );
    }
}
