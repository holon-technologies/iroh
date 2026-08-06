use std::{convert::Infallible, fmt};

use krikos_base::SecretKey;
use rand_core::{TryCryptoRng, TryRng};

use super::{AuthenticatedTransportAdapter, AuthenticatedTransportFacts, TransportExporterValue};
use crate::{
    AccountId, AgreementSecretKey, AuthenticatedTransportBinding, CanonicalWire,
    ConfirmationParticipant, ConnectionEphemeralSecret, DeviceAuthorizationProposal,
    DeviceDescriptor, DevicePresenceChallenge, Digest, EndpointPublicKey, Extensions,
    HashAlgorithm, IdentityError, MemoryPairingNonceStore, NonceConsumeResult, PairingAdmission,
    PairingCeremony, PairingChallenge, PairingConfirmationOutcome, PairingConsumeError,
    PairingConsumeOutcome, PairingNonceKey, PairingNonceStore, PairingPossessionProof,
    PairingSessionId, PairingTicket, PairingTicketRequest, PairingTicketSecrets, PresenceProof,
    ProtocolSignature, ProtocolVersion, SigningPublicKey, Timestamp,
};

struct TestAuthenticatedTransportAdapter {
    facts: AuthenticatedTransportFacts,
}

impl TestAuthenticatedTransportAdapter {
    fn new(
        session_id: PairingSessionId,
        controller_endpoint: EndpointPublicKey,
        proposed_endpoint: EndpointPublicKey,
        exporter_bytes: [u8; 32],
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            facts: AuthenticatedTransportFacts {
                session_id,
                controller_endpoint,
                proposed_endpoint,
                exporter: TransportExporterValue::new(exporter_bytes)?,
            },
        })
    }

    fn into_binding(self) -> Result<AuthenticatedTransportBinding, IdentityError> {
        AuthenticatedTransportBinding::from_authenticated_adapter(self)
    }
}

impl AuthenticatedTransportAdapter for TestAuthenticatedTransportAdapter {
    fn into_authenticated_transport_facts(self) -> AuthenticatedTransportFacts {
        self.facts
    }
}

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

#[derive(Debug)]
struct InjectedEntropyFailure;

impl fmt::Display for InjectedEntropyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected entropy failure")
    }
}

impl std::error::Error for InjectedEntropyFailure {}

struct FailingRng;

impl TryRng for FailingRng {
    type Error = InjectedEntropyFailure;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(InjectedEntropyFailure)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(InjectedEntropyFailure)
    }

    fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
        Err(InjectedEntropyFailure)
    }
}

impl TryCryptoRng for FailingRng {}

struct ScriptedFillRng {
    fills: [u8; 3],
    next_fill: usize,
}

impl ScriptedFillRng {
    const fn new(fills: [u8; 3]) -> Self {
        Self {
            fills,
            next_fill: 0,
        }
    }
}

impl TryRng for ScriptedFillRng {
    type Error = InjectedEntropyFailure;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Err(InjectedEntropyFailure)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Err(InjectedEntropyFailure)
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        let seed = self
            .fills
            .get(self.next_fill)
            .copied()
            .ok_or(InjectedEntropyFailure)?;
        self.next_fill = self
            .next_fill
            .checked_add(1)
            .ok_or(InjectedEntropyFailure)?;
        destination.fill(seed);
        Ok(())
    }
}

impl TryCryptoRng for ScriptedFillRng {}

fn account_id(seed: u8) -> AccountId {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [seed; 32]);
    AccountId::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn descriptor(
    application_secret: &SecretKey,
    agreement_secret: &AgreementSecretKey,
    endpoint_secret: &SecretKey,
) -> DeviceDescriptor {
    DeviceDescriptor::new(
        SigningPublicKey::ed25519(*application_secret.public().as_bytes()).unwrap(),
        agreement_secret.public_key().unwrap(),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*endpoint_secret.public().as_bytes()).unwrap(),
        ),
        Extensions::default(),
    )
    .unwrap()
}

struct DeviceSecrets {
    application: SecretKey,
    agreement: AgreementSecretKey,
    endpoint: SecretKey,
}

impl DeviceSecrets {
    fn new(seed: u8) -> Self {
        Self {
            application: SecretKey::from_bytes(&[seed; 32]),
            agreement: AgreementSecretKey::from_bytes([seed.checked_add(1).unwrap(); 32]),
            endpoint: SecretKey::from_bytes(&[seed.checked_add(2).unwrap(); 32]),
        }
    }

    fn descriptor(&self) -> DeviceDescriptor {
        descriptor(&self.application, &self.agreement, &self.endpoint)
    }
}

struct TicketFixture {
    ticket: PairingTicket,
    ticket_secrets: PairingTicketSecrets,
    proposed_secrets: DeviceSecrets,
    controller_secrets: DeviceSecrets,
}

fn ticket_fixture() -> TicketFixture {
    ticket_fixture_with_rng(0x5a)
}

fn ticket_fixture_with_rng(random_seed: u8) -> TicketFixture {
    let proposed_secrets = DeviceSecrets::new(10);
    let controller_secrets = DeviceSecrets::new(20);
    let request = PairingTicketRequest::new(
        account_id(1),
        proposed_secrets.descriptor(),
        b"relay.example.invalid".to_vec(),
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(601_000),
        Extensions::default(),
    )
    .unwrap();
    let (ticket, ticket_secrets) =
        PairingTicket::issue_with_rng(request, &mut RepeatingRng(random_seed)).unwrap();
    TicketFixture {
        ticket,
        ticket_secrets,
        proposed_secrets,
        controller_secrets,
    }
}

#[allow(clippy::too_many_arguments)]
fn ticket_wire(
    ticket: &PairingTicket,
    account_id: AccountId,
    proposed_device_id: crate::DeviceId,
    proposed_endpoint: EndpointPublicKey,
    commitment: Digest,
) -> Vec<u8> {
    postcard::to_stdvec(&(
        ProtocolVersion::V1,
        account_id,
        ticket.proposed_device().clone(),
        proposed_device_id,
        ticket.ephemeral_public_key(),
        proposed_endpoint,
        ticket.endpoint_hint().to_vec(),
        commitment,
        ticket.issued_at(),
        ticket.expires_at(),
        ticket.nonce(),
        ticket.extensions().clone(),
    ))
    .unwrap()
}

#[test]
fn ticket_is_bounded_canonical_and_binds_the_derived_device() {
    let secrets = DeviceSecrets::new(2);
    let descriptor = secrets.descriptor();
    let request = PairingTicketRequest::new(
        account_id(1),
        descriptor.clone(),
        b"relay.example.invalid".to_vec(),
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(601_000),
        Extensions::default(),
    )
    .unwrap();
    let (ticket, _secrets) =
        PairingTicket::issue_with_rng(request, &mut RepeatingRng(0x5a)).unwrap();

    assert_eq!(ticket.proposed_device_id(), descriptor.id().unwrap());
    assert_eq!(ticket.proposed_endpoint(), descriptor.endpoint_key());
    let encoded = ticket.to_canonical_bytes().unwrap();
    assert!(encoded.len() <= crate::limits::MAX_PAIRING_TICKET_BYTES);
    assert_eq!(
        PairingTicket::from_canonical_bytes(&encoded).unwrap(),
        ticket
    );
}

#[test]
fn ticket_rejects_bounds_bad_time_entropy_and_low_order_ephemeral_keys() {
    let secrets = DeviceSecrets::new(2);
    assert!(matches!(
        PairingTicketRequest::new(
            account_id(1),
            secrets.descriptor(),
            vec![0; crate::MAX_PAIRING_ENDPOINT_HINT_BYTES + 1],
            Timestamp::from_unix_millis(1_000),
            Timestamp::from_unix_millis(2_000),
            Extensions::default(),
        ),
        Err(IdentityError::LimitExceeded { .. })
    ));
    assert!(
        PairingTicketRequest::new(
            account_id(1),
            secrets.descriptor(),
            Vec::new(),
            Timestamp::from_unix_millis(1_000),
            Timestamp::from_unix_millis(601_001),
            Extensions::default(),
        )
        .is_err()
    );
    assert!(
        PairingTicketRequest::new(
            account_id(1),
            secrets.descriptor(),
            Vec::new(),
            Timestamp::from_unix_millis(1_000),
            Timestamp::from_unix_millis(1_000),
            Extensions::default(),
        )
        .is_err()
    );

    let request = PairingTicketRequest::new(
        account_id(1),
        secrets.descriptor(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(2_000),
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        PairingTicket::issue_with_rng(request, &mut RepeatingRng(0)),
        Err(IdentityError::ZeroValue { .. })
    ));

    let request = PairingTicketRequest::new(
        account_id(1),
        secrets.descriptor(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(2_000),
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        PairingTicket::issue_with_rng(request, &mut FailingRng),
        Err(IdentityError::EntropyUnavailable)
    ));
    assert!(matches!(
        ConnectionEphemeralSecret::generate_with_rng(&mut FailingRng),
        Err(IdentityError::EntropyUnavailable)
    ));

    let fixture = ticket_fixture();
    let mut encoded = fixture.ticket.to_canonical_bytes().unwrap();
    let public_key = fixture.ticket.ephemeral_public_key();
    let start = encoded
        .windows(32)
        .position(|window| window == public_key.as_bytes())
        .expect("ticket encoding must contain its exact ephemeral public key");
    encoded[start..start + 32].fill(0);
    let result = PairingTicket::from_canonical_bytes(&encoded);
    assert!(result.is_err(), "unexpected low-order result: {result:?}");
}

#[test]
fn ticket_generation_rejects_all_zero_ephemeral_source_material() {
    let secrets = DeviceSecrets::new(2);
    let request = PairingTicketRequest::new(
        account_id(1),
        secrets.descriptor(),
        Vec::new(),
        Timestamp::from_unix_millis(1_000),
        Timestamp::from_unix_millis(2_000),
        Extensions::default(),
    )
    .unwrap();
    let mut rng = ScriptedFillRng::new([1, 0, 2]);

    assert!(matches!(
        PairingTicket::issue_with_rng(request, &mut rng),
        Err(IdentityError::ZeroValue { .. })
    ));
}

#[test]
fn connection_generation_rejects_all_zero_source_material_before_clamping() {
    let mut rng = ScriptedFillRng::new([0, 1, 2]);
    assert!(matches!(
        ConnectionEphemeralSecret::generate_with_rng(&mut rng),
        Err(IdentityError::ZeroValue { .. })
    ));

    assert!(
        ConnectionEphemeralSecret::from_bytes([0; 32])
            .public_key()
            .is_ok(),
        "the explicit deterministic compatibility constructor remains infallible"
    );
}

#[test]
fn ticket_wire_rejects_wrong_derived_device_and_endpoint() {
    let fixture = ticket_fixture();
    let wrong_device = DeviceSecrets::new(80).descriptor();
    let wrong_id = wrong_device.id().unwrap();
    let wrong_endpoint = wrong_device.endpoint_key();
    let wrong_id_wire = ticket_wire(
        &fixture.ticket,
        fixture.ticket.account_id(),
        wrong_id,
        fixture.ticket.proposed_endpoint(),
        fixture.ticket.random_secret_commitment(),
    );
    let result = PairingTicket::from_canonical_bytes(&wrong_id_wire);
    assert!(result.is_err(), "unexpected wrong-id result: {result:?}");

    let wrong_endpoint_wire = ticket_wire(
        &fixture.ticket,
        fixture.ticket.account_id(),
        fixture.ticket.proposed_device_id(),
        wrong_endpoint,
        fixture.ticket.random_secret_commitment(),
    );
    let result = PairingTicket::from_canonical_bytes(&wrong_endpoint_wire);
    assert!(
        result.is_err(),
        "unexpected wrong-endpoint result: {result:?}"
    );
}

#[derive(Debug, Default, Clone)]
struct DurableNonceStore {
    consumed: Vec<PairingNonceKey>,
    fail_next: bool,
}

impl PairingNonceStore for DurableNonceStore {
    type Error = &'static str;

    fn is_consumed(&mut self, key: PairingNonceKey) -> Result<bool, Self::Error> {
        Ok(self.consumed.contains(&key))
    }

    fn consume_atomically(
        &mut self,
        key: PairingNonceKey,
        _expires_at: Timestamp,
    ) -> Result<NonceConsumeResult, Self::Error> {
        if self.fail_next {
            self.fail_next = false;
            return Err("injected durable write failure");
        }
        if self.consumed.contains(&key) {
            return Ok(NonceConsumeResult::AlreadyConsumed);
        }
        self.consumed.push(key);
        Ok(NonceConsumeResult::Consumed)
    }
}

fn accept_ticket(
    ticket: PairingTicket,
    now: Timestamp,
) -> Result<PairingAdmission, PairingConsumeError<&'static str>> {
    PairingCeremony::accept(ticket, &mut DurableNonceStore::default(), now)
}

fn connect_fixture(
    fixture: &TicketFixture,
    exporter_seed: u8,
) -> crate::PairingCeremony<crate::Connected> {
    let admission =
        accept_ticket(fixture.ticket.clone(), Timestamp::from_unix_millis(2_000)).unwrap();
    let PairingAdmission::Issued(issued) = admission else {
        panic!("fresh ticket must be issued");
    };
    let controller = fixture.controller_secrets.descriptor();
    let binding = TestAuthenticatedTransportAdapter::new(
        PairingSessionId::new([0x31; 32]).unwrap(),
        controller.endpoint_key(),
        fixture.ticket.proposed_endpoint(),
        [exporter_seed; 32],
    )
    .unwrap()
    .into_binding()
    .unwrap();
    issued
        .connect(
            controller,
            binding,
            PairingChallenge::new([0x41; 32]).unwrap(),
            ConnectionEphemeralSecret::from_bytes([0x51; 32]),
        )
        .unwrap()
}

fn connect_ticket(
    fixture: &TicketFixture,
    ticket: PairingTicket,
    session_seed: u8,
    challenge_seed: u8,
    exporter_seed: u8,
) -> Result<crate::PairingCeremony<crate::Connected>, IdentityError> {
    let PairingAdmission::Issued(issued) =
        accept_ticket(ticket.clone(), Timestamp::from_unix_millis(2_000))
            .map_err(|_| IdentityError::StaleEvidence)?
    else {
        return Err(IdentityError::StaleEvidence);
    };
    let controller = fixture.controller_secrets.descriptor();
    let binding = TestAuthenticatedTransportAdapter::new(
        PairingSessionId::new([session_seed; 32])?,
        controller.endpoint_key(),
        ticket.proposed_endpoint(),
        [exporter_seed; 32],
    )?
    .into_binding()?;
    issued.connect(
        controller,
        binding,
        PairingChallenge::new([challenge_seed; 32])?,
        ConnectionEphemeralSecret::from_bytes([0x51; 32]),
    )
}

fn connect_with_controller_and_connection(
    fixture: &TicketFixture,
    controller: DeviceDescriptor,
    connection_secret_seed: u8,
) -> Result<crate::PairingCeremony<crate::Connected>, IdentityError> {
    let PairingAdmission::Issued(issued) =
        accept_ticket(fixture.ticket.clone(), Timestamp::from_unix_millis(2_000))
            .map_err(|_| IdentityError::StaleEvidence)?
    else {
        return Err(IdentityError::StaleEvidence);
    };
    let binding = TestAuthenticatedTransportAdapter::new(
        PairingSessionId::new([0x31; 32])?,
        controller.endpoint_key(),
        fixture.ticket.proposed_endpoint(),
        [0x61; 32],
    )?
    .into_binding()?;
    issued.connect(
        controller,
        binding,
        PairingChallenge::new([0x41; 32])?,
        ConnectionEphemeralSecret::from_bytes([connection_secret_seed; 32]),
    )
}

fn proof_for(
    fixture: &TicketFixture,
    connected: &crate::PairingCeremony<crate::Connected>,
) -> PairingPossessionProof {
    let transcript = connected.transcript();
    let application_signature = fixture
        .proposed_secrets
        .application
        .sign(&transcript.application_possession_signing_bytes().unwrap());
    let endpoint_signature = fixture
        .proposed_secrets
        .endpoint
        .sign(&transcript.endpoint_possession_signing_bytes().unwrap());
    PairingPossessionProof::create(
        transcript,
        &fixture.ticket_secrets,
        &fixture.proposed_secrets.agreement,
        ProtocolSignature::ed25519(application_signature.to_bytes()),
        ProtocolSignature::ed25519(endpoint_signature.to_bytes()),
    )
    .unwrap()
}

fn signed_confirmation(
    proven: &crate::PairingCeremony<crate::Proven>,
    endpoint_secret: &SecretKey,
    participant: ConfirmationParticipant,
    observed_short_auth: crate::ShortAuthString,
    confirmed_at: Timestamp,
) -> crate::PairingConfirmation {
    let signing_bytes = proven
        .confirmation_signing_bytes(participant, observed_short_auth, confirmed_at)
        .unwrap();
    let signature = endpoint_secret.sign(&signing_bytes);
    proven.signed_confirmation(
        participant,
        observed_short_auth,
        confirmed_at,
        ProtocolSignature::ed25519(signature.to_bytes()),
    )
}

fn confirmed_fixture(fixture: &TicketFixture) -> crate::PairingCeremony<crate::Confirmed> {
    let connected = connect_fixture(fixture, 0x61);
    let proof = proof_for(fixture, &connected);
    let proven = connected.verify_possession(proof).unwrap();
    let short_auth = proven.short_auth_string();
    let controller = signed_confirmation(
        &proven,
        &fixture.controller_secrets.endpoint,
        ConfirmationParticipant::Controller,
        short_auth,
        Timestamp::from_unix_millis(3_000),
    );
    let proposed = signed_confirmation(
        &proven,
        &fixture.proposed_secrets.endpoint,
        ConfirmationParticipant::ProposedDevice,
        short_auth,
        Timestamp::from_unix_millis(3_001),
    );
    let PairingConfirmationOutcome::Confirmed(confirmed) = proven.confirm(controller, proposed)
    else {
        panic!("matching exact transcript values must confirm");
    };
    *confirmed
}

fn consumed_proposal(outcome: PairingConsumeOutcome) -> &'static DeviceAuthorizationProposal {
    let PairingConsumeOutcome::Consumed(consumed) = outcome else {
        panic!("fresh confirmed ceremony must be consumed");
    };
    Box::leak(Box::new((*consumed).into_proposal()))
}

#[test]
fn complete_transcript_proves_every_key_role_and_consumes_before_proposal() {
    let fixture = ticket_fixture();
    let confirmed = confirmed_fixture(&fixture);
    let mut store = DurableNonceStore::default();
    let proposal = consumed_proposal(
        confirmed
            .consume(&mut store, Timestamp::from_unix_millis(4_000))
            .unwrap(),
    );

    assert_eq!(proposal.account_id(), fixture.ticket.account_id());
    assert_eq!(
        proposal.proposed_device_id(),
        fixture.ticket.proposed_device_id()
    );
    assert_eq!(store.consumed.len(), 1);
    assert!(proposal.proposal_id().is_ok());
}

#[test]
fn possession_proof_is_canonical_and_ticket_id_prevents_account_tampering() {
    let fixture = ticket_fixture();
    let connected = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &connected);
    let encoded = proof.to_canonical_bytes().unwrap();
    let decoded = PairingPossessionProof::from_canonical_bytes(&encoded).unwrap();
    assert_eq!(decoded.to_canonical_bytes().unwrap(), encoded);
    assert!(connected.verify_possession(decoded).is_ok());

    let tampered_wire = ticket_wire(
        &fixture.ticket,
        account_id(90),
        fixture.ticket.proposed_device_id(),
        fixture.ticket.proposed_endpoint(),
        fixture.ticket.random_secret_commitment(),
    );
    let tampered_ticket = PairingTicket::from_canonical_bytes(&tampered_wire).unwrap();
    let connected = connect_ticket(&fixture, tampered_ticket, 0x31, 0x41, 0x61).unwrap();
    let transcript = connected.transcript();
    let application = fixture
        .proposed_secrets
        .application
        .sign(&transcript.application_possession_signing_bytes().unwrap());
    let endpoint = fixture
        .proposed_secrets
        .endpoint
        .sign(&transcript.endpoint_possession_signing_bytes().unwrap());
    assert!(matches!(
        PairingPossessionProof::create(
            transcript,
            &fixture.ticket_secrets,
            &fixture.proposed_secrets.agreement,
            ProtocolSignature::ed25519(application.to_bytes()),
            ProtocolSignature::ed25519(endpoint.to_bytes()),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn exporter_substitution_and_each_forged_signature_are_rejected() {
    let fixture = ticket_fixture();
    let original = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &original);
    let substituted = connect_fixture(&fixture, 0x62);
    assert!(matches!(
        substituted.verify_possession(proof),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let connected = connect_fixture(&fixture, 0x61);
    let transcript = connected.transcript();
    let wrong = SecretKey::from_bytes(&[0x70; 32]);
    let wrong_application = wrong.sign(&transcript.application_possession_signing_bytes().unwrap());
    let endpoint = fixture
        .proposed_secrets
        .endpoint
        .sign(&transcript.endpoint_possession_signing_bytes().unwrap());
    let proof = PairingPossessionProof::create(
        transcript,
        &fixture.ticket_secrets,
        &fixture.proposed_secrets.agreement,
        ProtocolSignature::ed25519(wrong_application.to_bytes()),
        ProtocolSignature::ed25519(endpoint.to_bytes()),
    )
    .unwrap();
    assert_eq!(
        connected.verify_possession(proof).unwrap_err(),
        IdentityError::InvalidSignature
    );

    let connected = connect_fixture(&fixture, 0x61);
    let transcript = connected.transcript();
    let application = fixture
        .proposed_secrets
        .application
        .sign(&transcript.application_possession_signing_bytes().unwrap());
    let wrong_endpoint = wrong.sign(&transcript.endpoint_possession_signing_bytes().unwrap());
    let proof = PairingPossessionProof::create(
        transcript,
        &fixture.ticket_secrets,
        &fixture.proposed_secrets.agreement,
        ProtocolSignature::ed25519(application.to_bytes()),
        ProtocolSignature::ed25519(wrong_endpoint.to_bytes()),
    )
    .unwrap();
    assert_eq!(
        connected.verify_possession(proof).unwrap_err(),
        IdentityError::InvalidSignature
    );
}

#[test]
fn challenge_session_controller_descriptor_and_endpoint_substitution_fail() {
    let fixture = ticket_fixture();
    let original = connect_ticket(&fixture, fixture.ticket.clone(), 0x31, 0x41, 0x61).unwrap();
    let original_proof = proof_for(&fixture, &original);
    let session_substituted =
        connect_ticket(&fixture, fixture.ticket.clone(), 0x32, 0x41, 0x61).unwrap();
    assert!(matches!(
        session_substituted.verify_possession(original_proof),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let original = connect_fixture(&fixture, 0x61);
    let original_proof = proof_for(&fixture, &original);
    let challenge_substituted =
        connect_ticket(&fixture, fixture.ticket.clone(), 0x31, 0x42, 0x61).unwrap();
    assert!(matches!(
        challenge_substituted.verify_possession(original_proof),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let PairingAdmission::Issued(issued) =
        accept_ticket(fixture.ticket.clone(), Timestamp::from_unix_millis(2_000)).unwrap()
    else {
        panic!("fixture ticket must be live");
    };
    let controller = fixture.controller_secrets.descriptor();
    let wrong_endpoint = DeviceSecrets::new(90).descriptor().endpoint_key();
    let binding = TestAuthenticatedTransportAdapter::new(
        PairingSessionId::new([0x31; 32]).unwrap(),
        controller.endpoint_key(),
        wrong_endpoint,
        [0x61; 32],
    )
    .unwrap()
    .into_binding()
    .unwrap();
    assert!(matches!(
        issued.connect(
            controller,
            binding,
            PairingChallenge::new([0x41; 32]).unwrap(),
            ConnectionEphemeralSecret::from_bytes([0x51; 32]),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn descriptor_connection_ephemeral_and_commitment_substitution_fail() {
    let fixture = ticket_fixture();
    let original = connect_fixture(&fixture, 0x61);
    let original_proof = proof_for(&fixture, &original);
    let descriptor_substituted =
        connect_with_controller_and_connection(&fixture, DeviceSecrets::new(30).descriptor(), 0x51)
            .unwrap();
    assert!(matches!(
        descriptor_substituted.verify_possession(original_proof),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let original = connect_fixture(&fixture, 0x61);
    let original_proof = proof_for(&fixture, &original);
    let connection_ephemeral_substituted = connect_with_controller_and_connection(
        &fixture,
        fixture.controller_secrets.descriptor(),
        0x52,
    )
    .unwrap();
    assert!(matches!(
        connection_ephemeral_substituted.verify_possession(original_proof),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let original = connect_fixture(&fixture, 0x61);
    let original_proof = proof_for(&fixture, &original);
    let commitment_substituted_wire = ticket_wire(
        &fixture.ticket,
        fixture.ticket.account_id(),
        fixture.ticket.proposed_device_id(),
        fixture.ticket.proposed_endpoint(),
        Digest::new(HashAlgorithm::Blake3_256, [0x91; 32]),
    );
    let commitment_substituted_ticket =
        PairingTicket::from_canonical_bytes(&commitment_substituted_wire).unwrap();
    let commitment_substituted =
        connect_ticket(&fixture, commitment_substituted_ticket, 0x31, 0x41, 0x61).unwrap();
    assert!(matches!(
        commitment_substituted.verify_possession(original_proof),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn individual_agreement_and_pairing_ephemeral_mac_corruption_fail() {
    let fixture = ticket_fixture();
    let connected = connect_fixture(&fixture, 0x61);
    let mut agreement_corrupted = proof_for(&fixture, &connected);
    agreement_corrupted.agreement_mac.0[0] ^= 1;
    assert_eq!(
        connected
            .verify_possession(agreement_corrupted)
            .unwrap_err(),
        IdentityError::InvalidProof
    );

    let connected = connect_fixture(&fixture, 0x61);
    let mut ephemeral_corrupted = proof_for(&fixture, &connected);
    ephemeral_corrupted.pairing_ephemeral_mac.0[0] ^= 1;
    assert_eq!(
        connected
            .verify_possession(ephemeral_corrupted)
            .unwrap_err(),
        IdentityError::InvalidProof
    );
}

#[test]
fn transcript_rejects_all_cross_device_role_and_ephemeral_public_key_reuse() {
    let fixture = ticket_fixture();
    let controller_keys = &fixture.controller_secrets;
    let reused_proposed_endpoint = fixture
        .ticket
        .proposed_device()
        .endpoint_key()
        .as_signing_key();
    let controller = DeviceDescriptor::new(
        reused_proposed_endpoint,
        controller_keys.agreement.public_key().unwrap(),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*controller_keys.endpoint.public().as_bytes()).unwrap(),
        ),
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        connect_with_controller_and_connection(&fixture, controller, 0x51),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let reused_proposed_application = fixture.ticket.proposed_device().application_signing_key();
    let controller = DeviceDescriptor::new(
        reused_proposed_application,
        controller_keys.agreement.public_key().unwrap(),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*controller_keys.endpoint.public().as_bytes()).unwrap(),
        ),
        Extensions::default(),
    )
    .unwrap();
    assert!(matches!(
        connect_with_controller_and_connection(&fixture, controller, 0x51),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let pairing_ephemeral_reuses_agreement = ticket_fixture_with_rng(11);
    assert!(matches!(
        connect_with_controller_and_connection(
            &pairing_ephemeral_reuses_agreement,
            pairing_ephemeral_reuses_agreement
                .controller_secrets
                .descriptor(),
            0x51,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    assert!(matches!(
        connect_with_controller_and_connection(
            &fixture,
            fixture.controller_secrets.descriptor(),
            11,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
    assert!(matches!(
        connect_with_controller_and_connection(
            &fixture,
            fixture.controller_secrets.descriptor(),
            0x5a,
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn wrong_agreement_or_ticket_secret_cannot_create_a_valid_proof() {
    let fixture = ticket_fixture();
    let connected = connect_fixture(&fixture, 0x61);
    let transcript = connected.transcript();
    let application = fixture
        .proposed_secrets
        .application
        .sign(&transcript.application_possession_signing_bytes().unwrap());
    let endpoint = fixture
        .proposed_secrets
        .endpoint
        .sign(&transcript.endpoint_possession_signing_bytes().unwrap());
    let wrong_agreement = AgreementSecretKey::from_bytes([0x71; 32]);
    assert!(matches!(
        PairingPossessionProof::create(
            transcript,
            &fixture.ticket_secrets,
            &wrong_agreement,
            ProtocolSignature::ed25519(application.to_bytes()),
            ProtocolSignature::ed25519(endpoint.to_bytes()),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));

    let other = ticket_fixture_with_rng(0x6a);
    assert!(matches!(
        PairingPossessionProof::create(
            transcript,
            &other.ticket_secrets,
            &fixture.proposed_secrets.agreement,
            ProtocolSignature::ed25519(application.to_bytes()),
            ProtocolSignature::ed25519(endpoint.to_bytes()),
        ),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn short_auth_mismatch_cancels_without_proposal() {
    let fixture = ticket_fixture();
    let connected = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &connected);
    let proven = connected.verify_possession(proof).unwrap();
    let short_auth = proven.short_auth_string();
    let wrong_short_auth = crate::ShortAuthString::new(*b"000000").unwrap();
    let controller = signed_confirmation(
        &proven,
        &fixture.controller_secrets.endpoint,
        ConfirmationParticipant::Controller,
        short_auth,
        Timestamp::from_unix_millis(3_000),
    );
    let proposed = signed_confirmation(
        &proven,
        &fixture.proposed_secrets.endpoint,
        ConfirmationParticipant::ProposedDevice,
        wrong_short_auth,
        Timestamp::from_unix_millis(3_001),
    );
    assert!(matches!(
        proven.confirm(controller, proposed),
        PairingConfirmationOutcome::Cancelled(_)
    ));
}

#[test]
fn one_proven_holder_cannot_synthesize_both_participant_confirmations() {
    let fixture = ticket_fixture();
    let connected = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &connected);
    let proven = connected.verify_possession(proof).unwrap();
    let short_auth = proven.short_auth_string();
    let controller = signed_confirmation(
        &proven,
        &fixture.controller_secrets.endpoint,
        ConfirmationParticipant::Controller,
        short_auth,
        Timestamp::from_unix_millis(3_000),
    );
    let forged_proposed = signed_confirmation(
        &proven,
        &fixture.controller_secrets.endpoint,
        ConfirmationParticipant::ProposedDevice,
        short_auth,
        Timestamp::from_unix_millis(3_001),
    );

    assert!(matches!(
        proven.confirm(controller, forged_proposed),
        PairingConfirmationOutcome::Cancelled(_)
    ));

    let connected = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &connected);
    let proven = connected.verify_possession(proof).unwrap();
    let short_auth = proven.short_auth_string();
    let forged_controller = signed_confirmation(
        &proven,
        &fixture.proposed_secrets.endpoint,
        ConfirmationParticipant::Controller,
        short_auth,
        Timestamp::from_unix_millis(3_000),
    );
    let proposed = signed_confirmation(
        &proven,
        &fixture.proposed_secrets.endpoint,
        ConfirmationParticipant::ProposedDevice,
        short_auth,
        Timestamp::from_unix_millis(3_001),
    );
    assert!(matches!(
        proven.confirm(forged_controller, proposed),
        PairingConfirmationOutcome::Cancelled(_)
    ));
}

#[test]
fn confirmation_evidence_binds_participant_and_authenticated_session() {
    let fixture = ticket_fixture();
    let connected = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &connected);
    let proven = connected.verify_possession(proof).unwrap();
    let short_auth = proven.short_auth_string();
    let controller_bytes = proven
        .confirmation_signing_bytes(
            ConfirmationParticipant::Controller,
            short_auth,
            Timestamp::from_unix_millis(3_000),
        )
        .unwrap();
    let proposed_bytes = proven
        .confirmation_signing_bytes(
            ConfirmationParticipant::ProposedDevice,
            short_auth,
            Timestamp::from_unix_millis(3_000),
        )
        .unwrap();
    assert!(controller_bytes.starts_with(b"KRIKOS-ID/pairing-confirmation/v1\0"));
    assert_ne!(controller_bytes, proposed_bytes);

    let other_session = connect_ticket(&fixture, fixture.ticket.clone(), 0x32, 0x41, 0x61).unwrap();
    let other_proof = proof_for(&fixture, &other_session);
    let other_proven = other_session.verify_possession(other_proof).unwrap();
    let other_bytes = other_proven
        .confirmation_signing_bytes(
            ConfirmationParticipant::Controller,
            other_proven.short_auth_string(),
            Timestamp::from_unix_millis(3_000),
        )
        .unwrap();
    assert_ne!(controller_bytes, other_bytes);
}

#[test]
fn replay_store_reopen_and_atomic_failure_never_emit_a_proposal() {
    let fixture = ticket_fixture();
    let confirmed = confirmed_fixture(&fixture);
    let mut store = DurableNonceStore {
        consumed: Vec::new(),
        fail_next: true,
    };
    assert!(
        store.consumed.is_empty(),
        "no pre-consume proposal side effect"
    );
    assert!(matches!(
        confirmed.consume(&mut store, Timestamp::from_unix_millis(4_000)),
        Err(PairingConsumeError::Store("injected durable write failure"))
    ));
    assert!(store.consumed.is_empty());

    let confirmed = confirmed_fixture(&fixture);
    let _proposal = consumed_proposal(
        confirmed
            .consume(&mut store, Timestamp::from_unix_millis(4_000))
            .unwrap(),
    );
    let reopened = DurableNonceStore {
        consumed: store.consumed.clone(),
        fail_next: false,
    };
    let mut reopened = reopened;
    let replay = confirmed_fixture(&fixture);
    assert!(matches!(
        replay.consume(&mut reopened, Timestamp::from_unix_millis(4_001)),
        Err(PairingConsumeError::AlreadyConsumed)
    ));
}

#[test]
fn expiry_is_terminal_and_durably_tombstoned_at_consume() {
    let fixture = ticket_fixture();
    let mut admission_store = DurableNonceStore::default();
    let admission = PairingCeremony::accept(
        fixture.ticket.clone(),
        &mut admission_store,
        Timestamp::from_unix_millis(601_001),
    )
    .unwrap();
    assert!(matches!(admission, PairingAdmission::Expired(_)));
    assert_eq!(admission_store.consumed.len(), 1);

    let confirmed = confirmed_fixture(&fixture);
    let mut store = DurableNonceStore::default();
    assert!(matches!(
        confirmed
            .consume(&mut store, Timestamp::from_unix_millis(601_001))
            .unwrap(),
        PairingConsumeOutcome::Expired(_)
    ));
    assert_eq!(store.consumed.len(), 1);
    let replay = confirmed_fixture(&fixture);
    assert!(matches!(
        replay.consume(&mut store, Timestamp::from_unix_millis(4_000)),
        Err(PairingConsumeError::AlreadyConsumed)
    ));
}

#[test]
fn expired_admission_cannot_revive_after_clock_rollback() {
    let fixture = ticket_fixture();
    let mut store = DurableNonceStore::default();
    let expired = PairingCeremony::accept(
        fixture.ticket.clone(),
        &mut store,
        Timestamp::from_unix_millis(601_001),
    )
    .unwrap();
    assert!(matches!(expired, PairingAdmission::Expired(_)));

    let mut reopened = store.clone();
    let rolled_back = PairingCeremony::accept(
        fixture.ticket.clone(),
        &mut reopened,
        Timestamp::from_unix_millis(4_000),
    );
    assert!(matches!(
        rolled_back,
        Err(PairingConsumeError::AlreadyConsumed)
    ));
}

#[test]
fn production_memory_nonce_store_keeps_expiry_tombstones_across_clock_rollback() {
    let fixture = ticket_fixture();
    let mut store = MemoryPairingNonceStore::new();
    let expired = PairingCeremony::accept(
        fixture.ticket.clone(),
        &mut store,
        Timestamp::from_unix_millis(601_001),
    )
    .unwrap();
    assert!(matches!(expired, PairingAdmission::Expired(_)));

    assert!(matches!(
        PairingCeremony::accept(
            fixture.ticket,
            &mut store,
            Timestamp::from_unix_millis(4_000),
        ),
        Err(PairingConsumeError::AlreadyConsumed)
    ));
}

#[test]
fn pairing_future_skew_and_expiry_boundaries_are_exact() {
    let proposed = DeviceSecrets::new(10);
    let request = PairingTicketRequest::new(
        account_id(1),
        proposed.descriptor(),
        Vec::new(),
        Timestamp::from_unix_millis(121_000),
        Timestamp::from_unix_millis(122_000),
        Extensions::default(),
    )
    .unwrap();
    let (ticket, _) = PairingTicket::issue_with_rng(request, &mut RepeatingRng(0x5a)).unwrap();
    assert!(matches!(
        accept_ticket(ticket.clone(), Timestamp::from_unix_millis(1_000)).unwrap(),
        PairingAdmission::Issued(_)
    ));
    assert!(matches!(
        accept_ticket(ticket.clone(), Timestamp::from_unix_millis(999)),
        Err(PairingConsumeError::Protocol(
            IdentityError::InvalidRelationship { .. }
        ))
    ));
    assert!(matches!(
        accept_ticket(ticket.clone(), Timestamp::from_unix_millis(122_000)).unwrap(),
        PairingAdmission::Issued(_)
    ));
    assert!(matches!(
        accept_ticket(ticket, Timestamp::from_unix_millis(122_001)).unwrap(),
        PairingAdmission::Expired(_)
    ));
}

#[test]
fn duplicate_reorder_and_restart_model_emits_at_most_one_proposal() {
    let fixture = ticket_fixture();
    for actions in [[0_u8, 1, 0, 2], [1_u8, 0, 2, 0], [2_u8, 0, 1, 0]] {
        let mut store = DurableNonceStore::default();
        let mut proposals = 0_u8;
        for action in actions {
            match action {
                0 => {
                    let confirmed = confirmed_fixture(&fixture);
                    match confirmed.consume(&mut store, Timestamp::from_unix_millis(4_000)) {
                        Ok(PairingConsumeOutcome::Consumed(_)) => proposals += 1,
                        Err(PairingConsumeError::AlreadyConsumed) => {}
                        unexpected => panic!("unexpected model outcome: {unexpected:?}"),
                    }
                }
                1 => {
                    store = DurableNonceStore {
                        consumed: store.consumed.clone(),
                        fail_next: false,
                    };
                }
                2 => {
                    let connected = connect_fixture(&fixture, 0x61);
                    let other_session =
                        connect_ticket(&fixture, fixture.ticket.clone(), 0x32, 0x41, 0x61).unwrap();
                    assert!(
                        other_session
                            .verify_possession(proof_for(&fixture, &connected))
                            .is_err()
                    );
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(proposals, 1);
    }
}

fn assert_canonical_corpus_seed<T: CanonicalWire>(input: &[u8], expected_selector: usize) {
    const DECODER_COUNT: usize = 6;
    let Some((&selector, encoded_payload)) = input.split_first() else {
        panic!("fuzz corpus seed must include a selector");
    };
    assert_eq!(usize::from(selector) % DECODER_COUNT, expected_selector);
    let hexadecimal = encoded_payload
        .strip_prefix(b"hex:")
        .expect("checked-in text corpus seed must use the hex wrapper");
    let hexadecimal: String = std::str::from_utf8(hexadecimal)
        .expect("checked-in corpus hex must be UTF-8")
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let payload = hex::decode(hexadecimal).expect("checked-in corpus hex must decode");
    let decoded = T::from_canonical_bytes(&payload).unwrap_or_else(|error| {
        panic!("selector {expected_selector} corpus payload must be canonical: {error:?}")
    });
    assert_eq!(decoded.to_canonical_bytes().unwrap(), payload);
}

#[test]
fn every_pairing_fuzz_selector_has_a_valid_canonical_seed() {
    assert_canonical_corpus_seed::<PairingTicket>(
        include_bytes!("../../../../fuzz/corpus/identity_pairing/seed.txt"),
        0,
    );
    assert_canonical_corpus_seed::<crate::PairingTranscript>(
        include_bytes!("../../../../fuzz/corpus/identity_pairing/selector-1-pairing-transcript"),
        1,
    );
    assert_canonical_corpus_seed::<PairingPossessionProof>(
        include_bytes!("../../../../fuzz/corpus/identity_pairing/selector-2-pairing-proof"),
        2,
    );
    assert_canonical_corpus_seed::<DeviceAuthorizationProposal>(
        include_bytes!(
            "../../../../fuzz/corpus/identity_pairing/selector-3-device-authorization-proposal"
        ),
        3,
    );
    assert_canonical_corpus_seed::<DevicePresenceChallenge>(
        include_bytes!("../../../../fuzz/corpus/identity_pairing/selector-4-presence-challenge"),
        4,
    );
    assert_canonical_corpus_seed::<PresenceProof>(
        include_bytes!("../../../../fuzz/corpus/identity_pairing/selector-5-presence-proof"),
        5,
    );
}

#[test]
fn secrets_are_redacted_and_short_auth_is_deterministic() {
    let fixture = ticket_fixture();
    assert_eq!(
        format!("{:?}", fixture.ticket_secrets),
        "PairingTicketSecrets(<redacted>)"
    );
    let first = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &first);
    let first = first.verify_possession(proof).unwrap().short_auth_string();
    let second = connect_fixture(&fixture, 0x61);
    let proof = proof_for(&fixture, &second);
    let second = second.verify_possession(proof).unwrap().short_auth_string();
    let mut expected_ticket = hex::decode(concat!(
        "010101010101010101010101010101010101010101010101010101010101010101010101",
        "43a72e714401762df66b68c26dfbdf2682aaec9f2474eca4613e424a0fbafd3c0173b2",
        "d8b76aa9b53660032bc8f5d8bee3a3ae4e3b3a7fd49ade81f7347a34aa68010b513a",
        "d9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d0001343b62",
        "f7a40db173198b2d5d3ff1df419169d8e27f50f0f7b8845d993abdff0a01b0d08f3",
        "5b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c010b513ad9",
        "b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d1572656c6179",
        "2e6578616d706c652e696e76616c6964014b2319918aa3b10e598e85505e5062aa4c",
        "65babbf3d4c3eaf544c3ddb1ef090ae807a8d724"
    ))
    .unwrap();
    expected_ticket.extend_from_slice(&[0x5a; 32]);
    expected_ticket.push(0);
    assert_eq!(
        fixture.ticket.to_canonical_bytes().unwrap(),
        expected_ticket
    );
    assert_eq!(
        fixture.ticket.ticket_id().unwrap().as_digest().to_string(),
        "b3:835f0016f42c6ba397fe992b3df1ef11c8567903554ce56a249dfc9869b8d4fc"
    );
    assert_eq!(first.to_string(), "580158");
    assert_eq!(first, second);
}
