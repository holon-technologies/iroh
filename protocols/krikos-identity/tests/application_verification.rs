use krikos_base::SecretKey;
use krikos_identity::{
    AccountId, AgreementPublicKey, ApplicationAuthorizationView, ApplicationDeviceStatus,
    ApplicationEventBody, ApplicationEventCounter, ApplicationId, AuthorizationContext,
    CanonicalWire, CheckpointId, DeviceAuthorization, DeviceClass, DeviceDescriptor, Digest,
    EndpointPublicKey, Epoch, Extensions, HashAlgorithm, IdentityError, ProtocolSignature,
    SignedApplicationEvent, SigningPublicKey, verify_application_event,
};

fn typed_id<T: CanonicalWire>(seed: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [seed; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

fn fixture_authorization(secret: &SecretKey) -> DeviceAuthorization {
    let endpoint_secret = SecretKey::from_bytes(&[0x32; 32]);
    let descriptor = DeviceDescriptor::new(
        SigningPublicKey::ed25519(*secret.public().as_bytes()).unwrap(),
        AgreementPublicKey::x25519([
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap(),
        EndpointPublicKey::new(
            SigningPublicKey::ed25519(*endpoint_secret.public().as_bytes()).unwrap(),
        ),
        Extensions::default(),
    )
    .unwrap();
    DeviceAuthorization::new(
        descriptor.id().unwrap(),
        descriptor,
        DeviceClass::ApplicationOnly,
        None,
        Vec::new(),
        Epoch::new(3),
        Extensions::default(),
    )
    .unwrap()
}

fn context() -> AuthorizationContext {
    AuthorizationContext::new(typed_id::<AccountId>(0x41), Epoch::new(7), typed_id(0x42))
}

fn signed_event(
    secret: &SecretKey,
    authorization: &DeviceAuthorization,
    context: AuthorizationContext,
    payload: Vec<u8>,
) -> SignedApplicationEvent {
    let body = ApplicationEventBody::new(
        context.account_id(),
        ApplicationId::new(Digest::new(HashAlgorithm::Blake3_256, [0x43; 32])),
        authorization.device_id(),
        context.epoch(),
        context.checkpoint_id(),
        ApplicationEventCounter::new(11),
        payload,
        Extensions::default(),
    )
    .unwrap();
    let signature = secret.sign(&body.signing_bytes().unwrap());
    SignedApplicationEvent::new(body, ProtocolSignature::ed25519(signature.to_bytes())).unwrap()
}

struct View<'a> {
    context: AuthorizationContext,
    status: ApplicationDeviceStatus,
    authorization: Option<&'a DeviceAuthorization>,
}

impl ApplicationAuthorizationView for View<'_> {
    fn authorization_context(&self) -> AuthorizationContext {
        self.context
    }

    fn device_status(&self, _device_id: krikos_identity::DeviceId) -> ApplicationDeviceStatus {
        self.status
    }

    fn device_authorization(
        &self,
        _device_id: krikos_identity::DeviceId,
    ) -> Option<&DeviceAuthorization> {
        self.authorization
    }
}

#[test]
fn application_signature_is_bound_to_exact_body_and_known_context() {
    let secret = SecretKey::from_bytes(&[0x31; 32]);
    let authorization = fixture_authorization(&secret);
    let event = signed_event(&secret, &authorization, context(), b"payload".to_vec());
    let view = View {
        context: context(),
        status: ApplicationDeviceStatus::Active,
        authorization: Some(&authorization),
    };

    assert_eq!(
        verify_application_event(&event, &view).unwrap(),
        event.application_event_id().unwrap()
    );

    let tampered_body = ApplicationEventBody::new(
        event.body().account_id(),
        event.body().application_id(),
        event.body().device_id(),
        event.body().account_epoch(),
        event.body().checkpoint_id(),
        event.body().local_counter(),
        b"tampered".to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let tampered = SignedApplicationEvent::new(tampered_body, event.signature()).unwrap();
    assert_eq!(
        verify_application_event(&tampered, &view),
        Err(IdentityError::InvalidSignature)
    );
}

#[test]
fn application_verification_fails_closed_for_wrong_basis_or_device_status() {
    let secret = SecretKey::from_bytes(&[0x31; 32]);
    let authorization = fixture_authorization(&secret);
    let event = signed_event(&secret, &authorization, context(), Vec::new());

    for (status, expected) in [
        (
            ApplicationDeviceStatus::Unknown,
            IdentityError::DeviceNotAuthorized,
        ),
        (
            ApplicationDeviceStatus::Suspended,
            IdentityError::DeviceSuspended,
        ),
        (
            ApplicationDeviceStatus::Revoked,
            IdentityError::DeviceRevoked,
        ),
    ] {
        let view = View {
            context: context(),
            status,
            authorization: Some(&authorization),
        };
        assert_eq!(verify_application_event(&event, &view), Err(expected));
    }

    let missing = View {
        context: context(),
        status: ApplicationDeviceStatus::Active,
        authorization: None,
    };
    assert_eq!(
        verify_application_event(&event, &missing),
        Err(IdentityError::DeviceNotAuthorized)
    );

    let wrong_account = View {
        context: AuthorizationContext::new(
            typed_id::<AccountId>(0x51),
            context().epoch(),
            context().checkpoint_id(),
        ),
        status: ApplicationDeviceStatus::Active,
        authorization: Some(&authorization),
    };
    assert_eq!(
        verify_application_event(&event, &wrong_account),
        Err(IdentityError::AccountMismatch)
    );

    let wrong_epoch = View {
        context: AuthorizationContext::new(
            context().account_id(),
            Epoch::new(8),
            context().checkpoint_id(),
        ),
        status: ApplicationDeviceStatus::Active,
        authorization: Some(&authorization),
    };
    assert_eq!(
        verify_application_event(&event, &wrong_epoch),
        Err(IdentityError::InvalidEpoch)
    );

    let wrong_checkpoint = View {
        context: AuthorizationContext::new(
            context().account_id(),
            context().epoch(),
            typed_id::<CheckpointId>(0x52),
        ),
        status: ApplicationDeviceStatus::Active,
        authorization: Some(&authorization),
    };
    assert!(matches!(
        verify_application_event(&event, &wrong_checkpoint),
        Err(IdentityError::InvalidRelationship { .. })
    ));
}

#[test]
fn application_verification_rejects_forged_or_not_yet_authorized_signers() {
    let secret = SecretKey::from_bytes(&[0x31; 32]);
    let authorization = fixture_authorization(&secret);
    let event = signed_event(&secret, &authorization, context(), Vec::new());
    let view = View {
        context: context(),
        status: ApplicationDeviceStatus::Active,
        authorization: Some(&authorization),
    };

    let attacker = SecretKey::from_bytes(&[0x33; 32]);
    let forged = SignedApplicationEvent::new(
        event.body().clone(),
        ProtocolSignature::ed25519(
            attacker
                .sign(&event.body().signing_bytes().unwrap())
                .to_bytes(),
        ),
    )
    .unwrap();
    assert_eq!(
        verify_application_event(&forged, &view),
        Err(IdentityError::InvalidSignature)
    );

    let future_authorization = DeviceAuthorization::new(
        authorization.device_id(),
        authorization.descriptor().clone(),
        authorization.device_class(),
        authorization.metadata_commitment(),
        authorization.capabilities().to_vec(),
        Epoch::new(8),
        Extensions::default(),
    )
    .unwrap();
    let future_view = View {
        context: context(),
        status: ApplicationDeviceStatus::Active,
        authorization: Some(&future_authorization),
    };
    assert_eq!(
        verify_application_event(&event, &future_view),
        Err(IdentityError::InvalidEpoch)
    );
}

#[test]
fn application_signature_domain_and_literal_vector_are_frozen() {
    // The signature was independently reproduced with Python cryptography's Ed25519
    // implementation from the same 32-byte seed and literal signing message.
    let secret = SecretKey::from_bytes(&[0x31; 32]);
    let authorization = fixture_authorization(&secret);
    let event = signed_event(&secret, &authorization, context(), b"payload".to_vec());

    assert_eq!(
        hex::encode(event.body().signing_bytes().unwrap()),
        "4b52494b4f532d49442f6170706c69636174696f6e2d6576656e742d7369676e61747572652f76310001014141414141414141414141414141414141414141414141414141414141414141014343434343434343434343434343434343434343434343434343434343434343010bab17cf309c883b316065a68c5f382609e0d3f4a7b087e5609c7deabc55d916070142424242424242424242424242424242424242424242424242424242424242420b077061796c6f616400"
    );
    assert_eq!(
        hex::encode(event.signature().as_bytes()),
        "ccc37fc482fd062736d4601f139d0157680eac0e7b6826e9df98465d4880ec45f502fc8caa2a516f21531b754cd8b4c3164ec7d4a9cdeb8584ac3300b9c2fa02"
    );
}

#[test]
fn context_field_substitution_fails_even_under_a_matching_substituted_view() {
    let secret = SecretKey::from_bytes(&[0x31; 32]);
    let authorization = fixture_authorization(&secret);
    let original = signed_event(&secret, &authorization, context(), b"payload".to_vec());
    let substituted_contexts = [
        AuthorizationContext::new(
            typed_id::<AccountId>(0x61),
            context().epoch(),
            context().checkpoint_id(),
        ),
        AuthorizationContext::new(
            context().account_id(),
            Epoch::new(8),
            context().checkpoint_id(),
        ),
        AuthorizationContext::new(
            context().account_id(),
            context().epoch(),
            typed_id::<CheckpointId>(0x62),
        ),
    ];
    for substituted_context in substituted_contexts {
        let substituted_body = ApplicationEventBody::new(
            substituted_context.account_id(),
            original.body().application_id(),
            original.body().device_id(),
            substituted_context.epoch(),
            substituted_context.checkpoint_id(),
            original.body().local_counter(),
            original.body().payload().to_vec(),
            Extensions::default(),
        )
        .unwrap();
        let substituted =
            SignedApplicationEvent::new(substituted_body, original.signature()).unwrap();
        let substituted_view = View {
            context: substituted_context,
            status: ApplicationDeviceStatus::Active,
            authorization: Some(&authorization),
        };
        assert_eq!(
            verify_application_event(&substituted, &substituted_view),
            Err(IdentityError::InvalidSignature)
        );
    }

    let other_secret = SecretKey::from_bytes(&[0x63; 32]);
    let other_authorization = fixture_authorization(&other_secret);
    let substituted_body = ApplicationEventBody::new(
        original.body().account_id(),
        original.body().application_id(),
        other_authorization.device_id(),
        original.body().account_epoch(),
        original.body().checkpoint_id(),
        original.body().local_counter(),
        original.body().payload().to_vec(),
        Extensions::default(),
    )
    .unwrap();
    let substituted = SignedApplicationEvent::new(substituted_body, original.signature()).unwrap();
    let substituted_view = View {
        context: context(),
        status: ApplicationDeviceStatus::Active,
        authorization: Some(&other_authorization),
    };
    assert_eq!(
        verify_application_event(&substituted, &substituted_view),
        Err(IdentityError::InvalidSignature)
    );
}
