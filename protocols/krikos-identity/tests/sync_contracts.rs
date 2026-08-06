use krikos_identity::{
    AccountId, CanonicalWire, CursorKey, Digest, EventId, HashAlgorithm, IdentityError,
    ProtocolVersion, SyncCursor, SyncFrame, SyncRequest, SyncResponse, SyncSessionBudget,
    limits::{MAX_EVENTS_PER_SYNC_BATCH, MAX_SYNC_FRAME_BYTES, MAX_SYNC_SESSION_BYTES},
    transport::{
        CHECKPOINT_ALPN, PAIRING_ALPN, PROPOSAL_ALPN, RECOVERY_ALPN, SYNC_ALPN,
        TRANSPARENCY_GOSSIP_ALPN,
    },
};

fn typed_id<T: CanonicalWire>(fill: u8) -> T {
    let digest = Digest::new(HashAlgorithm::Blake3_256, [fill; 32]);
    T::from_canonical_bytes(&digest.to_canonical_bytes().unwrap()).unwrap()
}

#[test]
fn sync_response_uses_closed_codepoints_and_rejects_ordinal_wire_bytes() {
    let account_id = typed_id(0x41);
    let frame = SyncFrame::new(account_id, Vec::new(), Vec::new(), None).unwrap();
    let frame_response = SyncResponse::frame(frame.clone());
    assert_eq!(frame_response.code(), SyncResponse::FRAME_CODE);
    assert_eq!(
        SyncResponse::from_canonical_bytes(&frame_response.to_canonical_bytes().unwrap()).unwrap(),
        frame_response
    );

    let complete = SyncResponse::complete(account_id, Vec::new()).unwrap();
    let complete_bytes = complete.to_canonical_bytes().unwrap();
    assert_eq!(complete.code(), SyncResponse::COMPLETE_CODE);
    assert_eq!(&complete_bytes[..3], &[1, 2, 0]);
    assert_eq!(
        SyncResponse::from_canonical_bytes(&complete_bytes).unwrap(),
        complete
    );

    let unknown = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        99_u16,
        Option::<SyncFrame>::None,
        Option::<AccountId>::None,
        Option::<Vec<EventId>>::None,
    ))
    .unwrap();
    assert!(matches!(
        SyncResponse::from_canonical_bytes(&unknown),
        Err(IdentityError::UnsupportedCodepoint {
            registry: "sync response",
            code: 99,
        })
    ));

    let old_frame_ordinal = postcard::to_stdvec(&(ProtocolVersion::V1, 0_u32, &frame)).unwrap();
    assert!(SyncResponse::from_canonical_bytes(&old_frame_ordinal).is_err());
    let old_complete_ordinal = postcard::to_stdvec(&(
        ProtocolVersion::V1,
        1_u32,
        account_id,
        Vec::<EventId>::new(),
    ))
    .unwrap();
    assert!(SyncResponse::from_canonical_bytes(&old_complete_ordinal).is_err());
}

#[test]
fn sync_request_cursor_and_frame_are_canonical_and_bounded() {
    let account_id = typed_id(1);
    let head_a = typed_id::<EventId>(2);
    let head_b = typed_id::<EventId>(3);
    let key = CursorKey::new([7; 32]).unwrap();
    let cursor = SyncCursor::issue(&key, account_id, vec![head_b, head_a], 17, 1_024).unwrap();
    cursor.verify(&key).unwrap();
    assert_eq!(
        cursor.verify(&CursorKey::new([8; 32]).unwrap()),
        Err(IdentityError::InvalidProof)
    );
    assert_eq!(cursor.source_heads(), &[head_a, head_b]);

    let request = SyncRequest::new(
        account_id,
        vec![head_b, head_a],
        Some(cursor.clone()),
        MAX_EVENTS_PER_SYNC_BATCH,
        MAX_SYNC_FRAME_BYTES,
    )
    .unwrap();
    assert_eq!(request.known_heads(), &[head_a, head_b]);
    let encoded = request.to_canonical_bytes().unwrap();
    assert_eq!(
        SyncRequest::from_canonical_bytes(&encoded).unwrap(),
        request
    );

    let frame = SyncFrame::new(account_id, vec![head_b, head_a], Vec::new(), Some(cursor)).unwrap();
    assert_eq!(frame.source_heads(), &[head_a, head_b]);
    let frame_bytes = frame.to_canonical_bytes().unwrap();
    assert!(frame_bytes.len() <= MAX_SYNC_FRAME_BYTES);
    assert_eq!(
        SyncFrame::from_canonical_bytes(&frame_bytes).unwrap(),
        frame
    );
    assert!(matches!(
        SyncFrame::from_canonical_bytes(&vec![0; MAX_SYNC_FRAME_BYTES + 1]),
        Err(IdentityError::LimitExceeded { .. })
    ));
}

#[test]
fn session_budget_is_exact_and_cannot_overflow() {
    let mut budget = SyncSessionBudget::new();
    budget.charge_bytes(MAX_SYNC_SESSION_BYTES).unwrap();
    assert_eq!(budget.remaining_bytes(), 0);
    assert!(matches!(
        budget.charge_bytes(1),
        Err(IdentityError::LimitExceeded { .. })
    ));
}

#[test]
fn v1_alpns_are_frozen_exactly() {
    assert_eq!(PAIRING_ALPN, b"krikos-identity/pairing/1");
    assert_eq!(SYNC_ALPN, b"krikos-identity/sync/1");
    assert_eq!(PROPOSAL_ALPN, b"krikos-identity/proposal/1");
    assert_eq!(CHECKPOINT_ALPN, b"krikos-identity/checkpoint/1");
    assert_eq!(
        TRANSPARENCY_GOSSIP_ALPN,
        b"krikos-identity/transparency-gossip/1"
    );
    assert_eq!(RECOVERY_ALPN, b"krikos-identity/recovery/1");
}
