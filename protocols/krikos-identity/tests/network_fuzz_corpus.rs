#![cfg(feature = "net")]

use krikos_identity::{
    CanonicalWire, DeviceAuthorizationProposal, SignedCheckpoint, SyncCursor, SyncFrame,
    SyncRequest, SyncResponse,
    net::{
        AuthorizedCheckpointRequest, AuthorizedProposalRequest, AuthorizedSyncRequest,
        EndpointAuthorizationRequest, IdentityProtocolAck, IdentityProtocolReply,
    },
};

fn payload(seed: &[u8], selector: u8) -> &[u8] {
    assert_eq!(seed.first(), Some(&selector));
    &seed[1..]
}

fn assert_corpus_pair<T: CanonicalWire>(accepted: &[u8], rejected: &[u8], selector: u8) {
    assert!(T::from_canonical_bytes(payload(accepted, selector)).is_ok());
    assert!(T::from_canonical_bytes(payload(rejected, selector)).is_err());
}

#[test]
fn network_schema_corpus_keeps_exact_selectors_and_accept_reject_baselines() {
    assert_corpus_pair::<SyncRequest>(
        include_bytes!("../../../fuzz/corpus/identity_sync/selector-00-sync-request-accepted.bin"),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-00-sync-request-rejected-truncated.bin"
        ),
        0,
    );
    for rejected in [
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-00-sync-request-rejected-duplicate-head.bin"
        )
        .as_slice(),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-00-sync-request-rejected-unsupported-version.bin"
        )
        .as_slice(),
    ] {
        assert!(SyncRequest::from_canonical_bytes(payload(rejected, 0)).is_err());
    }

    assert_corpus_pair::<SyncFrame>(
        include_bytes!("../../../fuzz/corpus/identity_sync/selector-01-sync-frame-accepted.bin"),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-01-sync-frame-rejected-truncated.bin"
        ),
        1,
    );
    for rejected in [
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-01-sync-frame-rejected-duplicate-head.bin"
        )
        .as_slice(),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-01-sync-frame-rejected-unsupported-version.bin"
        )
        .as_slice(),
    ] {
        assert!(SyncFrame::from_canonical_bytes(payload(rejected, 1)).is_err());
    }

    assert_corpus_pair::<SyncCursor>(
        include_bytes!("../../../fuzz/corpus/identity_sync/selector-02-sync-cursor-accepted.bin"),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-02-sync-cursor-rejected-truncated.bin"
        ),
        2,
    );
    for rejected in [
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-02-sync-cursor-rejected-duplicate-head.bin"
        )
        .as_slice(),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-02-sync-cursor-rejected-unsupported-version.bin"
        )
        .as_slice(),
    ] {
        assert!(SyncCursor::from_canonical_bytes(payload(rejected, 2)).is_err());
    }

    assert_corpus_pair::<SyncResponse>(
        include_bytes!("../../../fuzz/corpus/identity_sync/selector-03-sync-response-accepted.bin"),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-03-sync-response-rejected-truncated.bin"
        ),
        3,
    );
    for rejected in [
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-03-sync-response-rejected-legacy-ordinal.bin"
        )
        .as_slice(),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-03-sync-response-rejected-unsupported-codepoint.bin"
        )
        .as_slice(),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-03-sync-response-rejected-unsupported-version.bin"
        )
        .as_slice(),
    ] {
        assert!(SyncResponse::from_canonical_bytes(payload(rejected, 3)).is_err());
    }

    assert_corpus_pair::<EndpointAuthorizationRequest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-04-endpoint-authorization-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-04-endpoint-authorization-rejected-truncated.bin"
        ),
        4,
    );
    assert_corpus_pair::<AuthorizedSyncRequest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-05-authorized-sync-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-05-authorized-sync-rejected-truncated.bin"
        ),
        5,
    );
    assert_corpus_pair::<AuthorizedProposalRequest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-06-authorized-proposal-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-06-authorized-proposal-rejected-truncated.bin"
        ),
        6,
    );
    assert_corpus_pair::<AuthorizedCheckpointRequest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-07-authorized-checkpoint-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-07-authorized-checkpoint-rejected-truncated.bin"
        ),
        7,
    );

    let sync_mismatch = include_bytes!(
        "../../../fuzz/corpus/identity_sync/selector-05-authorized-sync-rejected-account-mismatch.bin"
    );
    let (sync_authorization, sync_request): (EndpointAuthorizationRequest, SyncRequest) =
        postcard::from_bytes(payload(sync_mismatch, 5)).unwrap();
    assert_ne!(sync_authorization.account_id(), sync_request.account_id());
    assert!(AuthorizedSyncRequest::from_canonical_bytes(payload(sync_mismatch, 5)).is_err());

    let proposal_mismatch = include_bytes!(
        "../../../fuzz/corpus/identity_sync/selector-06-authorized-proposal-rejected-account-mismatch.bin"
    );
    let (proposal_authorization, proposal): (
        EndpointAuthorizationRequest,
        DeviceAuthorizationProposal,
    ) = postcard::from_bytes(payload(proposal_mismatch, 6)).unwrap();
    assert_ne!(proposal_authorization.account_id(), proposal.account_id());
    assert!(
        AuthorizedProposalRequest::from_canonical_bytes(payload(proposal_mismatch, 6)).is_err()
    );

    let checkpoint_mismatch = include_bytes!(
        "../../../fuzz/corpus/identity_sync/selector-07-authorized-checkpoint-rejected-account-mismatch.bin"
    );
    let (checkpoint_authorization, checkpoint): (EndpointAuthorizationRequest, SignedCheckpoint) =
        postcard::from_bytes(payload(checkpoint_mismatch, 7)).unwrap();
    assert_ne!(
        checkpoint_authorization.account_id(),
        checkpoint.body().account_id()
    );
    assert!(
        AuthorizedCheckpointRequest::from_canonical_bytes(payload(checkpoint_mismatch, 7)).is_err()
    );

    assert_corpus_pair::<IdentityProtocolAck>(
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-08-identity-protocol-ack-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-08-identity-protocol-ack-rejected-truncated.bin"
        ),
        8,
    );
    assert_corpus_pair::<IdentityProtocolReply>(
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-09-identity-protocol-reply-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_sync/selector-09-identity-protocol-reply-rejected-truncated.bin"
        ),
        9,
    );
}
