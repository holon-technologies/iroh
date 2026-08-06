#![no_main]

use krikos_identity::{
    CanonicalWire, SyncCursor, SyncFrame, SyncRequest, SyncResponse,
    net::{
        AuthorizedCheckpointRequest, AuthorizedProposalRequest, AuthorizedSyncRequest,
        EndpointAuthorizationRequest, IdentityProtocolAck, IdentityProtocolReply,
    },
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT_BYTES: usize = 4 * 1024 * 1024 + 1;

fuzz_target!(|input: &[u8]| {
    if input.is_empty() || input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }
    let Some((selector, bytes)) = input.split_first() else {
        return;
    };
    match *selector {
        0 => {
            let _ = SyncRequest::from_canonical_bytes(bytes);
        }
        1 => {
            let _ = SyncFrame::from_canonical_bytes(bytes);
        }
        2 => {
            let _ = SyncCursor::from_canonical_bytes(bytes);
        }
        3 => {
            let _ = SyncResponse::from_canonical_bytes(bytes);
        }
        4 => {
            let _ = EndpointAuthorizationRequest::from_canonical_bytes(bytes);
        }
        5 => {
            if let Ok(request) = AuthorizedSyncRequest::from_canonical_bytes(bytes) {
                assert_eq!(
                    request.authorization().account_id(),
                    request.request().account_id()
                );
            }
        }
        6 => {
            if let Ok(request) = AuthorizedProposalRequest::from_canonical_bytes(bytes) {
                assert_eq!(
                    request.authorization().account_id(),
                    request.proposal().account_id()
                );
            }
        }
        7 => {
            if let Ok(request) = AuthorizedCheckpointRequest::from_canonical_bytes(bytes) {
                assert_eq!(
                    request.authorization().account_id(),
                    request.checkpoint().body().account_id()
                );
            }
        }
        8 => {
            let _ = IdentityProtocolAck::from_canonical_bytes(bytes);
        }
        9 => {
            let _ = IdentityProtocolReply::from_canonical_bytes(bytes);
        }
        _ => return,
    }
});
