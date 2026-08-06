//! Canonical bounded account synchronization wire contracts.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountId, AccountRevision, AccountStore, AuthorizedEvent, BatchCommitReceipt, CanonicalWire,
    EventHistoryCursor, EventId, IdentityError, ProtocolVersion, StoreFuture,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{
        MAX_EVENTS_PER_SYNC_BATCH, MAX_FORK_HEADS, MAX_SYNC_FRAME_BYTES, MAX_SYNC_SESSION_BYTES,
    },
    schema::BoundedVec,
};

/// Atomically reconcile one decoded frame after deterministic event reordering.
///
/// Every event is state-validated by the store before any source record or effect becomes
/// visible. Peer-advertised heads are availability metadata only and never bypass authority.
pub fn reconcile_sync_frame<'a, S: AccountStore + ?Sized>(
    store: &'a S,
    expected_revision: AccountRevision,
    frame: &'a SyncFrame,
) -> StoreFuture<'a, BatchCommitReceipt> {
    Box::pin(async move {
        if frame.account_id() != expected_revision.account_id() {
            return Err(IdentityError::AccountMismatch);
        }
        store
            .commit_events(expected_revision, frame.events().to_vec())
            .await
    })
}

/// Serve one bounded synchronization request from authenticated durable source history.
///
/// A first request freezes the store's exact complete revision. Every continuation authenticates
/// that revision and its next deterministic item, so later appends cannot leak into the resumed
/// session. Peer-advertised heads are used only to detect immediate convergence.
pub fn serve_sync_request<'a, S: AccountStore + ?Sized>(
    store: &'a S,
    cursor_key: &'a CursorKey,
    request: &'a SyncRequest,
) -> StoreFuture<'a, SyncResponse> {
    Box::pin(async move {
        let request_bytes = request.to_canonical_bytes()?.len();
        serve_sync_request_with_meter(
            store,
            cursor_key,
            request,
            request_bytes,
            canonical_sync_response_bytes,
        )
        .await
    })
}

pub(crate) type SyncResponseMeter = fn(&SyncResponse) -> Result<usize, IdentityError>;

#[derive(Clone, Copy)]
struct SyncResponseBudget {
    previously_delivered: usize,
    current_request_bytes: usize,
    maximum_bytes: usize,
    response_meter: SyncResponseMeter,
}

pub(crate) fn serve_sync_request_with_meter<'a, S: AccountStore + ?Sized>(
    store: &'a S,
    cursor_key: &'a CursorKey,
    request: &'a SyncRequest,
    current_request_bytes: usize,
    response_meter: SyncResponseMeter,
) -> StoreFuture<'a, SyncResponse> {
    Box::pin(async move {
        let snapshot = store.load_account(request.account_id()).await?.ok_or(
            IdentityError::InvalidRelationship {
                resource: "account store missing account",
            },
        )?;
        let (source_revision, after_cursor, delivered_bytes) =
            if let Some(cursor) = request.continuation() {
                cursor.verify(cursor_key)?;
                if cursor.account_id() != request.account_id() {
                    return Err(IdentityError::AccountMismatch);
                }
                let source_revision = crate::AccountRevision::from_frozen_heads(
                    cursor.account_id(),
                    cursor.source_heads().to_vec(),
                )?;
                let next_item = cursor.next_item();
                let after_cursor = if next_item == 0 {
                    None
                } else {
                    Some(EventHistoryCursor::from_verified_sync(
                        source_revision.clone(),
                        next_item
                            .checked_sub(1)
                            .ok_or(IdentityError::ArithmeticOverflow {
                                resource: "sync continuation cursor",
                            })?,
                    ))
                };
                (
                    source_revision,
                    after_cursor,
                    usize::try_from(cursor.delivered_bytes()).map_err(|_| {
                        IdentityError::ArithmeticOverflow {
                            resource: "sync continuation delivered bytes",
                        }
                    })?,
                )
            } else {
                (snapshot.revision().clone(), None, 0)
            };
        let response_budget = SyncResponseBudget {
            previously_delivered: delivered_bytes,
            current_request_bytes,
            maximum_bytes: request.max_frame_bytes(),
            response_meter,
        };

        if request.continuation().is_none() && request.known_heads() == source_revision.heads() {
            return bounded_sync_response(
                SyncResponse::complete(request.account_id(), source_revision.heads().to_vec())?,
                &response_budget,
            );
        }

        let page = store
            .event_history(
                source_revision.clone(),
                after_cursor,
                request.max_events(),
                crate::limits::MAX_HISTORY_PAGE_BYTES,
            )
            .await?;
        if page.source_revision() != &source_revision {
            return Err(IdentityError::StorageCorruption);
        }
        if page.records().is_empty() {
            return bounded_sync_response(
                SyncResponse::complete(request.account_id(), source_revision.heads().to_vec())?,
                &response_budget,
            );
        }

        let mut records = page.records().to_vec();
        let mut has_more = page.next_cursor().is_some();
        loop {
            let next_item = records
                .last()
                .map(|record| {
                    record
                        .cursor()
                        .checked_add(1)
                        .ok_or(IdentityError::ArithmeticOverflow {
                            resource: "sync continuation cursor",
                        })
                })
                .transpose()?;
            let events = records
                .iter()
                .map(|record| record.event().clone())
                .collect::<Vec<_>>();
            let response = if has_more {
                build_stable_sync_response(
                    cursor_key,
                    &source_revision,
                    next_item.ok_or(IdentityError::StorageCorruption)?,
                    &events,
                    &response_budget,
                )
            } else {
                SyncFrame::new(
                    request.account_id(),
                    source_revision.heads().to_vec(),
                    events,
                    None,
                )
                .map(SyncResponse::frame)
            };
            match response.and_then(|response| bounded_sync_response(response, &response_budget)) {
                Ok(response) => return Ok(response),
                Err(IdentityError::LimitExceeded { .. }) if records.len() > 1 => {
                    records.pop();
                    has_more = true;
                }
                Err(error) => return Err(error),
            }
        }
    })
}

fn build_stable_sync_response(
    key: &CursorKey,
    revision: &crate::AccountRevision,
    next_item: u64,
    events: &[AuthorizedEvent],
    response_budget: &SyncResponseBudget,
) -> Result<SyncResponse, IdentityError> {
    let mut delivered = response_budget
        .previously_delivered
        .checked_add(response_budget.current_request_bytes)
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "sync session bytes",
        })?;
    for _ in 0..=u64::BITS {
        let cursor = SyncCursor::issue(
            key,
            revision.account_id(),
            revision.heads().to_vec(),
            next_item,
            delivered,
        )?;
        let frame = SyncFrame::new(
            revision.account_id(),
            revision.heads().to_vec(),
            events.to_vec(),
            Some(cursor.clone()),
        )?;
        let response = SyncResponse::frame(frame);
        let encoded = response.to_canonical_bytes()?;
        if encoded.len() > response_budget.maximum_bytes {
            return Err(IdentityError::limit(
                "sync response bytes",
                encoded.len(),
                response_budget.maximum_bytes,
            ));
        }
        let response_bytes = (response_budget.response_meter)(&response)?;
        let next_delivered = response_budget
            .previously_delivered
            .checked_add(response_budget.current_request_bytes)
            .and_then(|consumed| consumed.checked_add(response_bytes))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "sync session bytes",
            })?;
        let mut budget = SyncSessionBudget::new();
        budget.charge_bytes(response_budget.previously_delivered)?;
        budget.charge_bytes(response_budget.current_request_bytes)?;
        budget.charge_bytes(response_bytes)?;
        if next_delivered == delivered {
            return Ok(response);
        }
        delivered = next_delivered;
    }
    Err(IdentityError::InvalidProof)
}

fn bounded_sync_response(
    response: SyncResponse,
    response_budget: &SyncResponseBudget,
) -> Result<SyncResponse, IdentityError> {
    let encoded = response.to_canonical_bytes()?;
    if encoded.len() > response_budget.maximum_bytes {
        return Err(IdentityError::limit(
            "sync response bytes",
            encoded.len(),
            response_budget.maximum_bytes,
        ));
    }
    let response_bytes = (response_budget.response_meter)(&response)?;
    let mut budget = SyncSessionBudget::new();
    budget.charge_bytes(response_budget.previously_delivered)?;
    budget.charge_bytes(response_budget.current_request_bytes)?;
    budget.charge_bytes(response_bytes)?;
    Ok(response)
}

fn canonical_sync_response_bytes(response: &SyncResponse) -> Result<usize, IdentityError> {
    response.to_canonical_bytes().map(|bytes| bytes.len())
}

/// Secret cursor-authentication key held by the session issuer.
pub struct CursorKey([u8; 32]);

impl CursorKey {
    /// Validate a nonzero 256-bit cursor key.
    pub fn new(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        if bytes == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "sync cursor key",
            });
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for CursorKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CursorKey(<redacted>)")
    }
}

fn sorted_heads(
    mut heads: Vec<EventId>,
) -> Result<BoundedVec<EventId, MAX_FORK_HEADS>, IdentityError> {
    heads.sort_unstable();
    BoundedVec::new("sync head set", heads).and_then(validate_sorted_heads)
}

fn validate_sorted_heads(
    heads: BoundedVec<EventId, MAX_FORK_HEADS>,
) -> Result<BoundedVec<EventId, MAX_FORK_HEADS>, IdentityError> {
    for pair in heads.as_slice().windows(2) {
        if pair[0] == pair[1] {
            return Err(IdentityError::DuplicateElement {
                resource: "sync head set",
            });
        }
        if pair[0] > pair[1] {
            return Err(IdentityError::NonCanonical);
        }
    }
    Ok(heads)
}

/// Key-authenticated continuation for one bounded synchronization session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncCursor {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    source_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
    next_item: u64,
    delivered_bytes: u64,
    authenticator: [u8; 32],
}

impl SyncCursor {
    /// Issue a cursor bound to the exact account, source head set, and progress counters.
    pub fn issue(
        key: &CursorKey,
        account_id: AccountId,
        source_heads: Vec<EventId>,
        next_item: u64,
        delivered_bytes: usize,
    ) -> Result<Self, IdentityError> {
        if delivered_bytes > MAX_SYNC_SESSION_BYTES {
            return Err(IdentityError::limit(
                "sync cursor delivered bytes",
                delivered_bytes,
                MAX_SYNC_SESSION_BYTES,
            ));
        }
        let source_heads = sorted_heads(source_heads)?;
        let delivered_bytes =
            u64::try_from(delivered_bytes).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "sync cursor delivered bytes",
            })?;
        let authenticator = cursor_authenticator(
            key,
            account_id,
            source_heads.as_slice(),
            next_item,
            delivered_bytes,
        )?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            source_heads,
            next_item,
            delivered_bytes,
            authenticator,
        })
    }

    /// Verify that this continuation was issued under `key` for its exact fields.
    pub fn verify(&self, key: &CursorKey) -> Result<(), IdentityError> {
        let expected = cursor_authenticator(
            key,
            self.account_id,
            self.source_heads.as_slice(),
            self.next_item,
            self.delivered_bytes,
        )?;
        if expected != self.authenticator {
            return Err(IdentityError::InvalidProof);
        }
        Ok(())
    }

    /// Account being resumed.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Exact complete sorted source revision used when the cursor was issued.
    pub fn source_heads(&self) -> &[EventId] {
        self.source_heads.as_slice()
    }

    /// Zero-based next source item.
    pub const fn next_item(&self) -> u64 {
        self.next_item
    }

    /// Exact session bytes already consumed when this continuation was issued.
    pub const fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes
    }
}

impl<'de> Deserialize<'de> for SyncCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            source_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
            next_item: u64,
            delivered_bytes: u64,
            authenticator: [u8; 32],
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        validate_sorted_heads(wire.source_heads.clone()).map_err(de::Error::custom)?;
        if wire.delivered_bytes
            > u64::try_from(MAX_SYNC_SESSION_BYTES).map_err(de::Error::custom)?
        {
            return Err(de::Error::custom(IdentityError::limit(
                "sync cursor delivered bytes",
                usize::try_from(wire.delivered_bytes).unwrap_or(usize::MAX),
                MAX_SYNC_SESSION_BYTES,
            )));
        }
        Ok(Self {
            protocol_version: wire.protocol_version,
            account_id: wire.account_id,
            source_heads: wire.source_heads,
            next_item: wire.next_item,
            delivered_bytes: wire.delivered_bytes,
            authenticator: wire.authenticator,
        })
    }
}

impl CanonicalCodec for SyncCursor {
    const RESOURCE: &'static str = "sync cursor bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

fn cursor_authenticator(
    key: &CursorKey,
    account_id: AccountId,
    source_heads: &[EventId],
    next_item: u64,
    delivered_bytes: u64,
) -> Result<[u8; 32], IdentityError> {
    let payload = encode_wire(&(
        ProtocolVersion::V1,
        account_id,
        source_heads,
        next_item,
        delivered_bytes,
    ))?;
    Ok(*blake3::keyed_hash(&key.0, &payload).as_bytes())
}

/// Bounded account synchronization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncRequest {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    known_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
    continuation: Option<SyncCursor>,
    max_events: u16,
    max_frame_bytes: u32,
}

impl SyncRequest {
    /// Construct a request with explicit item and encoded-byte limits.
    pub fn new(
        account_id: AccountId,
        known_heads: Vec<EventId>,
        continuation: Option<SyncCursor>,
        max_events: usize,
        max_frame_bytes: usize,
    ) -> Result<Self, IdentityError> {
        let known_heads = sorted_heads(known_heads)?;
        if max_events == 0 || max_events > MAX_EVENTS_PER_SYNC_BATCH {
            return Err(IdentityError::limit(
                "sync request event limit",
                max_events,
                MAX_EVENTS_PER_SYNC_BATCH,
            ));
        }
        if max_frame_bytes == 0 || max_frame_bytes > MAX_SYNC_FRAME_BYTES {
            return Err(IdentityError::limit(
                "sync request byte limit",
                max_frame_bytes,
                MAX_SYNC_FRAME_BYTES,
            ));
        }
        if continuation
            .as_ref()
            .is_some_and(|cursor| cursor.account_id != account_id)
        {
            return Err(IdentityError::AccountMismatch);
        }
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            known_heads,
            continuation,
            max_events: u16::try_from(max_events).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "sync request event limit",
                }
            })?,
            max_frame_bytes: u32::try_from(max_frame_bytes).map_err(|_| {
                IdentityError::ArithmeticOverflow {
                    resource: "sync request byte limit",
                }
            })?,
        })
    }

    /// Requested account.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Complete sorted heads already held by the requester.
    pub fn known_heads(&self) -> &[EventId] {
        self.known_heads.as_slice()
    }

    /// Optional authenticated continuation.
    pub const fn continuation(&self) -> Option<&SyncCursor> {
        self.continuation.as_ref()
    }

    /// Maximum events accepted in the response frame.
    pub const fn max_events(&self) -> usize {
        self.max_events as usize
    }

    /// Maximum encoded response frame bytes.
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes as usize
    }
}

impl<'de> Deserialize<'de> for SyncRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            known_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
            continuation: Option<SyncCursor>,
            max_events: u16,
            max_frame_bytes: u32,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        validate_sorted_heads(wire.known_heads.clone()).map_err(de::Error::custom)?;
        let request = Self::new(
            wire.account_id,
            wire.known_heads.into_vec(),
            wire.continuation,
            usize::from(wire.max_events),
            usize::try_from(wire.max_frame_bytes).map_err(de::Error::custom)?,
        )
        .map_err(de::Error::custom)?;
        Ok(request)
    }
}

impl CanonicalCodec for SyncRequest {
    const RESOURCE: &'static str = "sync request bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// One atomic, bounded synchronization frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncFrame {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    source_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
    events: BoundedVec<AuthorizedEvent, MAX_EVENTS_PER_SYNC_BATCH>,
    continuation: Option<SyncCursor>,
}

impl SyncFrame {
    /// Construct a frame and enforce both event-count and exact encoded-byte limits.
    pub fn new(
        account_id: AccountId,
        source_heads: Vec<EventId>,
        events: Vec<AuthorizedEvent>,
        continuation: Option<SyncCursor>,
    ) -> Result<Self, IdentityError> {
        let source_heads = sorted_heads(source_heads)?;
        let events = BoundedVec::new("sync frame events", events)?;
        if continuation.as_ref().is_some_and(|cursor| {
            cursor.account_id != account_id
                || cursor.source_heads.as_slice() != source_heads.as_slice()
        }) {
            return Err(IdentityError::InvalidRelationship {
                resource: "sync frame continuation",
            });
        }
        let frame = Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            source_heads,
            events,
            continuation,
        };
        let encoded_len = encode_wire(&frame)?.len();
        if encoded_len > MAX_SYNC_FRAME_BYTES {
            return Err(IdentityError::limit(
                "sync frame bytes",
                encoded_len,
                MAX_SYNC_FRAME_BYTES,
            ));
        }
        Ok(frame)
    }

    /// Account whose source records are carried.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Complete sorted source revision.
    pub fn source_heads(&self) -> &[EventId] {
        self.source_heads.as_slice()
    }

    /// Bounded canonical event envelopes.
    pub fn events(&self) -> &[AuthorizedEvent] {
        self.events.as_slice()
    }

    /// Authenticated continuation when more source records remain.
    pub const fn continuation(&self) -> Option<&SyncCursor> {
        self.continuation.as_ref()
    }
}

impl<'de> Deserialize<'de> for SyncFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_id: AccountId,
            source_heads: BoundedVec<EventId, MAX_FORK_HEADS>,
            events: BoundedVec<AuthorizedEvent, MAX_EVENTS_PER_SYNC_BATCH>,
            continuation: Option<SyncCursor>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: wire.protocol_version.get(),
            }));
        }
        validate_sorted_heads(wire.source_heads.clone()).map_err(de::Error::custom)?;
        Self::new(
            wire.account_id,
            wire.source_heads.into_vec(),
            wire.events.into_vec(),
            wire.continuation,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for SyncFrame {
    const RESOURCE: &'static str = "sync frame bytes";
    const MAX_ENCODED_BYTES: usize = MAX_SYNC_FRAME_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

const SYNC_RESPONSE_FRAME_CODE: u16 = 1;
const SYNC_RESPONSE_COMPLETE_CODE: u16 = 2;

/// Versioned bounded synchronization response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncResponse {
    protocol_version: ProtocolVersion,
    response_code: u16,
    frame: Option<SyncFrame>,
    complete_account_id: Option<AccountId>,
    complete_heads: Option<BoundedVec<EventId, MAX_FORK_HEADS>>,
}

impl SyncResponse {
    /// Closed v1 codepoint for an event-bearing synchronization frame.
    pub const FRAME_CODE: u16 = SYNC_RESPONSE_FRAME_CODE;

    /// Closed v1 codepoint for a convergence response carrying the final head set.
    pub const COMPLETE_CODE: u16 = SYNC_RESPONSE_COMPLETE_CODE;

    /// Wrap one validated source-record frame.
    pub const fn frame(frame: SyncFrame) -> Self {
        Self {
            protocol_version: ProtocolVersion::V1,
            response_code: SYNC_RESPONSE_FRAME_CODE,
            frame: Some(frame),
            complete_account_id: None,
            complete_heads: None,
        }
    }

    /// Report convergence at one complete sorted head set.
    pub fn complete(account_id: AccountId, heads: Vec<EventId>) -> Result<Self, IdentityError> {
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            response_code: SYNC_RESPONSE_COMPLETE_CODE,
            frame: None,
            complete_account_id: Some(account_id),
            complete_heads: Some(sorted_heads(heads)?),
        })
    }

    /// Closed v1 response codepoint.
    pub const fn code(&self) -> u16 {
        self.response_code
    }

    /// Frame payload, when this response carries source records.
    pub const fn as_frame(&self) -> Option<&SyncFrame> {
        self.frame.as_ref()
    }

    /// Complete convergence head set and account, when present.
    pub fn as_complete(&self) -> Option<(AccountId, &[EventId])> {
        match (self.complete_account_id, self.complete_heads.as_ref()) {
            (Some(account_id), Some(heads)) => Some((account_id, heads.as_slice())),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), IdentityError> {
        if self.protocol_version != ProtocolVersion::V1 {
            return Err(IdentityError::UnsupportedVersion {
                version: self.protocol_version.get(),
            });
        }
        match (
            self.response_code,
            &self.frame,
            self.complete_account_id,
            &self.complete_heads,
        ) {
            (SYNC_RESPONSE_FRAME_CODE, Some(_), None, None) => Ok(()),
            (SYNC_RESPONSE_COMPLETE_CODE, None, Some(_), Some(heads)) => {
                validate_sorted_heads(heads.clone()).map(|_| ())
            }
            (SYNC_RESPONSE_FRAME_CODE | SYNC_RESPONSE_COMPLETE_CODE, _, _, _) => {
                Err(IdentityError::InvalidRelationship {
                    resource: "sync response payload",
                })
            }
            (code, _, _, _) => Err(IdentityError::UnsupportedCodepoint {
                registry: "sync response",
                code,
            }),
        }
    }
}

impl<'de> Deserialize<'de> for SyncResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            response_code: u16,
            frame: Option<SyncFrame>,
            complete_account_id: Option<AccountId>,
            complete_heads: Option<BoundedVec<EventId, MAX_FORK_HEADS>>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let response = Self {
            protocol_version: wire.protocol_version,
            response_code: wire.response_code,
            frame: wire.frame,
            complete_account_id: wire.complete_account_id,
            complete_heads: wire.complete_heads,
        };
        response.validate().map_err(de::Error::custom)?;
        Ok(response)
    }
}

impl CanonicalCodec for SyncResponse {
    const RESOURCE: &'static str = "sync response bytes";
    const MAX_ENCODED_BYTES: usize = MAX_SYNC_FRAME_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        #[derive(Deserialize, Serialize)]
        struct Wire {
            protocol_version: u16,
            response_code: u16,
            frame: Option<SyncFrame>,
            complete_account_id: Option<AccountId>,
            complete_heads: Option<BoundedVec<EventId, MAX_FORK_HEADS>>,
        }

        let wire: Wire = decode_wire(bytes)?;
        let response = Self {
            protocol_version: ProtocolVersion::new(wire.protocol_version)?,
            response_code: wire.response_code,
            frame: wire.frame,
            complete_account_id: wire.complete_account_id,
            complete_heads: wire.complete_heads,
        };
        response.validate()?;
        Ok(response)
    }
}

/// Exact deterministic byte budget for one synchronization session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSessionBudget {
    consumed_bytes: usize,
}

impl SyncSessionBudget {
    /// Start an empty session budget.
    pub const fn new() -> Self {
        Self { consumed_bytes: 0 }
    }

    /// Charge exact encoded bytes before processing or allocation.
    pub fn charge_bytes(&mut self, encoded_bytes: usize) -> Result<(), IdentityError> {
        let consumed = self.consumed_bytes.checked_add(encoded_bytes).ok_or(
            IdentityError::ArithmeticOverflow {
                resource: "sync session bytes",
            },
        )?;
        if consumed > MAX_SYNC_SESSION_BYTES {
            return Err(IdentityError::limit(
                "sync session bytes",
                consumed,
                MAX_SYNC_SESSION_BYTES,
            ));
        }
        self.consumed_bytes = consumed;
        Ok(())
    }

    /// Total exact encoded bytes charged so far.
    pub const fn consumed_bytes(&self) -> usize {
        self.consumed_bytes
    }

    /// Remaining allowed encoded bytes.
    pub const fn remaining_bytes(&self) -> usize {
        MAX_SYNC_SESSION_BYTES - self.consumed_bytes
    }
}

impl Default for SyncSessionBudget {
    fn default() -> Self {
        Self::new()
    }
}
