//! Named bounds for every protocol-controlled allocation and collection.

use std::time::Duration;

/// Largest accepted canonical protocol object.
pub const MAX_ENCODED_OBJECT_BYTES: usize = 1024 * 1024;
/// Largest accepted account-control event.
pub const MAX_ACCOUNT_EVENT_BYTES: usize = 256 * 1024;
/// Largest accepted device-pairing ticket.
pub const MAX_PAIRING_TICKET_BYTES: usize = 16 * 1024;
/// Largest accepted synchronization frame.
pub const MAX_SYNC_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// Maximum account events in one synchronization batch.
pub const MAX_EVENTS_PER_SYNC_BATCH: usize = 256;
/// Maximum controllers retained by one account.
pub const MAX_CONTROLLERS: usize = 64;
/// Maximum devices retained by one account, including tombstones.
pub const MAX_DEVICES: usize = 1024;
/// Maximum rules in one control policy.
pub const MAX_POLICY_RULES: usize = 64;
/// Maximum signatures accepted as authorization for one object.
pub const MAX_AUTHORIZATION_SIGNATURES: usize = 64;
/// Maximum simultaneously accepted controller-signature suites during migration.
pub const MAX_ACTIVE_CRYPTO_SUITES: usize = 2;
/// Maximum encoded public signing key in an explicit crypto migration.
pub const MAX_ALGORITHM_PUBLIC_KEY_BYTES: usize = 4 * 1024;
/// Maximum encoded signature in an explicit crypto migration.
pub const MAX_ALGORITHM_SIGNATURE_BYTES: usize = 8 * 1024;
/// Maximum capabilities granted to one device.
pub const MAX_CAPABILITIES_PER_DEVICE: usize = 128;
/// Maximum constraints attached to one capability.
pub const MAX_CONSTRAINTS_PER_CAPABILITY: usize = 32;
/// Maximum capability-delegation chain depth.
pub const MAX_DELEGATION_DEPTH: usize = 8;
/// Maximum transparency providers configured for one account.
pub const MAX_TRANSPARENCY_PROVIDERS: usize = 16;
/// Maximum recovery guardians configured for one account.
pub const MAX_RECOVERY_GUARDIANS: usize = 16;
/// Maximum hashes accepted in one Merkle proof path.
pub const MAX_MERKLE_PROOF_HASHES: usize = 64;
/// Maximum leaves materialized in one account-state sorted Merkle set.
pub const MAX_MERKLE_SET_LEAVES: usize = 2_048;
/// Maximum leaves held by one bounded in-memory provider-log generation.
///
/// Durable providers rotate to a new versioned log generation before reaching this bound.
pub const MAX_MERKLE_LOG_LEAVES: usize = 1_048_576;
/// Maximum extension fields on one extensible v1 object.
pub const MAX_EXTENSIONS: usize = 32;
/// Maximum value bytes in one extension field.
pub const MAX_EXTENSION_VALUE_BYTES: usize = 16 * 1024;
/// Maximum combined value bytes across an object's extension fields.
pub const MAX_TOTAL_EXTENSION_BYTES: usize = 64 * 1024;
/// Maximum retained branch heads for one account fork.
pub const MAX_FORK_HEADS: usize = 16;
/// Maximum encoded fork evidence retained in one account revision.
pub const MAX_FORK_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum UTF-8 bytes in a capability namespace or action.
pub const MAX_CAPABILITY_NAME_BYTES: usize = 128;
/// Maximum encoded bytes in a capability resource selector.
pub const MAX_RESOURCE_SELECTOR_BYTES: usize = 1024;
/// Maximum encrypted private-metadata envelope.
pub const MAX_PRIVATE_METADATA_BYTES: usize = 256 * 1024;
/// Maximum encrypted account backup envelope.
pub const MAX_PRIVATE_BACKUP_BYTES: usize = MAX_ENCODED_OBJECT_BYTES;
/// Maximum application-private bytes carried by one account backup.
pub const MAX_APPLICATION_BACKUP_DATA_BYTES: usize = 256 * 1024;
/// Maximum private relationship-label bytes accepted before blinding.
pub const MAX_PRIVATE_LABEL_BYTES: usize = 128;
/// Maximum normalized relying-party context bytes.
pub const MAX_RELYING_PARTY_CONTEXT_BYTES: usize = 253;
/// Maximum selectively disclosed claims in one portable credential.
pub const MAX_CREDENTIAL_CLAIMS: usize = 64;
/// Maximum portable-credential claim-name bytes.
pub const MAX_CREDENTIAL_CLAIM_NAME_BYTES: usize = 64;
/// Maximum disclosed value bytes in one portable-credential claim.
pub const MAX_CREDENTIAL_CLAIM_VALUE_BYTES: usize = 16 * 1024;
/// Maximum complete canonical portable credential export.
pub const MAX_PORTABLE_CREDENTIAL_BYTES: usize = 512 * 1024;
/// Maximum exact canonical bytes sent to an offline or hardware signer.
pub const MAX_OFFLINE_SIGNING_REQUEST_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;
/// Maximum complete canonical signed application event.
pub const MAX_APPLICATION_EVENT_BYTES: usize = 1024 * 1024;
/// Maximum application payload, reserving bounded envelope/signature overhead.
pub const MAX_APPLICATION_PAYLOAD_BYTES: usize = MAX_APPLICATION_EVENT_BYTES - 4 * 1024;
/// Maximum encoded wrapped group key for one recipient.
pub const MAX_KEY_WRAP_BYTES: usize = 4 * 1024;
/// Maximum pending account proposals retained locally.
pub const MAX_PENDING_PROPOSALS: usize = 128;
/// Maximum live, unconsumed pairing tickets retained locally.
pub const MAX_LIVE_PAIRING_TICKETS: usize = 64;
/// Maximum durable pairing nonce tombstones retained by one nonce store instance.
///
/// Reaching this bound is an availability failure; an implementation must never evict a
/// tombstone in a way that permits a previously consumed ticket to revive.
pub const MAX_PAIRING_NONCE_TOMBSTONES: usize = 65_536;
/// Maximum concurrent recovery attempts for one account.
pub const MAX_CONCURRENT_RECOVERY_ATTEMPTS: usize = 8;
/// Maximum complete canonical social attestation.
pub const MAX_SOCIAL_ATTESTATION_BYTES: usize = 64 * 1024;
/// Maximum explicitly enabled social-attestation chain depth.
pub const MAX_SOCIAL_TRANSITIVITY_DEPTH: usize = 8;
/// Maximum lowercase ASCII DNS-style name bytes.
pub const MAX_NORMALIZED_NAME_BYTES: usize = 253;
/// Maximum complete canonical signed name claim.
pub const MAX_NAME_CLAIM_BYTES: usize = 64 * 1024;
/// Maximum name claims returned by one resolver query.
pub const MAX_NAME_CLAIMS: usize = 64;
/// Maximum history events processed in one page or projection call.
pub const MAX_HISTORY_PAGE_EVENTS: usize = 256;
/// Maximum encoded history bytes returned in one page.
pub const MAX_HISTORY_PAGE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum total bytes exchanged in one synchronization session.
pub const MAX_SYNC_SESSION_BYTES: usize = 16 * 1024 * 1024;
/// Maximum bytes returned by one provider account-history request.
pub const MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum concurrently running identity streams or child tasks.
pub const MAX_CONCURRENT_IDENTITY_TASKS: usize = 64;
/// Capacity of identity actor and effect queues.
pub const IDENTITY_QUEUE_CAPACITY: usize = 256;
/// Maximum attempts for a bounded retry policy.
pub const MAX_RETRIES: u8 = 8;
/// Maximum validity of a device-pairing ticket.
pub const MAX_PAIRING_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Maximum validity of a presence proof.
pub const MAX_PRESENCE_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// Maximum accepted future clock skew for time-bound proofs.
pub const MAX_FUTURE_CLOCK_SKEW: Duration = Duration::from_secs(2 * 60);
/// Maximum graceful shutdown duration for identity tasks.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

const _: () = {
    assert!(MAX_ENCODED_OBJECT_BYTES > 0);
    assert!(MAX_ACCOUNT_EVENT_BYTES <= MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_PAIRING_TICKET_BYTES <= MAX_ACCOUNT_EVENT_BYTES);
    assert!(MAX_SYNC_FRAME_BYTES >= MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_EVENTS_PER_SYNC_BATCH > 0);
    assert!(MAX_CONTROLLERS > 0);
    assert!(MAX_DEVICES >= MAX_CONTROLLERS);
    assert!(MAX_POLICY_RULES > 0);
    assert!(MAX_AUTHORIZATION_SIGNATURES >= MAX_CONTROLLERS);
    assert!(MAX_ACTIVE_CRYPTO_SUITES == 2);
    assert!(MAX_ALGORITHM_PUBLIC_KEY_BYTES <= MAX_ACCOUNT_EVENT_BYTES);
    assert!(MAX_ALGORITHM_SIGNATURE_BYTES <= MAX_ACCOUNT_EVENT_BYTES);
    assert!(MAX_CAPABILITIES_PER_DEVICE > 0);
    assert!(MAX_CONSTRAINTS_PER_CAPABILITY > 0);
    assert!(MAX_DELEGATION_DEPTH > 0);
    assert!(MAX_TRANSPARENCY_PROVIDERS > 0);
    assert!(MAX_RECOVERY_GUARDIANS > 0);
    assert!(MAX_MERKLE_PROOF_HASHES == u64::BITS as usize);
    assert!(MAX_MERKLE_SET_LEAVES >= MAX_DEVICES + MAX_CONTROLLERS);
    assert!(MAX_MERKLE_LOG_LEAVES >= MAX_MERKLE_SET_LEAVES);
    assert!(MAX_EXTENSIONS > 0);
    assert!(MAX_EXTENSION_VALUE_BYTES <= MAX_TOTAL_EXTENSION_BYTES);
    assert!(MAX_TOTAL_EXTENSION_BYTES <= MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_FORK_HEADS > 1);
    assert!(MAX_FORK_EVIDENCE_BYTES >= MAX_ACCOUNT_EVENT_BYTES);
    assert!(MAX_CAPABILITY_NAME_BYTES > 0);
    assert!(MAX_RESOURCE_SELECTOR_BYTES > 0);
    assert!(MAX_PRIVATE_METADATA_BYTES <= MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_PRIVATE_BACKUP_BYTES == MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_APPLICATION_BACKUP_DATA_BYTES < MAX_PRIVATE_BACKUP_BYTES);
    assert!(MAX_PRIVATE_LABEL_BYTES > 0);
    assert!(MAX_RELYING_PARTY_CONTEXT_BYTES <= 253);
    assert!(MAX_CREDENTIAL_CLAIMS > 0);
    assert!(MAX_CREDENTIAL_CLAIM_NAME_BYTES <= MAX_PRIVATE_LABEL_BYTES);
    assert!(MAX_CREDENTIAL_CLAIM_VALUE_BYTES <= MAX_PRIVATE_METADATA_BYTES);
    assert!(MAX_PORTABLE_CREDENTIAL_BYTES < MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_OFFLINE_SIGNING_REQUEST_BYTES <= MAX_ACCOUNT_EVENT_BYTES);
    assert!(MAX_APPLICATION_EVENT_BYTES == MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_APPLICATION_PAYLOAD_BYTES < MAX_APPLICATION_EVENT_BYTES);
    assert!(MAX_KEY_WRAP_BYTES <= MAX_PAIRING_TICKET_BYTES);
    assert!(MAX_PENDING_PROPOSALS > 0);
    assert!(MAX_LIVE_PAIRING_TICKETS > 0);
    assert!(MAX_CONCURRENT_RECOVERY_ATTEMPTS > 0);
    assert!(MAX_SOCIAL_ATTESTATION_BYTES <= MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_SOCIAL_TRANSITIVITY_DEPTH > 0);
    assert!(MAX_NORMALIZED_NAME_BYTES <= 253);
    assert!(MAX_NAME_CLAIM_BYTES <= MAX_ENCODED_OBJECT_BYTES);
    assert!(MAX_NAME_CLAIMS > 0);
    assert!(MAX_HISTORY_PAGE_EVENTS == MAX_EVENTS_PER_SYNC_BATCH);
    assert!(MAX_HISTORY_PAGE_BYTES == MAX_SYNC_FRAME_BYTES);
    assert!(MAX_SYNC_SESSION_BYTES >= MAX_SYNC_FRAME_BYTES);
    assert!(MAX_PROVIDER_ACCOUNT_RESPONSE_BYTES <= MAX_SYNC_SESSION_BYTES);
    assert!(MAX_CONCURRENT_IDENTITY_TASKS > 0);
    assert!(IDENTITY_QUEUE_CAPACITY >= MAX_CONCURRENT_IDENTITY_TASKS);
    assert!(MAX_RETRIES > 0);
};
