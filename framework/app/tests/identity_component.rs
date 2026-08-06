#![cfg(feature = "identity")]

use std::sync::Arc;

use krikos_app::{DataRoot, IdentityProtocolComponent, StandardBundle};
use krikos_identity::{
    AccountId, CheckpointId, CursorKey, DeviceId, IdentityError, MemoryAccountStore,
    net::DenyIdentityProtocolService,
    transport::{CheckpointDeviceEndpoint, VerifiedCheckpointView},
};

#[derive(Debug)]
struct EmptyCheckpointView;

impl VerifiedCheckpointView for EmptyCheckpointView {
    fn device_endpoint(
        &self,
        _account_id: AccountId,
        _checkpoint_id: CheckpointId,
        _device_id: DeviceId,
    ) -> Result<Option<CheckpointDeviceEndpoint>, IdentityError> {
        Ok(None)
    }
}

fn component(seed: u8) -> IdentityProtocolComponent {
    IdentityProtocolComponent::new(
        Arc::new(MemoryAccountStore::new()),
        Arc::new(DenyIdentityProtocolService),
        Arc::new(EmptyCheckpointView),
        CursorKey::new([seed; 32]).unwrap(),
    )
}

#[tokio::test]
async fn opt_in_component_registers_six_handlers_on_existing_endpoint() {
    let application = StandardBundle::ephemeral()
        .local_only()
        .identity_protocols(component(7))
        .start()
        .await
        .unwrap();
    for expected in [
        krikos_identity::transport::PAIRING_ALPN,
        krikos_identity::transport::SYNC_ALPN,
        krikos_identity::transport::PROPOSAL_ALPN,
        krikos_identity::transport::CHECKPOINT_ALPN,
        krikos_identity::transport::TRANSPARENCY_GOSSIP_ALPN,
        krikos_identity::transport::RECOVERY_ALPN,
    ] {
        assert!(application.registered_alpns().any(|alpn| alpn == expected));
    }
    assert_eq!(application.metrics().protocol_count(), 9);
    application.shutdown().await.unwrap();
}

#[tokio::test]
async fn account_component_does_not_rewrite_endpoint_identity_persistence() {
    let directory = tempfile::tempdir().unwrap();
    let root = DataRoot::open(directory.path()).unwrap();
    let identity_path = root.identity_path();
    drop(root);

    let with_account_identity = StandardBundle::persistent(directory.path())
        .local_only()
        .identity_protocols(component(8))
        .start()
        .await
        .unwrap();
    let endpoint_id = with_account_identity.endpoint_id();
    with_account_identity.shutdown().await.unwrap();
    drop(with_account_identity);
    let before = std::fs::read(&identity_path).unwrap();

    let without_account_identity = StandardBundle::persistent(directory.path())
        .local_only()
        .start()
        .await
        .unwrap();
    assert_eq!(without_account_identity.endpoint_id(), endpoint_id);
    without_account_identity.shutdown().await.unwrap();
    drop(without_account_identity);
    let after = std::fs::read(identity_path).unwrap();
    assert_eq!(after, before);
}
