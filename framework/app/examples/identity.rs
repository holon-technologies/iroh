//! Starts the standard bundle with the opt-in, default-deny identity protocol component.

use std::sync::Arc;

use krikos_app::{IdentityProtocolComponent, StandardBundle};
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

fn main() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("example runtime must build")
        .block_on(async {
            let identity = IdentityProtocolComponent::new(
                Arc::new(MemoryAccountStore::new()),
                Arc::new(DenyIdentityProtocolService),
                Arc::new(EmptyCheckpointView),
                CursorKey::new([7; 32]).expect("constant cursor key is nonzero"),
            );
            let application = StandardBundle::ephemeral()
                .local_only()
                .identity_protocols(identity)
                .start()
                .await
                .expect("identity-enabled application must start");
            println!("identity endpoint: {}", application.endpoint_id());
            application
                .shutdown()
                .await
                .expect("identity-enabled application must stop");
        });
}
