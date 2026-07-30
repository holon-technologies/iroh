use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_app::{RegistryError, StandardBundle};

const CUSTOM_ALPN: &[u8] = b"/holon/test/echo/1";

#[derive(Debug)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, _connection: Connection) -> Result<(), AcceptError> {
        Ok(())
    }
}

#[test]
fn standard_alpns_cannot_be_replaced() {
    let result = StandardBundle::ephemeral().protocol(iroh_blobs::ALPN, Echo);
    assert!(matches!(result, Err(RegistryError::Duplicate { .. })));
}

#[tokio::test]
async fn custom_protocol_crosses_the_bounded_extension_boundary() {
    let app = StandardBundle::ephemeral()
        .local_only()
        .protocol(CUSTOM_ALPN, Echo)
        .unwrap()
        .start()
        .await
        .unwrap();
    assert!(app.registered_alpns().any(|alpn| alpn == CUSTOM_ALPN));
    assert_eq!(app.metrics().protocol_count(), 4);
    app.shutdown().await.unwrap();
}
