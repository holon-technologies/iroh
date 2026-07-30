use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use iroh_app::{LifecycleState, StandardBundle, StandardStartStage};

#[tokio::test]
async fn ephemeral_standard_bundle_starts_healthy_and_stops_cleanly() {
    let app = StandardBundle::ephemeral()
        .local_only()
        .start()
        .await
        .unwrap();

    assert_eq!(app.health().lifecycle().state(), LifecycleState::Running);
    assert_eq!(app.metrics().protocol_count(), 3);
    assert!(app.registered_alpns().any(|alpn| alpn == iroh_blobs::ALPN));
    assert!(app.registered_alpns().any(|alpn| alpn == iroh_docs::ALPN));
    assert!(app.registered_alpns().any(|alpn| alpn == iroh_gossip::ALPN));
    assert_eq!(app.endpoint().id(), app.endpoint_id());

    app.shutdown().await.unwrap();
    assert_eq!(app.health().lifecycle().state(), LifecycleState::Stopped);
}

#[tokio::test]
async fn bind_failure_releases_data_root_lock() {
    let root = tempfile::tempdir().unwrap();
    let occupied = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let address = occupied.local_addr().unwrap();

    let error = StandardBundle::persistent(root.path())
        .local_only()
        .bind_addr(address)
        .start()
        .await
        .unwrap_err();
    assert_eq!(error.stage(), StandardStartStage::Endpoint);
    assert!(!root.path().join(".iroh-app.lock").exists());
}

#[tokio::test]
async fn corrupt_manifest_fails_before_network_exposure() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("manifest.json"), b"not-json").unwrap();

    let error = StandardBundle::persistent(root.path())
        .local_only()
        .start()
        .await
        .unwrap_err();
    assert_eq!(error.stage(), StandardStartStage::DataRoot);
    assert!(!root.path().join(".iroh-app.lock").exists());
}
