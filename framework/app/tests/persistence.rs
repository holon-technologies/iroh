use krikos_app::{DataRoot, DataRootError, StandardBundle};

#[tokio::test]
async fn persisted_identity_and_manifest_survive_clean_restart() {
    let root = tempfile::tempdir().unwrap();
    let first = StandardBundle::persistent(root.path())
        .local_only()
        .start()
        .await
        .unwrap();
    let endpoint_id = first.endpoint_id();
    first.shutdown().await.unwrap();

    let second = StandardBundle::persistent(root.path())
        .local_only()
        .start()
        .await
        .unwrap();
    assert_eq!(second.endpoint_id(), endpoint_id);
    second.shutdown().await.unwrap();

    let data_root = DataRoot::open(root.path()).unwrap();
    assert_eq!(data_root.schema_version(), 1);
    assert!(data_root.blobs_path().is_dir());
    assert!(data_root.docs_path().is_dir());
}

#[test]
fn unsupported_manifest_version_is_typed() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("manifest.json"),
        br#"{"schema_version":999,"framework":"iroh-app"}"#,
    )
    .unwrap();
    assert!(matches!(
        DataRoot::open(root.path()),
        Err(DataRootError::UnsupportedSchema { found: 999, .. })
    ));
}

#[test]
fn v1_manifest_fixture_opens() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("manifest.json"),
        include_bytes!("fixtures/manifest-v1.json"),
    )
    .unwrap();
    assert_eq!(DataRoot::open(root.path()).unwrap().schema_version(), 1);
}

#[tokio::test]
async fn exclusive_lease_blocks_a_second_process_and_releases_on_drop() {
    let root = tempfile::tempdir().unwrap();
    let first = StandardBundle::persistent(root.path())
        .local_only()
        .start()
        .await
        .unwrap();
    assert!(
        StandardBundle::persistent(root.path())
            .local_only()
            .start()
            .await
            .is_err()
    );

    drop(first);
    let restarted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match StandardBundle::persistent(root.path())
                .local_only()
                .start()
                .await
            {
                Ok(app) => break app,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("drop-triggered bounded shutdown releases the data root");
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn corrupt_docs_store_rolls_back_endpoint_and_data_root_lease() {
    let root = tempfile::tempdir().unwrap();
    let data_root = DataRoot::open(root.path()).unwrap();
    std::fs::write(data_root.docs_path().join("docs.redb"), b"corrupt").unwrap();

    assert!(
        StandardBundle::persistent(root.path())
            .local_only()
            .start()
            .await
            .is_err()
    );
    assert!(!root.path().join(".iroh-app.lock").exists());
}
