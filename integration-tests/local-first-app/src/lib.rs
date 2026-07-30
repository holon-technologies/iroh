//! Executable two-node acceptance scenario for the local-first application framework.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures_util::StreamExt;
use krikos::{
    RelayMap,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use krikos_app::{Application, StandardBundle, StandardBundleBuilder};
use krikos_docs::{
    AuthorId,
    api::{
        Doc,
        protocol::{AddrInfoOptions, ShareMode},
    },
    engine::LiveEvent,
};
use tokio::io::AsyncReadExt;

/// Bounded extension protocol used by the acceptance scenario.
pub const ECHO_ALPN: &[u8] = b"/holon/local-first/echo/1";
const NOTE_KEY: &[u8] = b"notes/welcome.md";
const NOTE_BYTES: &[u8] = b"Local-first state survives the network and a restart.\n";
const MAX_INVITATION_LENGTH: usize = 64 * 1024;
const MAX_ECHO_MESSAGE: usize = 4 * 1024;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(15);

/// Network path exercised by the scenario.
#[derive(Clone, Debug)]
pub enum ScenarioNetwork {
    /// Local addresses with no relay.
    Direct,
    /// A supplied compatible relay with application peer addresses filtered to relay-only.
    RelayOnly(RelayMap),
}

/// Runs create/share/sync/read/restart and custom-ALPN acceptance for two persisted nodes.
pub async fn run_two_node_scenario(network: ScenarioNetwork) -> Result<()> {
    let root_a = tempfile::tempdir().context("create node A root")?;
    let root_b = tempfile::tempdir().context("create node B root")?;

    let node_a = configure(StandardBundle::persistent(root_a.path()), &network)
        .start()
        .await
        .context("start node A")?;
    let node_b = configure(StandardBundle::persistent(root_b.path()), &network)
        .protocol(ECHO_ALPN, Echo)?
        .start()
        .await
        .context("start node B")?;
    if matches!(network, ScenarioNetwork::RelayOnly(_)) {
        tokio::time::timeout(CONVERGENCE_TIMEOUT, node_a.endpoint().online())
            .await
            .context("node A did not reach relay")?;
        tokio::time::timeout(CONVERGENCE_TIMEOUT, node_b.endpoint().online())
            .await
            .context("node B did not reach relay")?;
    }
    assert_custom_echo(&node_a, &node_b, &network).await?;

    let endpoint_a = node_a.endpoint_id();
    let endpoint_b = node_b.endpoint_id();
    let author_a = node_a.docs().author_default().await?;
    let author_b = node_b.docs().author_default().await?;
    let doc_a = node_a.docs().create().await?;
    let namespace = doc_a.id();

    let note = Bytes::from_static(NOTE_BYTES);
    let tag = node_a.blobs().blobs().add_bytes(note.clone()).await?;
    ensure!(
        tag.hash == krikos_blobs::Hash::new(&note),
        "blob hash mismatch"
    );
    doc_a
        .set_hash(
            author_a,
            NOTE_KEY,
            tag.hash,
            u64::try_from(note.len()).context("note length exceeds u64")?,
        )
        .await?;

    let mut ticket = doc_a
        .share(ShareMode::Read, AddrInfoOptions::RelayAndAddresses)
        .await?;
    if matches!(network, ScenarioNetwork::RelayOnly(_)) {
        for node in &mut ticket.nodes {
            node.addrs.retain(krikos::TransportAddr::is_relay);
            ensure!(
                !node.addrs.is_empty(),
                "relay-only invitation has no relay address"
            );
        }
    }
    let invitation = ticket.to_string();
    ensure!(
        invitation.len() <= MAX_INVITATION_LENGTH,
        "invitation exceeds bound"
    );
    let parsed = invitation.parse::<krikos_docs::DocTicket>()?;
    let peers = parsed.nodes.clone();
    let (doc_b, mut progress) = node_b.docs().import_and_subscribe(parsed).await?;
    observe_content_ready(&mut progress, tag.hash).await?;
    let received = wait_for_note(&node_b, &doc_b, author_a, tag.hash).await?;
    ensure!(received == note, "node B read different note bytes");

    ensure!(
        doc_b
            .set_bytes(
                author_b,
                Bytes::from_static(b"notes/unauthorized.md"),
                Bytes::from_static(b"must fail"),
            )
            .await
            .is_err(),
        "read capability unexpectedly permitted a write"
    );
    doc_b.start_sync(peers).await?;
    let resynced = wait_for_note(&node_b, &doc_b, author_a, tag.hash).await?;
    ensure!(resynced == note, "idempotent resync changed note bytes");

    node_b.shutdown().await?;
    node_a.shutdown().await?;
    drop(node_b);
    drop(node_a);

    let restarted_a = configure(StandardBundle::persistent(root_a.path()), &network)
        .start()
        .await?;
    let restarted_b = configure(StandardBundle::persistent(root_b.path()), &network)
        .protocol(ECHO_ALPN, Echo)?
        .start()
        .await?;
    ensure!(
        restarted_a.endpoint_id() == endpoint_a,
        "node A identity changed"
    );
    ensure!(
        restarted_b.endpoint_id() == endpoint_b,
        "node B identity changed"
    );
    let reopened_a = restarted_a
        .docs()
        .open(namespace)
        .await?
        .context("node A lost its document")?;
    let reopened_b = restarted_b
        .docs()
        .open(namespace)
        .await?
        .context("node B lost its document")?;
    let persisted_a = wait_for_note(&restarted_a, &reopened_a, author_a, tag.hash).await?;
    let persisted_b = wait_for_note(&restarted_b, &reopened_b, author_a, tag.hash).await?;
    ensure!(persisted_a == note, "node A lost blob bytes after restart");
    ensure!(persisted_b == note, "node B lost blob bytes after restart");

    restarted_b.shutdown().await?;
    restarted_a.shutdown().await?;
    Ok(())
}

fn configure(builder: StandardBundleBuilder, network: &ScenarioNetwork) -> StandardBundleBuilder {
    match network {
        ScenarioNetwork::Direct => builder.local_only(),
        ScenarioNetwork::RelayOnly(relay_map) => builder
            .relay_map(relay_map.clone())
            .tls_ca_config(krikos::tls::CaTlsConfig::insecure_skip_verify()),
    }
}

async fn observe_content_ready(
    progress: &mut (impl futures_util::Stream<Item = anyhow::Result<LiveEvent>> + Unpin),
    expected_hash: krikos_blobs::Hash,
) -> Result<()> {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        while let Some(event) = progress.next().await {
            match event? {
                LiveEvent::ContentReady { hash } if hash == expected_hash => return Ok(()),
                LiveEvent::InsertRemote {
                    entry,
                    content_status: krikos_docs::ContentStatus::Complete,
                    ..
                } if entry.content_hash() == expected_hash => return Ok(()),
                _ => {}
            }
        }
        anyhow::bail!("document progress stream ended before content was ready")
    })
    .await
    .context("document content convergence timed out")?
}

async fn wait_for_note(
    application: &Application,
    doc: &Doc,
    author: AuthorId,
    expected_hash: krikos_blobs::Hash,
) -> Result<Bytes> {
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            if let Some(entry) = doc.get_exact(author, NOTE_KEY, false).await?
                && entry.content_hash() == expected_hash
            {
                let mut reader = application.blobs().blobs().reader(expected_hash);
                let mut bytes = Vec::new();
                if reader.read_to_end(&mut bytes).await.is_ok() {
                    ensure!(
                        krikos_blobs::Hash::new(&bytes) == expected_hash,
                        "downloaded blob failed hash validation"
                    );
                    return Ok(Bytes::from(bytes));
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("note convergence timed out")?
}

async fn assert_custom_echo(
    client: &Application,
    server: &Application,
    network: &ScenarioNetwork,
) -> Result<()> {
    let mut server_addr = server.endpoint().addr();
    if matches!(network, ScenarioNetwork::RelayOnly(_)) {
        server_addr.addrs.retain(krikos::TransportAddr::is_relay);
        ensure!(
            !server_addr.addrs.is_empty(),
            "relay-only echo address has no relay"
        );
    }
    let connection = client.endpoint().connect(server_addr, ECHO_ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"extension-boundary").await?;
    send.finish()?;
    let response = recv.read_to_end(MAX_ECHO_MESSAGE).await?;
    ensure!(
        response == b"extension-boundary",
        "custom ALPN echo mismatch"
    );
    connection.close(0_u32.into(), b"complete");
    Ok(())
}

/// Bounded echo handler demonstrating framework extension without internal changes.
#[derive(Clone, Debug)]
pub struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request = recv
            .read_to_end(MAX_ECHO_MESSAGE)
            .await
            .map_err(AcceptError::from_err)?;
        send.write_all(&request)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish().map_err(AcceptError::from_err)?;
        connection.closed().await;
        Ok(())
    }
}
