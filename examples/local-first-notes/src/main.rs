use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
};
use iroh_app::{Application, StandardBundle};
use iroh_docs::{AuthorId, api::Doc, api::protocol::AddrInfoOptions, api::protocol::ShareMode};
use tokio::io::AsyncReadExt;

const ECHO_ALPN: &[u8] = b"/holon/local-first/notes-echo/1";
const NOTE_KEY: &[u8] = b"notes/demo.md";
const MAX_ECHO_BYTES: usize = 4 * 1024;
const SYNC_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(
        args.next()
            .context("usage: local-first-notes DATA_ROOT [TEXT]")?,
    );
    let note = args
        .next()
        .map(|text| text.to_string_lossy().into_owned())
        .unwrap_or_else(|| "hello from a local-first Iroh application".to_owned());
    ensure!(
        args.next().is_none(),
        "usage: local-first-notes DATA_ROOT [TEXT]"
    );
    let node_a_root = root.join("node-a");
    let node_b_root = root.join("node-b");

    let node_a = StandardBundle::persistent(&node_a_root)
        .local_only()
        .start()
        .await?;
    let node_b = StandardBundle::persistent(&node_b_root)
        .local_only()
        .protocol(ECHO_ALPN, Echo)?
        .start()
        .await?;
    echo(&node_a, &node_b).await?;

    let author_a = node_a.docs().author_default().await?;
    let author_b = node_b.docs().author_default().await?;
    let doc_a = node_a.docs().create().await?;
    let namespace = doc_a.id();
    let note = Bytes::from(note);
    let tag = node_a.blobs().blobs().add_bytes(note.clone()).await?;
    doc_a
        .set_hash(
            author_a,
            NOTE_KEY,
            tag.hash,
            u64::try_from(note.len()).context("note is too large")?,
        )
        .await?;
    let ticket = doc_a
        .share(ShareMode::Read, AddrInfoOptions::RelayAndAddresses)
        .await?;
    let invitation = ticket.to_string();
    ensure!(invitation.len() <= 64 * 1024, "invitation is too large");
    let doc_b = node_b
        .docs()
        .import(invitation.parse::<iroh_docs::DocTicket>()?)
        .await?;
    let received = read_when_ready(&node_b, &doc_b, author_a, tag.hash).await?;
    ensure!(received == note, "nodes disagree about note bytes");
    ensure!(
        doc_b
            .set_bytes(
                author_b,
                Bytes::from_static(b"notes/not-allowed.md"),
                Bytes::from_static(b"write"),
            )
            .await
            .is_err(),
        "read-only invitation allowed a write"
    );

    println!("node A: {}", node_a.endpoint_id());
    println!("node B: {}", node_b.endpoint_id());
    println!("document: {namespace}");
    println!("read-only invitation: {invitation}");
    println!("node B read: {}", String::from_utf8_lossy(&received));

    node_b.shutdown().await?;
    node_a.shutdown().await?;
    drop(node_b);
    drop(node_a);

    let restarted_a = StandardBundle::persistent(node_a_root)
        .local_only()
        .start()
        .await?;
    let reopened = restarted_a
        .docs()
        .open(namespace)
        .await?
        .context("document was not durable")?;
    ensure!(
        read_when_ready(&restarted_a, &reopened, author_a, tag.hash).await? == note,
        "note was not durable"
    );
    println!("restart retained identity and note state");
    restarted_a.shutdown().await?;
    Ok(())
}

async fn read_when_ready(
    application: &Application,
    doc: &Doc,
    author: AuthorId,
    hash: iroh_blobs::Hash,
) -> Result<Bytes> {
    tokio::time::timeout(SYNC_TIMEOUT, async {
        loop {
            if let Some(entry) = doc.get_exact(author, NOTE_KEY, false).await?
                && entry.content_hash() == hash
            {
                let mut reader = application.blobs().blobs().reader(hash);
                let mut bytes = Vec::new();
                if reader.read_to_end(&mut bytes).await.is_ok() {
                    ensure!(iroh_blobs::Hash::new(&bytes) == hash, "hash mismatch");
                    return Ok(Bytes::from(bytes));
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("note synchronization timed out")?
}

async fn echo(client: &Application, server: &Application) -> Result<()> {
    let connection = client
        .endpoint()
        .connect(server.endpoint().addr(), ECHO_ALPN)
        .await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"custom protocol works").await?;
    send.finish()?;
    ensure!(
        recv.read_to_end(MAX_ECHO_BYTES).await? == b"custom protocol works",
        "echo mismatch"
    );
    connection.close(0_u32.into(), b"complete");
    Ok(())
}

#[derive(Clone, Debug)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let request = recv
            .read_to_end(MAX_ECHO_BYTES)
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
