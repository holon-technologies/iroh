//! Example that runs an krikos node with a direct local address and no relay server.
//!
//! You can think of this as a local version of [sendme](https://www.iroh.computer/sendme)
//! that only works for individual files.
//!
//! **This example is using a non-default feature of krikos, so you need to run it with the
//! examples feature enabled.**
//!
//! Run the following command to run the "accept" side, which hosts the content:
//!  $ cargo run --example mdns-address-lookup -- accept [FILE_PATH]
//! Wait for output that looks like the following:
//!  $ cargo run --example mdns-address-lookup -- connect [NODE_ID] [IP:PORT] [HASH] -o [FILE_PATH]
//! Run that command on another machine in the same local network, replacing `[FILE_PATH]` with the
//! destination path. The filename is retained for compatibility with the upstream example; this
//! fork uses an explicit bounded address because the external 1.x mDNS adapter is not part of v2.
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use krikos::{
    Endpoint, EndpointAddr, PublicKey, RelayMode, SecretKey, endpoint::presets, protocol::Router,
};
use krikos_blobs::{BlobsProtocol, Hash, store::mem::MemStore};

mod common;
use common::{get_or_generate_secret_key, setup_logging};

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Launch an krikos node and provide the content at the given path
    Accept {
        /// path to the file you want to provide
        path: PathBuf,
    },
    /// Get the node_id and hash string from a node running accept in the local network
    /// Download the content from that node.
    Connect {
        /// Endpoint ID of a node on the local network
        endpoint_id: PublicKey,
        /// Direct socket address printed by the accepting node
        direct_addr: SocketAddr,
        /// Hash of content you want to download from the node
        hash: Hash,
        /// save the content to a file
        #[clap(long, short)]
        out: Option<PathBuf>,
    },
}

async fn accept(path: &Path) -> Result<()> {
    if !path.is_file() {
        println!("Content must be a file.");
        return Ok(());
    }

    let key = get_or_generate_secret_key()?;

    println!("Starting direct local krikos node...");
    // create a new node
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Default)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let builder = Router::builder(endpoint.clone());
    let store = MemStore::new();
    let blobs = BlobsProtocol::new(&store, None);
    let builder = builder.accept(krikos_blobs::ALPN, blobs.clone());
    let node = builder.spawn();

    if !path.is_file() {
        println!("Content must be a file.");
        node.shutdown().await?;
        return Ok(());
    }
    let absolute = path.canonicalize()?;
    println!("Adding {} as {}...", path.display(), absolute.display());
    let tag = store.add_path(absolute).await?;
    let addr = node.endpoint().addr();
    let direct_addr = addr
        .ip_addrs()
        .next()
        .context("endpoint did not expose a direct IP address")?;
    println!(
        "To fetch the blob:\n\tcargo run --example mdns-address-lookup -- connect {} {} {} -o [FILE_PATH]",
        node.endpoint().id(),
        direct_addr,
        tag.hash
    );
    tokio::signal::ctrl_c().await?;
    node.shutdown().await?;
    Ok(())
}

async fn connect(
    node_id: PublicKey,
    direct_addr: SocketAddr,
    hash: Hash,
    out: Option<PathBuf>,
) -> Result<()> {
    let key = SecretKey::generate();

    println!("Starting direct local krikos node...");
    // create a new node
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let store = MemStore::new();

    println!("NodeID: {}", endpoint.id());
    let addr = EndpointAddr::new(node_id).with_ip_addr(direct_addr);
    let conn = endpoint.connect(addr, krikos_blobs::ALPN).await?;
    let stats = store.remote().fetch(conn, hash).await?;
    println!(
        "Fetched {} bytes for hash {}",
        stats.payload_bytes_read, hash
    );
    if let Some(path) = out {
        let absolute = std::env::current_dir()?.join(&path);
        ensure!(!absolute.is_dir(), "output must not be a directory");
        println!(
            "exporting {hash} to {} -> {}",
            path.display(),
            absolute.display()
        );
        let size = store.export(hash, absolute).await?;
        println!("Exported {size} bytes");
    }

    endpoint.close().await;
    // Shutdown the store. This is not needed for the mem store, but would be
    // necessary for a persistent store to allow it to write any pending data to disk.
    store.shutdown().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logging();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Accept { path } => {
            accept(path).await?;
        }
        Commands::Connect {
            endpoint_id,
            direct_addr,
            hash,
            out,
        } => {
            connect(*endpoint_id, *direct_addr, *hash, out.clone()).await?;
        }
    }
    Ok(())
}
