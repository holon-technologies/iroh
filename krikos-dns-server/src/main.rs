#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::Parser;
use krikos_dns_server::{Server, config::Config};
use n0_error::{Result, StdResultExt};
use tracing::{debug, info};

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    /// Path to config file
    #[clap(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Install `ring` as default crypto provider for rustls.
    // This helps when both ring and aws-lc-rs rustls features are enabled
    // (e.g. via `--all-features` in the release build), otherwise rustls
    // panics because it can't determine a default provider from crate features.
    // `ring` is enabled by the default `ring` feature of this crate.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to set default crypto provider");

    let args = Cli::parse();

    let config = if let Some(path) = args.config {
        debug!("loading config from {:?}", path);
        Config::load(path).await?
    } else {
        debug!("using default config");
        Config::default()
    };

    let server = Server::bind(config).await?;
    tokio::signal::ctrl_c().await.anyerr()?;
    info!("shutdown");
    server.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::{Parser, error::ErrorKind};

    use super::Cli;

    #[test]
    fn cli_reports_package_version() {
        let error = Cli::try_parse_from(["iroh-dns-server", "--version"])
            .expect_err("--version exits after displaying version information");

        assert_eq!(error.kind(), ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }
}
