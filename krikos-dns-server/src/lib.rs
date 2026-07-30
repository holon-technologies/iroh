//! A DNS server and [pkarr] relay.
#![forbid(unsafe_code)]
//!
//! [`Server`] combines a DNS server (UDP and TCP) with an HTTP/HTTPS server
//! into a single process. Clients publish self-signed DNS records as [pkarr]
//! signed packets at `PUT /pkarr`; the server persists them and answers DNS
//! queries for the published names, including DNS-over-HTTPS at `/dns-query`.
//!
//! With the mainline fallback enabled, keys missing from the local store are
//! looked up on the BitTorrent mainline DHT.
//!
//! # Example
//!
//! ```no_run
//! use krikos_dns_server::{Server, config::Config};
//! # async fn run() -> n0_error::Result<()> {
//! let config = Config::load("config.toml").await?;
//! let server = Server::bind(config).await?;
//! server.join().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [pkarr]: https://github.com/Nuhvi/pkarr/

#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]

mod admission;
pub mod config;
mod dns;
mod http;
mod metrics;
mod server;
mod state;
mod store;
#[cfg(feature = "test-utils")]
pub mod test_utils;
mod util;

pub use crate::{metrics::Metrics, server::Server};
