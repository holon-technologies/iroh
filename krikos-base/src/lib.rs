//! Base types and utilities for Krikos.
//!
//! # Features
//!
//! - `key-types` enables deterministic key, signature, endpoint-identifier, and address types.
//! - `os-rng` adds the `SecretKey::generate` operating-system entropy convenience API.
//! - `key` is a backward-compatible aggregate for `key-types` plus `os-rng`.
//! - `relay` enables relay URL types.
#![forbid(unsafe_code)]
#![cfg_attr(krikos_docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

#[cfg(feature = "key-types")]
mod endpoint_addr;
#[cfg(feature = "key-types")]
mod key;
#[cfg(feature = "relay")]
mod relay_url;

#[cfg(feature = "key-types")]
pub use self::endpoint_addr::{
    AddressLimitError, AddressLimits, CustomAddr, EndpointAddr, MAX_CUSTOM_ADDR_BYTES,
    MAX_ENDPOINT_ADDR_BYTES, MAX_ENDPOINT_ADDRS, MAX_RELAY_URL_BYTES, TransportAddr,
};
#[cfg(feature = "key-types")]
pub use self::key::{
    EndpointId, KeyParsingError, PublicKey, SecretKey, Signature, SignatureError,
    SignatureParsingError,
};
#[cfg(feature = "relay")]
pub use self::relay_url::{RelayUrl, RelayUrlParseError};
