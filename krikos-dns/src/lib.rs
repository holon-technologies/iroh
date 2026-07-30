//! DNS-based endpoint discovery for krikos.
//!
//! This crate contains the core types for publishing and resolving krikos endpoint
//! information via DNS, using the [pkarr](https://pkarr.org) signed packet format.
#![deny(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

mod attrs;
#[cfg(not(wasm_browser))]
pub mod dns;
pub mod endpoint_info;
pub mod pkarr;

pub use attrs::{EncodingError, KRIKOS_TXT_NAME, ParseError};
#[cfg(target_os = "android")]
pub use krikos_resolver::install_android_jni_context;
