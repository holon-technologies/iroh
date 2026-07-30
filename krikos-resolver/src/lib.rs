//! Provider-neutral DNS resolution for Iroh.
//!
//! This crate owns host, address, and TXT resolution. It deliberately has no knowledge of
//! endpoint identifiers, endpoint records, pkarr, or DNS publication.
#![deny(unsafe_code)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

#[cfg(any(target_os = "android", doc))]
#[allow(
    unsafe_code,
    reason = "the Android JNI boundary has a public safety contract and a reviewed unsafe operation"
)]
mod android;
mod dns;
mod error;
mod hickory;
mod runtime;

#[cfg(any(target_os = "android", doc))]
pub use android::install_android_jni_context;
pub use dns::{
    BoxIter, DNS_TIMEOUT, DnsResolver, MAX_ADDRESS_RECORDS_PER_FAMILY, Resolver, TxtRecordData,
};
pub use error::{BuildError, DnsError, StaggeredError};
pub use hickory::{Builder, DnsProtocol};
pub use runtime::DnsRuntime;
