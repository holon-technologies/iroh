//! Bounded fuzzing facades over production parsers and registries.

use crate::{ProtocolRegistry, data_root::validate_manifest_bytes};

const MAX_FUZZ_PROTOCOLS: usize = 32;

/// Summary of one bounded protocol-registry fuzz input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryFuzzOutcome {
    /// Number of ALPN candidates passed to the production registry.
    pub attempted: usize,
    /// Number of unique, valid candidates accepted.
    pub accepted: usize,
}

/// Parses and validates untrusted bytes through the production data-root manifest path.
#[must_use]
pub fn fuzz_manifest(input: &[u8]) -> bool {
    validate_manifest_bytes(input).is_ok()
}

/// Exercises bounded ALPN registration using length-prefixed candidates from `input`.
#[must_use]
pub fn fuzz_protocol_registration(input: &[u8]) -> RegistryFuzzOutcome {
    let mut registry = ProtocolRegistry::new(MAX_FUZZ_PROTOCOLS, 255)
        .expect("fixed fuzz registry bounds are valid");
    let mut cursor = 0;
    let mut attempted = 0;
    let mut accepted = 0;
    while attempted < MAX_FUZZ_PROTOCOLS && cursor < input.len() {
        let length = usize::from(input[cursor]);
        cursor = cursor.saturating_add(1);
        let end = cursor.saturating_add(length).min(input.len());
        attempted += 1;
        if registry
            .register_marker(&input[cursor..end], "fuzz")
            .is_ok()
        {
            accepted += 1;
        }
        cursor = end;
    }
    RegistryFuzzOutcome {
        attempted,
        accepted,
    }
}
