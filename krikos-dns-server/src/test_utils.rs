//! Deterministic controls used only by bounded integration and fuzz workloads.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use krikos_base::PublicKey;
use krikos_dns::pkarr::SignedPacket;

use crate::{config::Config, http::doh::extract::decode_request};

/// Reserved DNS name whose admitted UDP handler remains active for the hold duration.
pub const RESOURCE_CANARY_UDP_HOLD_NAME: &str = "_iroh-resource-canary-hold.invalid.";

/// Time an admitted reserved UDP request remains active.
pub const RESOURCE_CANARY_UDP_HOLD_DURATION: Duration = Duration::from_secs(3);

/// Maximum DNS message accepted by the bounded DoH fuzz adapter.
pub const FUZZ_MAX_DOH_BYTES: usize = 65_535;

/// Maximum key-plus-payload input accepted by the bounded pkarr fuzz adapter.
pub const FUZZ_MAX_PKARR_BYTES: usize = PublicKey::LENGTH + SignedPacket::MAX_RELAY_PAYLOAD_BYTES;

/// Maximum TOML input accepted by the bounded configuration fuzz adapter.
pub const FUZZ_MAX_CONFIG_BYTES: usize = 65_535;

/// Stable result class for bounded parser fuzz adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FuzzValidationOutcome {
    /// The input parsed and passed structural validation.
    Accepted,
    /// The input was within its byte bound but invalid.
    Rejected,
    /// The input exceeded the adapter's byte bound and was not parsed.
    TooLarge,
}

/// Exercises the production DoH request decoder without opening a listener.
pub fn fuzz_doh_request(input: &[u8]) -> FuzzValidationOutcome {
    if input.len() > FUZZ_MAX_DOH_BYTES {
        return FuzzValidationOutcome::TooLarge;
    }
    let source = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
    if decode_request(input, source).is_ok() {
        FuzzValidationOutcome::Accepted
    } else {
        FuzzValidationOutcome::Rejected
    }
}

/// Exercises the production pkarr relay-payload verifier without opening storage.
pub fn fuzz_pkarr_body(input: &[u8]) -> FuzzValidationOutcome {
    if input.len() > FUZZ_MAX_PKARR_BYTES {
        return FuzzValidationOutcome::TooLarge;
    }
    let Some(key_bytes) = input.get(..PublicKey::LENGTH) else {
        return FuzzValidationOutcome::Rejected;
    };
    let key_bytes: &[u8; PublicKey::LENGTH] = key_bytes
        .try_into()
        .expect("a PublicKey::LENGTH slice must convert to the matching array");
    let Ok(public_key) = PublicKey::from_bytes(key_bytes) else {
        return FuzzValidationOutcome::Rejected;
    };
    if SignedPacket::from_relay_payload(&public_key, &input[PublicKey::LENGTH..]).is_ok() {
        FuzzValidationOutcome::Accepted
    } else {
        FuzzValidationOutcome::Rejected
    }
}

/// Parses and validates a complete DNS-server configuration without performing I/O.
pub fn fuzz_config(input: &[u8]) -> FuzzValidationOutcome {
    if input.len() > FUZZ_MAX_CONFIG_BYTES {
        return FuzzValidationOutcome::TooLarge;
    }
    let Ok(input) = std::str::from_utf8(input) else {
        return FuzzValidationOutcome::Rejected;
    };
    match toml::from_str::<Config>(input) {
        Ok(config) if config.validate().is_ok() => FuzzValidationOutcome::Accepted,
        Ok(_) | Err(_) => FuzzValidationOutcome::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_fuzz_adapters_classify_valid_invalid_and_oversized_inputs() {
        let valid_root_a_query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        assert_eq!(
            fuzz_doh_request(&valid_root_a_query),
            FuzzValidationOutcome::Accepted
        );
        assert_eq!(fuzz_doh_request(&[]), FuzzValidationOutcome::Rejected);
        assert_eq!(
            fuzz_config(include_bytes!("../config.dev.toml")),
            FuzzValidationOutcome::Accepted
        );
        assert_eq!(fuzz_config(&[0xff]), FuzzValidationOutcome::Rejected);
        assert_eq!(fuzz_pkarr_body(&[]), FuzzValidationOutcome::Rejected);

        assert_eq!(
            fuzz_doh_request(&vec![0; FUZZ_MAX_DOH_BYTES + 1]),
            FuzzValidationOutcome::TooLarge
        );
        assert_eq!(
            fuzz_config(&vec![0; FUZZ_MAX_CONFIG_BYTES + 1]),
            FuzzValidationOutcome::TooLarge
        );
        assert_eq!(
            fuzz_pkarr_body(&vec![0; FUZZ_MAX_PKARR_BYTES + 1]),
            FuzzValidationOutcome::TooLarge
        );
    }
}
