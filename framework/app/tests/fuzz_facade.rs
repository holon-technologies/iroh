#![cfg(feature = "fuzzing")]

use krikos_app::fuzz::{fuzz_manifest, fuzz_protocol_registration};

#[test]
fn manifest_fuzz_facade_uses_production_validation() {
    assert!(fuzz_manifest(
        br#"{"schema_version":1,"framework":"krikos-app"}"#
    ));
    assert!(!fuzz_manifest(
        br#"{"schema_version":2,"framework":"krikos-app"}"#
    ));
    assert!(!fuzz_manifest(&vec![b'x'; 64 * 1024 + 1]));
}

#[test]
fn protocol_registration_fuzz_facade_is_bounded() {
    let outcome = fuzz_protocol_registration(&vec![b'a'; 128 * 1024]);
    assert!(outcome.attempted <= 32);
    assert!(outcome.accepted <= outcome.attempted);
}
