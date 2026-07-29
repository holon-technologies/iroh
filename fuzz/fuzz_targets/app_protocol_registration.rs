#![no_main]

use iroh_app::fuzz::fuzz_protocol_registration;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _outcome = fuzz_protocol_registration(input);
});
