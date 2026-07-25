#![no_main]

use iroh_dns_server::test_utils::fuzz_doh_request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _outcome = fuzz_doh_request(input);
});
