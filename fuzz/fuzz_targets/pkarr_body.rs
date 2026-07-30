#![no_main]

use krikos_dns_server::test_utils::fuzz_pkarr_body;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _outcome = fuzz_pkarr_body(input);
});
