#![no_main]

use krikos_app::fuzz::fuzz_manifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _valid = fuzz_manifest(input);
});
