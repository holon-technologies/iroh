#![no_main]

use krikos_docs::DocTicket;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _binary = DocTicket::decode_bytes(input);
    if let Ok(text) = std::str::from_utf8(input) {
        let _text = DocTicket::decode_string(text);
    }
});
