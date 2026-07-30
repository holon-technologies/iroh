#![no_main]

use krikos_blobs::ticket::BlobTicket;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _binary = BlobTicket::decode_bytes(input);
    if let Ok(text) = std::str::from_utf8(input) {
        let _text = BlobTicket::decode_string(text);
    }
});
