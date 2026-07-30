#![no_main]

use krikos_base::EndpointId;
use krikos_gossip::proto::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _message = postcard::from_bytes::<Message<EndpointId>>(input);
});
