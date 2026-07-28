use std::str::FromStr;

use iroh::{EndpointAddr, PublicKey};
use iroh_blobs::{
    ALPN, BlobFormat, Hash, HashAndFormat,
    hashseq::HashSeq,
    protocol::{ChunkRanges, ChunkRangesExt, GetRequest, RangeSpec, Request},
    ticket::BlobTicket,
};

const HASH_HELLO: [u8; 32] = [
    0xea, 0x8f, 0x16, 0x3d, 0xb3, 0x86, 0x82, 0x92, 0x5e, 0x44, 0x91, 0xc5, 0xe5, 0x8d, 0x4b, 0xb3,
    0x50, 0x6e, 0xf8, 0xc1, 0x4e, 0xb7, 0x8a, 0x86, 0xe9, 0x08, 0xc5, 0x62, 0x4a, 0x67, 0x20, 0x0f,
];

#[test]
fn alpn_and_hash_vectors_are_stable() {
    assert_eq!(ALPN, b"/iroh-bytes/4");
    assert_eq!(Hash::new("hello").as_bytes(), &HASH_HELLO);
    assert_eq!(
        postcard::to_stdvec(&Hash::new("hello")).unwrap(),
        HASH_HELLO
    );

    let sequence: HashSeq = [Hash::from([0x11; 32]), Hash::from([0x22; 32])]
        .into_iter()
        .collect();
    let mut expected = vec![0x11; 32];
    expected.extend([0x22; 32]);
    assert_eq!(sequence.into_inner(), expected);
}

#[test]
fn request_and_range_vectors_are_stable() {
    let request = Request::from(GetRequest::blob(Hash::from([0xda; 32])));
    let mut expected = vec![0x00];
    expected.extend([0xda; 32]);
    expected.extend([0x02, 0x00, 0x01, 0x00, 0x01, 0x00]);
    assert_eq!(postcard::to_stdvec(&request).unwrap(), expected);

    let ranges = RangeSpec::new(&ChunkRanges::chunks(1..3) | &ChunkRanges::chunks(9..13));
    assert_eq!(postcard::to_stdvec(&ranges).unwrap(), [4, 1, 2, 6, 4]);
}

#[test]
fn ticket_and_hash_format_vectors_are_stable() {
    let hash =
        Hash::from_str("0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072").unwrap();
    let endpoint_id =
        PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
            .unwrap();
    let ticket = BlobTicket::new(EndpointAddr::new(endpoint_id), hash, BlobFormat::Raw);
    assert_eq!(
        ticket.to_string(),
        "blobacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaaaaafyju2y4tel43bymjvsdax7k5mbrotl2p2lsbdetff6ctftksqhe"
    );

    let hash_and_format = HashAndFormat::hash_seq(Hash::from([0x33; 32]));
    let mut expected = vec![0x33; 32];
    expected.push(1);
    assert_eq!(postcard::to_stdvec(&hash_and_format).unwrap(), expected);
}
