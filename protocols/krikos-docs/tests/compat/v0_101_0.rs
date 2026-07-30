use std::str::FromStr;

use krikos::{EndpointAddr, PublicKey};
use krikos_blobs::Hash;
use krikos_docs::{
    ALPN, Author, Capability, DocTicket, NamespaceId, NamespaceSecret, Record, SignedEntry,
    limits::MAX_PEERS_PER_DOCUMENT,
};

const SIGNED_ENTRY_HEX: &str = "4b523f1b6d9b00a4779fc9f8f105a9e36f062ceb7d511b632905782042ad30acb6dd07bfced4ecd5f3aa58321e8ace63f48f988ed8461bfdcd8b0e902187a10e228ddc6998329b7faa64875fe80da36406ea8d87e3e57bb048323e9cb66c0b343b60c4e709fb978b878e37d0c362edfc06c8cdc774c8b29d94e48eaa06cca60f5055154f42065ea5a1bea05463826be2684eb92df92c100027aabaae57ca554207bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5776972652d666f726d61742d7465737400af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f32628080f9c0c1c48203";

#[test]
fn alpn_and_ticket_vectors_are_stable() {
    assert_eq!(ALPN, b"/iroh-sync/1");

    let endpoint_id =
        PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
            .unwrap();
    let namespace_id = NamespaceId::from(endpoint_id.as_bytes());
    let ticket = DocTicket::new(
        Capability::Read(namespace_id),
        vec![EndpointAddr::new(endpoint_id)],
    );
    let encoded = ticket.to_string();
    assert_eq!(
        encoded,
        "docaaa24wh7razsigwifvx7oyiqi3wwpnihfukcywenabr6sqwzu5kqfnqbvzmp7cbteqnmqllp65qrarxnm62qoliufrmi2add5fbntj2vak3aa"
    );

    let decoded = DocTicket::from_str(&encoded).unwrap();
    assert_eq!(decoded.capability.id(), namespace_id);
    assert_eq!(decoded.nodes.len(), 1);
    assert_eq!(decoded.nodes[0].id, endpoint_id);
}

#[test]
fn ticket_peer_limit_is_enforced() {
    let endpoint_id =
        PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
            .unwrap();
    let namespace_id = NamespaceId::from(endpoint_id.as_bytes());
    let peers = vec![EndpointAddr::new(endpoint_id); MAX_PEERS_PER_DOCUMENT + 1];
    let error = DocTicket::try_new(Capability::Read(namespace_id), peers).unwrap_err();
    assert!(error.to_string().contains("ticket peers"));
}

#[test]
fn signed_entry_vector_is_stable() {
    let author = Author::from_bytes(&[0xa1; 32]);
    let namespace = NamespaceSecret::from_bytes(&[0xb2; 32]);
    let record = Record::new(Hash::EMPTY, 0, 1_700_000_000_000_000u64);
    let signed = SignedEntry::from_parts(&namespace, &author, b"wire-format-test", record);

    let bytes = postcard::to_stdvec(&signed).unwrap();
    assert_eq!(hex::encode(&bytes), SIGNED_ENTRY_HEX);
    assert_eq!(postcard::from_bytes::<SignedEntry>(&bytes).unwrap(), signed);
}
