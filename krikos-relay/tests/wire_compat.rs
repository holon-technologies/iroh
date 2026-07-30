//! Public relay compatibility constants pinned by `docs/relay-compatibility.md`.

use krikos_relay::{
    MAX_PACKET_SIZE,
    http::{CLIENT_AUTH_HEADER, ProtocolVersion, RELAY_PATH, RELAY_PROBE_PATH, X_IROH_ENDPOINT_ID},
    protos::{common::FrameType, relay::MAX_RESTART_DURATION_MILLIS},
};

#[test]
fn v1_v2_public_wire_registry_is_frozen() {
    assert_eq!(RELAY_PATH, "/relay");
    assert_eq!(RELAY_PROBE_PATH, "/ping");
    assert_eq!(CLIENT_AUTH_HEADER.as_str(), "x-iroh-relay-client-auth-v1");
    assert_eq!(X_IROH_ENDPOINT_ID, "X-Iroh-NodeId");
    assert_eq!(
        ProtocolVersion::ALL,
        &[ProtocolVersion::V2, ProtocolVersion::V1]
    );
    assert_eq!(ProtocolVersion::V1.to_str(), "iroh-relay-v1");
    assert_eq!(ProtocolVersion::V2.to_str(), "iroh-relay-v2");

    let tags = [
        (FrameType::ServerChallenge, 0),
        (FrameType::ClientAuth, 1),
        (FrameType::ServerConfirmsAuth, 2),
        (FrameType::ServerDeniesAuth, 3),
        (FrameType::ClientToRelayDatagram, 4),
        (FrameType::ClientToRelayDatagramBatch, 5),
        (FrameType::RelayToClientDatagram, 6),
        (FrameType::RelayToClientDatagramBatch, 7),
        (FrameType::EndpointGone, 8),
        (FrameType::Ping, 9),
        (FrameType::Pong, 10),
        (FrameType::Health, 11),
        (FrameType::Restarting, 12),
        (FrameType::Status, 13),
    ];
    for (frame, expected) in tags {
        assert_eq!(u32::from(frame), expected);
    }

    assert_eq!(MAX_PACKET_SIZE, 64 * 1024);
    assert_eq!(MAX_RESTART_DURATION_MILLIS, u64::from(u32::MAX));
}
