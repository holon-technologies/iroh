use iroh::SecretKey;
use iroh_relay::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};
use iroh_sim::{
    RelayAdmissionDecision, RelayEnvironment, RelayImpairmentSpec, RelayProtocolVersion,
    RelayRouteDecision, RelayRoutingOracle, RelaySpec,
};
use n0_future::{SinkExt, StreamExt};

fn relay(id: &str, url: &str) -> RelaySpec {
    RelaySpec {
        id: id.to_owned(),
        url: url.to_owned(),
        online: true,
        max_sessions: 4,
        byte_capacity: 64 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    }
}

#[tokio::test]
async fn production_sessions_route_only_within_the_selected_relay() {
    let environment = RelayEnvironment::new(&[
        relay("r1", "https://r1.invalid"),
        relay("r2", "https://r2.invalid"),
    ])
    .unwrap();
    let a_key = SecretKey::from_bytes(&[11; 32]);
    let b_key = SecretKey::from_bytes(&[12; 32]);
    let c_key = SecretKey::from_bytes(&[13; 32]);
    let a_id = a_key.public();
    let b_id = b_key.public();
    let mut a = environment.connect_client("r1", a_key, None).await.unwrap();
    let mut b = environment.connect_client("r1", b_key, None).await.unwrap();
    let c_id = c_key.public();
    let _c = environment.connect_client("r2", c_key, None).await.unwrap();
    let mut oracle = RelayRoutingOracle::new(&[
        relay("r1", "https://r1.invalid"),
        relay("r2", "https://r2.invalid"),
    ])
    .unwrap();
    assert_eq!(
        oracle.connect("r1", &a_id.to_string()),
        RelayAdmissionDecision::Accepted
    );
    assert_eq!(
        oracle.connect("r1", &b_id.to_string()),
        RelayAdmissionDecision::Accepted
    );
    assert_eq!(
        oracle.connect("r2", &c_id.to_string()),
        RelayAdmissionDecision::Accepted
    );
    assert_eq!(
        oracle.route("r1", &a_id.to_string(), &b_id.to_string()),
        RelayRouteDecision::Routed
    );

    let payload = Datagrams::from(b"relay identity boundary");
    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: b_id,
        datagrams: payload.clone(),
    })
    .await
    .unwrap();
    assert_eq!(
        b.next().await.unwrap().unwrap(),
        RelayToClientMsg::Datagrams {
            remote_endpoint_id: a_id,
            datagrams: payload,
        }
    );

    assert_eq!(
        oracle.route("r1", &a_id.to_string(), &c_id.to_string()),
        RelayRouteDecision::UnknownDestination
    );
    let forwarded = environment.forwarded_packets();
    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: c_id,
        datagrams: Datagrams::from(b"must not cross relays"),
    })
    .await
    .unwrap();
    let ping = [14; 8];
    a.send(ClientToRelayMsg::Ping(ping)).await.unwrap();
    assert_eq!(
        a.next().await.unwrap().unwrap(),
        RelayToClientMsg::Pong(ping)
    );
    assert_eq!(environment.forwarded_packets(), forwarded);

    environment.shutdown().await;
    assert_eq!(environment.session_count("r1").unwrap(), 0);
    assert_eq!(environment.session_count("r2").unwrap(), 0);
}

#[tokio::test]
async fn outage_closes_old_sessions_and_restart_accepts_new_generation() {
    let environment = RelayEnvironment::new(&[relay("home", "https://home.invalid")]).unwrap();
    let key = SecretKey::from_bytes(&[21; 32]);
    let mut old = environment
        .connect_client("home", key.clone(), None)
        .await
        .unwrap();
    assert_eq!(environment.generation("home").unwrap(), 0);

    environment.set_online("home", false).await.unwrap();
    let mut oracle = RelayRoutingOracle::new(&[relay("home", "https://home.invalid")]).unwrap();
    assert_eq!(
        oracle.connect("home", "endpoint"),
        RelayAdmissionDecision::Accepted
    );
    assert_eq!(
        oracle.set_online("home", false),
        RelayAdmissionDecision::Accepted
    );
    assert_eq!(
        oracle.route("home", "endpoint", "endpoint"),
        RelayRouteDecision::Offline
    );
    assert!(old.next().await.is_none());
    assert!(
        environment
            .connect_client("home", key.clone(), None)
            .await
            .is_err()
    );

    environment.set_online("home", true).await.unwrap();
    assert_eq!(
        oracle.set_online("home", true),
        RelayAdmissionDecision::Accepted
    );
    assert_eq!(environment.generation("home").unwrap(), 1);
    let _new = environment.connect_client("home", key, None).await.unwrap();
    assert_eq!(environment.session_count("home").unwrap(), 1);

    environment.shutdown().await;
}

#[tokio::test]
async fn bounded_relay_rejects_overload_before_authentication() {
    let mut spec = relay("small", "https://small.invalid");
    spec.max_sessions = 1;
    let environment = RelayEnvironment::new(&[spec.clone()]).unwrap();
    let mut oracle = RelayRoutingOracle::new(&[spec]).unwrap();
    assert_eq!(
        oracle.connect("small", "first"),
        RelayAdmissionDecision::Accepted
    );
    let _first = environment
        .connect_client("small", SecretKey::from_bytes(&[31; 32]), None)
        .await
        .unwrap();
    let error = environment
        .connect_client("small", SecretKey::from_bytes(&[32; 32]), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("capacity"));
    assert_eq!(
        oracle.connect("small", "second"),
        RelayAdmissionDecision::Capacity
    );
    environment.shutdown().await;
}

#[test]
fn pure_oracle_inventory_is_stably_ordered() {
    let mut oracle = RelayRoutingOracle::new(&[relay("r", "https://r.invalid")]).unwrap();
    for endpoint in ["zeta", "alpha", "middle"] {
        assert_eq!(
            oracle.connect("r", endpoint),
            RelayAdmissionDecision::Accepted
        );
    }
    assert_eq!(oracle.sessions("r").unwrap(), ["alpha", "middle", "zeta"]);
}

#[tokio::test(start_paused = true)]
async fn deterministic_connection_impairment_delays_and_rejects_selected_attempts() {
    let spec = relay("impaired", "https://impaired.invalid");
    let environment = RelayEnvironment::new_with_impairments(
        &[spec],
        &[RelayImpairmentSpec {
            relay: "impaired".to_owned(),
            connection_delay_nanos: 5_000_000,
            reject_connect_attempts: vec![1],
            drop_every_nth_packet: None,
            ..RelayImpairmentSpec::default()
        }],
    )
    .unwrap();
    let started = tokio::time::Instant::now();
    let error = environment
        .connect_client("impaired", SecretKey::from_bytes(&[41; 32]), None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("attempt 1"));
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(5));

    let _client = environment
        .connect_client("impaired", SecretKey::from_bytes(&[42; 32]), None)
        .await
        .unwrap();
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(10));
    let coverage = environment.coverage();
    assert_eq!(coverage["impaired"].connect_attempts, 2);
    assert_eq!(coverage["impaired"].authenticated_sessions, 1);
    environment.shutdown().await;
}

#[tokio::test]
async fn deterministic_frame_impairment_drops_only_the_selected_production_route() {
    let spec = relay("lossy", "https://lossy.invalid");
    let environment = RelayEnvironment::new_with_impairments(
        &[spec],
        &[RelayImpairmentSpec {
            relay: "lossy".to_owned(),
            connection_delay_nanos: 0,
            reject_connect_attempts: Vec::new(),
            drop_every_nth_packet: Some(2),
            ..RelayImpairmentSpec::default()
        }],
    )
    .unwrap();
    let a_key = SecretKey::from_bytes(&[43; 32]);
    let b_key = SecretKey::from_bytes(&[44; 32]);
    let a_id = a_key.public();
    let b_id = b_key.public();
    let mut a = environment
        .connect_client("lossy", a_key, None)
        .await
        .unwrap();
    let mut b = environment
        .connect_client("lossy", b_key, None)
        .await
        .unwrap();

    let first = Datagrams::from(b"first route");
    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: b_id,
        datagrams: first.clone(),
    })
    .await
    .unwrap();
    assert_eq!(
        b.next().await.unwrap().unwrap(),
        RelayToClientMsg::Datagrams {
            remote_endpoint_id: a_id,
            datagrams: first,
        }
    );

    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: b_id,
        datagrams: Datagrams::from(b"dropped route"),
    })
    .await
    .unwrap();
    let ping = [45; 8];
    a.send(ClientToRelayMsg::Ping(ping)).await.unwrap();
    assert_eq!(
        a.next().await.unwrap().unwrap(),
        RelayToClientMsg::Pong(ping)
    );
    let coverage = environment.coverage();
    assert_eq!(coverage["lossy"].forwarded_packets, 1);
    assert_eq!(coverage["lossy"].dropped_packets, 1);

    let third = Datagrams::from(b"third route");
    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: b_id,
        datagrams: third.clone(),
    })
    .await
    .unwrap();
    assert_eq!(
        b.next().await.unwrap().unwrap(),
        RelayToClientMsg::Datagrams {
            remote_endpoint_id: a_id,
            datagrams: third,
        }
    );
    environment.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn production_relay_rate_limit_applies_deterministically_to_client_frames() {
    let spec = relay("limited", "https://limited.invalid");
    let environment = RelayEnvironment::new_with_impairments(
        &[spec],
        &[RelayImpairmentSpec {
            relay: "limited".to_owned(),
            client_rx_bytes_per_second: Some(1_024),
            client_rx_max_burst_bytes: Some(1_024),
            ..RelayImpairmentSpec::default()
        }],
    )
    .unwrap();
    let a_key = SecretKey::from_bytes(&[46; 32]);
    let b_key = SecretKey::from_bytes(&[47; 32]);
    let a_id = a_key.public();
    let b_id = b_key.public();
    let mut a = environment
        .connect_client("limited", a_key, None)
        .await
        .unwrap();
    let mut b = environment
        .connect_client("limited", b_key, None)
        .await
        .unwrap();

    let payload = Datagrams::from(vec![0x5a; 2_048]);
    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: b_id,
        datagrams: payload.clone(),
    })
    .await
    .unwrap();
    assert_eq!(
        b.next().await.unwrap().unwrap(),
        RelayToClientMsg::Datagrams {
            remote_endpoint_id: a_id,
            datagrams: payload,
        }
    );
    let second = Datagrams::from(b"rate-limited-next-frame");
    let started = tokio::time::Instant::now();
    a.send(ClientToRelayMsg::Datagrams {
        dst_endpoint_id: b_id,
        datagrams: second.clone(),
    })
    .await
    .unwrap();
    assert_eq!(
        b.next().await.unwrap().unwrap(),
        RelayToClientMsg::Datagrams {
            remote_endpoint_id: a_id,
            datagrams: second,
        }
    );
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(1),
        "rate-limited elapsed={:?}",
        started.elapsed()
    );
    environment.shutdown().await;
}
