use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use iroh::SecretKey;
use iroh_relay::protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg};
use iroh_sim::{RelayEnvironment, RelayProtocolVersion, RelaySpec};
use n0_future::{SinkExt, StreamExt};

fn stage5_relay(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("relay benchmark runtime");

    let mut construction = c.benchmark_group("stage5_relay_construction");
    construction.bench_function("production_builder_connector_disabled", |b| {
        b.iter(|| black_box(iroh::endpoint::Builder::empty()));
    });
    construction.bench_function("bounded_relay_environment", |b| {
        b.iter_batched(
            relay_spec,
            |spec| black_box(RelayEnvironment::new(&[spec]).unwrap()),
            BatchSize::SmallInput,
        );
    });
    construction.finish();

    let mut session = c.benchmark_group("stage5_relay_session");
    session.bench_function("production_websocket_authentication", |b| {
        let environment = RelayEnvironment::new(&[relay_spec()]).unwrap();
        b.iter_batched(
            || SecretKey::from_bytes(&[7; 32]),
            |key| {
                runtime.block_on(async {
                    let client = environment
                        .connect_client("bench", key, None)
                        .await
                        .unwrap();
                    black_box(client);
                    environment.shutdown().await;
                });
            },
            BatchSize::SmallInput,
        );
    });
    session.finish();

    let payload = Datagrams::from(vec![0xa5; 1_200]);
    let environment = RelayEnvironment::new(&[relay_spec()]).unwrap();
    let (mut sender, mut receiver, sender_id, receiver_id) = runtime.block_on(async {
        let sender_key = SecretKey::from_bytes(&[8; 32]);
        let receiver_key = SecretKey::from_bytes(&[9; 32]);
        let sender_id = sender_key.public();
        let receiver_id = receiver_key.public();
        let sender = environment
            .connect_client("bench", sender_key, None)
            .await
            .unwrap();
        let receiver = environment
            .connect_client("bench", receiver_key, None)
            .await
            .unwrap();
        (sender, receiver, sender_id, receiver_id)
    });
    let mut routing = c.benchmark_group("stage5_relay_routing");
    routing.throughput(Throughput::Bytes(1_200));
    routing.bench_function("production_authenticated_datagram", |b| {
        b.iter(|| {
            runtime.block_on(async {
                sender
                    .send(ClientToRelayMsg::Datagrams {
                        dst_endpoint_id: receiver_id,
                        datagrams: payload.clone(),
                    })
                    .await
                    .unwrap();
                let received = receiver.next().await.unwrap().unwrap();
                assert!(matches!(
                    received,
                    RelayToClientMsg::Datagrams {
                        remote_endpoint_id,
                        ..
                    } if remote_endpoint_id == sender_id
                ));
                black_box(received);
            });
        });
    });
    routing.finish();
    runtime.block_on(environment.shutdown());
}

fn relay_spec() -> RelaySpec {
    RelaySpec {
        id: "bench".to_owned(),
        url: "https://bench.invalid".to_owned(),
        online: true,
        max_sessions: 8,
        byte_capacity: 256 * 1024,
        protocol_version: RelayProtocolVersion::V2,
    }
}

criterion_group!(benches, stage5_relay);
criterion_main!(benches);
