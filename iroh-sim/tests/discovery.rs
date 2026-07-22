use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use iroh::{SecretKey, address_lookup::AddressLookup};
use iroh_runtime::RootSeed;
use iroh_sim::{
    DeterministicDiscovery, Kernel, KernelConfig, KernelDriver, ResourceKind, TraceBuffer,
};
use n0_future::StreamExt;

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn delayed_failure_success_stale_suppression_and_expiry_are_ordered() {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 100,
            max_virtual_time: Duration::from_millis(20),
            max_tasks: 8,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let context = Arc::new(kernel.runtime_context(RootSeed::new([52; 32]), SystemTime::UNIX_EPOCH));
    let provider = DeterministicDiscovery::new("primary", 8, kernel.clone(), context).unwrap();
    let endpoint = SecretKey::from_bytes(&[7; 32]).public();
    provider
        .publish(
            "failure",
            "server",
            endpoint,
            Vec::new(),
            2_000_000,
            10_000_000,
            true,
        )
        .unwrap();
    provider
        .publish(
            "success",
            "server",
            endpoint,
            vec!["192.0.2.2:31002".parse().unwrap()],
            5_000_000,
            10_000_000,
            false,
        )
        .unwrap();
    provider
        .publish(
            "stale",
            "server",
            endpoint,
            vec!["192.0.2.99:31002".parse().unwrap()],
            10_000_000,
            5_000_000,
            false,
        )
        .unwrap();

    let mut stream = provider.resolve(endpoint).unwrap();
    let driver = KernelDriver::new(kernel.clone(), 100).unwrap();
    assert!(driver.drive(stream.next()).await.unwrap().unwrap().is_err());
    let item = driver.drive(stream.next()).await.unwrap().unwrap().unwrap();
    assert_eq!(
        item.endpoint_info().ip_addrs().copied().collect::<Vec<_>>(),
        vec!["192.0.2.2:31002".parse().unwrap()]
    );
    assert!(driver.drive(stream.next()).await.unwrap().is_none());
    assert!(provider.snapshots().is_empty());
    assert_eq!(kernel.ledger().current(ResourceKind::DiscoveryRecord), 0);

    let transitions = trace
        .events()
        .into_iter()
        .filter_map(|event| match event.event {
            iroh_runtime::TraceEventKind::DiscoveryRecord { transition, .. } => Some(transition),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(transitions.iter().any(|value| value == "resolved"));
    assert!(transitions.iter().any(|value| value == "stale_suppressed"));
    assert!(transitions.iter().any(|value| value == "expired"));
}

#[test]
fn withdrawal_cancels_expiry_and_releases_record_ownership() {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 10,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 1,
        },
        Arc::new(trace),
    )
    .unwrap();
    let context = Arc::new(kernel.runtime_context(RootSeed::new([53; 32]), SystemTime::UNIX_EPOCH));
    let provider = DeterministicDiscovery::new("primary", 1, kernel.clone(), context).unwrap();
    provider
        .publish(
            "server",
            "server",
            SecretKey::from_bytes(&[8; 32]).public(),
            vec!["192.0.2.2:31002".parse().unwrap()],
            0,
            1_000_000_000,
            false,
        )
        .unwrap();
    provider.withdraw("server", "server").unwrap();

    assert!(provider.snapshots().is_empty());
    assert_eq!(kernel.ledger().current(ResourceKind::DiscoveryRecord), 0);
    assert_eq!(
        kernel.run_until_idle().unwrap().virtual_time,
        Duration::ZERO
    );
}
