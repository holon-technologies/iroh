use std::{
    future::pending,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};

use iroh::dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData};
use iroh_runtime::RootSeed;
use iroh_sim::{
    DeterministicDnsRuntime, Kernel, KernelConfig, KernelDriver, TraceBuffer, normalized_trace_json,
};
use n0_error::AnyError;
use n0_future::boxed::BoxFuture;

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn seeded_stagger_retries_and_virtual_timeout_are_replay_stable() {
    let first = run_stagger([55; 32]).await;
    let second = run_stagger([55; 32]).await;
    assert_eq!(first, second);
    assert!((8_000_000..=24_000_000).contains(&first.0));
}

async fn run_stagger(seed: [u8; 32]) -> (u64, Vec<Vec<u8>>) {
    let (kernel, trace, runtime) = fixture(seed);
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = DnsResolver::custom_with_runtime(
        ScriptedResolver {
            calls: calls.clone(),
        },
        runtime.clone(),
    );
    let driver = KernelDriver::new(kernel.clone(), 100).unwrap();
    let addresses = driver
        .drive(resolver.lookup_ipv4_staggered("peer.invalid", Duration::from_millis(50), &[10, 20]))
        .await
        .unwrap()
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(
        addresses,
        vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 55))]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(runtime.take_error().is_none());
    (
        kernel.now().as_nanos().try_into().unwrap(),
        trace
            .events()
            .iter()
            .map(|event| normalized_trace_json(event).unwrap())
            .collect(),
    )
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn hanging_dns_query_times_out_on_kernel_virtual_time() {
    let (kernel, _trace, runtime) = fixture([56; 32]);
    let resolver = DnsResolver::custom_with_runtime(HangingResolver, runtime.clone());
    let driver = KernelDriver::new(kernel.clone(), 100).unwrap();
    let result = driver
        .drive(resolver.lookup_ipv4("peer.invalid", Duration::from_millis(5)))
        .await
        .unwrap();
    let error = match result {
        Ok(_) => panic!("hanging lookup unexpectedly succeeded"),
        Err(error) => error,
    };

    assert!(matches!(error, DnsError::Timeout { .. }));
    assert_eq!(kernel.now(), Duration::from_millis(5));
    assert!(runtime.take_error().is_none());
}

fn fixture(seed: [u8; 32]) -> (Kernel, TraceBuffer, DeterministicDnsRuntime) {
    let trace = TraceBuffer::default();
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 100,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 8,
        },
        Arc::new(trace.clone()),
    )
    .unwrap();
    let context = kernel.runtime_context(RootSeed::new(seed), SystemTime::UNIX_EPOCH);
    let runtime = DeterministicDnsRuntime::new(
        kernel.clone(),
        context.decisions().stream("dns/stagger").unwrap(),
    );
    (kernel, trace, runtime)
}

#[derive(Clone, Debug)]
struct ScriptedResolver {
    calls: Arc<AtomicUsize>,
}

impl Resolver for ScriptedResolver {
    fn lookup_ipv4(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if call < 2 {
                Err(dns_error())
            } else {
                Ok(Box::new([Ipv4Addr::new(192, 0, 2, 55)].into_iter()) as BoxIter<_>)
            }
        })
    }

    fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async { Err(dns_error()) })
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        Box::pin(async { Err(dns_error()) })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}

fn dns_error() -> DnsError {
    DnsError::from(AnyError::from_std(std::io::Error::other(
        "scripted DNS miss",
    )))
}

#[derive(Clone, Debug)]
struct HangingResolver;

impl Resolver for HangingResolver {
    fn lookup_ipv4(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(pending())
    }

    fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(pending())
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        Box::pin(pending())
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}
