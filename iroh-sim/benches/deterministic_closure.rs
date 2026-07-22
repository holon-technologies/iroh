use std::{hint::black_box, sync::Arc, time::Duration};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use iroh::simulation::SimulationCryptoMode;
use iroh_runtime::{ClockSleep, NoopTraceSink, RootSeed};
use iroh_sim::{
    IpFamily, Kernel, KernelConfig, KernelDriver, ScenarioBuilder, ScenarioOperation,
    ScenarioRunner, SwarmTemplate,
};

fn deterministic_closure(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("deterministic-closure benchmark runtime");

    let template = SwarmTemplate::from_json(include_bytes!("../swarms/direct-smoke.json"))
        .unwrap()
        .resolve(&[])
        .unwrap();
    c.bench_function("deterministic_closure/swarm_materialization", |b| {
        let mut ordinal = 0u64;
        b.iter(|| {
            ordinal = ordinal
                .checked_add(1)
                .expect("criterion iteration count fits in u64");
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&ordinal.to_le_bytes());
            black_box(template.materialize(RootSeed::new(seed)).unwrap());
        });
    });

    c.bench_function("deterministic_closure/root_driver_ready", |b| {
        b.iter_batched(
            kernel_driver,
            |driver| black_box(runtime.block_on(driver.drive(async { 1u64 })).unwrap()),
            BatchSize::SmallInput,
        );
    });

    c.bench_function("deterministic_closure/injected_timer", |b| {
        b.iter_batched(
            || {
                let (kernel, driver) = kernel_driver_parts();
                let context = kernel
                    .runtime_context(RootSeed::new([0x51; 32]), std::time::SystemTime::UNIX_EPOCH);
                let sleep = ClockSleep::after(context.clock(), Duration::from_nanos(1)).unwrap();
                (driver, sleep)
            },
            |(driver, sleep)| {
                runtime.block_on(driver.drive(sleep)).unwrap().unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    let scenario = ScenarioBuilder::direct_ip_echo(
        "bench/deterministic-tls-handshake",
        IpFamily::Ipv4,
        ScenarioOperation::Stream,
    )
    .unwrap()
    .build()
    .unwrap();
    for (name, mode) in [
        (
            "deterministic_test",
            SimulationCryptoMode::DeterministicTest,
        ),
        (
            "production_provider",
            SimulationCryptoMode::ProductionProvider,
        ),
    ] {
        c.bench_function(
            &format!("deterministic_closure/tls_scenario_handshake/{name}"),
            |b| {
                b.iter_batched(
                    || scenario.clone(),
                    |scenario| {
                        let runner = ScenarioRunner::with_crypto_mode(
                            scenario,
                            RootSeed::new([0x71; 32]),
                            std::time::SystemTime::UNIX_EPOCH,
                            Arc::new(NoopTraceSink),
                            mode,
                        )
                        .unwrap();
                        black_box(runtime.block_on(runner.run()).unwrap());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn kernel_driver() -> KernelDriver {
    kernel_driver_parts().1
}

fn kernel_driver_parts() -> (Kernel, KernelDriver) {
    let kernel = Kernel::new(
        KernelConfig {
            max_events: 64,
            max_virtual_time: Duration::from_secs(1),
            max_tasks: 8,
        },
        Arc::new(NoopTraceSink),
    )
    .unwrap();
    let driver = KernelDriver::new(kernel.clone(), 64).unwrap();
    (kernel, driver)
}

criterion_group!(benches, deterministic_closure);
criterion_main!(benches);
