# Stage 6 scheduler performance

Stage 6 adds a domain-separated `kernel/ready-task` draw for every kernel task poll, causal ready waves, fairness accounting, and a structured `task_scheduled` trace event. The Criterion benchmark in `iroh-sim/benches/stage6_scheduler.rs` measures the complete lifecycle of 256 immediately-ready tasks, including task admission, tracing, polling, completion, and final accounting.

## 2026-07-21 native baseline

Command:

```text
cargo bench -p iroh-sim --bench stage6_scheduler -- --sample-size 10
```

| Policy | Median time | Throughput |
| --- | ---: | ---: |
| FIFO component baseline | 5.473 ms | 46.78 K tasks/s |
| Seeded fair scheduler | 5.641 ms | 45.38 K tasks/s |

The measured median overhead is approximately 3.1% for this intentionally scheduler-heavy workload. Production scenario cost is dominated by QUIC, topology, and trace work, so this benchmark is the conservative micro-level comparison rather than a claim about end-to-end wall time. Nightly CI retains the full Criterion reports so regressions are compared against the runner and compiler actually used by the project.

The benchmark is bounded and performs no host networking. A run is valid only when all 256 tasks complete, the kernel reaches `Quiescence::Complete`, and the event count is returned to Criterion as an observed value.
