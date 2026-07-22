# Stage 4 environment performance

The Stage 4 microbenchmarks are durable Criterion targets, not correctness tests. Run them with:

```bash
cargo bench -p iroh-sim --bench stage4_environment
```

They measure one hot operation at a time with structured tracing disabled through
`NoopTraceSink`. The scheduled nightly job retains Criterion reports so regressions can be compared
across revisions.

## 2026-07-21 reference measurement

The implementation-exit measurement below used an optimized local Linux x86-64 build and
Criterion's quick profile. Ranges are indicative; the retained nightly reports are the review
source for statistically significant changes.

| Operation | Time per operation | Throughput |
|---|---:|---:|
| Existing endpoint-independent NAT mapping translation/reuse | 797–800 ns | 1.25 M operations/s |
| One ordered stateful firewall allow decision | 165.3–165.5 ns | 6.04 M operations/s |
| Replace then withdraw one bounded discovery record | 840–854 ns | 1.17–1.19 M cycles/s |
| Production endpoint builder with all simulation hooks disabled (the normal default) | 132–134 ns | 7.46–7.60 M builders/s |
| Production endpoint builder with port mapping explicitly disabled | 147.7–148.1 ns | 6.75–6.77 M builders/s |

The production-default benchmark is the disabled simulation-path guardrail: normal builders keep
the runtime/socket/monitor/port-mapper/crypto simulation fields as `None` and allocate no simulator
object. It does not claim that a builder microbenchmark represents established-connection packet
throughput. Existing endpoint, Noq, and relay benchmarks remain authoritative for that data plane.

Review a regression only after rerunning the full Criterion profile on comparable hardware. NAT,
firewall, or discovery optimizations must retain stable trace semantics and resource ownership;
the benchmark is not permission to remove those correctness properties.
