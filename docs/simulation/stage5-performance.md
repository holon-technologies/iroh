# Stage 5 relay performance

Stage 5 adds an optional relay-connector branch to the production relay actor and a test-only
in-memory transport for production relay protocol sessions. The durable Criterion target is:

```bash
cargo bench -p iroh-sim --bench stage5_relay
```

It measures four distinct costs:

| Benchmark | Boundary measured |
|---|---|
| `production_builder_connector_disabled` | Normal endpoint construction with no simulation connector installed |
| `bounded_relay_environment` | Simulator ownership and production relay registry construction |
| `production_websocket_authentication` | Production WebSocket framing, challenge/signature authentication, authorization, server actor registration, and shutdown over an in-memory byte pipe |
| `production_authenticated_datagram` | Production client framing, server routing/registry lookup, and receiving-client framing for a 1,200-byte payload |

The connector-disabled benchmark is the production guardrail. The production branch remains the
existing `ClientBuilder::connect` call and no connector trait dispatch occurs unless a simulation
environment explicitly installs one. The in-memory measurements are simulator throughput
baselines; they do not replace the native network relay benchmarks because they intentionally omit
DNS, TCP, TLS, HTTP upgrade, kernel scheduling, and network latency.

Nightly CI retains the full Criterion reports. Performance review should compare reports from
equivalent hardware and confirm correctness suites before accepting a change. A faster number is
not useful if authentication, duplicate-identity handling, routing isolation, lifecycle ownership,
or cleanup coverage has been bypassed.

## 2026-07-21 closeout sample

The Stage 7 closeout reran the target in the development container with the optimized benchmark
profile and 100 Criterion samples:

| Benchmark | Observed interval |
|---|---:|
| connector-disabled builder | 127.73–128.64 ns |
| bounded relay environment | 3.8042–4.6372 µs |
| production WebSocket authentication | 1.1950–1.2036 ms |
| authenticated 1,200-byte datagram | 2.5367–2.5455 µs, 449.59–451.14 MiB/s |

These values are characterization evidence, not portable thresholds. Criterion raw reports under
`target/criterion` remain the source for same-runner/base-revision comparisons.
