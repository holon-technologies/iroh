# Stage 1 Performance Sample

This is a non-gating smoke baseline captured on 2026-07-21 while implementing Stage 1. It proves the existing release benchmark remains runnable through the new production runtime adapters; a single local sample is not a statistically valid regression threshold.

## Environment

- Source base: `f2eb930dda`; dirty implementation worktree status digest at capture: `4ce814314876aaf17e686306c19c9df6199b4454321d684ffe6219e699d111ad`
- OS: Ubuntu Linux, kernel `6.8.0-134-generic`, x86-64
- CPU allocation: 4 cores, AMD Ryzen 7 8845HS
- Memory: 22 GiB
- Build: Cargo release profile, default `iroh-bench` features unless noted

## Direct IP sample

```bash
cargo run --release -p iroh-bench --bin bulk -- \
  iroh --download-size 16M --streams 4 --max_streams 4
```

- Connection: 7.42 ms
- Aggregate: 64 MiB in 90.60 ms, 706.42 MiB/s
- Per-stream median: 178.62 MiB/s, 89 ms

## Local relay-only sample

The first attempt found a pre-existing benchmark-harness assumption: `--only-relay` clears IP transports, but the harness indexed the first bound IP socket. The harness now adds a direct address only when one exists, allowing the documented relay-only mode to run.

```bash
cargo run --release -p iroh-bench --bin bulk --features local-relay -- \
  iroh --download-size 4M --streams 2 --max_streams 2 --only-relay
```

- Connection: 252.55 ms
- Aggregate: 8 MiB in 117.20 ms, 68.26 MiB/s
- Per-stream median: 34.47 MiB/s, 115 ms

Both samples printed the benchmark's existing “Endpoint dropped without calling `Endpoint::close`” server teardown diagnostic. That harness cleanup issue is retained as follow-up evidence and is not attributed to the runtime capability path.

## Interpretation

No pass/fail threshold is established from these observations. A performance gate needs repeated samples on a stable runner, raw artifact retention, confidence intervals, and direct comparison with a clean base-revision build using identical commands and feature sets. Connection-establishment, packet throughput, and local relay paths are represented here; future benchmark work should separate endpoint construction and steady-state relay-server measurements.

## Stage 2 direct-IP comparison

The exact direct-IP command above was rerun after the Stage 2 injected socket boundary was in
place. One build-and-run sample and three immediately repeated executions produced aggregate
throughput of 571.36, 678.35, 559.10, and 771.15 MiB/s. The four-sample median was 624.86 MiB/s,
with connection times between 8.04 and 9.94 ms. The earlier single Stage 1 observation was
706.42 MiB/s and 7.42 ms.

The spread within the Stage 2 samples is larger than their median difference from the lone Stage
1 sample, so this evidence does not establish a regression. It does establish that the normal OS
socket/default-builder path remains functional after capability injection. A defensible gate still
requires interleaved clean-base and candidate trials on an isolated runner. The existing endpoint
teardown diagnostic appeared in every sample and remains a benchmark-harness issue.
