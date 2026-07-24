# Production Resource Canary Evidence

**Date:** 2026-07-24  
**Result:** Passed  
**Source revision:** `fce2f1eb3f29c30b18a06b3b63022bb924b46ba1`  
**Manifest SHA-256:** `f469ea3b02302da95981c41e16b142c78d311af3c2c815dd5b8db81e1c9d5537`

## Evidence Qualification

The feature-gated `iroh-bench` canary ran from a clean optimized release build on the documented
minimum host class. The report identifies itself as production evidence and records:

- `mode: evidence`;
- `evidence: true`;
- `release_build: true`;
- `source_clean: true`;
- `all_lanes: true`;
- 100% workload scale;
- exact 30-second warm-up, 300-second measurement, and 30-second cooldown phases; and
- an absolute one-second sample interval.

The command was:

```text
target/release/resource-canary run --lane all --scale-percent 100 \
  --warmup-seconds 30 --measurement-seconds 300 --cooldown-seconds 30 \
  --sample-interval-seconds 1 --baseline-seconds 5
```

The retained [run report](resource-canary/2026-07-24/run.json), [preflight report](resource-canary/2026-07-24/preflight.json),
and [manifest](resource-canary/2026-07-24/manifest.json) are immutable copies of the finalized
artifact.

## Host

| Property | Observed |
| --- | ---: |
| Platform | Linux x86-64, kernel 6.8.0-136-generic |
| CPU | AMD Ryzen 7 8845HS, 8 online cores |
| Visible memory | 33,654,890,496 bytes |
| Available memory before load | 31,706,284,032 bytes |
| Effective descriptor limit | 1,048,576 |
| Free artifact storage | 120,654,807,040 bytes |
| Idle baseline CPU | 1.62% |
| Largest competitor CPU | 0.17% |
| Largest competitor RSS | 289,890,304 bytes |

Preflight passed every static minimum and contamination threshold.

## Resource Results

| Lane | Samples (warm/measure/cool) | Peak CPU | Peak RSS | Peak FDs | Shutdown |
| --- | ---: | ---: | ---: | ---: | ---: |
| DNS | 30 / 300 / 30 | 15.40% | 51,785,728 B (0.154%) | 2,063 (0.197%) | 12,163 ms |
| Relay | 30 / 300 / 30 | 8.78% | 278,056,960 B (0.826%) | 10,479 (0.999%) | 55 ms |
| Endpoint | 30 / 300 / 30 | 57.46% | 531,341,312 B (1.579%) | 14 (0.001%) | 124 ms |

Every lane retained more than 30% CPU, memory, and descriptor headroom and shut down inside the
20-second deadline.

## Admission and Continuity Results

### DNS

- UDP: 2,048 offered at 1,000/s; exactly 1,024 completed and 1,024 were rejected by the production
  admission limit. Achieved rate was 999.401/s.
- TCP: 512 offered; exactly 256 active and 256 rejected.
- HTTP connections: 1,024 offered at 400/s; exactly 512 active and 512 initial capacity
  rejections. Achieved rate was 399.821/s.
- HTTP requests: 2,048 offered; exactly 1,024 admitted and 1,024 rejected.
- Timed continuity: 357 successful UDP operations, 357 HTTP-connection rejections, and 357
  HTTP-request rejections.
- Store background failures: zero. Post-release admission recovered.

### Relay

- Pending establishment overload produced bounded rejection.
- Sessions: 8,192 offered; exactly 4,096 retained and 4,096 rejected.
- Session high-water: exactly 4,096.
- Rejection classification: one per-identity rejection, 2,804 global-capacity rejections, and
  1,651 rate rejections for setup plus timed continuity.
- Fill achieved 199.993/s against 200/s; overload achieved 399.929/s against 400/s.
- Timed continuity: 360 successful pings and 360 rejected excess sessions with no client timeout.
- Post-release admission recovered.

### Endpoint

- Connections: 4,096 offered; exactly 2,048 accepted and 2,048 rejected.
- Timed continuity: 330 successful replacement operations and 330 overload rejections.
- Client and server task high-water: 2,051 of 4,096, leaving 49.93% task headroom; no task
  rejection or exhausted counter.
- Noq client/server packet-event, packet-byte, connection, and control-event rejections: zero.
- Largest per-connection packet-event depth: 6 of 32.
- Largest endpoint packet-byte depth: 3,692 of 67,108,864 bytes.
- Largest endpoint control-event depth: 9 of 4,096.
- Post-release admission recovered.

## Integrity

The artifact directory and every retained file are read-only. `manifest.sha256` verifies
`manifest.json`; the manifest records the byte length and SHA-256 digest of every preflight,
partial report, final report, and sample stream. The manifest digest printed by the canary matches
the retained file:

```text
f469ea3b02302da95981c41e16b142c78d311af3c2c815dd5b8db81e1c9d5537
```

This evidence closes the production-host 2x capacity follow-up. It does not authorize increasing
any production default; a proposed increase must repeat the profile at twice the proposed value.
