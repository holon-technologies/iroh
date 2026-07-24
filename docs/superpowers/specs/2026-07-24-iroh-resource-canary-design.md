# Iroh Production Resource Canary Design

**Date:** 2026-07-24

## Goal

Produce reproducible, retained evidence that the finite DNS-server, relay, and endpoint defaults
remain bounded at twice their configured offered load while preserving at least 30% CPU, memory,
file-descriptor, task, and queue headroom. The canary must fail closed when the host baseline is
contaminated and must never send traffic outside loopback.

This evidence is required before any production capacity default is raised. The canary does not
raise defaults, benchmark Internet paths, or replace the deterministic and saturation tests already
in the workspace.

## Host Profile and Preconditions

The initial documented minimum host profile is Linux x86-64 with:

- 8 online CPU cores;
- at least 30 GiB of visible memory;
- an effective open-file limit of at least 8,192;
- at least 20 GiB of free artifact/build storage; and
- no competing process using 20% or more of total CPU or memory.

The harness records the kernel, CPU model, source revision, visible memory, file limit, load,
storage, and the largest competing processes. It samples an idle baseline before load and refuses
to run if CPU use exceeds 20%, available memory is below 70%, or the static host requirements are
not met. Historical swap occupancy is recorded but is not alone a failure; active host pressure is
represented by available memory and sampled CPU.

The host profile is an evidence qualification, not a universal support promise. Runs may reduce
load or duration for smoke diagnosis, but they still require this host minimum and cannot be
classified as production evidence.

## Workload Model

The canary is a feature-gated `iroh-bench` binary. It runs three independent loopback lanes so a
failure is attributable to one ownership boundary.

1. **DNS ingress:** offers 2,048 UDP requests at 1,000 requests per second, 512 DNS TCP
   connections, 1,024 HTTP connections, 2,048 HTTP requests, and 400 new HTTP connections per
   second. These are twice the current production defaults. The first 1,024 UDP requests are held
   after the unchanged Hickory admission semaphore admits them; the remaining requests traverse
   its rejection path. DNS and HTTP requests use fixed, bounded messages and a local persistent
   store with mainline fallback disabled. UDP and HTTP/2 saturation use feature-gated reserved
   test requests that hold admitted work while exercising the unchanged production admission
   middleware; these controls are absent from normal builds.
2. **Relay admission:** offers 512 pending establishments, 8,192 authenticated sessions, and 400
   new connections per second against the production relay protocol. Fill is paced at the
   production 200-connection-per-second rate and overload is paced at twice that rate. Endpoint
   identities are deterministically derived and no identity offers more than four sessions.
   Bounded client-driver tasks answer relay keepalive pings so every admitted session remains
   active throughout fill, overload, and measurement.
3. **Endpoint admission:** offers 4,096 direct loopback QUIC connections against the default 2,048
   connection ceiling. The accepted connections remain open during measurement, while rejected
   attempts are counted and drained.

Production counts are derived from the service default configuration at build time, doubled with
checked arithmetic, validated as nonzero, and constrained by absolute compiled ceilings. Arrival
campaigns use absolute deadlines, record schedule lag and achieved rate, and fail when campaigns
of at least 20 attempts achieve less than 95% of target. The default timing is a 30-second warm-up,
300-second measurement, and 30-second cooldown, sampled on absolute one-second deadlines. Missed
ticks are skipped rather than backfilled so incomplete coverage still fails. Each timed phase
retains successful service work and rejected overload attempts once per second. Explicit smoke
overrides may reduce duration and scale but are marked non-evidence in the output.

## Ownership, Shutdown, and Failure

Each lane owns its server, clients, worker task set, cancellation token, and sampler. Worker task
sets are bounded by the configured offered counts. Admission never waits for additional worker
capacity. A lane cancels and drains its workers before shutting down its server.

Each network operation has a finite timeout. The complete shutdown path—client release, worker
drain, recovery proof, and server termination—has one production 20-second deadline. Cleanup is
attempted even when workload setup or measurement fails. A timeout, task panic, counter overflow,
incomplete sample, external address, or host preflight failure makes the report fail. Partial
artifacts remain available for diagnosis.

The load generator and services share the same host, so host CPU and memory measurements include
generator cost and are conservative. Service admission metrics and process resource observations
are recorded separately where the runtime exposes them.

## Evidence and Acceptance

The harness writes a run directory containing the preflight report, final and partial JSON reports,
and line-oriented one-second samples tagged with lifecycle phase. Successful and rejected latency
distributions are retained separately in microseconds. The report contains configuration, host
profile, workload outcomes, arrival rates, admission snapshots, rejection status classes, peak
RSS, peak descriptors, peak tasks/threads, task-spawn rejection/exhaustion state, queue high-water
marks (including the largest per-connection Noq packet-event depth), and shutdown duration.

Finalization uses create-new writes, records the SHA-256 and byte count of every retained artifact
in `manifest.json`, prints and stores an independent SHA-256 for that manifest, and removes write
bits from files and the run directory. Preflight and lane failures are finalized in the same way.
Capacity evidence additionally requires a clean source tree, an optimized Cargo `release` build,
all three lanes, 100% scale, exact 30/300/30 timing, and a one-second sample interval.

An evidence run passes only when:

- peak total CPU is at most 70%;
- peak process RSS is at most 70% of visible memory;
- peak descriptors are at most 70% of the effective descriptor limit;
- endpoint live-task high-water marks and current counts, plus all exposed queues, retain at least
  30% unused capacity where the workload is not intentionally saturating the admission ledger;
- endpoint task spawns report no rejections or exhausted counters;
- both endpoint Noq queues report no packet-event, byte, connection, or control rejection, and
  per-connection packet-event headroom is evaluated against its per-connection limit;
- the intentionally saturated admission ledger never exceeds its maximum and reports overload;
- successful work continues while excess work is rejected in warm-up, measurement, and cooldown;
- each timed phase retains its expected one-second samples with at most one boundary sample of
  tolerance per phase;
- every DNS UDP/HTTP and relay arrival is scheduled; typed DNS capacity/rate outcomes and relay
  endpoint/global/session-pending/rate plus client-visible outcomes exactly conserve the offered
  attempts; and campaigns meet their rate floor;
- accounting counters do not exhaust or regress; and
- each lane shuts down within 20 seconds.

Admission rejections are expected at 2x offered load and are not by themselves a failure. Growth
beyond a configured maximum, missing rejection evidence, background failure, or inability to
recover capacity is a failure.

## Rollout and Rollback

The first run is local and loopback-only. A retained passing report may close the operational audit
follow-up but does not authorize a default increase. Any future increase must repeat the same
profile at twice the proposed value.

The harness and DNS hold controls are isolated behind opt-in Cargo features and do not ship in
normal library artifacts. Narrow read-only task-capacity snapshots and relay default constants are
public diagnostic interfaces used to keep evidence tied to production configuration. Rollback
removes the feature-gated tooling, diagnostic exposure, and evidence documents; it never restores
an unlimited runtime or ingress path.
