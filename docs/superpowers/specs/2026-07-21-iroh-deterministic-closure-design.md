# Iroh deterministic-closure design

**Status:** approved on 2026-07-21

## Outcome

Close the remaining pre-continuous-run gaps in Iroh's deterministic simulation platform. The
production-endpoint lane must no longer depend on Tokio scheduling or Tokio/ambient time for any
simulator-supported behavior. A byte-replayable test-TLS lane, a production-crypto semantic-parity
lane, swarm-generated campaign inputs, and stronger realistic-backend evidence complete the work.

The always-on campaign fleet and a Vortex-style multi-process nondeterministic harness are explicit
non-goals for this phase.

## Constraints

- Normal endpoint builders retain operating-system entropy, the production Rustls provider, Tokio,
  and system time. Simulation behavior cannot be selected by an environment variable or normal
  feature configuration.
- Test-only crypto remains reachable solely through
  `Builder::simulation_environment_for_test` with `iroh_runtime::UnsafeTestOnly`.
- Production QUIC, Noq, endpoint, identity, relay actors, Rustls protocol state machine, and
  application behavior remain exercised. A deterministic key-exchange implementation is a named
  fidelity exception, never described as the production cryptographic backend.
- Backend observations determine the determinism grade. Scenario requirements cannot upgrade it.
- Existing schema/artifact replay fails closed. Compatibility is explicit and versioned.
- Secure material and private keys are never written to traces or diagnostics. Simulation seeds are
  public replay identifiers, not production secrets.
- Capability skips remain different from parity matches and infrastructure failures.

## 1. Kernel-owned execution

`TokioBridge` is replaced by a kernel root-operation driver. The driver admits an operation as a
structured kernel task, drives `Kernel::step` until the operation publishes its result, and then
closes and joins the operation group. Root operations participate in seeded ready-task selection,
fairness, task history, cancellation, panic containment, and event budgets exactly like endpoint
children.

The runner no longer uses `tokio::spawn` for paired connect, stream, or datagram operations. It
constructs the paired futures directly and submits their combined future to the kernel driver.
Endpoint bind, action completion, and shutdown are also driven through the kernel where they can
affect simulated behavior. Tokio may still host CLI orchestration outside the behavioral boundary;
its scheduling is not consulted by the simulated protocol.

Driver failure is typed and fail-closed:

- kernel budget, virtual-time, task, trace, and timer errors retain their existing classifications;
- a root panic is reported as a simulator failure with its task snapshot;
- quiescence before an operation result is a deterministic stall, not a timeout;
- cancellation closes the root group and requires bounded cleanup before returning.

## 2. One injected time model

`iroh::runtime` gains reusable clock-backed sleep, resettable sleep, interval, and timeout helpers.
They preserve Tokio interval's documented burst cadence where existing behavior relies on it, but
all deadlines and wakeups come from `RuntimeContext::clock`.

The supported relay actor, remote-state actor, socket shutdown, reconnect, cleanup, ping, flush,
idle, upgrade, scheduled path-open, scheduled hole-punch, and simulation relay-delay paths migrate
to these helpers. State transitions record injected-clock instants only. Production construction
continues to install `TokioClock`, so normal behavior remains unchanged.

A checked boundary inventory rejects direct `tokio::spawn`, `tokio::time`, `n0_future::time`, and
ambient `Instant::now` in the simulator-supported non-test modules unless a reviewed allowlist
classifies the occurrence outside behavioral execution.

## 3. Two honest TLS lanes

Rustls's `SecureRandom` interface alone cannot make TLS byte-deterministic: the ring/AWS-LC key
exchange implementations obtain their own system entropy. Therefore the platform provides two
separate lanes.

### Deterministic test-TLS lane

- Uses a simulation-only `CryptoProvider` derived from the configured production provider.
- Replaces Rustls random filling and the negotiated X25519 group with deterministic,
  domain-separated implementations scoped to one run and endpoint.
- Retains the production cipher suites, signature verification, key loading, Rustls state machine,
  Iroh certificates, endpoint identities, and QUIC implementation.
- Refuses construction without an active `UnsafeTestOnly` simulation environment.
- Does not silently fall back to system entropy.
- Produces byte-identical raw traces for the same source, scenario, and seed.
- Records `deterministic_test_crypto` as a fidelity exception.

The deterministic entropy owner is run-scoped and reset between campaign runs. It cannot use a
process-global mutable seed that would couple concurrent workers. No intentional per-run memory
leak or permanent default-provider installation is permitted.

### Production-crypto parity lane

- Uses the normal configured ring/AWS-LC provider and secure entropy.
- Requires exact normalized semantic replay while masking only opaque ciphertext payload hashes.
- Compares terminal state, identity, routing, delivery, timing, decisions, scheduling, resources,
  and other non-opaque trace fields with the deterministic lane.

The two lanes are complementary: raw replay validates deterministic infrastructure; production
crypto parity validates that the test provider did not change externally meaningful behavior.

### Feasibility finding: Rustls provider ownership

Implementation reached the design's mandatory stop condition. Rustls 0.23's public
`CryptoProvider` stores `secure_random: &'static dyn SecureRandom` and
`kx_groups: Vec<&'static dyn SupportedKxGroup>`. Consequently a provider whose entropy and X25519
state are owned by one simulation run cannot be built through the public API: it must either leak
run state to obtain `'static`, dispatch through process-global/thread-local state, or use a forked
provider API. The first two violate the isolation and no-leak invariants approved above.

Resolution: the approved implementation maintains a narrow workspace Rustls 0.23.41 fork whose
provider owns these two component families through `Arc`. The clock, actor, relay, shutdown, and
root-driver closure now proceeds with run-owned deterministic TLS state and no leaks or ambient
dispatch. The alternatives considered at the stop condition were:

- maintain a narrow Rustls fork that accepts owned `Arc` provider components;
- allow process-isolated, process-lifetime leaked test providers; or
- retain production crypto as the sole semantic-replay escape and drop raw ciphertext replay.

## 4. Grades and compatibility

New artifacts support these grades:

- `fully_deterministic`: no scheduler, clock, environment, or entropy escape; raw trace replay is
  required;
- `semantically_deterministic`: production crypto is the only admitted nondeterminism; complete
  normalized trace replay is required;
- `controlled_runtime`: accepted only for explicitly compatible historical artifacts and rejected
  for newly generated supported scenarios.

Manifests record the crypto lane, trace-comparison mode, fidelity exceptions, and observed escapes.
`fully_deterministic` is invalid when any escape exists or raw comparison is disabled.
`semantically_deterministic` is invalid when an escape other than production cryptographic entropy
exists. Replay selects comparison behavior from the immutable manifest, never from CLI defaults.

Corpus migration preserves provenance and prior signatures. A corpus entry is upgraded only after
both its new raw/semantic replay expectation and inventory have been reviewed.

## 5. Swarm materialization

A new strict, independently versioned `SwarmSpec` describes bounded choices over an existing base
scenario. It does not weaken or overload scenario schema v2. Choices cover:

- topology size, address-family composition, interfaces, and links;
- NAT/firewall mapping and filtering variants;
- relay/discovery availability and lifecycle patterns;
- workload operation and payload mix;
- fault enablement, probability/weight, stability, duration, and correlation;
- ready-task pressure and fairness-relevant concurrency.

Every campaign seed domain-separates materialization decisions from runtime behavioral decisions.
Before execution, it emits a complete canonical `Scenario`; the run artifact retains the swarm
schema/version, template digest, selected values, and materialized scenario. Replay consumes only
the materialized scenario. Minimization also operates on that scenario and retains its swarm
provenance.

Invalid or unsupported selections fail materialization before any endpoint starts. Fixed
validation seed sets prove that every declared option can be selected without probabilistic CI
assertions.

## 6. Realistic-backend evidence

The canonical parity catalogue expands only where Patchbay or another existing realistic backend
can produce evidence. Targeted dimensions include partition symmetry, NAT expiry/rebinding,
direct-to-relay fallback, relay restart/overload, IPv4/IPv6 path changes, suspend/resume, and address
replacement.

Parity fixtures add evidence identity and freshness metadata. Comparison fails when:

- a previously common supported capability becomes an unexplained skip;
- the fixture is incompatible with the scenario/catalog schema;
- evidence claims a dimension the backend did not observe;
- required source/run identity or freshness metadata is missing;
- common semantic outcomes differ.

True diverse-router, captive-portal, and platform-specific gaps remain explicit skips until real
evidence exists.

## 7. Validation and completion

Completion, after resolving the provider-ownership decision, requires:

- zero current manifest escapes in the deterministic lane;
- production crypto as the sole admitted escape in the semantic lane;
- identical raw deterministic traces across repeated runs and fresh child processes;
- worker-count- and completion-order-independent swarm materialization and campaign summaries;
- exact normalized production-crypto replay and cross-lane semantic parity;
- passing rare-ready-order corpus replay and minimization;
- fixed-seed coverage of every swarm choice;
- strict Patchbay common-capability comparisons with honest skips;
- green native/all-feature/minimal/WASM builds, Clippy, runtime/simulator/relay/Iroh tests,
  benchmarks, corpus, schemas, and boundary checks;
- updated operations policy, runbooks, and CI tiers without adding an always-on service.
