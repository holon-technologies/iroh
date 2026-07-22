# Iroh Deterministic Simulation Stage 4 Implementation Plan

## Goal and exit gate

Extend the deterministic direct-IP platform with stateful NAT/firewall behavior, deterministic
discovery/DNS, interface and route mobility, and common-backend scenario semantics. Stage 4 is
complete when the agreed public/full-cone/restricted/port-restricted/symmetric/double-NAT,
mapping-expiry/rebinding, firewall, discovery-expiry/conflict, and switch-uplink matrix has stable
deterministic outcomes and documented parity or an explicit semantic difference against Patchbay.

## Chosen architecture

Keep translation/filtering in the synthetic packet path, not in endpoint fixtures. A `NatGateway`
owns canonical inside/outside interfaces, mapping/filter policy, allocator stream, mapping table,
expiry generation, hairpin policy, and resource tokens. Outbound traversal translates before route
selection; inbound traversal applies reverse mapping and filtering before destination socket lookup.
Every mapping mutation and firewall decision is typed trace data.

Interface, route, port-mapping, and discovery state remain environment capabilities. Scenario
actions mutate those capabilities; production Iroh consumes the same monitor, address-lookup,
port-mapping, and socket rebind seams already used by normal code. Discovery providers use the
virtual wall/monotonic clocks and stable update ordering. Backend capability checks remain exact.

### Task 1: Stateful NAT and firewall reference model

- [x] Define strict NAT topology/policy schema for public, endpoint-independent,
  address-dependent, address+port-dependent, double NAT/CGNAT, hairpin, expiry, and rebinding.
- [x] Implement deterministic external-port allocation, outbound mapping keys, inbound filter
  keys, generation-safe expiry, collision handling, and resource ledger ownership.
- [x] Implement ordered firewall rules for direction, protocol, address/prefix, port range,
  connection state, allow/drop/reject, and default policy.
- [x] Emit mapping create/reuse/expire/rebind and firewall allow/drop/reject trace events with
  stable NAT/mapping/rule identities.
- [x] Add table/property tests for every mapping/filter combination, expiry boundaries,
  allocation exhaustion, hairpin, double translation, and empty cleanup.

### Task 2: Integrate translation with synthetic routing and sockets

- [x] Add NAT gateways to network topology with explicit inside-host/upstream-chain placement and
  reject ambiguous or cyclic placement.
- [x] Apply outbound/inbound/hairpin translations transactionally with routing, queue, packet,
  and mapping reservations; rejected packets must not consume phantom capacity or time.
- [x] Preserve original/translated tuples in packet trace context and socket receive metadata.
- [x] Implement external-address changes, mapping invalidation/preservation policy, sleep/resume,
  and explicit NAT rebinding without stale scheduled delivery.
- [x] Prove multi-hop, double-NAT, IPv4 public/private, IPv6 public/no-NAT, and family-mismatch
  behavior with deterministic traces.

### Task 3: Port mapping, interface monitor, and mobility actions

- [x] Generalize the disabled/concrete port-mapper wrapper into an injected capability and retain
  existing production defaults.
- [x] Add simulator port-map requests, renewal, conflict, expiry, external-address observation,
  and cleanup using the NAT model.
- [x] Extend the static monitor into mutable canonical interface/address/route state and inject
  ordered network-change notifications into production socket logic.
- [x] Activate `nat_change` and `interface_change` actions plus route/address/uplink and
  sleep/resume actions with typed observations and capability checks.
- [x] Run production QUIC through address loss/addition, socket rebind, uplink switch, path
  degradation, mapping expiry, and reconnection/migration scenarios.

### Task 4: Deterministic discovery and DNS

- [x] Implement bounded discovery providers with delayed success/error, duplicate/conflicting
  records, provenance, TTL/expiry, withdrawal, stale delivery, and stable update ordering.
- [x] Inject virtual clocks into Iroh memory/discovery timestamps and DNS timeout/stagger paths
  used by supported scenarios without weakening production wall-clock defaults.
- [x] Activate `discovery_update` actions and typed observations; model aggregation semantics
  rather than replacing production address-lookup logic.
- [x] Add discovery convergence, stale-record rejection, conflict precedence, provider failure,
  and reconnect-after-update invariants/scenarios.

### Task 5: Common semantics and Patchbay parity

- [x] Define backend-independent NAT/firewall/mobility observations and terminal classes.
- [x] Port representative Patchbay public, full-cone, restricted, symmetric, double-NAT,
  degradation, outage, and switch-uplink cases into canonical scenarios.
- [x] Add a Patchbay adapter or fixture-result importer that reports capability skips and compares
  semantic outcomes without requiring byte-identical packet timing.
- [x] Publish the agreed parity matrix with deterministic outcome, Patchbay outcome, known
  environmental variance, and owner for every intentional difference.

### Task 6: Operations, corpus, performance, and exit audit

- [x] Extend minimization reducers, corpus metadata, campaigns, failure artifacts, and `explain`
  for NAT mappings, firewall rules, discovery records, interfaces, and routes.
- [x] Add reviewed mapping-expiry/rebind and discovery-conflict regressions to the permanent corpus.
- [x] Add PR smoke and sharded nightly NAT/discovery/mobility campaigns with retained unique
  failures and bounded resource/time budgets.
- [x] Measure translation/filter/discovery throughput and disabled production-path overhead.
- [x] Refresh and classify boundary inventory; run native/wasm/regression/lint/workflow gates and
  complete the scenario-by-scenario parity audit.

## Constraints

- Never infer NAT type from labels at packet time; validated policy data drives behavior.
- Never globally replace secure entropy, DNS, interfaces, or port mapping.
- Use virtual time for mapping/record expiry and behavioral deadlines.
- Translation, filtering, and allocation decisions must be seed-isolated and replay visible.
- Reject unsupported address-family translation rather than silently approximating NAT64/NAT66.
- Preserve resource ownership across cancellation, expiry, rebinding, and endpoint shutdown.
