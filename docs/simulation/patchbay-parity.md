# Deterministic simulator and Patchbay parity

This matrix defines semantic parity, not packet-timeline identity. Patchbay runs production Iroh in
Linux namespaces with real kernel scheduling and clocks. The deterministic backend runs production
QUIC over simulator-owned sockets, time, NAT, firewall, interfaces, routes, and discovery. Their
packet order and timing are therefore expected to differ.

The shared contract is versioned by `PARITY_FIXTURE_SCHEMA_VERSION`. Patchbay's smaller test receipt
is independently versioned by `PATCHBAY_RECEIPT_SCHEMA_VERSION`. The comparison uses only explicitly
selected dimensions: terminal class, authenticated connections, intact/corrupt application
deliveries, NAT lifecycle, firewall decisions, mobility transitions, relay lifecycle, and selected path class.
Unsupported dimensions are a typed capability skip; they are never silently treated as a pass.
Delivery parity means both backends observed at least one successful exchange and agree whether any
corruption occurred. Raw directional event counts remain diagnostic because Patchbay ping and the
deterministic stream round trip do not emit the same number of observer events.

## Stage 4 matrix

| Canonical case | Deterministic outcome | Patchbay outcome | Compared now | Known variance or intentional difference | Owner |
|---|---|---|---|---|---|
| `public` | Success; production QUIC authenticates and completes a stream round trip | `nat_none_x_none`: relay first, then direct, ping succeeds | terminal, authentication, delivery | Selected-path events are not yet exported by the deterministic production endpoint | Iroh connectivity |
| `full_cone` | Success through endpoint-independent mapping/filtering; mapping lifecycle is traced | `nat_easiest_x_none`: relay-to-direct succeeds | terminal, authentication, delivery | Patchbay tests bilateral hole punching; the Stage 4 canonical case isolates outbound NAT behavior | Iroh connectivity |
| `port_restricted` | Success through endpoint-independent mapping plus address-and-port filtering and ordered firewall rules | `nat_easy_x_none`: relay-to-direct succeeds | terminal, authentication, delivery | Firewall/NAT internals are observable only on the deterministic side | Iroh connectivity |
| `symmetric` | Success for address-and-port-dependent outbound mapping to a public peer | `nat_hard_x_none` succeeds; `nat_hard_x_hard` is ignored because direct hole punching is not expected without port prediction | terminal, authentication, delivery | Hard-to-hard relay/direct selection is deferred to Stage 5 and is reported as a path-capability skip | Iroh connectivity |
| `double_nat` | Success through two ordered stateful translations with independent mappings and cleanup | No direct Patchbay double-NAT fixture exists | terminal, authentication, delivery | Patchbay result is an explicit NAT/path capability gap, not a parity pass | Simulation + Patchbay owners |
| `degradation_mild` | Success with 10 ms modeled latency and 10 Mbit/s bandwidth | client/server level 0: 10 ms latency, 5 ms jitter, 0.5% loss; both pass | terminal, authentication, delivery | Seeded loss/reordering and kernel jitter do not share a packet timeline or distribution with Linux `netem` | Iroh connectivity |
| `outage_recovery` | Existing connection survives a deterministic partition/heal and delivers afterward | client/server link-down for 5 seconds recover, deliver through fallback, and return direct | terminal, authentication, delivery | Relay fallback and return-to-direct are Stage 5 path dimensions; Stage 4 compares recovered application behavior | Iroh connectivity |
| `switch_uplink` | IPv4 connection delivers before and after interface-down plus route activation; mobility transitions are typed | 18 client/server IPv4/IPv6/dual-stack switch cases pass | terminal, authentication, delivery, mobility | IPv6 family transitions and selected-path family are retained Patchbay coverage until deterministic path events are available | Iroh connectivity |

The canonical scenarios are constructed by `canonical_patchbay_scenarios()` in
`iroh-sim/src/parity_catalog.rs`. Every catalog entry is schema-validated and executed against real
production QUIC in the `iroh-sim` parity test. The source mapping points back to the corresponding
tests in `iroh/tests/patchbay/`.

## Result import and comparison

Patchbay adapters write a strict `ParityFixture` JSON document containing:

- stable case and backend identity;
- source revision plus immutable run ID and scenario digest;
- observation epoch and a bounded evidence-validity window;
- separate sorted capability and actually-observed dimension lists;
- either a completed `SemanticOutcome` or a skip with sorted missing capabilities and a reason;
- no host path, wall-clock duration, packet timestamp, or opaque kernel identifier.

`ParityFixture::from_json` rejects unknown fields, schema drift, missing identity, false capability
claims, noncanonical lists, invalid paths, and contradictory skips. Operational comparison also
rejects stale or implausibly future-dated evidence and a scenario digest mismatch. `compare_semantic_outcomes` requires a sorted
explicit dimension list and reports `match`, `difference`, or `skipped`. A checked-in Patchbay fixture and round-trip test live at
`iroh-sim/tests/fixtures/patchbay-public.json` and `iroh-sim/tests/parity.rs`. Operators export and
compare immutable evidence with `cargo sim parity export`, `cargo sim parity import-patchbay`, and
`cargo sim parity compare`; the
commands intersect declared capabilities and fail on a semantic difference or skip.

## Fresh Patchbay evidence pipeline

The privileged Patchbay workflow no longer treats the checked fixture as current execution
evidence. After `nat::nat_none_x_none` proves an authenticated relay connection, direct-path
upgrade, and successful ping, it atomically creates a receipt at
`IROH_PATCHBAY_PARITY_RECEIPT`. Receipt creation is part of the test result: serialization or an
existing output file fails the test. The workflow then:

1. imports the receipt with the current source revision and observation epoch;
2. binds it to the canonical catalog scenario digest and derives an immutable run ID;
3. exports the deterministic public case from the same revision and epoch;
4. compares terminal, authentication, and delivery semantics; and
5. uploads the receipt, both fixtures, and the comparison report.

The Patchbay job requires Linux user namespaces. A host that cannot write `setgroups` cannot
produce realistic evidence; this is an infrastructure failure, not a capability skip or parity
match. The self-hosted workflow enables unprivileged namespaces before the run.

When a Patchbay job refreshes a fixture, review the semantic diff with the production revision. Do
not overwrite a difference merely because a run is environmentally flaky. Record the variance here,
keep the previous artifact, and assign the row owner until the behavior is explained.

Stage 5 relay-specific outcomes and the deterministic/production-local/Patchbay capability matrix
are documented in [`relay-parity.md`](relay-parity.md).
