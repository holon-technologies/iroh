# Relay semantic parity

Relay parity compares externally meaningful outcomes, never packet timing. Three fixture backends
are named explicitly: `deterministic`, `production_local`, and `patchbay`. A backend that cannot
observe a requested dimension emits a typed capability skip with a reason; absence is not a pass.

The shared dimensions are terminal class, authenticated connections, intact/corrupt deliveries,
relay online/offline transitions, and ordered selected-path classes (`relay`, `direct_ipv4`, or
`direct_ipv6`). Production-handler coverage counters are deterministic evidence, but are not a
cross-backend semantic dimension because Patchbay and production-local fixtures obtain equivalent
evidence through their own instrumentation.

## Stage 5 matrix

| Case | Deterministic production path | Production-local equivalent | Patchbay equivalent | Compared semantics | Intentional difference |
|---|---|---|---|---|---|
| Relay only | Production QUIC over the production Iroh relay actor and production relay client/server session handlers | Loopback relay service with OS TCP/TLS/HTTP | Relay-backed endpoint connection | terminal, authentication, delivery, path | Deterministic transport omits listener mechanics, not relay protocol mechanics |
| Relay restart | Server session registry is shut down, generation advances, endpoint actors reconnect, new QUIC connection delivers | Restart local relay process/service | Relay outage/recovery scenario | terminal, authentication, delivery, relay lifecycle, path | Wall-clock reconnect timing is intentionally excluded |
| Relay to direct | First exchange routes through relay; discovered synthetic IP becomes the selected direct IPv4 path | Loopback relay plus local UDP address publication | Existing relay-to-direct Patchbay cases | terminal, authentication, delivery, path | Kernel path-validation packet timing differs |
| Direct failure/fallback | Stable direct path is partitioned and the same authenticated QUIC connection delivers through relay | Local network fault plus loopback relay | Link-down fallback cases | terminal, authentication, delivery, path | Linux `netem` distribution is not compared to seeded packet scheduling |
| Multiple relays | Independent production registries prove cross-relay destination isolation | Two local relay services | Multi-relay deployment fixture when available | terminal, authentication, delivery, path | Patchbay reports a typed capability skip if only one relay is provisioned |
| Capacity/duplicate identity | Production admission limit and active/inactive duplicate registry behavior | Local relay configuration | Deployment-specific | terminal and explicit handler assertions | Capacity policy is configuration, so fixtures must record it |

## Differential oracle

`RelayRoutingOracle` models only online state, bounded admission, stable identity membership, and
same-relay routing. Tests compare its decisions with production sessions for accepted delivery,
unknown/cross-relay destinations, outage invalidation, capacity rejection, and stable ordering.
It intentionally does not model authentication, WebSocket framing, duplicate-session health
frames, reconnect timing, backpressure, or QUIC. Those differences are permanent and are why oracle
execution never increments production relay coverage.

The deterministic backend's in-memory transport bypasses DNS, TCP, TLS, and HTTP upgrade. It still
runs WebSocket framing, challenge/signature authentication, authorization, server client actors,
the duplicate-identity registry, packet routing, and shutdown. Production-local and Patchbay lanes
remain responsible for the bypassed adapters and real kernel behavior.
