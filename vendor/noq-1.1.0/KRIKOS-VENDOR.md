# Krikos Noq vendor delta

Upstream base: `noq` 1.1.0. Published fork: `krikos-noq` 1.1.0-holon.1. The Rust library name
remains `noq` so the fork is source-compatible at import sites. The package name and exact
prerelease version make downstream dependency provenance explicit.

This directory is an exact copy of the crates.io `noq` 1.1.0 package plus a narrow
resource-accounting patch owned by the Iroh project.

## Why it is vendored

The upstream endpoint uses unbounded Tokio channels for network-fed
endpoint-to-connection events and connection-to-endpoint protocol events. It also creates
connection drivers without a way for an embedding application to attach a conserved
connection-lifetime permit. A peer can therefore grow queued event memory, while outer admission
cannot prove that a released application handle also means the Noq driver and shared state have
finished.

The Iroh delta adds:

- explicit finite `EventQueueLimits` on endpoint construction;
- per-connection packet-item and endpoint-wide packet-byte accounting;
- a conserved bidirectional normal/control-event budget;
- reserved terminal-event credits and coalesced close/rebind/address-change state;
- fixed-cardinality queue rejection diagnostics;
- an opaque `ConnectionLifetimeToken` retained through final Noq connection-state drop;
- guarded connect and accept entry points used by Iroh and relay QAD; and
- saturation, recovery, token-conservation, and raw-sender-bypass tests.

Packet admission failure behaves as QUIC packet loss. Control admission failure closes only the
affected connection with a typed local resource-limit reason. Close and terminal delivery are
never silently discarded.

## Updating

1. Copy the newly locked crates.io package into a fresh versioned vendor directory.
2. Reapply only the queue-budget wrappers, lifetime token, explicit-limit constructors, and tests.
3. Review upstream Noq for equivalent item, byte, control, terminal, and connection-lifetime
   bounds.
4. Run the vendored Noq tests plus Iroh endpoint, simulation, relay-QAD, and browser checks.
5. Increment the Holon prerelease revision, update exact `krikos-noq` dependencies, the local source
   patch, package verifier, lockfiles, changelog, and this document together.

Do not remove this patch merely because outer endpoint or task admission exists. Queue admission
must occur before channel allocation, and connection capacity must remain owned until both the
driver and shared Noq state have terminated.
