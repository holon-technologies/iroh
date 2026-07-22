# Iroh Hickory Server vendor delta

This directory is an exact copy of the crates.io `hickory-server` 0.26.1 package plus a narrow
resource-admission patch owned by the Iroh project.

## Why it is vendored

The upstream UDP loop creates one Tokio task per accepted datagram, and the TCP loop creates one
task per accepted connection, before an application `RequestHandler` runs. Handler middleware can
therefore bound expensive authority work but cannot bound the number of live transport tasks.

The Iroh delta adds:

- `ServerLimits` with nonzero UDP-request and TCP-connection capacities;
- non-blocking semaphore admission before `JoinSet::spawn`;
- owned permits released on completion, cancellation, or panic unwinding;
- an infallible `AdmissionObserver` for fixed-cardinality metrics; and
- unit and loopback saturation tests for rejection and permit conservation.

The crates.io package omits Hickory's workspace-only `test-support` crate while retaining imports
from it. The test build aliases this crate as `test_support` and provides a no-op `subscribe` helper
so the packaged unit tests remain runnable. Production code is unaffected.

## Updating

1. Copy the newly locked crates.io package into a fresh versioned vendor directory.
2. Reapply only the admission types, the two pre-spawn checks, observation callbacks, and tests.
3. Review upstream UDP/TCP loops to determine whether equivalent hard limits now exist.
4. Run the vendored server tests and `iroh-dns-server` saturation/lifecycle tests.
5. Update the root `[patch.crates-io]`, workspace exclusion, `Cargo.lock`, and this document in one
   dedicated change.

Do not remove the patch merely because handler-level or Tower concurrency limits exist: admission
must happen before the transport task is created.
