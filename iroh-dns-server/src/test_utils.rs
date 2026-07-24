//! Deterministic controls used only by bounded integration workloads.

use std::time::Duration;

/// Reserved DNS name whose admitted UDP handler remains active for the hold duration.
pub const RESOURCE_CANARY_UDP_HOLD_NAME: &str = "_iroh-resource-canary-hold.invalid.";

/// Time an admitted reserved UDP request remains active.
pub const RESOURCE_CANARY_UDP_HOLD_DURATION: Duration = Duration::from_secs(3);
