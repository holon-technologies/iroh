//! Stable identifiers used by runtime observations and replay artifacts.

use std::{
    fmt,
    marker::PhantomData,
    num::NonZeroU64,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

macro_rules! stable_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Creates an ID, returning `None` for the reserved zero value.
            pub const fn new(value: u64) -> Option<Self> {
                match NonZeroU64::new(value) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            /// Returns the numeric representation.
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }

        impl From<NonZeroU64> for $name {
            fn from(value: NonZeroU64) -> Self {
                Self(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

stable_id!(TaskId, "Stable identity of a runtime task.");
stable_id!(TimerId, "Stable identity of a runtime timer.");
stable_id!(DecisionId, "Stable identity of a behavioral decision.");
stable_id!(TraceSequence, "Monotonic sequence number of a trace event.");

/// Allocates monotonically increasing, nonzero stable identifiers.
#[derive(Debug)]
pub struct IdAllocator<I> {
    next: AtomicU64,
    marker: PhantomData<fn() -> I>,
}

impl<I> Default for IdAllocator<I> {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(1),
            marker: PhantomData,
        }
    }
}

impl<I> IdAllocator<I>
where
    I: From<NonZeroU64>,
{
    /// Restores an allocator whose next result is `next`.
    ///
    /// This is used by replay/checkpoint restoration as well as fresh construction.
    pub const fn from_next(next: NonZeroU64) -> Self {
        Self {
            next: AtomicU64::new(next.get()),
            marker: PhantomData,
        }
    }

    /// Allocates the next ID without ever wrapping back to one.
    pub fn allocate(&self) -> Result<I, IdExhausted> {
        let allocated = self
            .next
            .fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| match current {
                    0 => None,
                    u64::MAX => Some(0),
                    current => Some(current + 1),
                },
            )
            .map_err(|_| IdExhausted)?;
        let allocated = NonZeroU64::new(allocated).ok_or(IdExhausted)?;
        Ok(I::from(allocated))
    }
}

/// A stable identifier space has been exhausted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdExhausted;

impl fmt::Display for IdExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("stable identifier space exhausted")
    }
}

impl std::error::Error for IdExhausted {}
