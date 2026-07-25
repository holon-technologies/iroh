use std::{fmt, panic::AssertUnwindSafe};

/// Opaque ownership token retained until a Noq connection's shared state is fully dropped.
///
/// Embedders use this to attach a non-clonable connection-capacity permit to the complete Noq
/// connection lifetime, including the driver and all stream/path handles.
pub struct ConnectionLifetimeToken {
    // The guard is never exposed or accessed; it is retained solely for its drop behavior. Keep
    // that implementation detail from removing the historical unwind-safety auto-traits from
    // every public connection and stream handle that transitively owns this token.
    _guard: AssertUnwindSafe<Box<dyn Send + Sync + 'static>>,
}

impl ConnectionLifetimeToken {
    /// Erases and owns a connection-lifetime guard.
    pub fn new(guard: impl Send + Sync + 'static) -> Self {
        Self {
            _guard: AssertUnwindSafe(Box::new(guard)),
        }
    }
}

impl fmt::Debug for ConnectionLifetimeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionLifetimeToken")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        panic::{RefUnwindSafe, UnwindSafe},
        sync::Arc,
    };

    use super::ConnectionLifetimeToken;
    use crate::{Connection, RecvStream, SendStream, WeakConnectionHandle};

    #[test]
    fn lifetime_guard_preserves_public_handle_unwind_safety() {
        fn assert_unwind_safe<T: UnwindSafe + RefUnwindSafe>() {}

        assert_unwind_safe::<ConnectionLifetimeToken>();
        assert_unwind_safe::<Connection>();
        assert_unwind_safe::<WeakConnectionHandle>();
        assert_unwind_safe::<SendStream>();
        assert_unwind_safe::<RecvStream>();
    }

    #[test]
    fn lifetime_token_erases_non_unwind_safe_guard() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.try_acquire_owned().expect("permit is available");
        let token = ConnectionLifetimeToken::new(permit);

        fn assert_unwind_safe<T: UnwindSafe + RefUnwindSafe>(_: &T) {}
        assert_unwind_safe(&token);
    }
}
