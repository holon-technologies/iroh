use std::fmt;

/// Opaque ownership token retained until a Noq connection's shared state is fully dropped.
///
/// Embedders use this to attach a non-clonable connection-capacity permit to the complete Noq
/// connection lifetime, including the driver and all stream/path handles.
pub struct ConnectionLifetimeToken {
    _guard: Box<dyn Send + Sync + 'static>,
}

impl ConnectionLifetimeToken {
    /// Erases and owns a connection-lifetime guard.
    pub fn new(guard: impl Send + Sync + 'static) -> Self {
        Self {
            _guard: Box::new(guard),
        }
    }
}

impl fmt::Debug for ConnectionLifetimeToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionLifetimeToken")
            .finish_non_exhaustive()
    }
}
