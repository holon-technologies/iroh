//! Deterministically controlled interface-state source for production socket actors.

use std::{future::Future, pin::Pin};

use iroh::simulation::NetworkMonitor;
use n0_watcher::{Direct, Watchable};
use netwatch::netmon::State;

/// In-memory network monitor whose changes occur only through explicit simulator actions.
#[derive(Debug)]
pub struct StaticNetworkMonitor {
    state: Watchable<State>,
}

impl StaticNetworkMonitor {
    /// Creates a monitor with a stable initial interface view.
    pub fn new(state: State) -> Self {
        Self {
            state: Watchable::new(state),
        }
    }

    /// Replaces the visible interface state and wakes production observers when it changed.
    pub fn set_state(&self, state: State) -> bool {
        self.state.set(state).is_ok()
    }
}

impl NetworkMonitor for StaticNetworkMonitor {
    fn interface_state(&self) -> Direct<State> {
        self.state.watch()
    }

    fn network_change(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::ready(()))
    }
}
