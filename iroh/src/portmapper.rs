//! Portmapper integration.
//!
//! Wraps the real [`portmapper`] crate when the `portmapper` feature is enabled,
//! or provides a no-op stub otherwise.

use std::net::SocketAddrV4;

#[cfg(not(wasm_browser))]
use std::sync::Arc;

use tokio::sync::watch;

/// Configuration for the portmapper service (UPnP, PCP, NAT-PMP).
///
/// Port mapping asks the local router to open an external port so peers can
/// reach this endpoint directly, improving connectivity behind NATs. The
/// discovery step (UPnP uses SSDP multicast) can, however, trigger firewall
/// prompts on some networks — see [`PortmapperConfig::Disabled`].
///
/// Used with [`crate::endpoint::Builder::portmapper_config`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PortmapperConfig {
    /// Enable portmapping with default settings.
    ///
    /// This is the default.
    #[non_exhaustive]
    Enabled {},
    /// Disable portmapping.
    ///
    /// Skips the UPnP/PCP/NAT-PMP gateway probing. Use this to avoid the
    /// SSDP multicast discovery that can raise firewall dialogs (notably on
    /// macOS), at the cost of potentially worse direct connectivity behind
    /// some NATs.
    Disabled,
}

impl Default for PortmapperConfig {
    fn default() -> Self {
        PortmapperConfig::Enabled {}
    }
}

pub(crate) fn create_client(
    config: &PortmapperConfig,
    #[cfg(not(wasm_browser))] injected: Option<Arc<dyn crate::simulation::PortMapper>>,
) -> Client {
    #[cfg(not(wasm_browser))]
    if let Some(client) = injected {
        return Client::Injected(client);
    }
    match config {
        #[cfg(all(not(wasm_browser), feature = "portmapper"))]
        PortmapperConfig::Enabled {} => Client::Enabled(::portmapper::Client::default()),
        _ => {
            let (tx, rx) = watch::channel(None);
            Client::Disabled { _tx: tx, rx }
        }
    }
}

/// Portmapper client: either the real implementation or a no-op.
///
/// The disabled variant is used when the `portmapper` feature is off, on wasm,
/// or when portmapping is disabled via [`PortmapperConfig::Disabled`].
#[derive(Debug)]
pub(crate) enum Client {
    /// Explicit simulator-owned implementation.
    #[cfg(not(wasm_browser))]
    Injected(Arc<dyn crate::simulation::PortMapper>),
    /// The real portmapper client (requires the `portmapper` feature).
    #[cfg(all(not(wasm_browser), feature = "portmapper"))]
    Enabled(::portmapper::Client),
    /// No-op: keeps the sender alive so the receiver never closes.
    Disabled {
        _tx: watch::Sender<Option<SocketAddrV4>>,
        rx: watch::Receiver<Option<SocketAddrV4>>,
    },
}

impl Client {
    pub(crate) fn procure_mapping(&self) {
        match self {
            #[cfg(not(wasm_browser))]
            Client::Injected(c) => c.procure_mapping(),
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.procure_mapping(),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn update_local_port(&self, _port: std::num::NonZeroU16) {
        match self {
            #[cfg(not(wasm_browser))]
            Client::Injected(c) => c.update_local_port(_port),
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.update_local_port(_port),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn deactivate(&self) {
        match self {
            #[cfg(not(wasm_browser))]
            Client::Injected(c) => c.deactivate(),
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.deactivate(),
            Client::Disabled { .. } => {}
        }
    }

    pub(crate) fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
        match self {
            #[cfg(not(wasm_browser))]
            Client::Injected(c) => c.watch_external_address(),
            #[cfg(all(not(wasm_browser), feature = "portmapper"))]
            Client::Enabled(c) => c.watch_external_address(),
            Client::Disabled { rx, .. } => rx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU16,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    use super::*;

    #[derive(Debug)]
    struct Injected {
        calls: AtomicU64,
        tx: watch::Sender<Option<SocketAddrV4>>,
    }

    impl crate::simulation::PortMapper for Injected {
        fn procure_mapping(&self) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }

        fn update_local_port(&self, port: NonZeroU16) {
            self.calls
                .fetch_add(u64::from(port.get()), Ordering::Relaxed);
        }

        fn deactivate(&self) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }

        fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
            self.tx.subscribe()
        }
    }

    #[test]
    fn injected_client_is_used_even_when_production_mapping_is_disabled() {
        let (tx, _) = watch::channel(None);
        let injected = Arc::new(Injected {
            calls: AtomicU64::new(0),
            tx,
        });
        let client = create_client(&PortmapperConfig::Disabled, Some(injected.clone()));

        client.update_local_port(NonZeroU16::new(7).unwrap());
        client.procure_mapping();
        client.deactivate();

        assert_eq!(injected.calls.load(Ordering::Relaxed), 9);
        assert!(client.watch_external_address().borrow().is_none());
    }
}
