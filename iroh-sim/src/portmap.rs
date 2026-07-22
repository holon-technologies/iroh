//! Deterministic port-mapping capability consumed by Iroh's production socket actor.

use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh::simulation::PortMapper;
use tokio::sync::watch;

use crate::{EventClass, Kernel, ScheduledEvent, SyntheticNetwork};

/// Simulator-owned UPnP/PCP/NAT-PMP-equivalent lease source.
pub struct DeterministicPortMapper {
    id: String,
    host: String,
    nat: String,
    kernel: Kernel,
    network: SyntheticNetwork,
    state: Arc<Mutex<PortMapperState>>,
    external: watch::Sender<Option<SocketAddrV4>>,
}

#[derive(Default)]
struct PortMapperState {
    local_port: Option<NonZeroU16>,
    mapping: Option<String>,
    expiry: Option<ScheduledEvent>,
    active: bool,
    error: Option<String>,
}

impl fmt::Debug for DeterministicPortMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeterministicPortMapper")
            .field("id", &self.id)
            .field("host", &self.host)
            .field("nat", &self.nat)
            .finish_non_exhaustive()
    }
}

impl DeterministicPortMapper {
    pub fn new(
        id: impl Into<String>,
        host: impl Into<String>,
        nat: impl Into<String>,
        kernel: Kernel,
        network: SyntheticNetwork,
    ) -> Self {
        let (external, _) = watch::channel(None);
        Self {
            id: id.into(),
            host: host.into(),
            nat: nat.into(),
            kernel,
            network,
            state: Arc::new(Mutex::new(PortMapperState {
                active: true,
                ..PortMapperState::default()
            })),
            external,
        }
    }

    /// Returns and clears the last synchronous environment failure.
    pub fn take_error(&self) -> Option<String> {
        self.state
            .lock()
            .expect("port mapper lock poisoned")
            .error
            .take()
    }

    /// Activates the capability and requests/renews its current local port.
    pub fn activate(&self) {
        self.state.lock().expect("port mapper lock poisoned").active = true;
        self.record(self.procure());
    }

    /// Returns the currently published external address.
    pub fn external_address(&self) -> Option<SocketAddrV4> {
        *self.external.borrow()
    }

    /// Returns the gateway identity whose lease this capability publishes.
    pub fn nat_id(&self) -> &str {
        &self.nat
    }

    /// Re-reads a retained lease after an external-address change and republishes it.
    pub fn refresh(&self) {
        let should_refresh = {
            let state = self.state.lock().expect("port mapper lock poisoned");
            state.active && state.mapping.is_some()
        };
        if should_refresh {
            self.record(self.procure());
        }
    }

    fn procure(&self) -> Result<(), String> {
        let local_port = {
            let state = self.state.lock().expect("port mapper lock poisoned");
            if !state.active {
                return Ok(());
            }
            state
                .local_port
                .ok_or_else(|| "local port is unset".to_owned())?
        };
        let mapping = self
            .network
            .procure_port_mapping(&self.host, &self.nat, local_port.get())
            .map_err(|error| error.to_string())?;
        let SocketAddr::V4(external) = mapping.external else {
            return Err("NAT returned a non-IPv4 port mapping".to_owned());
        };
        let state = Arc::downgrade(&self.state);
        let publisher = self.external.clone();
        let mapping_id = mapping.mapping.clone();
        let (_, expiry) = self
            .kernel
            .schedule_cancellable_at(
                Duration::from_nanos(mapping.expires_nanos),
                EventClass::Infrastructure,
                move || {
                    if let Some(state) = state.upgrade() {
                        let mut state = state.lock().expect("port mapper lock poisoned");
                        if state.mapping.as_deref() == Some(mapping_id.as_str()) {
                            state.mapping = None;
                            state.expiry = None;
                            publisher.send_replace(None);
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|error| error.to_string())?;
        let mut state = self.state.lock().expect("port mapper lock poisoned");
        state.mapping = Some(mapping.mapping);
        state.expiry = Some(expiry);
        self.external.send_replace(Some(external));
        Ok(())
    }

    fn record(&self, result: Result<(), String>) {
        if let Err(error) = result {
            self.state.lock().expect("port mapper lock poisoned").error = Some(error);
        }
    }
}

impl PortMapper for DeterministicPortMapper {
    fn procure_mapping(&self) {
        self.record(self.procure());
    }

    fn update_local_port(&self, port: NonZeroU16) {
        self.state
            .lock()
            .expect("port mapper lock poisoned")
            .local_port = Some(port);
    }

    fn deactivate(&self) {
        let mapping = {
            let mut state = self.state.lock().expect("port mapper lock poisoned");
            state.active = false;
            state.expiry = None;
            state.mapping.take()
        };
        if let Some(mapping) = mapping {
            let result = self
                .network
                .release_port_mapping(&self.nat, &mapping)
                .map(|_| ())
                .map_err(|error| error.to_string());
            self.record(result);
        }
        self.external.send_replace(None);
    }

    fn watch_external_address(&self) -> watch::Receiver<Option<SocketAddrV4>> {
        self.external.subscribe()
    }
}
