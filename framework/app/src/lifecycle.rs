use std::{collections::BTreeSet, fmt, future::Future, pin::Pin, sync::Arc};

use tokio_util::sync::CancellationToken;

use crate::{
    AppConfig, BuildError, ComponentError, IdentityPolicy, IdentityStore, ProtocolRegistry,
    RunningApp,
};

/// Heap-owned future used by framework lifecycle capabilities.
pub type ComponentFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Explicit application lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Configuration is valid but no side effects have started.
    Configured,
    /// Identity and components are being acquired.
    Starting,
    /// All components are healthy and the handle is published.
    Running,
    /// Cancellation was issued and owned work is being joined.
    Draining,
    /// All owned work stopped cleanly.
    Stopped,
    /// Startup, runtime, or shutdown failed.
    Failed,
}

impl LifecycleState {
    pub(crate) const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Configured, Self::Starting)
                | (Self::Starting, Self::Running | Self::Failed)
                | (Self::Running, Self::Draining | Self::Failed)
                | (Self::Draining, Self::Stopped | Self::Failed)
        ) || self as u8 == next as u8
    }
}

/// Cancellation capability shared with one supervised component.
#[derive(Clone, Debug)]
pub struct ComponentContext {
    cancellation: CancellationToken,
}

impl ComponentContext {
    pub(crate) fn new(cancellation: CancellationToken) -> Self {
        Self { cancellation }
    }

    /// Resolves when the application begins draining.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// Returns whether application cancellation has been issued.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// A lifecycle-managed application component.
pub trait Component: fmt::Debug + Send + Sync + 'static {
    /// Stable, low-cardinality component name.
    fn name(&self) -> &str;

    /// Acquires resources and returns the component's owned runtime and shutdown operations.
    fn start(
        &self,
        context: ComponentContext,
    ) -> ComponentFuture<Result<StartedComponent, ComponentError>>;
}

pub(crate) type ShutdownAction =
    Box<dyn FnOnce() -> ComponentFuture<Result<(), ComponentError>> + Send + 'static>;

/// Runtime and shutdown operations returned by a successfully started component.
pub struct StartedComponent {
    pub(crate) run: ComponentFuture<Result<(), ComponentError>>,
    pub(crate) shutdown: ShutdownAction,
}

impl fmt::Debug for StartedComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StartedComponent(..)")
    }
}

impl StartedComponent {
    /// Wraps one long-running future and its bounded graceful-shutdown operation.
    pub fn new<Run, Shutdown, ShutdownFuture>(run: Run, shutdown: Shutdown) -> Self
    where
        Run: Future<Output = Result<(), ComponentError>> + Send + 'static,
        Shutdown: FnOnce() -> ShutdownFuture + Send + 'static,
        ShutdownFuture: Future<Output = Result<(), ComponentError>> + Send + 'static,
    {
        Self {
            run: Box::pin(run),
            shutdown: Box::new(move || Box::pin(shutdown())),
        }
    }
}

/// Builder whose validation is side-effect free.
pub struct AppBuilder {
    config: AppConfig,
    identity_store: Arc<dyn IdentityStore>,
    identity_policy: IdentityPolicy,
    components: Vec<Box<dyn Component>>,
    protocols: Option<ProtocolRegistry>,
}

impl fmt::Debug for AppBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppBuilder")
            .field("config", &self.config)
            .field("identity_store", &self.identity_store)
            .field("identity_policy", &self.identity_policy)
            .field("component_count", &self.components.len())
            .finish_non_exhaustive()
    }
}

impl AppBuilder {
    /// Starts an application definition with an explicit identity-store capability.
    #[must_use]
    pub fn new(identity_store: Arc<dyn IdentityStore>) -> Self {
        Self {
            config: AppConfig::default(),
            identity_store,
            identity_policy: IdentityPolicy::default(),
            components: Vec::new(),
            protocols: None,
        }
    }

    /// Replaces lifecycle resource and failure policy.
    #[must_use]
    pub fn config(mut self, config: AppConfig) -> Self {
        self.config = config;
        self
    }

    /// Selects explicit identity create/load behavior.
    #[must_use]
    pub fn identity_policy(mut self, policy: IdentityPolicy) -> Self {
        self.identity_policy = policy;
        self
    }

    /// Adds one lifecycle-managed component in startup dependency order.
    #[must_use]
    pub fn component(mut self, component: impl Component) -> Self {
        self.components.push(Box::new(component));
        self
    }

    /// Sets the bounded protocol registry owned by the application.
    #[must_use]
    pub fn protocol_registry(mut self, protocols: ProtocolRegistry) -> Self {
        self.protocols = Some(protocols);
        self
    }

    /// Validates all configuration without loading identity or starting components.
    pub fn build(self) -> Result<ConfiguredApp, BuildError> {
        self.config.validate()?;
        let protocols = match self.protocols {
            Some(protocols) => protocols,
            None => {
                ProtocolRegistry::new(self.config.protocol_limit, self.config.alpn_length_limit)?
            }
        };
        protocols.ensure_within(self.config.protocol_limit, self.config.alpn_length_limit)?;
        validate_component_names(&self.components)?;
        Ok(ConfiguredApp {
            config: self.config,
            identity_store: self.identity_store,
            identity_policy: self.identity_policy,
            components: self.components,
            protocols,
        })
    }
}

fn validate_component_names(components: &[Box<dyn Component>]) -> Result<(), BuildError> {
    let mut names = BTreeSet::new();
    for component in components {
        let name = component.name();
        if name.is_empty() || name.len() > 64 {
            return Err(BuildError::InvalidComponentName);
        }
        if !names.insert(name.to_owned()) {
            return Err(BuildError::DuplicateComponent {
                name: name.to_owned(),
            });
        }
    }
    Ok(())
}

/// Side-effect-free application definition ready for atomic startup.
pub struct ConfiguredApp {
    pub(crate) config: AppConfig,
    pub(crate) identity_store: Arc<dyn IdentityStore>,
    pub(crate) identity_policy: IdentityPolicy,
    pub(crate) components: Vec<Box<dyn Component>>,
    pub(crate) protocols: ProtocolRegistry,
}

impl fmt::Debug for ConfiguredApp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfiguredApp")
            .field("state", &LifecycleState::Configured)
            .field("config", &self.config)
            .field("component_count", &self.components.len())
            .field("protocol_count", &self.protocols.len())
            .finish_non_exhaustive()
    }
}

impl ConfiguredApp {
    /// Current pre-start lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        LifecycleState::Configured
    }

    /// Atomically acquires identity and components, publishing a handle only after success.
    pub async fn start(self) -> Result<RunningApp, crate::StartupError> {
        crate::supervisor::start(self).await
    }

    pub(crate) fn take_protocols(&mut self) -> ProtocolRegistry {
        std::mem::replace(
            &mut self.protocols,
            ProtocolRegistry::new(1, 1).expect("constant registry bounds are valid"),
        )
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::LifecycleState;

    proptest! {
        #[test]
        fn terminal_states_never_transition(state in 0_u8..=1) {
            let terminal = if state == 0 {
                LifecycleState::Stopped
            } else {
                LifecycleState::Failed
            };
            prop_assert!(!terminal.can_transition_to(LifecycleState::Running));
            prop_assert!(!terminal.can_transition_to(LifecycleState::Draining));
        }
    }

    #[test]
    fn legal_transition_graph_is_explicit() {
        assert!(LifecycleState::Configured.can_transition_to(LifecycleState::Starting));
        assert!(LifecycleState::Starting.can_transition_to(LifecycleState::Running));
        assert!(LifecycleState::Running.can_transition_to(LifecycleState::Draining));
        assert!(LifecycleState::Draining.can_transition_to(LifecycleState::Stopped));
        assert!(!LifecycleState::Configured.can_transition_to(LifecycleState::Running));
    }
}
