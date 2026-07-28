//! Experimental local-first application lifecycle.
//!
//! This crate is intentionally unpublished while the framework's public name and API are being
//! evaluated. It provides an atomic lifecycle boundary: configuration and identity are validated
//! before components start, partially started applications are rolled back, and one supervisor
//! owns runtime failure and bounded shutdown.

mod config;
mod error;
mod identity;
mod lifecycle;
mod protocol_registry;
mod supervisor;

pub use config::AppConfig;
pub use error::{
    BuildError, ComponentError, ComponentFailure, ConfigError, ControlError, FailurePhase,
    IdentityError, RegistryError, ShutdownError, ShutdownReport, StartupError, WaitError,
};
pub use identity::{FileIdentityStore, IdentityPolicy, IdentityStore, MemoryIdentityStore};
pub use lifecycle::{
    AppBuilder, Component, ComponentContext, ComponentFuture, ConfiguredApp, LifecycleState,
    StartedComponent,
};
pub use protocol_registry::ProtocolRegistry;
pub use supervisor::{Health, RunningApp};
