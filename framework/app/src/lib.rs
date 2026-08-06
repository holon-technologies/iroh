//! Experimental local-first application lifecycle.
//!
//! This crate is intentionally unpublished while the framework's public name and API are being
//! evaluated. It provides an atomic lifecycle boundary: configuration and identity are validated
//! before components start, partially started applications are rolled back, and one supervisor
//! owns runtime failure and bounded shutdown.

mod application;
mod config;
mod data_root;
mod error;
mod identity;
#[cfg(feature = "identity")]
mod identity_protocol;
mod lifecycle;
mod protocol_registry;
mod standard_bundle;
mod supervisor;

#[cfg(feature = "fuzzing")]
pub mod fuzz;

pub use application::{Application, ApplicationHealth, ApplicationMetrics};
pub use config::AppConfig;
pub use data_root::DataRoot;
pub use error::{
    BuildError, ComponentError, ComponentFailure, ConfigError, ControlError, DataRootError,
    FailurePhase, IdentityError, RegistryError, ShutdownError, ShutdownReport, StandardStartError,
    StandardStartStage, StartupError, WaitError,
};
pub use identity::{FileIdentityStore, IdentityPolicy, IdentityStore, MemoryIdentityStore};
#[cfg(feature = "identity")]
pub use identity_protocol::IdentityProtocolComponent;
pub use lifecycle::{
    AppBuilder, Component, ComponentContext, ComponentFuture, ConfiguredApp, LifecycleState,
    StartedComponent,
};
pub use protocol_registry::ProtocolRegistry;
pub use standard_bundle::{StandardBundle, StandardBundleBuilder};
pub use supervisor::{Health, RunningApp};
