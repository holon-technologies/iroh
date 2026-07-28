use std::{
    future::{pending, ready},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use iroh_app::{
    AppBuilder, AppConfig, Component, ComponentContext, ComponentError, ComponentFuture,
    FileIdentityStore, IdentityError, IdentityPolicy, IdentityStore, LifecycleState,
    MemoryIdentityStore, ProtocolRegistry, RegistryError, StartedComponent,
};
use tokio::sync::Notify;

#[derive(Debug)]
struct FakeComponent {
    name: &'static str,
    fail_start: bool,
    runtime_failure: Arc<Notify>,
    shutdown_hangs: bool,
    events: Arc<std::sync::Mutex<Vec<String>>>,
    dropped: Arc<AtomicBool>,
}

impl FakeComponent {
    fn healthy(name: &'static str, events: Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        Self {
            name,
            fail_start: false,
            runtime_failure: Arc::new(Notify::new()),
            shutdown_hangs: false,
            events,
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[derive(Debug)]
struct DropCanary(Arc<AtomicBool>);

impl Drop for DropCanary {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Component for FakeComponent {
    fn name(&self) -> &str {
        self.name
    }

    fn start(
        &self,
        context: ComponentContext,
    ) -> ComponentFuture<Result<StartedComponent, ComponentError>> {
        let name = self.name;
        let fail_start = self.fail_start;
        let runtime_failure = self.runtime_failure.clone();
        let shutdown_hangs = self.shutdown_hangs;
        let events = self.events.clone();
        let dropped = self.dropped.clone();
        Box::pin(async move {
            events.lock().unwrap().push(format!("start:{name}"));
            if fail_start {
                return Err(ComponentError::new("injected startup failure"));
            }
            let run = async move {
                let _canary = DropCanary(dropped);
                tokio::select! {
                    () = context.cancelled() => Ok(()),
                    () = runtime_failure.notified() => {
                        Err(ComponentError::new("injected runtime failure"))
                    }
                }
            };
            let shutdown = move || async move {
                events.lock().unwrap().push(format!("stop:{name}"));
                if shutdown_hangs {
                    pending::<Result<(), ComponentError>>().await
                } else {
                    ready(Ok(())).await
                }
            };
            Ok(StartedComponent::new(run, shutdown))
        })
    }
}

#[derive(Debug)]
struct CountingIdentityStore {
    calls: Arc<AtomicUsize>,
    fail: bool,
}

impl IdentityStore for CountingIdentityStore {
    fn load(&self) -> ComponentFuture<Result<Option<iroh_base::SecretKey>, IdentityError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(IdentityError::unavailable("load"))
            } else {
                Ok(None)
            }
        })
    }

    fn create(
        &self,
        _identity: iroh_base::SecretKey,
    ) -> ComponentFuture<Result<(), IdentityError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn replace(
        &self,
        _identity: iroh_base::SecretKey,
    ) -> ComponentFuture<Result<(), IdentityError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn invalid_configuration_has_no_identity_side_effects() {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(CountingIdentityStore {
        calls: calls.clone(),
        fail: false,
    });
    let config = AppConfig::default().with_protocol_limit(0);
    assert!(AppBuilder::new(store).config(config).build().is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn registry_rejects_duplicate_oversized_and_excess_alpns() {
    let mut registry = ProtocolRegistry::new(2, 8).unwrap();
    registry.register_marker(b"/one", "one").unwrap();
    assert!(matches!(
        registry.register_marker(b"/one", "duplicate"),
        Err(RegistryError::Duplicate { .. })
    ));
    assert!(matches!(
        registry.register_marker(b"/way-too-long", "large"),
        Err(RegistryError::AlpnTooLong { .. })
    ));
    registry.register_marker(b"/two", "two").unwrap();
    assert!(matches!(
        registry.register_marker(b"/tri", "three"),
        Err(RegistryError::ProtocolLimit { .. })
    ));
}

#[tokio::test]
async fn identity_failure_precedes_component_side_effects() {
    let calls = Arc::new(AtomicUsize::new(0));
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let app = AppBuilder::new(Arc::new(CountingIdentityStore {
        calls: calls.clone(),
        fail: true,
    }))
    .component(FakeComponent::healthy("network", events.clone()))
    .build()
    .unwrap();

    let error = app.start().await.unwrap_err();
    assert_eq!(error.stage(), "identity");
    assert!(events.lock().unwrap().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn startup_failure_rolls_back_started_components_in_reverse_order() {
    for failing_index in 0..3 {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut builder = AppBuilder::new(Arc::new(MemoryIdentityStore::new()));
        for index in 0..3 {
            let mut component =
                FakeComponent::healthy(["first", "second", "third"][index], events.clone());
            component.fail_start = index == failing_index;
            builder = builder.component(component);
        }

        let error = builder.build().unwrap().start().await.unwrap_err();
        assert_eq!(error.stage(), ["first", "second", "third"][failing_index]);
        let expected_stops: Vec<_> = (0..failing_index)
            .rev()
            .map(|index| format!("stop:{}", ["first", "second", "third"][index]))
            .collect();
        let actual_stops: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.starts_with("stop:"))
            .cloned()
            .collect();
        assert_eq!(actual_stops, expected_stops);
    }
}

#[tokio::test]
async fn runtime_failure_changes_health_and_triggers_fail_fast_shutdown() {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let failing = FakeComponent::healthy("failing", events.clone());
    let trigger = failing.runtime_failure.clone();
    let running = AppBuilder::new(Arc::new(MemoryIdentityStore::new()))
        .component(failing)
        .component(FakeComponent::healthy("peer", events))
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();

    trigger.notify_one();
    let failure = running.wait_for_failure().await.unwrap();
    assert_eq!(failure.component(), "failing");
    assert!(matches!(
        running.state(),
        LifecycleState::Draining | LifecycleState::Failed
    ));
    assert!(running.shutdown().await.is_err());
}

#[tokio::test]
async fn concurrent_shutdown_is_idempotent() {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let running = AppBuilder::new(Arc::new(MemoryIdentityStore::new()))
        .component(FakeComponent::healthy("worker", events.clone()))
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();

    let second_handle = running.clone();
    let (left, right) = tokio::join!(running.shutdown(), second_handle.shutdown());
    assert!(left.is_ok());
    assert!(right.is_ok());
    assert_eq!(running.state(), LifecycleState::Stopped);
    assert_eq!(
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "stop:worker")
            .count(),
        1
    );
}

#[tokio::test]
async fn shutdown_uses_one_absolute_deadline_and_reports_timeout() {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut component = FakeComponent::healthy("stuck", events);
    component.shutdown_hangs = true;
    let running = AppBuilder::new(Arc::new(MemoryIdentityStore::new()))
        .config(AppConfig::default().with_shutdown_timeout(Duration::from_millis(25)))
        .component(component)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();

    let error = running.shutdown().await.unwrap_err();
    assert!(error.timed_out().iter().any(|name| name == "stuck"));
    assert_eq!(running.state(), LifecycleState::Failed);
}

#[tokio::test]
async fn dropping_last_handle_cancels_owned_tasks() {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let component = FakeComponent::healthy("worker", events);
    let dropped = component.dropped.clone();
    let running = AppBuilder::new(Arc::new(MemoryIdentityStore::new()))
        .component(component)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    tokio::task::yield_now().await;
    drop(running);
    tokio::task::yield_now().await;
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn identity_policy_is_explicit_and_memory_identity_is_stable() {
    let store = Arc::new(MemoryIdentityStore::new());
    let first = AppBuilder::new(store.clone())
        .identity_policy(IdentityPolicy::LoadOrCreate)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    let first_id = first.endpoint_id();
    first.shutdown().await.unwrap();

    let second = AppBuilder::new(store)
        .identity_policy(IdentityPolicy::LoadOnly)
        .build()
        .unwrap()
        .start()
        .await
        .unwrap();
    assert_eq!(first_id, second.endpoint_id());
    second.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn file_identity_is_atomic_private_and_errors_redact_paths() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let secret_name = "do-not-leak-identity-name";
    let path = root.path().join(secret_name);
    let store = FileIdentityStore::new(&path);
    let identity = iroh_base::SecretKey::generate();
    store.create(identity.clone()).await.unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0);
    assert_eq!(
        store.load().await.unwrap().unwrap().public(),
        identity.public()
    );
    let error = store.create(identity).await.unwrap_err();
    assert!(!error.to_string().contains(secret_name));
}
