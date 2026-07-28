use std::{
    collections::BTreeSet,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use iroh_base::EndpointId;
use tokio::{
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

use crate::{
    ComponentContext, ComponentError, ComponentFailure, ConfiguredApp, ControlError, FailurePhase,
    LifecycleState, ProtocolRegistry, ShutdownError, ShutdownReport, StartupError, WaitError,
    identity::resolve_identity, lifecycle::ShutdownAction,
};

#[derive(Clone, Debug)]
enum SupervisorCommand {
    RefreshHealth,
}

/// Current aggregate lifecycle health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Health {
    state: LifecycleState,
    failure: Option<ComponentFailure>,
}

impl Health {
    /// Current explicit lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    /// First observed runtime or shutdown failure.
    #[must_use]
    pub const fn failure(&self) -> Option<&ComponentFailure> {
        self.failure.as_ref()
    }
}

struct RunningInner {
    endpoint_id: EndpointId,
    cancellation: CancellationToken,
    health: watch::Receiver<Health>,
    report: Arc<Mutex<Option<ShutdownReport>>>,
    task: Mutex<Option<JoinHandle<()>>>,
    control: mpsc::Sender<SupervisorCommand>,
    shutdown_timeout: Duration,
    _protocols: ProtocolRegistry,
}

impl fmt::Debug for RunningInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunningInner")
            .field("endpoint_id", &self.endpoint_id)
            .field("state", &self.health.borrow().state)
            .finish_non_exhaustive()
    }
}

impl Drop for RunningInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Ok(mut task) = self.task.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}

/// Cloneable handle to one fully started application.
#[derive(Clone, Debug)]
pub struct RunningApp {
    inner: Arc<RunningInner>,
}

impl RunningApp {
    /// Stable endpoint identity for this application.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.inner.endpoint_id
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.inner.health.borrow().state
    }

    /// Current aggregate health snapshot.
    #[must_use]
    pub fn health(&self) -> Health {
        self.inner.health.borrow().clone()
    }

    /// Requests a low-cost health refresh without waiting for queue capacity.
    pub fn try_refresh_health(&self) -> Result<(), ControlError> {
        self.inner
            .control
            .try_send(SupervisorCommand::RefreshHealth)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ControlError::QueueSaturated,
                mpsc::error::TrySendError::Closed(_) => ControlError::Stopped,
            })
    }

    /// Waits for the first runtime failure.
    pub async fn wait_for_failure(&self) -> Result<ComponentFailure, WaitError> {
        let mut health = self.inner.health.clone();
        loop {
            let snapshot = health.borrow().clone();
            if let Some(failure) = snapshot.failure {
                return Ok(failure);
            }
            if matches!(
                snapshot.state,
                LifecycleState::Stopped | LifecycleState::Failed
            ) {
                return Err(WaitError);
            }
            if health.changed().await.is_err() {
                return Err(WaitError);
            }
        }
    }

    /// Idempotently drains all components within one absolute deadline.
    pub async fn shutdown(&self) -> Result<ShutdownReport, ShutdownError> {
        self.inner.cancellation.cancel();
        let mut health = self.inner.health.clone();
        let wait = async {
            loop {
                let state = health.borrow().state;
                if matches!(state, LifecycleState::Stopped | LifecycleState::Failed) {
                    break;
                }
                if health.changed().await.is_err() {
                    break;
                }
            }
        };
        let outer_timeout = self
            .inner
            .shutdown_timeout
            .saturating_add(Duration::from_secs(1));
        if timeout(outer_timeout, wait).await.is_err() {
            let report = ShutdownReport {
                failed: Vec::new(),
                timed_out: vec!["supervisor".to_owned()],
            };
            return Err(ShutdownError { report });
        }

        let task = self.inner.task.lock().ok().and_then(|mut task| task.take());
        if let Some(task) = task {
            let _ = task.await;
        }
        let report = self
            .inner
            .report
            .lock()
            .ok()
            .and_then(|report| report.clone())
            .unwrap_or_else(|| ShutdownReport {
                failed: Vec::new(),
                timed_out: vec!["supervisor".to_owned()],
            });
        if report.is_clean() {
            Ok(report)
        } else {
            Err(ShutdownError { report })
        }
    }
}

struct OwnedComponent {
    name: String,
    run: crate::ComponentFuture<Result<(), ComponentError>>,
    shutdown: ShutdownAction,
}

pub(crate) async fn start(mut configured: ConfiguredApp) -> Result<RunningApp, StartupError> {
    debug_assert!(LifecycleState::Configured.can_transition_to(LifecycleState::Starting));
    let identity = match timeout(
        configured.config.startup_timeout,
        resolve_identity(&*configured.identity_store, configured.identity_policy),
    )
    .await
    {
        Ok(Ok(identity)) => identity,
        Ok(Err(error)) => {
            return Err(startup_error("identity", error, ShutdownReport::default()));
        }
        Err(_) => {
            return Err(startup_error(
                "identity",
                ComponentError::new("identity startup deadline exceeded"),
                ShutdownReport::default(),
            ));
        }
    };

    let cancellation = CancellationToken::new();
    let mut started = Vec::with_capacity(configured.components.len());
    for component in configured.components.drain(..) {
        let name = component.name().to_owned();
        let context = ComponentContext::new(cancellation.clone());
        let result = timeout(configured.config.startup_timeout, component.start(context)).await;
        match result {
            Ok(Ok(component)) => started.push(OwnedComponent {
                name,
                run: component.run,
                shutdown: component.shutdown,
            }),
            Ok(Err(error)) => {
                cancellation.cancel();
                let cleanup = rollback(started, configured.config.shutdown_timeout).await;
                return Err(startup_error(name, error, cleanup));
            }
            Err(_) => {
                cancellation.cancel();
                let cleanup = rollback(started, configured.config.shutdown_timeout).await;
                return Err(startup_error(
                    name,
                    ComponentError::new("component startup deadline exceeded"),
                    cleanup,
                ));
            }
        }
    }

    let (health_tx, health_rx) = watch::channel(Health {
        state: LifecycleState::Running,
        failure: None,
    });
    let report = Arc::new(Mutex::new(None));
    let report_for_task = report.clone();
    let (control_tx, control_rx) = mpsc::channel(configured.config.command_queue_capacity);
    let task_cancellation = cancellation.clone();
    let shutdown_timeout = configured.config.shutdown_timeout;
    let fail_fast = configured.config.fail_fast;
    let task = tokio::spawn(async move {
        supervise(
            started,
            task_cancellation,
            health_tx,
            control_rx,
            report_for_task,
            shutdown_timeout,
            fail_fast,
        )
        .await;
    });
    let protocols = configured.take_protocols();
    Ok(RunningApp {
        inner: Arc::new(RunningInner {
            endpoint_id: identity.public(),
            cancellation,
            health: health_rx,
            report,
            task: Mutex::new(Some(task)),
            control: control_tx,
            shutdown_timeout,
            _protocols: protocols,
        }),
    })
}

fn startup_error(
    stage: impl Into<String>,
    error: impl fmt::Display,
    cleanup: ShutdownReport,
) -> StartupError {
    let stage = stage.into();
    StartupError {
        failure: ComponentFailure::new(stage.clone(), FailurePhase::Startup, error),
        stage,
        cleanup,
    }
}

async fn rollback(components: Vec<OwnedComponent>, timeout_duration: Duration) -> ShutdownReport {
    let deadline = Instant::now() + timeout_duration;
    let mut report = ShutdownReport::default();
    for component in components.into_iter().rev() {
        match timeout_at(deadline, (component.shutdown)()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => report.failed.push(ComponentFailure::new(
                component.name,
                FailurePhase::Shutdown,
                error,
            )),
            Err(_) => report.timed_out.push(component.name),
        }
    }
    report
}

async fn supervise(
    components: Vec<OwnedComponent>,
    cancellation: CancellationToken,
    health_tx: watch::Sender<Health>,
    mut control_rx: mpsc::Receiver<SupervisorCommand>,
    report_slot: Arc<Mutex<Option<ShutdownReport>>>,
    shutdown_timeout: Duration,
    fail_fast: bool,
) {
    let mut tasks = JoinSet::new();
    let mut shutdowns = Vec::with_capacity(components.len());
    let mut active = BTreeSet::new();
    for component in components {
        active.insert(component.name.clone());
        shutdowns.push((component.name.clone(), component.shutdown));
        tasks.spawn(async move { (component.name, component.run.await) });
    }

    let mut first_failure = None;
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            command = control_rx.recv() => {
                if matches!(command, Some(SupervisorCommand::RefreshHealth)) {
                    let _ = health_tx.send(health_tx.borrow().clone());
                }
                if command.is_none() {
                    cancellation.cancel();
                    break;
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                let failure = match result {
                    Some(Ok((name, Ok(())))) => {
                        active.remove(&name);
                        ComponentFailure::new(name, FailurePhase::Runtime, "component exited unexpectedly")
                    }
                    Some(Ok((name, Err(error)))) => {
                        active.remove(&name);
                        ComponentFailure::new(name, FailurePhase::Runtime, error)
                    }
                    Some(Err(error)) => ComponentFailure::new(
                        "component-task",
                        FailurePhase::Runtime,
                        error,
                    ),
                    None => break,
                };
                if first_failure.is_none() {
                    first_failure = Some(failure.clone());
                    let _ = health_tx.send(Health {
                        state: LifecycleState::Draining,
                        failure: Some(failure),
                    });
                }
                if fail_fast || tasks.is_empty() {
                    cancellation.cancel();
                    break;
                }
            }
        }
    }

    debug_assert!(LifecycleState::Running.can_transition_to(LifecycleState::Draining));
    let _ = health_tx.send(Health {
        state: LifecycleState::Draining,
        failure: first_failure.clone(),
    });
    let deadline = Instant::now() + shutdown_timeout;
    let mut report = ShutdownReport::default();
    if let Some(failure) = first_failure.clone() {
        report.failed.push(failure);
    }

    for (name, shutdown) in shutdowns.into_iter().rev() {
        match timeout_at(deadline, shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let failure = ComponentFailure::new(name, FailurePhase::Shutdown, error);
                if first_failure.is_none() {
                    first_failure = Some(failure.clone());
                }
                report.failed.push(failure);
            }
            Err(_) => report.timed_out.push(name),
        }
    }

    while !tasks.is_empty() {
        match timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok((name, result)))) => {
                active.remove(&name);
                if let Err(error) = result {
                    let failure = ComponentFailure::new(name, FailurePhase::Runtime, error);
                    if !report
                        .failed
                        .iter()
                        .any(|item| item.component() == failure.component())
                    {
                        report.failed.push(failure);
                    }
                }
            }
            Ok(Some(Err(error))) => report.failed.push(ComponentFailure::new(
                "component-task",
                FailurePhase::Shutdown,
                error,
            )),
            Ok(None) => break,
            Err(_) => {
                report.timed_out.extend(active.iter().cloned());
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
        }
    }
    report.timed_out.sort();
    report.timed_out.dedup();
    let final_state = if report.is_clean() {
        LifecycleState::Stopped
    } else {
        LifecycleState::Failed
    };
    debug_assert!(LifecycleState::Draining.can_transition_to(final_state));
    if let Ok(mut slot) = report_slot.lock() {
        *slot = Some(report.clone());
    }
    let _ = health_tx.send(Health {
        state: final_state,
        failure: first_failure.or_else(|| report.failed.first().cloned()),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_control_queue_reports_saturation() {
        let (sender, _receiver) = mpsc::channel(1);
        sender.try_send(SupervisorCommand::RefreshHealth).unwrap();
        assert!(matches!(
            sender.try_send(SupervisorCommand::RefreshHealth),
            Err(mpsc::error::TrySendError::Full(_))
        ));
    }
}
