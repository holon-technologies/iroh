//! Deterministic root-operation driver for simulator harness futures.

use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use crate::{Kernel, KernelError, KernelStep, Quiescence};

/// Polls harness-owned root operations around deterministic kernel steps.
///
/// The root operation is polled in a fixed lane before each kernel step. Endpoint and relay
/// children, timers, and environment events are owned and selected by the kernel itself.
#[derive(Clone, Debug)]
pub struct KernelDriver {
    kernel: Kernel,
    max_turns: u64,
}

impl KernelDriver {
    /// Creates a driver with a hard root-poll/kernel-step watchdog.
    pub fn new(kernel: Kernel, max_turns: u64) -> Result<Self, KernelDriverError> {
        if max_turns == 0 {
            return Err(KernelDriverError::InvalidConfig);
        }
        Ok(Self { kernel, max_turns })
    }

    /// Drives one root operation to completion.
    #[allow(
        clippy::unused_async,
        reason = "the driver is an async orchestration boundary that manually polls its root future"
    )]
    pub async fn drive<F: Future>(&self, future: F) -> Result<F::Output, KernelDriverError> {
        let mut future = std::pin::pin!(future);
        let root_wake = Arc::new(RootWake(AtomicBool::new(true)));
        let waker = Waker::from(root_wake.clone());
        let mut context = Context::from_waker(&waker);
        for _ in 0..self.max_turns {
            if root_wake.0.swap(false, Ordering::AcqRel) {
                let mut root_poll = tokio::task::unconstrained(Pin::as_mut(&mut future));
                if let Poll::Ready(result) = Future::poll(Pin::new(&mut root_poll), &mut context) {
                    return Ok(result);
                }
            }
            match self.kernel.step()? {
                KernelStep::Progress => {}
                KernelStep::Idle(run) => {
                    return Err(KernelDriverError::Stalled {
                        live_tasks: match run.quiescence {
                            Quiescence::Complete => 0,
                            Quiescence::Stalled { live_tasks } => live_tasks,
                        },
                    });
                }
            }
        }
        Err(KernelDriverError::WatchdogExhausted {
            max_turns: self.max_turns,
        })
    }

    /// Drives kernel work until an externally observable condition becomes true.
    #[allow(
        clippy::unused_async,
        reason = "the driver keeps one await-compatible API for root operations and conditions"
    )]
    pub async fn drive_until(&self, condition: impl Fn() -> bool) -> Result<(), KernelDriverError> {
        for _ in 0..self.max_turns {
            if condition() {
                return Ok(());
            }
            match self.kernel.step()? {
                KernelStep::Progress => {}
                KernelStep::Idle(run) => {
                    return Err(KernelDriverError::Stalled {
                        live_tasks: match run.quiescence {
                            Quiescence::Complete => 0,
                            Quiescence::Stalled { live_tasks } => live_tasks,
                        },
                    });
                }
            }
        }
        Err(KernelDriverError::WatchdogExhausted {
            max_turns: self.max_turns,
        })
    }

    /// Gives already-enqueued endpoint work one deterministic kernel step.
    #[allow(
        clippy::unused_async,
        reason = "the driver keeps one await-compatible API for deterministic kernel turns"
    )]
    pub async fn drive_one(&self) -> Result<(), KernelDriverError> {
        match self.kernel.step()? {
            KernelStep::Progress => Ok(()),
            KernelStep::Idle(run) => Err(KernelDriverError::Stalled {
                live_tasks: match run.quiescence {
                    Quiescence::Complete => 0,
                    Quiescence::Stalled { live_tasks } => live_tasks,
                },
            }),
        }
    }
}

/// Root readiness is retained explicitly and never delegated to an external executor.
#[derive(Debug)]
struct RootWake(AtomicBool);

impl Wake for RootWake {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

/// The deterministic root driver could not continue safely.
#[derive(Debug)]
pub enum KernelDriverError {
    /// A zero watchdog bound is invalid.
    InvalidConfig,
    /// The deterministic kernel rejected a step.
    Kernel(KernelError),
    /// The root remained pending with no kernel work able to wake it.
    Stalled { live_tasks: u64 },
    /// The operation did not complete within the configured hard bound.
    WatchdogExhausted { max_turns: u64 },
}

impl fmt::Display for KernelDriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("kernel driver max_turns must be nonzero"),
            Self::Kernel(error) => write!(f, "kernel driver failure: {error}"),
            Self::Stalled { live_tasks } => write!(
                f,
                "kernel root operation stalled with {live_tasks} retained task(s)"
            ),
            Self::WatchdogExhausted { max_turns } => {
                write!(f, "kernel driver exhausted {max_turns} deterministic turns")
            }
        }
    }
}

impl std::error::Error for KernelDriverError {}

impl From<KernelError> for KernelDriverError {
    fn from(value: KernelError) -> Self {
        Self::Kernel(value)
    }
}
