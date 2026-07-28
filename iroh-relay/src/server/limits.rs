use derive_more::Debug;

use super::*;

/// Default relay connection-accept rate per second.
pub const DEFAULT_ACCEPT_CONN_LIMIT: f64 = 200.0;
/// Default relay connection-accept burst.
pub const DEFAULT_ACCEPT_CONN_BURST: usize = 400;
const DEFAULT_MAX_PENDING_ESTABLISHMENTS: usize = 256;
const DEFAULT_MAX_REGISTERED_SESSIONS: usize = 4_096;
const DEFAULT_MAX_SESSIONS_PER_ENDPOINT: usize = 4;
const DEFAULT_ACCEPT_CONN_BURST_NONZERO: NonZeroUsize =
    NonZeroUsize::new(DEFAULT_ACCEPT_CONN_BURST).expect("default accept burst is nonzero");
const DEFAULT_MAX_PENDING_ESTABLISHMENTS_NONZERO: NonZeroUsize =
    NonZeroUsize::new(DEFAULT_MAX_PENDING_ESTABLISHMENTS)
        .expect("default pending-establishment capacity is nonzero");
const DEFAULT_MAX_REGISTERED_SESSIONS_NONZERO: NonZeroUsize =
    NonZeroUsize::new(DEFAULT_MAX_REGISTERED_SESSIONS)
        .expect("default registered-session capacity is nonzero");
const DEFAULT_MAX_SESSIONS_PER_ENDPOINT_NONZERO: NonZeroUsize =
    NonZeroUsize::new(DEFAULT_MAX_SESSIONS_PER_ENDPOINT)
        .expect("default endpoint-session capacity is nonzero");

/// Relay admission and per-client traffic limits.
#[derive(Debug)]
#[non_exhaustive]
pub struct Limits {
    /// Rate limits for incoming traffic from a client connection.
    pub client_rx: Option<ClientRateLimit>,
    /// Rate limit for accepting new connections, in connections per second.
    ///
    /// The rate and burst must either both be set or both be omitted. Omitting both uses the
    /// production default of 200 connections per second.
    pub accept_conn_limit: Option<f64>,
    /// Burst limit for accepting new connections.
    ///
    /// The rate and burst must either both be set or both be omitted. Omitting both uses the
    /// production default of 400 connections.
    pub accept_conn_burst: Option<usize>,
    /// Maximum number of accepted sockets that may still be establishing a relay session.
    pub max_pending_establishments: usize,
    /// Maximum number of registered relay sessions.
    pub max_registered_sessions: usize,
    /// Maximum number of registered relay sessions for one endpoint identity.
    pub max_sessions_per_endpoint: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            client_rx: None,
            accept_conn_limit: None,
            accept_conn_burst: None,
            max_pending_establishments: DEFAULT_MAX_PENDING_ESTABLISHMENTS,
            max_registered_sessions: DEFAULT_MAX_REGISTERED_SESSIONS,
            max_sessions_per_endpoint: DEFAULT_MAX_SESSIONS_PER_ENDPOINT,
        }
    }
}

/// A validated relay admission configuration.
#[derive(Debug, Clone)]
pub(super) struct AdmissionPolicy {
    pub(super) accept_conn_limit: f64,
    pub(super) accept_conn_burst: NonZeroUsize,
    pub(super) max_pending_establishments: NonZeroUsize,
    pub(super) max_registered_sessions: NonZeroUsize,
    pub(super) max_sessions_per_endpoint: NonZeroUsize,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            accept_conn_limit: DEFAULT_ACCEPT_CONN_LIMIT,
            accept_conn_burst: DEFAULT_ACCEPT_CONN_BURST_NONZERO,
            max_pending_establishments: DEFAULT_MAX_PENDING_ESTABLISHMENTS_NONZERO,
            max_registered_sessions: DEFAULT_MAX_REGISTERED_SESSIONS_NONZERO,
            max_sessions_per_endpoint: DEFAULT_MAX_SESSIONS_PER_ENDPOINT_NONZERO,
        }
    }
}

/// Invalid relay admission configuration.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum AdmissionPolicyError {
    #[error("accept_conn_limit and accept_conn_burst must be configured together")]
    IncompleteAcceptRateLimit {},
    #[error("accept_conn_limit must be finite and greater than zero, got {value}")]
    InvalidAcceptRate { value: f64 },
    #[error("accept_conn_burst must be greater than zero")]
    ZeroAcceptBurst {},
    #[error("max_pending_establishments must be greater than zero")]
    ZeroPendingEstablishments {},
    #[error("max_registered_sessions must be greater than zero")]
    ZeroRegisteredSessions {},
    #[error("max_sessions_per_endpoint must be greater than zero")]
    ZeroSessionsPerEndpoint {},
    #[error("{field} value {value} exceeds supported maximum {maximum}")]
    CapacityTooLarge {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
}

impl TryFrom<&Limits> for AdmissionPolicy {
    type Error = AdmissionPolicyError;

    fn try_from(limits: &Limits) -> Result<Self, Self::Error> {
        let (accept_conn_limit, accept_conn_burst) =
            match (limits.accept_conn_limit, limits.accept_conn_burst) {
                (None, None) => (DEFAULT_ACCEPT_CONN_LIMIT, DEFAULT_ACCEPT_CONN_BURST_NONZERO),
                (Some(rate), Some(burst)) => {
                    if !rate.is_finite() || rate <= 0.0 {
                        return Err(e!(AdmissionPolicyError::InvalidAcceptRate { value: rate }));
                    }
                    let burst = NonZeroUsize::new(burst)
                        .ok_or_else(|| e!(AdmissionPolicyError::ZeroAcceptBurst))?;
                    (rate, burst)
                }
                (Some(_), None) | (None, Some(_)) => {
                    return Err(e!(AdmissionPolicyError::IncompleteAcceptRateLimit));
                }
            };

        let max_pending_establishments = NonZeroUsize::new(limits.max_pending_establishments)
            .ok_or_else(|| e!(AdmissionPolicyError::ZeroPendingEstablishments))?;
        let max_registered_sessions = NonZeroUsize::new(limits.max_registered_sessions)
            .ok_or_else(|| e!(AdmissionPolicyError::ZeroRegisteredSessions))?;
        let max_sessions_per_endpoint = NonZeroUsize::new(limits.max_sessions_per_endpoint)
            .ok_or_else(|| e!(AdmissionPolicyError::ZeroSessionsPerEndpoint))?;

        for (field, value) in [
            (
                "max_pending_establishments",
                max_pending_establishments.get(),
            ),
            ("max_registered_sessions", max_registered_sessions.get()),
        ] {
            if value > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(e!(AdmissionPolicyError::CapacityTooLarge {
                    field,
                    value,
                    maximum: tokio::sync::Semaphore::MAX_PERMITS,
                }));
            }
        }

        Ok(Self {
            accept_conn_limit,
            accept_conn_burst,
            max_pending_establishments,
            max_registered_sessions,
            max_sessions_per_endpoint,
        })
    }
}
