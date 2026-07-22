#[cfg(wasm_browser)]
use n0_future::time::Instant;
use n0_future::time::{self, Duration};
#[cfg(not(wasm_browser))]
use std::time::Instant;
use tracing::debug;

/// Maximum time for a ping response in the relay protocol.
const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum timeout for an RTT-based health check ping.
const MIN_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_millis(500);

/// Tracks pings on a single relay connection.
///
/// Only the last ping needs is useful, any previously sent ping is forgotten and ignored.
#[derive(Debug)]
pub struct PingTracker {
    inner: Option<PingInner>,
    max_timeout: Duration,
    /// Last measured round-trip time to the relay server.
    last_rtt: Option<Duration>,
}

#[derive(Debug)]
struct PingInner {
    data: [u8; 8],
    deadline: Instant,
    sent_at: Instant,
}

impl Default for PingTracker {
    fn default() -> Self {
        Self::new(PING_TIMEOUT)
    }
}

impl PingTracker {
    /// Creates a new ping tracker with the given maximum ping timeout.
    pub fn new(max_timeout: Duration) -> Self {
        Self {
            inner: None,
            max_timeout,
            last_rtt: None,
        }
    }

    /// Returns the maximum ping timeout.
    pub fn max_timeout(&self) -> Duration {
        self.max_timeout
    }

    /// Starts a new ping with an RTT-based timeout.
    pub fn new_ping(&mut self) -> [u8; 8] {
        let timeout = self.ping_timeout();
        self.new_ping_with_timeout(timeout)
    }

    /// Starts a new ping with a custom timeout.
    pub fn new_ping_with_timeout(&mut self, timeout: Duration) -> [u8; 8] {
        let ping_data = rand::random();
        self.new_ping_with_data_at(timeout, ping_data, Instant::now())
    }

    /// Starts a ping from caller-owned entropy and monotonic time.
    pub fn new_ping_with_data_at(
        &mut self,
        timeout: Duration,
        ping_data: [u8; 8],
        now: Instant,
    ) -> [u8; 8] {
        debug!(data = ?ping_data, "Sending ping to relay server.");
        self.inner = Some(PingInner {
            data: ping_data,
            deadline: now + timeout,
            sent_at: now,
        });
        ping_data
    }

    /// Updates the ping tracker with a received pong.
    ///
    /// Only the pong of the most recent ping will do anything.  There is no harm feeding
    /// any pong however.
    pub fn pong_received(&mut self, data: [u8; 8]) {
        self.pong_received_at(data, Instant::now());
    }

    /// Updates the tracker using caller-owned monotonic time.
    pub fn pong_received_at(&mut self, data: [u8; 8], now: Instant) {
        if let Some(inner) = &self.inner
            && inner.data == data
        {
            let rtt = now.saturating_duration_since(inner.sent_at);
            debug!(?data, ?rtt, "Pong received from relay server");
            self.last_rtt = Some(rtt);
            self.inner = None;
        }
    }

    /// Returns the timeout for the next ping.
    ///
    /// Uses 3x the last measured RTT (to account for jitter), falling back to
    /// the default timeout if no RTT has been measured yet.
    pub fn ping_timeout(&self) -> Duration {
        self.last_rtt
            .map(|rtt| (rtt * 3).clamp(MIN_HEALTH_CHECK_TIMEOUT, self.max_timeout))
            .unwrap_or(self.max_timeout)
    }

    /// Returns the current ping deadline, if a ping is outstanding.
    pub fn deadline(&self) -> Option<Instant> {
        self.inner.as_ref().map(|inner| inner.deadline)
    }

    /// Marks the current ping as timed out.
    pub fn timeout_elapsed(&mut self) {
        if let Some(PingInner { data, .. }) = self.inner.take() {
            debug!(?data, "Ping timeout.");
        }
    }

    /// Cancel-safe waiting for a ping timeout.
    ///
    /// Unless the most recent sent ping times out, this will never return.
    pub async fn timeout(&mut self) {
        match self.inner {
            Some(PingInner { deadline, data, .. }) => {
                #[cfg(not(wasm_browser))]
                let deadline = deadline.into();
                time::sleep_until(deadline).await;
                debug!(?data, "Ping timeout.");
                self.inner = None;
            }
            None => std::future::pending().await,
        }
    }
}
