use super::*;

/// Connection status of a single home relay.
///
/// Observed via [`Endpoint::home_relay_status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatus {
    url: RelayUrl,
    state: RelayConnectionState,
}

impl RelayStatus {
    pub(crate) fn new(url: RelayUrl, state: RelayConnectionState) -> Self {
        Self { url, state }
    }

    /// Returns the URL of the home relay.
    pub fn url(&self) -> &RelayUrl {
        &self.url
    }

    /// Returns `true` if the endpoint is connected to the relay.
    pub fn is_connected(&self) -> bool {
        self.state.is_connected()
    }

    /// Returns the most recent connection error, if the relay is currently
    /// disconnected.
    ///
    /// Returns `None` when the relay is connected, or when the endpoint has
    /// not yet observed a failed connection attempt.
    pub fn last_error(&self) -> Option<&AnyError> {
        self.state.last_error().map(Arc::as_ref)
    }
}

/// Configuration of the relay servers for an [`Endpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMode {
    /// Disable relay servers completely.
    /// This means that neither listening nor dialing relays will be available.
    Disabled,
    /// Use the default relay map, with production relay servers from n0.
    ///
    /// See [`crate::defaults::prod`] for the severs used.
    Default,
    /// Use the staging relay servers from n0.
    Staging,
    /// Use a custom relay map.
    Custom(RelayMap),
}

impl RelayMode {
    /// Returns the relay map for this mode.
    pub fn relay_map(&self) -> RelayMap {
        match self {
            RelayMode::Disabled => RelayMap::empty(),
            RelayMode::Default => crate::defaults::prod::default_relay_map(),
            RelayMode::Staging => crate::defaults::staging::default_relay_map(),
            RelayMode::Custom(relay_map) => relay_map.clone(),
        }
    }

    /// Create a custom relay mode from a list of [`RelayUrl`]s.
    ///
    /// # Example
    ///
    /// ```
    /// # fn main() -> n0_error::Result<()> {
    /// # use iroh::RelayMode;
    /// RelayMode::custom([
    ///     "https://use1-1.relay.n0.iroh.link.".parse()?,
    ///     "https://euw-1.relay.n0.iroh.link.".parse()?,
    /// ]);
    /// # Ok(()) }
    /// ```
    pub fn custom(map: impl IntoIterator<Item = RelayUrl>) -> Self {
        let m = RelayMap::from_iter(map);
        Self::Custom(m)
    }
}

/// Environment variable to force the use of staging relays.
pub const ENV_FORCE_STAGING_RELAYS: &str = "IROH_FORCE_STAGING_RELAYS";

/// Returns `true` if the use of staging relays is forced.
pub fn force_staging_infra() -> bool {
    matches!(std::env::var(ENV_FORCE_STAGING_RELAYS), Ok(value) if !value.is_empty())
}

/// Returns the default relay mode.
///
/// If the `IROH_FORCE_STAGING_RELAYS` environment variable is non empty, it will return `RelayMode::Staging`.
/// Otherwise, it will return `RelayMode::Default`.
pub fn default_relay_mode() -> RelayMode {
    // Use staging in testing
    match force_staging_infra() {
        true => RelayMode::Staging,
        false => RelayMode::Default,
    }
}
