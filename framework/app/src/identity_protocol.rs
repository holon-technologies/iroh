//! Opt-in account-identity protocol composition for the standard application bundle.

use std::{fmt, sync::Arc};

use krikos::Endpoint;
use krikos_identity::{
    AccountStore, CursorKey,
    net::{IdentityProtocolHandlers, IdentityProtocolKind, IdentityProtocolService},
    transport::VerifiedCheckpointView,
};

use crate::{ProtocolRegistry, RegistryError};

/// Account-identity protocol dependencies composed with the application's existing endpoint.
///
/// This component owns no endpoint secret. `krikos-app::IdentityStore` remains the sole endpoint
/// key persistence boundary; the account store supplied here contains Krikos account source
/// records only.
pub struct IdentityProtocolComponent {
    account_store: Arc<dyn AccountStore>,
    service: Arc<dyn IdentityProtocolService>,
    checkpoints: Arc<dyn VerifiedCheckpointView>,
    cursor_key: CursorKey,
}

impl fmt::Debug for IdentityProtocolComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityProtocolComponent")
            .finish_non_exhaustive()
    }
}

impl IdentityProtocolComponent {
    /// Compose account source storage, operational callbacks, checkpoint lookup, and cursor key.
    pub fn new(
        account_store: Arc<dyn AccountStore>,
        service: Arc<dyn IdentityProtocolService>,
        checkpoints: Arc<dyn VerifiedCheckpointView>,
        cursor_key: CursorKey,
    ) -> Self {
        Self {
            account_store,
            service,
            checkpoints,
            cursor_key,
        }
    }

    pub(crate) fn register(
        self,
        _endpoint: &Endpoint,
        protocols: &mut ProtocolRegistry,
    ) -> Result<(), RegistryError> {
        let handlers = IdentityProtocolHandlers::new(
            self.service,
            self.checkpoints,
            self.account_store,
            self.cursor_key,
        );
        for kind in [
            IdentityProtocolKind::Pairing,
            IdentityProtocolKind::Sync,
            IdentityProtocolKind::Proposal,
            IdentityProtocolKind::Checkpoint,
            IdentityProtocolKind::TransparencyGossip,
            IdentityProtocolKind::Recovery,
        ] {
            protocols.register(kind.alpn(), handlers.handler(kind))?;
        }
        Ok(())
    }
}

pub(crate) const IDENTITY_PROTOCOL_COUNT: usize = 6;

pub(crate) fn is_identity_alpn(alpn: &[u8]) -> bool {
    [
        IdentityProtocolKind::Pairing,
        IdentityProtocolKind::Sync,
        IdentityProtocolKind::Proposal,
        IdentityProtocolKind::Checkpoint,
        IdentityProtocolKind::TransparencyGossip,
        IdentityProtocolKind::Recovery,
    ]
    .into_iter()
    .any(|kind| kind.alpn() == alpn)
}
