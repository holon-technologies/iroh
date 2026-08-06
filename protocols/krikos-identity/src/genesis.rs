//! Canonical account genesis and stable account identity.

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountId, ControlPolicy, ControllerDescriptor, Extensions, GenesisAnchor, HashAlgorithm,
    IdentityError, ProtocolVersion, ProviderPolicy, ProviderPolicyVersion, RecoveryPolicy,
    RecoveryPolicyVersion, Timestamp,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::MAX_CONTROLLERS,
    schema::BoundedVec,
};

/// Secret-free canonical root of one stable account identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountGenesis {
    protocol_version: ProtocolVersion,
    account_nonce: [u8; 32],
    created_at: Timestamp,
    hash_algorithm: HashAlgorithm,
    initial_policy: ControlPolicy,
    initial_controllers: BoundedVec<ControllerDescriptor, MAX_CONTROLLERS>,
    initial_recovery_policy: RecoveryPolicy,
    initial_provider_policy: ProviderPolicy,
    extensions: Extensions,
}

impl AccountGenesis {
    /// Validate, canonically sort, and construct account genesis.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_nonce: [u8; 32],
        created_at: Timestamp,
        initial_policy: ControlPolicy,
        initial_controllers: Vec<ControllerDescriptor>,
        initial_recovery_policy: RecoveryPolicy,
        initial_provider_policy: ProviderPolicy,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if initial_controllers.len() > MAX_CONTROLLERS {
            return Err(IdentityError::limit(
                "initial controllers",
                initial_controllers.len(),
                MAX_CONTROLLERS,
            ));
        }
        let mut identified = initial_controllers
            .into_iter()
            .map(|controller| Ok((controller.id()?, controller)))
            .collect::<Result<Vec<_>, IdentityError>>()?;
        identified.sort_unstable_by_key(|(id, _)| *id);
        let controllers = identified
            .into_iter()
            .map(|(_, controller)| controller)
            .collect();
        Self::from_sorted(
            account_nonce,
            created_at,
            initial_policy,
            controllers,
            initial_recovery_policy,
            initial_provider_policy,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_sorted(
        account_nonce: [u8; 32],
        created_at: Timestamp,
        initial_policy: ControlPolicy,
        initial_controllers: Vec<ControllerDescriptor>,
        initial_recovery_policy: RecoveryPolicy,
        initial_provider_policy: ProviderPolicy,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if account_nonce == [0; 32] {
            return Err(IdentityError::ZeroValue {
                resource: "account nonce",
            });
        }
        if initial_controllers.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "initial controllers",
            });
        }
        let initial_controllers = BoundedVec::new("initial controllers", initial_controllers)?;
        for pair in initial_controllers.as_slice().windows(2) {
            let left = pair[0].id()?;
            let right = pair[1].id()?;
            if left == right {
                return Err(IdentityError::DuplicateElement {
                    resource: "initial controller identifiers",
                });
            }
            if left > right {
                return Err(IdentityError::NonCanonical);
            }
        }
        for (index, controller) in initial_controllers.as_slice().iter().enumerate() {
            if initial_controllers.as_slice()[..index]
                .iter()
                .any(|prior| prior.signing_key() == controller.signing_key())
            {
                return Err(IdentityError::DuplicateSigningKey);
            }
        }
        if initial_provider_policy.policy_version() != ProviderPolicyVersion::GENESIS {
            return Err(IdentityError::InvalidPolicy {
                resource: "genesis provider version",
            });
        }
        if initial_recovery_policy.policy_version() != RecoveryPolicyVersion::GENESIS {
            return Err(IdentityError::InvalidPolicy {
                resource: "genesis recovery version",
            });
        }
        initial_policy.validate_satisfiable(initial_controllers.as_slice())?;
        initial_recovery_policy.validate_controller_authority(initial_controllers.as_slice())?;
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            account_nonce,
            created_at,
            hash_algorithm: HashAlgorithm::Blake3_256,
            initial_policy,
            initial_controllers,
            initial_recovery_policy,
            initial_provider_policy,
            extensions,
        })
    }

    /// Stable account identifier derived directly from canonical genesis.
    pub fn account_id(&self) -> Result<AccountId, IdentityError> {
        AccountId::derive(self)
    }

    /// Domain-separated predecessor required by the first account event.
    pub fn genesis_anchor(&self) -> Result<GenesisAnchor, IdentityError> {
        GenesisAnchor::derive(self)
    }

    /// Explicit creation timestamp; metadata only, never ordering authority.
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Initial control policy.
    pub const fn initial_policy(&self) -> &ControlPolicy {
        &self.initial_policy
    }

    /// Canonically ordered initial controllers.
    pub fn initial_controllers(&self) -> &[ControllerDescriptor] {
        self.initial_controllers.as_slice()
    }

    /// Initial recovery policy.
    pub const fn initial_recovery_policy(&self) -> &RecoveryPolicy {
        &self.initial_recovery_policy
    }

    /// Initial provider policy.
    pub const fn initial_provider_policy(&self) -> &ProviderPolicy {
        &self.initial_provider_policy
    }
}

impl<'de> Deserialize<'de> for AccountGenesis {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            protocol_version: ProtocolVersion,
            account_nonce: [u8; 32],
            created_at: Timestamp,
            hash_algorithm: HashAlgorithm,
            initial_policy: ControlPolicy,
            initial_controllers: BoundedVec<ControllerDescriptor, MAX_CONTROLLERS>,
            initial_recovery_policy: RecoveryPolicy,
            initial_provider_policy: ProviderPolicy,
            extensions: Extensions,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.protocol_version != ProtocolVersion::V1
            || wire.hash_algorithm != HashAlgorithm::Blake3_256
        {
            return Err(de::Error::custom(IdentityError::InvalidEncoding));
        }
        Self::from_sorted(
            wire.account_nonce,
            wire.created_at,
            wire.initial_policy,
            wire.initial_controllers.into_vec(),
            wire.initial_recovery_policy,
            wire.initial_provider_policy,
            wire.extensions,
        )
        .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for AccountGenesis {
    const RESOURCE: &'static str = "account genesis bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}
