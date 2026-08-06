//! Weighted control, transparency-provider, and private recovery policies.

use std::{cmp::Ordering, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{
    ControlPolicyId, ControllerId, Digest, DurationMillis, Extensions, IdentityError,
    OperationKind, ProtocolVersion, ProviderPolicyId, ProviderPolicyVersion, ProviderQuorum,
    RecoveryPolicyId, RequiredWeight,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    keys::{ControllerClass, ControllerDescriptor, ProviderDescriptor},
    limits::{
        MAX_CONTROLLERS, MAX_POLICY_RULES, MAX_RECOVERY_GUARDIANS, MAX_TRANSPARENCY_PROVIDERS,
    },
    schema::BoundedVec,
};

/// Sorted, duplicate-free explicit controller identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerIdSet(Vec<ControllerId>);

impl ControllerIdSet {
    /// Validate, sort, and construct an explicit controller-ID set.
    pub fn new(mut identifiers: Vec<ControllerId>) -> Result<Self, IdentityError> {
        identifiers.sort_unstable_by(compare_controller_ids);
        Self::from_sorted(identifiers)
    }

    /// Borrow the canonical sorted identifiers.
    pub fn as_slice(&self) -> &[ControllerId] {
        &self.0
    }

    fn from_sorted(identifiers: Vec<ControllerId>) -> Result<Self, IdentityError> {
        validate_nonempty_bounded_set(
            "controller selector identifiers",
            identifiers.len(),
            MAX_CONTROLLERS,
        )?;
        for pair in identifiers.windows(2) {
            match compare_controller_ids(&pair[0], &pair[1]) {
                Ordering::Equal => {
                    return Err(IdentityError::DuplicateElement {
                        resource: "controller selector identifiers",
                    });
                }
                Ordering::Greater => return Err(IdentityError::NonCanonical),
                Ordering::Less => {}
            }
        }
        Ok(Self(identifiers))
    }

    fn contains(&self, identifier: &ControllerId) -> bool {
        self.0
            .binary_search_by(|candidate| compare_controller_ids(candidate, identifier))
            .is_ok()
    }
}

impl Serialize for ControllerIdSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ControllerIdSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let identifiers = BoundedVec::<ControllerId, MAX_CONTROLLERS>::deserialize(deserializer)?;
        Self::from_sorted(identifiers.into_vec()).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ControllerIdSet {
    const RESOURCE: &'static str = "controller identifier set bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Sorted, duplicate-free explicit controller classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerClassSet(Vec<ControllerClass>);

impl ControllerClassSet {
    /// Validate, sort, and construct an explicit controller-class set.
    pub fn new(mut classes: Vec<ControllerClass>) -> Result<Self, IdentityError> {
        classes.sort_unstable_by_key(|class| class.code());
        Self::from_sorted(classes)
    }

    /// Borrow the canonical sorted classes.
    pub fn as_slice(&self) -> &[ControllerClass] {
        &self.0
    }

    fn from_sorted(classes: Vec<ControllerClass>) -> Result<Self, IdentityError> {
        validate_nonempty_bounded_set(
            "controller selector classes",
            classes.len(),
            MAX_CONTROLLERS,
        )?;
        for pair in classes.windows(2) {
            if pair[0].code() == pair[1].code() {
                return Err(IdentityError::DuplicateElement {
                    resource: "controller selector classes",
                });
            }
            if pair[0].code() > pair[1].code() {
                return Err(IdentityError::NonCanonical);
            }
        }
        Ok(Self(classes))
    }

    fn contains(&self, class: ControllerClass) -> bool {
        self.0
            .binary_search_by_key(&class.code(), |candidate| candidate.code())
            .is_ok()
    }
}

impl Serialize for ControllerClassSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ControllerClassSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let classes = BoundedVec::<ControllerClass, MAX_CONTROLLERS>::deserialize(deserializer)?;
        Self::from_sorted(classes.into_vec()).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ControllerClassSet {
    const RESOURCE: &'static str = "controller class set bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Closed v1 selector for controllers eligible to satisfy one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerSelector {
    /// Every active controller whose immutable scope permits the operation.
    AnyActive,
    /// A canonical explicit controller-ID set.
    ControllerIds(ControllerIdSet),
    /// A canonical explicit controller-class set.
    ControllerClasses(ControllerClassSet),
}

impl ControllerSelector {
    /// Construct the any-active-controller selector.
    pub const fn any_active() -> Self {
        Self::AnyActive
    }

    /// Validate and construct an explicit controller-ID selector.
    pub fn controller_ids(identifiers: Vec<ControllerId>) -> Result<Self, IdentityError> {
        Ok(Self::ControllerIds(ControllerIdSet::new(identifiers)?))
    }

    /// Validate and construct an explicit controller-class selector.
    pub fn controller_classes(classes: Vec<ControllerClass>) -> Result<Self, IdentityError> {
        Ok(Self::ControllerClasses(ControllerClassSet::new(classes)?))
    }

    /// Test whether a controller descriptor belongs to this selector.
    pub fn matches_controller(
        &self,
        descriptor: &ControllerDescriptor,
    ) -> Result<bool, IdentityError> {
        match self {
            Self::AnyActive => Ok(true),
            Self::ControllerIds(identifiers) => Ok(identifiers.contains(&descriptor.id()?)),
            Self::ControllerClasses(classes) => Ok(classes.contains(descriptor.class())),
        }
    }

    fn explicit_ids(&self) -> Option<&[ControllerId]> {
        match self {
            Self::ControllerIds(identifiers) => Some(identifiers.as_slice()),
            Self::AnyActive | Self::ControllerClasses(_) => None,
        }
    }
}

impl Serialize for ControllerSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::AnyActive => (
                1_u16,
                Option::<&ControllerIdSet>::None,
                Option::<&ControllerClassSet>::None,
            )
                .serialize(serializer),
            Self::ControllerIds(identifiers) => (
                2_u16,
                Some(identifiers),
                Option::<&ControllerClassSet>::None,
            )
                .serialize(serializer),
            Self::ControllerClasses(classes) => {
                (3_u16, Option::<&ControllerIdSet>::None, Some(classes)).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for ControllerSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, identifiers, classes) =
            <(u16, Option<ControllerIdSet>, Option<ControllerClassSet>)>::deserialize(
                deserializer,
            )?;
        match (code, identifiers, classes) {
            (1, None, None) => Ok(Self::AnyActive),
            (2, Some(identifiers), None) => Ok(Self::ControllerIds(identifiers)),
            (3, None, Some(classes)) => Ok(Self::ControllerClasses(classes)),
            (1..=3, _, _) => Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "controller selector payload",
            })),
            (unsupported, _, _) => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "controller selector",
                code: unsupported,
            })),
        }
    }
}

impl CanonicalCodec for ControllerSelector {
    const RESOURCE: &'static str = "controller selector bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Minimum signed-provider freshness evidence required by one policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderFreshness {
    required: ProviderQuorum,
    maximum_age: DurationMillis,
}

impl ProviderFreshness {
    /// Construct a nonzero bounded freshness requirement.
    pub fn new(
        required: ProviderQuorum,
        maximum_age: DurationMillis,
    ) -> Result<Self, IdentityError> {
        if usize::from(required.get()) > MAX_TRANSPARENCY_PROVIDERS {
            return Err(IdentityError::limit(
                "provider freshness quorum",
                usize::from(required.get()),
                MAX_TRANSPARENCY_PROVIDERS,
            ));
        }
        if maximum_age.get() == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "provider freshness maximum age",
            });
        }
        Ok(Self {
            required,
            maximum_age,
        })
    }

    /// Required distinct configured-provider observations.
    pub const fn required(self) -> ProviderQuorum {
        self.required
    }

    /// Maximum signed-provider evidence age.
    pub const fn maximum_age(self) -> DurationMillis {
        self.maximum_age
    }
}

impl Serialize for ProviderFreshness {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (self.required, self.maximum_age).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProviderFreshness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (required, maximum_age) =
            <(ProviderQuorum, DurationMillis)>::deserialize(deserializer)?;
        Self::new(required, maximum_age).map_err(de::Error::custom)
    }
}

/// Closed v1 freshness requirement attached to a policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessRequirement {
    /// Validate relative to the latest locally known valid state.
    LatestKnown,
    /// Require signed observations from a bounded provider quorum.
    ProviderQuorum(ProviderFreshness),
}

impl FreshnessRequirement {
    /// Construct local latest-known-state freshness.
    pub const fn latest_known() -> Self {
        Self::LatestKnown
    }

    /// Construct signed-provider freshness.
    pub const fn provider_quorum(requirement: ProviderFreshness) -> Self {
        Self::ProviderQuorum(requirement)
    }
}

impl Serialize for FreshnessRequirement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::LatestKnown => (1_u16, Option::<ProviderFreshness>::None).serialize(serializer),
            Self::ProviderQuorum(requirement) => (2_u16, Some(*requirement)).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FreshnessRequirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, requirement) = <(u16, Option<ProviderFreshness>)>::deserialize(deserializer)?;
        match (code, requirement) {
            (1, None) => Ok(Self::LatestKnown),
            (2, Some(requirement)) => Ok(Self::ProviderQuorum(requirement)),
            (1 | 2, _) => Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "freshness requirement payload",
            })),
            (unsupported, _) => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "freshness requirement",
                code: unsupported,
            })),
        }
    }
}

/// One weighted, default-deny account-control authorization rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    operation: OperationKind,
    required_weight: RequiredWeight,
    eligible_controllers: ControllerSelector,
    freshness: FreshnessRequirement,
    delay: Option<DurationMillis>,
    extensions: Extensions,
}

impl PolicyRule {
    /// Construct one canonical policy rule.
    pub fn new(
        operation: OperationKind,
        required_weight: RequiredWeight,
        eligible_controllers: ControllerSelector,
        freshness: FreshnessRequirement,
        delay: Option<DurationMillis>,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if delay.is_some_and(|value| value.get() == 0) {
            return Err(IdentityError::ZeroValue {
                resource: "policy delay",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            operation,
            required_weight,
            eligible_controllers,
            freshness,
            delay,
            extensions,
        })
    }

    /// Account operation governed by this rule.
    pub const fn operation(&self) -> OperationKind {
        self.operation
    }

    /// Nonzero required controller weight.
    pub const fn required_weight(&self) -> RequiredWeight {
        self.required_weight
    }

    /// Eligible controller selector.
    pub const fn eligible_controllers(&self) -> &ControllerSelector {
        &self.eligible_controllers
    }

    /// Freshness requirement signed into admission evidence.
    pub const fn freshness(&self) -> FreshnessRequirement {
        self.freshness
    }

    /// Optional nonzero operation delay.
    pub const fn delay(&self) -> Option<DurationMillis> {
        self.delay
    }

    /// Signed forward-compatible extensions.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Serialize for PolicyRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            self.operation,
            self.required_weight,
            &self.eligible_controllers,
            self.freshness,
            self.delay,
            &self.extensions,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PolicyRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (operation, required_weight, selector, freshness, delay, extensions) =
            <(
                OperationKind,
                RequiredWeight,
                ControllerSelector,
                FreshnessRequirement,
                Option<DurationMillis>,
                Extensions,
            )>::deserialize(deserializer)?;
        Self::new(
            operation,
            required_weight,
            selector,
            freshness,
            delay,
            extensions,
        )
        .map_err(de::Error::custom)
    }
}

/// Versioned sorted weighted account-control policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPolicy {
    protocol_version: ProtocolVersion,
    rules: Vec<PolicyRule>,
    default_deny: bool,
    extensions: Extensions,
}

impl ControlPolicy {
    /// Validate, sort, and construct a default-deny v1 policy.
    pub fn new(mut rules: Vec<PolicyRule>, extensions: Extensions) -> Result<Self, IdentityError> {
        rules.sort_unstable_by_key(|rule| rule.operation().code());
        Self::from_sorted(rules, true, extensions)
    }

    fn from_sorted(
        rules: Vec<PolicyRule>,
        default_deny: bool,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        validate_nonempty_bounded_set("control policy rules", rules.len(), MAX_POLICY_RULES)?;
        if !default_deny {
            return Err(IdentityError::InvalidPolicy {
                resource: "non-default-deny control",
            });
        }
        for pair in rules.windows(2) {
            if pair[0].operation().code() == pair[1].operation().code() {
                return Err(IdentityError::DuplicateElement {
                    resource: "control policy rules",
                });
            }
            if pair[0].operation().code() > pair[1].operation().code() {
                return Err(IdentityError::NonCanonical);
            }
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            rules,
            default_deny,
            extensions,
        })
    }

    /// Derive the canonical control-policy identifier.
    pub fn id(&self) -> Result<ControlPolicyId, IdentityError> {
        ControlPolicyId::derive(self)
    }

    /// Canonical rules sorted by operation code.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Find the sole canonical rule for an operation, or deny when absent.
    pub fn rule_for(&self, operation: OperationKind) -> Option<&PolicyRule> {
        self.rules
            .binary_search_by_key(&operation, PolicyRule::operation)
            .ok()
            .map(|index| &self.rules[index])
    }

    /// V1 always denies operations without a rule.
    pub const fn default_deny(&self) -> bool {
        self.default_deny
    }

    /// Signed forward-compatible extensions.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Validate every rule against one bounded active-controller set.
    pub fn validate_satisfiable(
        &self,
        controllers: &[ControllerDescriptor],
    ) -> Result<(), IdentityError> {
        validate_active_controllers(controllers)?;
        for rule in &self.rules {
            if matches!(
                rule.operation(),
                OperationKind::BeginRecovery
                    | OperationKind::CancelRecovery
                    | OperationKind::FinalizeRecovery
            ) {
                // Recovery authorization is owned by RecoveryPolicy. These control-policy
                // entries are only the default-deny gate plus freshness/delay configuration.
                continue;
            }
            validate_explicit_controller_references(rule.eligible_controllers(), controllers)?;
            let total =
                eligible_weight(rule.eligible_controllers(), rule.operation(), controllers)?;
            if u64::from(rule.required_weight().get()) > total {
                return Err(IdentityError::UnsatisfiableThreshold);
            }
        }
        Ok(())
    }
}

impl Serialize for ControlPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            self.protocol_version,
            self.rules.as_slice(),
            self.default_deny,
            &self.extensions,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ControlPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (_version, rules, default_deny, extensions) = <(
            ProtocolVersion,
            BoundedVec<PolicyRule, MAX_POLICY_RULES>,
            bool,
            Extensions,
        )>::deserialize(deserializer)?;
        Self::from_sorted(rules.into_vec(), default_deny, extensions).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ControlPolicy {
    const RESOURCE: &'static str = "control policy bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Frozen v1 transparency-provider key-rotation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRotationRule {
    /// Provider replacement requires an account-authorized policy event.
    AccountEventOnly,
}

impl Serialize for ProviderRotationRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        1_u16.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProviderRotationRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u16::deserialize(deserializer)? {
            1 => Ok(Self::AccountEventOnly),
            unsupported => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "provider rotation rule",
                code: unsupported,
            })),
        }
    }
}

/// Validated replicated transparency-provider mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedProviderPolicy {
    providers: Vec<ProviderDescriptor>,
    sufficient_threshold: ProviderQuorum,
    preferred_replication: ProviderQuorum,
    maximum_evidence_age: DurationMillis,
    rotation_rule: ProviderRotationRule,
}

impl ReplicatedProviderPolicy {
    fn new(
        providers: Vec<ProviderDescriptor>,
        sufficient_threshold: ProviderQuorum,
        preferred_replication: ProviderQuorum,
        maximum_evidence_age: DurationMillis,
    ) -> Result<Self, IdentityError> {
        if providers.len() > MAX_TRANSPARENCY_PROVIDERS {
            return Err(IdentityError::limit(
                "provider policy providers",
                providers.len(),
                MAX_TRANSPARENCY_PROVIDERS,
            ));
        }
        let providers = sort_providers(providers)?;
        Self::from_sorted(
            providers,
            sufficient_threshold,
            preferred_replication,
            maximum_evidence_age,
            ProviderRotationRule::AccountEventOnly,
        )
    }

    fn from_sorted(
        providers: Vec<ProviderDescriptor>,
        sufficient_threshold: ProviderQuorum,
        preferred_replication: ProviderQuorum,
        maximum_evidence_age: DurationMillis,
        rotation_rule: ProviderRotationRule,
    ) -> Result<Self, IdentityError> {
        validate_nonempty_bounded_set(
            "provider policy providers",
            providers.len(),
            MAX_TRANSPARENCY_PROVIDERS,
        )?;
        validate_sorted_providers(&providers)?;
        let sufficient = usize::from(sufficient_threshold.get());
        let preferred = usize::from(preferred_replication.get());
        if sufficient > preferred || preferred > providers.len() {
            return Err(IdentityError::InvalidPolicy {
                resource: "provider threshold",
            });
        }
        if maximum_evidence_age.get() == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "provider maximum evidence age",
            });
        }
        Ok(Self {
            providers,
            sufficient_threshold,
            preferred_replication,
            maximum_evidence_age,
            rotation_rule,
        })
    }

    /// Canonical provider descriptors sorted by provider ID.
    pub fn providers(&self) -> &[ProviderDescriptor] {
        &self.providers
    }

    /// Minimum provider observations sufficient for account policy.
    pub const fn sufficient_threshold(&self) -> ProviderQuorum {
        self.sufficient_threshold
    }

    /// Preferred replication count.
    pub const fn preferred_replication(&self) -> ProviderQuorum {
        self.preferred_replication
    }

    /// Maximum accepted age of signed provider evidence.
    pub const fn maximum_evidence_age(&self) -> DurationMillis {
        self.maximum_evidence_age
    }
}

impl Serialize for ReplicatedProviderPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            self.providers.as_slice(),
            self.sufficient_threshold,
            self.preferred_replication,
            self.maximum_evidence_age,
            self.rotation_rule,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReplicatedProviderPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (providers, sufficient, preferred, maximum_age, rotation_rule) =
            <(
                BoundedVec<ProviderDescriptor, MAX_TRANSPARENCY_PROVIDERS>,
                ProviderQuorum,
                ProviderQuorum,
                DurationMillis,
                ProviderRotationRule,
            )>::deserialize(deserializer)?;
        Self::from_sorted(
            providers.into_vec(),
            sufficient,
            preferred,
            maximum_age,
            rotation_rule,
        )
        .map_err(de::Error::custom)
    }
}

/// Mutually exclusive local-only or replicated provider policy mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderMode {
    /// No account-level provider requirement.
    LocalOnly,
    /// A bounded configured provider set and thresholds.
    Replicated(ReplicatedProviderPolicy),
}

impl Serialize for ProviderMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::LocalOnly => {
                (1_u16, Option::<&ReplicatedProviderPolicy>::None).serialize(serializer)
            }
            Self::Replicated(policy) => (2_u16, Some(policy)).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ProviderMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, policy) = <(u16, Option<ReplicatedProviderPolicy>)>::deserialize(deserializer)?;
        match (code, policy) {
            (1, None) => Ok(Self::LocalOnly),
            (2, Some(policy)) => Ok(Self::Replicated(policy)),
            (1 | 2, _) => Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "provider mode payload",
            })),
            (unsupported, _) => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "provider mode",
                code: unsupported,
            })),
        }
    }
}

/// Versioned account minimum for transparency-provider evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPolicy {
    protocol_version: ProtocolVersion,
    policy_version: ProviderPolicyVersion,
    mode: ProviderMode,
    extensions: Extensions,
}

impl ProviderPolicy {
    /// Construct an explicit local-only provider policy.
    pub fn local_only(
        policy_version: ProviderPolicyVersion,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        Self::from_mode(policy_version, ProviderMode::LocalOnly, extensions)
    }

    /// Validate, sort, and construct a replicated provider policy.
    pub fn replicated(
        policy_version: ProviderPolicyVersion,
        providers: Vec<ProviderDescriptor>,
        sufficient_threshold: ProviderQuorum,
        preferred_replication: ProviderQuorum,
        maximum_evidence_age: DurationMillis,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        let replicated = ReplicatedProviderPolicy::new(
            providers,
            sufficient_threshold,
            preferred_replication,
            maximum_evidence_age,
        )?;
        Self::from_mode(
            policy_version,
            ProviderMode::Replicated(replicated),
            extensions,
        )
    }

    fn from_mode(
        policy_version: ProviderPolicyVersion,
        mode: ProviderMode,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            policy_version,
            mode,
            extensions,
        })
    }

    /// Derive the canonical provider-policy identifier.
    pub fn id(&self) -> Result<ProviderPolicyId, IdentityError> {
        ProviderPolicyId::derive(self)
    }

    /// Monotonic provider-policy version.
    pub const fn policy_version(&self) -> ProviderPolicyVersion {
        self.policy_version
    }

    /// Mutually exclusive provider mode.
    pub const fn mode(&self) -> &ProviderMode {
        &self.mode
    }

    /// Configured provider descriptors, absent for local-only mode.
    pub fn providers(&self) -> Option<&[ProviderDescriptor]> {
        match &self.mode {
            ProviderMode::LocalOnly => None,
            ProviderMode::Replicated(policy) => Some(policy.providers()),
        }
    }

    /// Signed forward-compatible extensions.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Serialize for ProviderPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            self.protocol_version,
            self.policy_version,
            &self.mode,
            &self.extensions,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProviderPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (_version, policy_version, mode, extensions) = <(
            ProtocolVersion,
            ProviderPolicyVersion,
            ProviderMode,
            Extensions,
        )>::deserialize(deserializer)?;
        Self::from_mode(policy_version, mode, extensions).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for ProviderPolicy {
    const RESOURCE: &'static str = "provider policy bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Monotonic recovery-policy revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RecoveryPolicyVersion(u64);

impl RecoveryPolicyVersion {
    /// Initial recovery-policy revision.
    pub const GENESIS: Self = Self(0);

    /// Construct from an exact wire value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the exact policy revision.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance exactly once, rejecting exhaustion.
    pub fn checked_next(self) -> Result<Self, IdentityError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "recovery policy version",
            })
    }
}

impl CanonicalCodec for RecoveryPolicyVersion {
    const RESOURCE: &'static str = "recovery policy version bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Blinded commitment to the private recovery guardian set.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct GuardianSetRoot(Digest);

impl GuardianSetRoot {
    /// Construct a nonzero domain-separated guardian-set commitment.
    pub fn new(digest: Digest) -> Result<Self, IdentityError> {
        if digest.as_bytes() == &[0; 32] {
            return Err(IdentityError::InvalidIdentifier {
                resource: "guardian set root",
            });
        }
        Ok(Self(digest))
    }

    /// Borrow the commitment digest.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for GuardianSetRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("GuardianSetRoot")
            .field(&self.0)
            .finish()
    }
}

impl<'de> Deserialize<'de> for GuardianSetRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Digest::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for GuardianSetRoot {
    const RESOURCE: &'static str = "guardian set root bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Controller authority required to start or cancel recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControllerThreshold {
    selector: ControllerSelector,
    required_weight: RequiredWeight,
}

impl ControllerThreshold {
    /// Construct an explicit controller threshold.
    pub const fn new(selector: ControllerSelector, required_weight: RequiredWeight) -> Self {
        Self {
            selector,
            required_weight,
        }
    }

    /// Eligible recovery controllers.
    pub const fn selector(&self) -> &ControllerSelector {
        &self.selector
    }

    /// Nonzero required controller weight.
    pub const fn required_weight(&self) -> RequiredWeight {
        self.required_weight
    }

    /// Validate this threshold against active controllers allowed to begin and cancel recovery.
    pub fn validate_satisfiable(
        &self,
        controllers: &[ControllerDescriptor],
    ) -> Result<(), IdentityError> {
        validate_active_controllers(controllers)?;
        validate_explicit_controller_references(&self.selector, controllers)?;
        for operation in [OperationKind::BeginRecovery, OperationKind::CancelRecovery] {
            let total = eligible_weight(&self.selector, operation, controllers)?;
            if u64::from(self.required_weight.get()) > total {
                return Err(IdentityError::UnsatisfiableThreshold);
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ControllerThreshold {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (selector, required_weight) =
            <(ControllerSelector, RequiredWeight)>::deserialize(deserializer)?;
        Ok(Self::new(selector, required_weight))
    }
}

/// Public aggregate parameters for a private guardian authority set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardianThreshold {
    guardian_set_root: GuardianSetRoot,
    guardian_count: u16,
    total_weight: u64,
    required_weight: RequiredWeight,
}

impl GuardianThreshold {
    /// Construct bounded guardian-set aggregate parameters.
    pub fn new(
        guardian_set_root: GuardianSetRoot,
        guardian_count: u16,
        total_weight: u64,
        required_weight: RequiredWeight,
    ) -> Result<Self, IdentityError> {
        if guardian_count == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "recovery guardian count",
            });
        }
        if usize::from(guardian_count) > MAX_RECOVERY_GUARDIANS {
            return Err(IdentityError::limit(
                "recovery guardian count",
                usize::from(guardian_count),
                MAX_RECOVERY_GUARDIANS,
            ));
        }
        if total_weight == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "recovery guardian total weight",
            });
        }
        let maximum_total = u64::from(guardian_count)
            .checked_mul(u64::from(u32::MAX))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "recovery guardian maximum total weight",
            })?;
        if total_weight < u64::from(guardian_count)
            || total_weight > maximum_total
            || u64::from(required_weight.get()) > total_weight
        {
            return Err(IdentityError::UnsatisfiableThreshold);
        }
        Ok(Self {
            guardian_set_root,
            guardian_count,
            total_weight,
            required_weight,
        })
    }

    /// Blinded guardian-set commitment.
    pub const fn guardian_set_root(&self) -> GuardianSetRoot {
        self.guardian_set_root
    }

    /// Number of committed nonzero-weight guardians.
    pub const fn guardian_count(&self) -> u16 {
        self.guardian_count
    }

    /// Checked aggregate guardian weight.
    pub const fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Nonzero required guardian weight.
    pub const fn required_weight(&self) -> RequiredWeight {
        self.required_weight
    }
}

impl<'de> Deserialize<'de> for GuardianThreshold {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (root, count, total, required) =
            <(GuardianSetRoot, u16, u64, RequiredWeight)>::deserialize(deserializer)?;
        Self::new(root, count, total, required).map_err(de::Error::custom)
    }
}

/// Mutually exclusive public recovery-authority modes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAuthority {
    /// A weighted controller selector.
    ControllerThreshold(ControllerThreshold),
    /// Aggregate parameters committing to private guardian identities.
    GuardianThreshold(GuardianThreshold),
}

impl RecoveryAuthority {
    /// Construct controller-threshold recovery authority.
    pub const fn controller_threshold(threshold: ControllerThreshold) -> Self {
        Self::ControllerThreshold(threshold)
    }

    /// Construct private guardian-threshold recovery authority.
    pub const fn guardian_threshold(threshold: GuardianThreshold) -> Self {
        Self::GuardianThreshold(threshold)
    }
}

impl Serialize for RecoveryAuthority {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::ControllerThreshold(threshold) => {
                (1_u16, Some(threshold), Option::<&GuardianThreshold>::None).serialize(serializer)
            }
            Self::GuardianThreshold(threshold) => {
                (2_u16, Option::<&ControllerThreshold>::None, Some(threshold)).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for RecoveryAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (code, controller, guardian) =
            <(u16, Option<ControllerThreshold>, Option<GuardianThreshold>)>::deserialize(
                deserializer,
            )?;
        match (code, controller, guardian) {
            (1, Some(threshold), None) => Ok(Self::ControllerThreshold(threshold)),
            (2, None, Some(threshold)) => Ok(Self::GuardianThreshold(threshold)),
            (1 | 2, _, _) => Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "recovery authority payload",
            })),
            (unsupported, _, _) => Err(de::Error::custom(IdentityError::UnsupportedCodepoint {
                registry: "recovery authority",
                code: unsupported,
            })),
        }
    }
}

/// Versioned recovery authority, mandatory delay, and attempt lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPolicy {
    protocol_version: ProtocolVersion,
    policy_version: RecoveryPolicyVersion,
    authority: RecoveryAuthority,
    delay: DurationMillis,
    lifetime: DurationMillis,
    extensions: Extensions,
}

impl RecoveryPolicy {
    /// Construct a recovery policy with a nonempty finalization window.
    pub fn new(
        policy_version: RecoveryPolicyVersion,
        authority: RecoveryAuthority,
        delay: DurationMillis,
        lifetime: DurationMillis,
        extensions: Extensions,
    ) -> Result<Self, IdentityError> {
        if delay.get() == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "recovery delay",
            });
        }
        if lifetime.get() == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "recovery lifetime",
            });
        }
        if lifetime.get() <= delay.get() {
            return Err(IdentityError::InvalidPolicy {
                resource: "recovery finalization window",
            });
        }
        extensions.validate_critical(&[])?;
        Ok(Self {
            protocol_version: ProtocolVersion::V1,
            policy_version,
            authority,
            delay,
            lifetime,
            extensions,
        })
    }

    /// Derive the canonical recovery-policy identifier.
    pub fn id(&self) -> Result<RecoveryPolicyId, IdentityError> {
        RecoveryPolicyId::derive(self)
    }

    /// Monotonic recovery-policy revision.
    pub const fn policy_version(&self) -> RecoveryPolicyVersion {
        self.policy_version
    }

    /// Explicit controller or private guardian authority.
    pub const fn authority(&self) -> &RecoveryAuthority {
        &self.authority
    }

    /// Mandatory provider-observed security delay.
    pub const fn delay(&self) -> DurationMillis {
        self.delay
    }

    /// Maximum lifetime of one authoritative recovery attempt.
    pub const fn lifetime(&self) -> DurationMillis {
        self.lifetime
    }

    /// Signed forward-compatible extensions.
    pub const fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Validate controller-threshold authority against active controllers.
    pub fn validate_controller_authority(
        &self,
        controllers: &[ControllerDescriptor],
    ) -> Result<(), IdentityError> {
        match &self.authority {
            RecoveryAuthority::ControllerThreshold(threshold) => {
                threshold.validate_satisfiable(controllers)
            }
            RecoveryAuthority::GuardianThreshold(_) => Ok(()),
        }
    }
}

impl Serialize for RecoveryPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (
            self.protocol_version,
            self.policy_version,
            &self.authority,
            self.delay,
            self.lifetime,
            &self.extensions,
        )
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RecoveryPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (_version, policy_version, authority, delay, lifetime, extensions) =
            <(
                ProtocolVersion,
                RecoveryPolicyVersion,
                RecoveryAuthority,
                DurationMillis,
                DurationMillis,
                Extensions,
            )>::deserialize(deserializer)?;
        Self::new(policy_version, authority, delay, lifetime, extensions).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for RecoveryPolicy {
    const RESOURCE: &'static str = "recovery policy bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

fn compare_controller_ids(left: &ControllerId, right: &ControllerId) -> Ordering {
    compare_digests(left.as_digest(), right.as_digest())
}

fn compare_digests(left: &Digest, right: &Digest) -> Ordering {
    left.algorithm()
        .code()
        .cmp(&right.algorithm().code())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn validate_nonempty_bounded_set(
    resource: &'static str,
    length: usize,
    maximum: usize,
) -> Result<(), IdentityError> {
    if length == 0 {
        return Err(IdentityError::EmptyCollection { resource });
    }
    if length > maximum {
        return Err(IdentityError::limit(resource, length, maximum));
    }
    Ok(())
}

fn validate_active_controllers(controllers: &[ControllerDescriptor]) -> Result<(), IdentityError> {
    validate_nonempty_bounded_set("active controllers", controllers.len(), MAX_CONTROLLERS)?;
    for (index, controller) in controllers.iter().enumerate() {
        let identifier = controller.id()?;
        for other in controllers.iter().skip(index + 1) {
            if controller.signing_key() == other.signing_key() {
                return Err(IdentityError::DuplicateSigningKey);
            }
            if identifier == other.id()? {
                return Err(IdentityError::DuplicateElement {
                    resource: "active controller identifiers",
                });
            }
        }
    }
    Ok(())
}

fn validate_explicit_controller_references(
    selector: &ControllerSelector,
    controllers: &[ControllerDescriptor],
) -> Result<(), IdentityError> {
    let Some(explicit_identifiers) = selector.explicit_ids() else {
        return Ok(());
    };
    for explicit_identifier in explicit_identifiers {
        let mut found = false;
        for controller in controllers {
            if controller.id()? == *explicit_identifier {
                found = true;
                break;
            }
        }
        if !found {
            return Err(IdentityError::InvalidRelationship {
                resource: "controller selector active membership",
            });
        }
    }
    Ok(())
}

fn eligible_weight(
    selector: &ControllerSelector,
    operation: OperationKind,
    controllers: &[ControllerDescriptor],
) -> Result<u64, IdentityError> {
    let mut total = 0_u64;
    for controller in controllers {
        if selector.matches_controller(controller)? && controller.scope().allows(operation) {
            total = total
                .checked_add(u64::from(controller.weight().get()))
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "eligible controller weight",
                })?;
        }
    }
    Ok(total)
}

fn sort_providers(
    providers: Vec<ProviderDescriptor>,
) -> Result<Vec<ProviderDescriptor>, IdentityError> {
    let mut keyed = providers
        .into_iter()
        .map(|provider| Ok((provider.id()?, provider)))
        .collect::<Result<Vec<_>, IdentityError>>()?;
    keyed.sort_unstable_by(|left, right| compare_digests(left.0.as_digest(), right.0.as_digest()));
    let providers = keyed
        .into_iter()
        .map(|(_identifier, provider)| provider)
        .collect::<Vec<_>>();
    validate_sorted_providers(&providers)?;
    Ok(providers)
}

fn validate_sorted_providers(providers: &[ProviderDescriptor]) -> Result<(), IdentityError> {
    for (index, provider) in providers.iter().enumerate() {
        if providers[..index]
            .iter()
            .any(|prior| prior.signing_key() == provider.signing_key())
        {
            return Err(IdentityError::DuplicateSigningKey);
        }
    }
    for pair in providers.windows(2) {
        let left = pair[0].id()?;
        let right = pair[1].id()?;
        match compare_digests(left.as_digest(), right.as_digest()) {
            Ordering::Equal => {
                return Err(IdentityError::DuplicateElement {
                    resource: "provider policy providers",
                });
            }
            Ordering::Greater => return Err(IdentityError::NonCanonical),
            Ordering::Less => {}
        }
    }
    Ok(())
}
