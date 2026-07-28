use super::*;

pub(super) fn duration_nanos(duration: Duration) -> Result<u64, ScenarioModelError> {
    u64::try_from(duration.as_nanos()).map_err(|_| ScenarioModelError::DurationOverflow)
}

pub(super) const fn default_true() -> bool {
    true
}

pub(super) fn unique_ids<'a>(
    kind: &'static str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<BTreeSet<&'a str>, ScenarioModelError> {
    let mut result = BTreeSet::new();
    for value in values {
        validate_id(kind, value)?;
        if !result.insert(value) {
            return Err(ScenarioModelError::DuplicateId(kind));
        }
    }
    Ok(result)
}

pub(super) fn require_reference(
    values: &BTreeSet<&str>,
    value: &str,
    error: fn(String) -> ScenarioModelError,
) -> Result<(), ScenarioModelError> {
    if values.contains(value) {
        Ok(())
    } else {
        Err(error(value.to_owned()))
    }
}

pub(super) fn require_capability(
    enabled: bool,
    name: &'static str,
) -> Result<(), ScenarioModelError> {
    if enabled {
        Ok(())
    } else {
        Err(ScenarioModelError::MissingCapability(name))
    }
}

pub(super) fn validate_nat_chains(nats: &[NatSpec]) -> Result<(), ScenarioModelError> {
    let upstreams = nats
        .iter()
        .map(|nat| (nat.id.as_str(), nat.upstream_nat.as_deref()))
        .collect::<BTreeMap<_, _>>();
    for nat in nats {
        let mut seen = BTreeSet::new();
        let mut current = Some(nat.id.as_str());
        while let Some(id) = current {
            if !seen.insert(id) {
                return Err(ScenarioModelError::InvalidNat(nat.id.clone()));
            }
            current = upstreams.get(id).copied().flatten();
        }
    }

    let referenced = nats
        .iter()
        .filter_map(|nat| nat.upstream_nat.as_deref())
        .collect::<BTreeSet<_>>();
    let mut roots = BTreeMap::<&str, usize>::new();
    for nat in nats
        .iter()
        .filter(|nat| !referenced.contains(nat.id.as_str()))
    {
        let count = roots.entry(nat.inside_host.as_str()).or_default();
        *count += 1;
        if *count > 1 {
            return Err(ScenarioModelError::InvalidNat(nat.id.clone()));
        }
    }
    Ok(())
}

pub(super) fn validate_id(kind: &'static str, value: &str) -> Result<(), ScenarioModelError> {
    if value.is_empty()
        || value.len() > 128
        || value.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(ScenarioModelError::InvalidId {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn parse_cidr(value: &str) -> Result<(IpAddr, u8), ScenarioModelError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| ScenarioModelError::InvalidCidr(value.to_owned()))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| ScenarioModelError::InvalidCidr(value.to_owned()))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ScenarioModelError::InvalidCidr(value.to_owned()))?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err(ScenarioModelError::InvalidCidr(value.to_owned()));
    }
    Ok((address, prefix))
}

pub(super) fn cidr_contains(network: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(network) & mask == u32::from(address) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(network) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

pub(super) fn looks_like_host_path(value: &str) -> bool {
    std::path::Path::new(value).is_absolute()
        || value.starts_with("~/")
        || (value.len() >= 3
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\'))
}

pub(super) fn is_unique<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

/// Strict schema, reference, capability, generation, or canonicalization failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScenarioModelError {
    Json(String),
    UnsupportedSchema(u16),
    InvalidMetadata,
    InvalidBudgets,
    TooManyActions,
    TooManyItems,
    NoAllowedTerminal,
    InvalidId { kind: &'static str, value: String },
    DuplicateId(&'static str),
    UnknownLink(String),
    UnknownHost(String),
    UnknownEndpoint(String),
    UnknownConnection(String),
    UnknownNat(String),
    UnknownRelay(String),
    UnknownDiscovery(String),
    UnknownInterface { host: String, interface: String },
    HostWithoutInterface(String),
    InterfaceWithoutAddress(String),
    DuplicateAddress(IpAddr),
    InvalidCidr(String),
    InvalidSocket(String),
    EndpointAddressNotOwned { endpoint: String, address: IpAddr },
    InvalidIdentityOrdinal(String),
    InvalidEndpointPath(String),
    InvalidLink(String),
    InvalidNat(String),
    InvalidRelay(String),
    InvalidFirewall(String),
    InvalidDiscovery(String),
    InvalidTrigger(String),
    ActionAfterBudget(String),
    InvalidAction(&'static str),
    InvalidPayload(u64),
    MissingCapability(&'static str),
    InvalidFaultRule(String),
    InvalidCompletion,
    InvalidInvariant(InvariantName),
    InvalidGeneratorConfig,
    Generation(String),
    Legacy(String),
    DurationOverflow,
}

impl fmt::Display for ScenarioModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "scenario JSON is invalid: {error}"),
            Self::UnsupportedSchema(version) => write!(f, "unsupported scenario schema {version}"),
            Self::InvalidMetadata => f.write_str("scenario metadata is invalid"),
            Self::InvalidBudgets => f.write_str("scenario budgets are invalid"),
            Self::TooManyActions => f.write_str("scenario action limit exceeded"),
            Self::TooManyItems => f.write_str("scenario item limit exceeded"),
            Self::NoAllowedTerminal => f.write_str("scenario has no allowed terminal state"),
            Self::InvalidId { kind, value } => write!(f, "invalid {kind} ID {value:?}"),
            Self::DuplicateId(kind) => write!(f, "duplicate {kind} ID"),
            Self::UnknownLink(value) => write!(f, "unknown link {value:?}"),
            Self::UnknownHost(value) => write!(f, "unknown host {value:?}"),
            Self::UnknownEndpoint(value) => write!(f, "unknown endpoint {value:?}"),
            Self::UnknownConnection(value) => write!(f, "unknown connection {value:?}"),
            Self::UnknownNat(value) => write!(f, "unknown NAT {value:?}"),
            Self::UnknownRelay(value) => write!(f, "unknown relay {value:?}"),
            Self::UnknownDiscovery(value) => {
                write!(f, "unknown discovery provider {value:?}")
            }
            Self::UnknownInterface { host, interface } => {
                write!(f, "unknown interface {host:?}/{interface:?}")
            }
            Self::HostWithoutInterface(value) => write!(f, "host {value:?} has no interface"),
            Self::InterfaceWithoutAddress(value) => write!(f, "interface {value:?} has no address"),
            Self::DuplicateAddress(value) => write!(f, "duplicate interface address {value}"),
            Self::InvalidCidr(value) => write!(f, "invalid interface CIDR {value:?}"),
            Self::InvalidSocket(value) => write!(f, "invalid endpoint socket {value:?}"),
            Self::EndpointAddressNotOwned { endpoint, address } => {
                write!(f, "endpoint {endpoint:?} host does not own {address}")
            }
            Self::InvalidIdentityOrdinal(value) => {
                write!(f, "endpoint {value:?} identity ordinal must be nonzero")
            }
            Self::InvalidEndpointPath(value) => {
                write!(f, "endpoint {value:?} has no direct or relay path")
            }
            Self::InvalidLink(value) => write!(f, "invalid link {value:?}"),
            Self::InvalidNat(value) => write!(f, "invalid NAT {value:?}"),
            Self::InvalidRelay(value) => write!(f, "invalid relay {value:?}"),
            Self::InvalidFirewall(value) => write!(f, "invalid firewall {value:?}"),
            Self::InvalidDiscovery(value) => write!(f, "invalid discovery record {value:?}"),
            Self::InvalidTrigger(value) => write!(f, "invalid action trigger {value:?}"),
            Self::ActionAfterBudget(value) => {
                write!(f, "action {value:?} exceeds virtual-time budget")
            }
            Self::InvalidAction(value) => write!(f, "invalid {value} action"),
            Self::InvalidPayload(value) => write!(f, "invalid payload size {value}"),
            Self::MissingCapability(value) => {
                write!(f, "scenario action requires {value} capability")
            }
            Self::InvalidFaultRule(value) => write!(f, "invalid fault rule {value:?}"),
            Self::InvalidCompletion => f.write_str("invalid completion policy"),
            Self::InvalidInvariant(value) => write!(f, "invalid invariant bounds for {value:?}"),
            Self::InvalidGeneratorConfig => f.write_str("invalid scenario generator bounds"),
            Self::Generation(error) => write!(f, "scenario generation failed: {error}"),
            Self::Legacy(error) => write!(f, "legacy scenario migration failed: {error}"),
            Self::DurationOverflow => f.write_str("scenario duration does not fit nanoseconds"),
        }
    }
}

impl std::error::Error for ScenarioModelError {}
