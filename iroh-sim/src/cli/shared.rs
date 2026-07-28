use super::*;

pub(super) fn simulation_runtime() -> Result<tokio::runtime::Runtime, CliError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .map_err(CliError::Io)
}

pub(super) fn default_budgets() -> RunBudgets {
    RunBudgets {
        max_events: 100_000,
        max_virtual_time_nanos: 60_000_000_000,
        max_tasks: 1_024,
        max_packets: 10_000,
    }
}

pub(super) struct CurrentIdentity {
    pub(super) source: SourceIdentity,
    pub(super) scenario_hash: String,
    pub(super) normalized_config: BTreeMap<String, String>,
    pub(super) features: Vec<String>,
    pub(super) lockfile_digest: String,
}

pub(super) struct DeclarativeIdentity {
    pub(super) source: SourceIdentity,
    pub(super) scenario_hash: String,
    pub(super) normalized_config: BTreeMap<String, String>,
    pub(super) features: Vec<String>,
    pub(super) fault_profile: String,
    pub(super) lockfile_digest: String,
}

pub(super) fn declarative_scenario_identity(
    workspace: &Path,
    scenario: &Scenario,
    artifact_root: Option<&Path>,
) -> Result<DeclarativeIdentity, CliError> {
    let canonical = scenario.to_canonical_json()?;
    let fault_bytes = serde_json::to_vec(&scenario.fault_rules)
        .map_err(|error| CliError::Trace(error.to_string()))?;
    let fault_profile = blake3::hash(&fault_bytes).to_hex().to_string();
    let mut features = BTreeSet::new();
    if scenario.requirements.synthetic_ip {
        features.insert("synthetic-ip".to_owned());
    }
    if scenario.requirements.virtual_time {
        features.insert("virtual-time".to_owned());
    }
    if scenario.requirements.nat {
        features.insert("nat".to_owned());
    }
    if scenario.requirements.relay {
        features.insert("relay".to_owned());
    }
    if scenario.requirements.discovery {
        features.insert("discovery".to_owned());
    }
    if scenario.requirements.mobility {
        features.insert("mobility".to_owned());
    }
    for action in &scenario.actions {
        let feature = match action.action {
            crate::ScenarioAction::StreamRoundTrip { .. } => Some("quic-stream"),
            crate::ScenarioAction::DatagramRoundTrip { .. }
            | crate::ScenarioAction::SendDatagram { .. } => Some("quic-datagram"),
            crate::ScenarioAction::Partition { .. } | crate::ScenarioAction::Heal { .. } => {
                Some("partition")
            }
            crate::ScenarioAction::SetLink { .. } => Some("link-update"),
            _ => None,
        };
        if let Some(feature) = feature {
            features.insert(feature.to_owned());
        }
    }
    Ok(DeclarativeIdentity {
        source: source_identity(workspace, artifact_root)?,
        scenario_hash: blake3::hash(&canonical).to_hex().to_string(),
        normalized_config: BTreeMap::from([
            (
                "backend".to_owned(),
                "stage3-declarative-direct-ip".to_owned(),
            ),
            ("fault_profile".to_owned(), fault_profile.clone()),
            (
                "scenario_schema".to_owned(),
                SCENARIO_SCHEMA_VERSION.to_string(),
            ),
        ]),
        features: features.into_iter().collect(),
        fault_profile,
        lockfile_digest: digest_file(&workspace.join("Cargo.lock"))?,
    })
}

pub(super) const fn manifest_crypto_mode(
    mode: iroh::simulation::SimulationCryptoMode,
) -> crate::CryptoMode {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            crate::CryptoMode::DeterministicTest
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            crate::CryptoMode::ProductionProvider
        }
    }
}

pub(super) const fn simulation_crypto_mode(
    mode: crate::CryptoMode,
) -> iroh::simulation::SimulationCryptoMode {
    match mode {
        crate::CryptoMode::DeterministicTest => {
            iroh::simulation::SimulationCryptoMode::DeterministicTest
        }
        crate::CryptoMode::ProductionProvider => {
            iroh::simulation::SimulationCryptoMode::ProductionProvider
        }
    }
}

pub(super) const fn determinism_grade(
    mode: iroh::simulation::SimulationCryptoMode,
) -> DeterminismGrade {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            DeterminismGrade::FullyDeterministic
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            DeterminismGrade::SemanticallyDeterministic
        }
    }
}

pub(super) const fn trace_comparison(
    mode: iroh::simulation::SimulationCryptoMode,
) -> crate::TraceComparisonMode {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            crate::TraceComparisonMode::Raw
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            crate::TraceComparisonMode::Semantic
        }
    }
}

pub(super) fn fidelity_exceptions(mode: iroh::simulation::SimulationCryptoMode) -> Vec<String> {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => {
            vec!["deterministic_test_crypto".to_owned()]
        }
        iroh::simulation::SimulationCryptoMode::ProductionProvider => Vec::new(),
    }
}

pub(super) fn crypto_escapes(mode: iroh::simulation::SimulationCryptoMode) -> Vec<String> {
    match mode {
        iroh::simulation::SimulationCryptoMode::DeterministicTest => Vec::new(),
        iroh::simulation::SimulationCryptoMode::ProductionProvider => {
            vec!["production_crypto_entropy".to_owned()]
        }
    }
}

pub(super) fn scenario_schema_version(bytes: &[u8]) -> Result<u16, CliError> {
    #[derive(serde::Deserialize)]
    struct Probe {
        schema_version: u16,
    }
    serde_json::from_slice::<Probe>(bytes)
        .map(|probe| probe.schema_version)
        .map_err(|error| CliError::ScenarioModel(ScenarioModelError::Json(error.to_string())))
}

pub(super) fn read_trace_jsonl(path: &Path) -> Result<Vec<TraceEvent>, CliError> {
    let bytes = read_file(path)?;
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        return Err(CliError::Trace("trace JSONL is truncated".to_owned()));
    }
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line).map_err(|error| CliError::Trace(error.to_string()))
        })
        .collect()
}

pub(super) fn scenario_identity(
    workspace: &Path,
    scenario: &Stage2Scenario,
    artifact_root: Option<&Path>,
) -> Result<CurrentIdentity, CliError> {
    let canonical = scenario.to_canonical_json()?;
    let (features, fault_profile) = match scenario.id.as_str() {
        "direct-ip/ipv4-stream" => (vec!["ipv4".to_owned(), "quic-stream".to_owned()], "none"),
        "direct-ip/ipv4-stream-loss" => (
            vec![
                "fault-loss".to_owned(),
                "ipv4".to_owned(),
                "quic-stream".to_owned(),
            ],
            "loss-250000ppm",
        ),
        "direct-ip/ipv4-stream-corruption" => (
            vec![
                "fault-corruption".to_owned(),
                "ipv4".to_owned(),
                "quic-stream".to_owned(),
            ],
            "corruption-250000ppm",
        ),
        "direct-ip/ipv6-stream" => (vec!["ipv6".to_owned(), "quic-stream".to_owned()], "none"),
        "direct-ip/ipv6-datagram" => (vec!["ipv6".to_owned(), "quic-datagram".to_owned()], "none"),
        _ => {
            return Err(CliError::Scenario(ScenarioError::UnsupportedScenario(
                scenario.id.clone(),
            )));
        }
    };
    Ok(CurrentIdentity {
        source: source_identity(workspace, artifact_root)?,
        scenario_hash: blake3::hash(&canonical).to_hex().to_string(),
        normalized_config: BTreeMap::from([
            ("backend".to_owned(), "stage2-synthetic-ip".to_owned()),
            ("network_faults".to_owned(), fault_profile.to_owned()),
        ]),
        features,
        lockfile_digest: digest_file(&workspace.join("Cargo.lock"))?,
    })
}

pub(super) fn source_identity(
    workspace: &Path,
    artifact_root: Option<&Path>,
) -> Result<SourceIdentity, CliError> {
    let revision = git_output(workspace, &["rev-parse", "HEAD"])?;
    let dirty = git_status_output_bytes(workspace, artifact_root)?;
    Ok(SourceIdentity {
        revision: String::from_utf8(revision)
            .map_err(|error| CliError::Identity(error.to_string()))?
            .trim()
            .to_owned(),
        dirty_digest: (!dirty.is_empty()).then(|| blake3::hash(&dirty).to_hex().to_string()),
    })
}

pub(super) fn git_output(workspace: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    git_output_bytes(workspace, args)
}

pub(super) fn git_output_bytes(workspace: &Path, args: &[&str]) -> Result<Vec<u8>, CliError> {
    let output = ProcessCommand::new("git")
        .args(args)
        .current_dir(workspace)
        .output()
        .map_err(CliError::Io)?;
    if !output.status.success() {
        return Err(CliError::Identity(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(output.stdout)
}

pub(super) fn git_status_output_bytes(
    workspace: &Path,
    artifact_root: Option<&Path>,
) -> Result<Vec<u8>, CliError> {
    let mut command = ProcessCommand::new("git");
    command
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .current_dir(workspace);
    if let Some(relative) = artifact_root.and_then(|root| root.strip_prefix(workspace).ok())
        && !relative.as_os_str().is_empty()
    {
        let relative = relative
            .to_str()
            .ok_or_else(|| CliError::Identity("artifact path is not UTF-8".to_owned()))?
            .replace('\\', "/");
        command.args(["--", "."]);
        command.arg(format!(":(exclude){relative}/**"));
    }
    let output = command.output().map_err(CliError::Io)?;
    if !output.status.success() {
        return Err(CliError::Identity(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    Ok(output.stdout)
}

pub(super) fn workspace_root() -> Result<PathBuf, CliError> {
    let mut current = std::env::current_dir().map_err(CliError::Io)?;
    loop {
        if current.join("Cargo.lock").is_file() && current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(CliError::WorkspaceNotFound);
        }
    }
}

pub(super) fn digest_file(path: &Path) -> Result<String, CliError> {
    Ok(blake3::hash(&read_file(path).map_err(CliError::Io)?)
        .to_hex()
        .to_string())
}

pub(super) fn parse_seed(value: &str) -> Result<RootSeed, CliError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::InvalidSeed);
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(CliError::InvalidSeed);
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| CliError::InvalidSeed)?;
        bytes[index] = u8::from_str_radix(text, 16).map_err(|_| CliError::InvalidSeed)?;
    }
    Ok(RootSeed::new(bytes))
}

pub(super) fn default_artifact_root(
    workspace: &Path,
    scenario: &Stage2Scenario,
    seed: &str,
) -> PathBuf {
    workspace
        .join("artifacts")
        .join(format!("{}-{}", scenario.id.replace('/', "-"), &seed[..16]))
}

pub(super) fn default_declarative_artifact_root(
    workspace: &Path,
    scenario: &Scenario,
    seed: &str,
) -> PathBuf {
    workspace.join("artifacts").join(format!(
        "{}-{}",
        scenario.metadata.id.replace('/', "-"),
        &seed[..16]
    ))
}

pub(super) fn absolutize(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir().map_err(CliError::Io)?.join(path))
    }
}

pub(super) fn normalized_trace_bytes(
    events: &[iroh_runtime::TraceEvent],
) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes.extend(
            normalized_trace_json(event).map_err(|error| CliError::Trace(error.to_string()))?,
        );
        bytes.push(b'\n');
    }
    Ok(bytes)
}

pub(super) fn raw_trace_bytes(events: &[iroh_runtime::TraceEvent]) -> Result<Vec<u8>, CliError> {
    let mut bytes = Vec::new();
    for event in events {
        bytes
            .extend(serde_json::to_vec(event).map_err(|error| CliError::Trace(error.to_string()))?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

pub(super) fn first_raw_trace_divergence(
    expected: &[iroh_runtime::TraceEvent],
    actual: &[iroh_runtime::TraceEvent],
) -> usize {
    expected
        .iter()
        .zip(actual)
        .position(|(expected, actual)| expected != actual)
        .unwrap_or_else(|| expected.len().min(actual.len()))
}

pub(super) fn first_different_line(expected: &[u8], actual: &[u8]) -> usize {
    let common_prefix = expected
        .iter()
        .zip(actual)
        .take_while(|(expected, actual)| expected == actual)
        .count();
    expected[..common_prefix]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        + 1
}

/// Stable command failure classes.
#[derive(Debug)]
pub enum CliError {
    Usage(String),
    InvalidSeed,
    InvalidSeedRange(String),
    InvalidParityCase(String),
    Io(std::io::Error),
    Identity(String),
    WorkspaceNotFound,
    WallEpochOverflow,
    ManifestHasNoParent,
    Scenario(ScenarioError),
    ScenarioModel(ScenarioModelError),
    Runner(String),
    Manifest(ManifestError),
    Compatibility(CompatibilityError),
    Artifact(ArtifactError),
    Trace(String),
    TraceDivergence {
        line: usize,
    },
    BackendIdentityMismatch,
    Failure(FailureError),
    FailureReplay(FailureReplayError),
    Minimization(MinimizationError),
    MinimizationOutputExists(PathBuf),
    Corpus(CorpusError),
    Campaign(CampaignError),
    Swarm(SwarmError),
    Soak(SoakError),
    SoakPlan(SoakPlanError),
    Coverage(CoverageError),
    Gate(GateError),
    SeedLease(SeedLeaseError),
    CoverageTrackerPoisoned,
    SoakOutputExists(PathBuf),
    SoakCoveragePolicyDigest {
        expected: String,
        actual: String,
    },
    SoakSwarmDigest {
        lane: String,
        expected: String,
        actual: String,
    },
    SoakRunFailures {
        failed: u64,
        errored: u64,
        infrastructure_error: Option<String>,
    },
    CampaignRunFailures(usize),
    Parity(ParityError),
    ParityDifference(Vec<String>),
    UnexpectedDeclarativeFailure(String),
    DeclarativeRunFailed {
        error: String,
        manifest: PathBuf,
        signature: String,
    },
    RunFailed {
        error: ScenarioError,
        manifest: PathBuf,
    },
    PostManifestFailure {
        error: String,
        manifest: PathBuf,
    },
    BackendUnavailable {
        operation: &'static str,
        artifact: PathBuf,
    },
}

impl CliError {
    /// Process exit code for automation.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_)
            | Self::InvalidSeed
            | Self::InvalidSeedRange(_)
            | Self::InvalidParityCase(_) => 64,
            Self::Scenario(_)
            | Self::ScenarioModel(_)
            | Self::Runner(_)
            | Self::RunFailed { .. }
            | Self::DeclarativeRunFailed { .. }
            | Self::UnexpectedDeclarativeFailure(_) => 70,
            Self::Compatibility(_) | Self::BackendIdentityMismatch => 65,
            Self::TraceDivergence { .. } | Self::FailureReplay(_) | Self::ParityDifference(_) => 66,
            Self::Io(_)
            | Self::Identity(_)
            | Self::WorkspaceNotFound
            | Self::Artifact(_)
            | Self::PostManifestFailure { .. }
            | Self::Failure(_)
            | Self::Minimization(_)
            | Self::Corpus(_)
            | Self::Campaign(_)
            | Self::Swarm(_)
            | Self::Soak(_)
            | Self::SoakPlan(_)
            | Self::Coverage(_)
            | Self::Gate(_)
            | Self::SeedLease(_)
            | Self::CoverageTrackerPoisoned
            | Self::SoakCoveragePolicyDigest { .. }
            | Self::SoakSwarmDigest { .. }
            | Self::SoakRunFailures { .. }
            | Self::CampaignRunFailures(_)
            | Self::Parity(_) => 74,
            Self::MinimizationOutputExists(_) | Self::SoakOutputExists(_) => 73,
            Self::Manifest(_)
            | Self::Trace(_)
            | Self::WallEpochOverflow
            | Self::ManifestHasNoParent => 65,
            Self::BackendUnavailable { .. } => BACKEND_UNAVAILABLE_EXIT,
        }
    }
}

impl From<GateError> for CliError {
    fn from(error: GateError) -> Self {
        Self::Gate(error)
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => f.write_str(message),
            Self::InvalidSeed => f.write_str("seed must be 64 lowercase hexadecimal characters"),
            Self::InvalidSeedRange(value) => {
                write!(
                    f,
                    "seed range must be a nonempty half-open range: {value:?}"
                )
            }
            Self::InvalidParityCase(value) => write!(
                f,
                "unknown parity case {value:?}; expected public, full-cone, port-restricted, symmetric, double-nat, degradation, outage-recovery, or switch-uplink"
            ),
            Self::Io(error) => write!(f, "artifact or input I/O failed: {error}"),
            Self::Identity(error) => write!(f, "source identity failed: {error}"),
            Self::WorkspaceNotFound => {
                f.write_str("workspace root with .git and Cargo.lock not found")
            }
            Self::WallEpochOverflow => f.write_str("manifest wall-clock epoch overflow"),
            Self::ManifestHasNoParent => f.write_str("manifest has no artifact directory"),
            Self::Scenario(error) => error.fmt(f),
            Self::ScenarioModel(error) => error.fmt(f),
            Self::Runner(error) => write!(f, "scenario runner failed: {error}"),
            Self::Manifest(error) => error.fmt(f),
            Self::Compatibility(error) => error.fmt(f),
            Self::Artifact(error) => error.fmt(f),
            Self::Trace(error) => write!(f, "trace encoding failed: {error}"),
            Self::TraceDivergence { line } => write!(f, "status=trace_divergence line={line}"),
            Self::BackendIdentityMismatch => f.write_str("manifest backend identity mismatch"),
            Self::Failure(error) => error.fmt(f),
            Self::FailureReplay(error) => error.fmt(f),
            Self::Minimization(error) => error.fmt(f),
            Self::MinimizationOutputExists(path) => write!(
                f,
                "minimization output already exists (use --resume): {}",
                path.display()
            ),
            Self::Corpus(error) => error.fmt(f),
            Self::Campaign(error) => error.fmt(f),
            Self::Swarm(error) => error.fmt(f),
            Self::Soak(error) => error.fmt(f),
            Self::SoakPlan(error) => error.fmt(f),
            Self::Coverage(error) => error.fmt(f),
            Self::Gate(error) => error.fmt(f),
            Self::SeedLease(error) => error.fmt(f),
            Self::CoverageTrackerPoisoned => f.write_str("coverage tracker lock poisoned"),
            Self::SoakOutputExists(path) => {
                write!(f, "soak artifact root already exists: {}", path.display())
            }
            Self::SoakCoveragePolicyDigest { expected, actual } => write!(
                f,
                "soak coverage policy digest mismatch: expected {expected}, actual {actual}"
            ),
            Self::SoakSwarmDigest {
                lane,
                expected,
                actual,
            } => write!(
                f,
                "soak swarm digest mismatch for {lane}: expected {expected}, actual {actual}"
            ),
            Self::SoakRunFailures {
                failed,
                errored,
                infrastructure_error,
            } => write!(
                f,
                "soak contained {failed} product failures and {errored} execution errors{}",
                infrastructure_error
                    .as_deref()
                    .map(|error| format!("; artifact infrastructure failed: {error}"))
                    .unwrap_or_default()
            ),
            Self::CampaignRunFailures(count) => {
                write!(f, "campaign contained {count} failed runs")
            }
            Self::Parity(error) => error.fmt(f),
            Self::ParityDifference(differences) => write!(
                f,
                "status=parity_difference dimensions={}",
                differences.join(",")
            ),
            Self::UnexpectedDeclarativeFailure(error) => {
                write!(f, "status=failure_appeared error={error}")
            }
            Self::DeclarativeRunFailed {
                error,
                manifest,
                signature,
            } => write!(
                f,
                "status=run_failed error={error} signature={signature}\ncargo sim replay {}",
                manifest.display()
            ),
            Self::RunFailed { error, manifest } => write!(
                f,
                "status=run_failed error={error}\ncargo sim replay {}",
                manifest.display()
            ),
            Self::PostManifestFailure { error, manifest } => write!(
                f,
                "status=artifact_failed error={error}\ncargo sim replay {}",
                manifest.display()
            ),
            Self::BackendUnavailable {
                operation,
                artifact,
            } => write!(
                f,
                "status=backend_unavailable operation={operation} stage=\"later than Stage 2\" input={:?}",
                artifact.file_name().unwrap_or_default()
            ),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ScenarioError> for CliError {
    fn from(value: ScenarioError) -> Self {
        Self::Scenario(value)
    }
}
impl From<ScenarioModelError> for CliError {
    fn from(value: ScenarioModelError) -> Self {
        Self::ScenarioModel(value)
    }
}
impl From<crate::RunnerError> for CliError {
    fn from(value: crate::RunnerError) -> Self {
        Self::Runner(value.to_string())
    }
}
impl From<ManifestError> for CliError {
    fn from(value: ManifestError) -> Self {
        Self::Manifest(value)
    }
}
impl From<CompatibilityError> for CliError {
    fn from(value: CompatibilityError) -> Self {
        Self::Compatibility(value)
    }
}
impl From<ArtifactError> for CliError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}
impl From<FailureError> for CliError {
    fn from(value: FailureError) -> Self {
        Self::Failure(value)
    }
}
impl From<FailureReplayError> for CliError {
    fn from(value: FailureReplayError) -> Self {
        Self::FailureReplay(value)
    }
}
impl From<MinimizationError> for CliError {
    fn from(value: MinimizationError) -> Self {
        Self::Minimization(value)
    }
}
impl From<CorpusError> for CliError {
    fn from(value: CorpusError) -> Self {
        Self::Corpus(value)
    }
}
impl From<CampaignError> for CliError {
    fn from(value: CampaignError) -> Self {
        Self::Campaign(value)
    }
}
impl From<SwarmError> for CliError {
    fn from(value: SwarmError) -> Self {
        Self::Swarm(value)
    }
}
impl From<SoakError> for CliError {
    fn from(value: SoakError) -> Self {
        Self::Soak(value)
    }
}
impl From<SoakPlanError> for CliError {
    fn from(value: SoakPlanError) -> Self {
        Self::SoakPlan(value)
    }
}
impl From<CoverageError> for CliError {
    fn from(value: CoverageError) -> Self {
        Self::Coverage(value)
    }
}
impl From<SeedLeaseError> for CliError {
    fn from(value: SeedLeaseError) -> Self {
        Self::SeedLease(value)
    }
}
impl From<ParityError> for CliError {
    fn from(value: ParityError) -> Self {
        Self::Parity(value)
    }
}
impl From<std::io::Error> for CliError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
