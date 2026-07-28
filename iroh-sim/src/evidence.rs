//! Manifests, traces, artifacts, corpus, failures, coverage, and parity evidence.

pub use crate::{
    artifact::{ArtifactError, ArtifactStore, ArtifactTraceWriter},
    corpus::{
        CORPUS_SCHEMA_VERSION, Corpus, CorpusEntry, CorpusError, CorpusExpectation, CorpusMetadata,
        CorpusMinimizationEvidence, CorpusPromotionEvidence, CorpusReplayEvidence, CorpusReport,
        CorpusReviewState,
    },
    coverage::{
        BehaviorTransition, COVERAGE_POLICY_SCHEMA_VERSION, COVERAGE_REPORT_SCHEMA_VERSION,
        CoverageBucket, CoverageCombination, CoverageCount, CoverageDimensionPolicy,
        CoverageDisposition, CoverageDomainBinding, CoverageDomainPolicy, CoverageError,
        CoverageEvidence, CoverageHigherOrder, CoverageLane, CoverageLanePolicy, CoverageLedger,
        CoverageObligations, CoverageObservation, CoveragePair, CoveragePhase, CoveragePolicy,
        CoverageReport, CoverageSelection, CoverageValuePolicy, IndividualObligation,
        KnownCoverageGap, OracleCoverage, PairwiseObligation, PhaseObligation, TransitionCoverage,
    },
    failure::{
        FAILURE_ARTIFACT_SCHEMA_VERSION, FAILURE_SIGNATURE_SCHEMA_VERSION, FailureArtifactBundle,
        FailureArtifactIndex, FailureError, FailureReplayError, FailureSignature,
        OPERATIONAL_OUTCOME_SCHEMA_VERSION, OperationalOutcome, OperationalOutcomeClass,
        OperationalOutcomeError, TerminalFailureClass, compare_failure_replay,
        verify_failure_artifacts,
    },
    manifest::{
        BackendCapabilities, CompatibilityError, CryptoMode, DeterminismGrade,
        MANIFEST_SCHEMA_VERSION, ManifestError, ReplayIdentity, RunBudgets, RunManifest,
        SIMULATOR_VERSION, SourceIdentity, TraceComparisonMode,
    },
    parity::{
        PARITY_FIXTURE_SCHEMA_VERSION, PATCHBAY_RECEIPT_SCHEMA_VERSION, ParityBackend,
        ParityComparison, ParityComparisonStatus, ParityError, ParityEvidence, ParityFixture,
        ParityFixtureResult, PatchbayReceipt, SemanticDimension, SemanticOutcome, SemanticTerminal,
        compare_parity_fixtures, compare_parity_fixtures_at, compare_semantic_outcomes,
        deterministic_semantic_outcome,
    },
    parity_catalog::{CanonicalParityCase, CanonicalParityScenario, canonical_patchbay_scenarios},
    trace::{
        DEFAULT_MAX_TRACE_BUFFER_EVENTS, TraceBuffer, TraceBufferError, TraceDivergence,
        TraceNormalizationError, first_trace_divergence, normalized_trace_json,
    },
};
