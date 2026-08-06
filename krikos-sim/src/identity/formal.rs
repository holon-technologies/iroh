//! Hermetic bounded exploration of the abstract account-control state machine.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

/// Hard state bound for the hermetic model checker.
pub const MAX_FORMAL_STATES: u64 = 4_096;
/// Hard attempted-transition bound for the hermetic model checker.
pub const MAX_FORMAL_TRANSITIONS: u64 = 200_000;
const CONTROLLER_MASK: u8 = 0b0000_0111;
const MAX_CONTROLLER_WEIGHT: u8 = 2;
const MAX_POLICY_WEIGHT: u8 = 4;
const MAX_FORMAL_ATTEMPTS_PER_STATE: usize = 128;

/// Six required design Section 31.7 properties.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FormalProperty {
    RevokedControllersCannotAuthorize,
    PolicyChangesUsePreviousPolicy,
    ForksAreDetectable,
    ThresholdRequirementsPreserved,
    RecoveryDoesNotRetainOldControllers,
    AcceptedEventsHaveUniquePredecessor,
}

impl FormalProperty {
    const ALL: [Self; 6] = [
        Self::RevokedControllersCannotAuthorize,
        Self::PolicyChangesUsePreviousPolicy,
        Self::ForksAreDetectable,
        Self::ThresholdRequirementsPreserved,
        Self::RecoveryDoesNotRetainOldControllers,
        Self::AcceptedEventsHaveUniquePredecessor,
    ];
}

/// Concrete counterexample mutation used to prove each checker is live independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormalMutation {
    RevokedControllerAuthorizes,
    PolicyAuthorizesItself,
    ForkIsHidden,
    ThresholdBecomesUnsatisfied,
    RecoveryRetainsOldController,
    AcceptedEventHasTwoPredecessors,
    RecoveryHidesFork,
}

/// Property-specific non-vacuity evidence from the bounded transition relation.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FormalPropertyEvidence {
    /// Every explored attempt for which the property predicate was evaluated.
    pub evaluations: u64,
    /// Attempts from a reachable state where the property's antecedent is true.
    pub antecedent_witnesses: u64,
    /// Accepted transitions relevant to the property.
    pub accepted_witnesses: u64,
    /// Rejected adversarial attempts relevant to the property.
    pub rejected_witnesses: u64,
}

/// Nonzero bounded exploration evidence and per-property witness counts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FormalCheckReport {
    pub schema_version: u16,
    pub states_explored: u64,
    pub transitions_explored: u64,
    pub maximum_depth: u8,
    pub property_checks: BTreeMap<FormalProperty, u64>,
    pub property_evidence: BTreeMap<FormalProperty, FormalPropertyEvidence>,
    pub tla_actions_validated: u64,
    pub tla_properties_validated: u64,
    pub semantic_parity_cases: u64,
    pub asymmetric_weight_witnesses: u64,
    pub transition_mutations_rejected: u64,
    pub portable_mutations_rejected: u64,
}

impl FormalCheckReport {
    /// Reports true only for a non-vacuous complete six-property run.
    pub fn is_non_vacuous(&self) -> bool {
        self.states_explored > 0
            && self.transitions_explored > 0
            && self.tla_actions_validated == 6
            && self.tla_properties_validated == 6
            && self.semantic_parity_cases > 0
            && self.asymmetric_weight_witnesses > 0
            && self.transition_mutations_rejected == 7
            && self.portable_mutations_rejected == 2
            && FormalProperty::ALL.iter().all(|property| {
                self.property_evidence
                    .get(property)
                    .is_some_and(|evidence| {
                        evidence.evaluations == self.transitions_explored
                            && evidence.antecedent_witnesses > 0
                            && evidence.accepted_witnesses > 0
                            && evidence.rejected_witnesses > 0
                    })
            })
    }

    /// Canonical machine-readable command output.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, FormalCheckError> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| FormalCheckError::Encoding(error.to_string()))?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Runs exhaustive breadth-first exploration within fixed controller and fork bounds.
pub fn check_account_control_model() -> Result<FormalCheckReport, FormalCheckError> {
    let specification = validate_checked_in_specification()?;
    let semantic_parity_cases = check_semantic_parity()?;
    let asymmetric_weight_witnesses = check_asymmetric_weight_witnesses()?;
    let transition_mutations_rejected = check_transition_mutation_controls()?;
    let portable_mutations_rejected = check_portable_mutation_controls()?;
    let initial = initial_state();
    let mut seen = BTreeSet::from([initial]);
    let mut queue = VecDeque::from([(initial, 0_u8)]);
    let mut transitions = 0_u64;
    let mut maximum_depth = 0_u8;
    let mut evidence = FormalProperty::ALL
        .into_iter()
        .map(|property| (property, FormalPropertyEvidence::default()))
        .collect::<BTreeMap<_, _>>();

    while let Some((state, depth)) = queue.pop_front() {
        maximum_depth = maximum_depth.max(depth);
        for attempt in attempts(state) {
            transitions = transitions
                .checked_add(1)
                .ok_or(FormalCheckError::ArithmeticOverflow)?;
            if transitions > MAX_FORMAL_TRANSITIONS {
                return Err(FormalCheckError::TransitionBoundExceeded);
            }
            let outcome = apply_attempt(state, attempt);
            check_outcome(&outcome, &mut evidence)?;
            if outcome.accepted && seen.insert(outcome.after) {
                let states =
                    u64::try_from(seen.len()).map_err(|_| FormalCheckError::ArithmeticOverflow)?;
                if states > MAX_FORMAL_STATES {
                    return Err(FormalCheckError::StateBoundExceeded);
                }
                queue.push_back((outcome.after, depth.saturating_add(1)));
            }
        }
    }

    let report = FormalCheckReport {
        schema_version: 2,
        states_explored: u64::try_from(seen.len())
            .map_err(|_| FormalCheckError::ArithmeticOverflow)?,
        transitions_explored: transitions,
        maximum_depth,
        property_checks: evidence
            .iter()
            .map(|(property, evidence)| (*property, evidence.evaluations))
            .collect(),
        property_evidence: evidence,
        tla_actions_validated: specification.actions,
        tla_properties_validated: specification.properties,
        semantic_parity_cases,
        asymmetric_weight_witnesses,
        transition_mutations_rejected,
        portable_mutations_rejected,
    };
    if !report.is_non_vacuous() {
        return Err(FormalCheckError::Vacuous);
    }
    Ok(report)
}

/// Applies one deliberate counterexample and requires the named property checker to reject it.
pub fn check_formal_mutation(mutation: FormalMutation) -> Result<(), FormalViolation> {
    let (before, attempt) = mutation_fixture(mutation);
    let outcome = apply_attempt_with_mutation(before, attempt, Some(mutation));
    let mut evidence = FormalProperty::ALL
        .into_iter()
        .map(|property| (property, FormalPropertyEvidence::default()))
        .collect::<BTreeMap<_, _>>();
    check_outcome(&outcome, &mut evidence)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpecificationEvidence {
    actions: u64,
    properties: u64,
}

fn validate_checked_in_specification() -> Result<SpecificationEvidence, FormalCheckError> {
    const SOURCE: &str = include_str!("../../../docs/identity/AccountControl.tla");
    const FORBIDDEN_GHOSTS: [&str; 4] = [
        "revokedAuthorized",
        "policyBypass",
        "recoveryRetained",
        "uniquePredecessor",
    ];
    const VARIABLES: [&str; 15] = [
        "active",
        "revoked",
        "threshold",
        "heads",
        "forkVisible",
        "lastAccepted",
        "lastKind",
        "lastApprovals",
        "predecessorCount",
        "priorActive",
        "priorRevoked",
        "priorThreshold",
        "priorHeads",
        "recoveryReplacement",
        "recoveryPreviousActive",
    ];
    const RECORD_FIELDS: [&str; 10] = [
        "lastAccepted'",
        "lastKind'",
        "lastApprovals'",
        "predecessorCount'",
        "priorActive'",
        "priorRevoked'",
        "priorThreshold'",
        "priorHeads'",
        "recoveryReplacement'",
        "recoveryPreviousActive'",
    ];
    const ACTIONS: [(&str, &[&str]); 6] = [
        (
            "AddController",
            &[
                "Authorized(approvals)",
                "active' = active \\cup {c}",
                "RecordAccepted(\"AddController\", approvals, 1, {})",
            ],
        ),
        (
            "RevokeController",
            &[
                "Authorized(approvals)",
                "WeightOf(active \\ {c}) >= threshold",
                "revoked' = revoked \\cup {c}",
                "RecordAccepted(\"RevokeController\", approvals, 1, {})",
            ],
        ),
        (
            "ChangePolicy",
            &[
                "Authorized(approvals)",
                "newThreshold \\in 1..WeightOf(active)",
                "threshold' = newThreshold",
                "RecordAccepted(\"ChangePolicy\", approvals, 1, {})",
            ],
        ),
        (
            "OpenFork",
            &[
                "Authorized(approvals)",
                "heads' = 2",
                "forkVisible' = TRUE",
                "RecordAccepted(\"OpenFork\", approvals, 1, {})",
            ],
        ),
        (
            "ResolveFork",
            &[
                "heads > 1",
                "Authorized(approvals)",
                "forkVisible' = FALSE",
                "RecordAccepted(\"ResolveFork\", approvals, heads, {})",
            ],
        ),
        (
            "Recover",
            &[
                "heads = 1",
                "replacement \\cap revoked = {}",
                "active' = replacement",
                "threshold' = newThreshold",
                "revoked' = revoked \\cup (active \\ replacement)",
                "RecordAccepted(\"Recover\", {}, 1, replacement)",
            ],
        ),
    ];
    const PROPERTIES: [(&str, &[&str]); 6] = [
        (
            "RevokedControllersCannotAuthorize",
            &["lastAccepted", "lastApprovals", "priorRevoked"],
        ),
        (
            "PolicyChangesUsePreviousPolicy",
            &["lastKind", "WeightOf(lastApprovals)", "priorThreshold"],
        ),
        (
            "ForksAreDetectable",
            &["heads", "forkVisible", "priorHeads", "ResolveFork"],
        ),
        (
            "ThresholdRequirementsPreserved",
            &["threshold", "WeightOf(active)", "active \\cap revoked"],
        ),
        (
            "RecoveryDoesNotRetainOldControllers",
            &[
                "lastKind",
                "recoveryReplacement",
                "recoveryPreviousActive",
                "revoked",
            ],
        ),
        (
            "AcceptedEventsHaveUniquePredecessor",
            &["lastAccepted", "lastKind", "predecessorCount", "priorHeads"],
        ),
    ];

    if FORBIDDEN_GHOSTS.iter().any(|name| SOURCE.contains(name)) {
        return Err(FormalCheckError::Specification(
            "TLA+ specification retains a fixed truth-value ghost variable".to_owned(),
        ));
    }
    let constants = definition_prefix(SOURCE, "CONSTANTS", "ASSUME")?;
    require_tokens("CONSTANTS", constants, &["Controllers", "ControllerWeight"])?;
    let assumptions = definition_prefix(SOURCE, "ASSUME", "VARIABLES")?;
    require_tokens(
        "ASSUME",
        assumptions,
        &[
            "Cardinality(Controllers) = 3",
            "ControllerWeight \\in [Controllers -> 1..2]",
            "ControllerWeight[c] = 2",
            "ControllerWeight[c] = 1",
        ],
    )?;
    let weighted = definition_body(SOURCE, "WeightOf")?;
    require_tokens(
        "WeightOf",
        weighted,
        &["ControllerWeight[c]", "WeightOf(controllerSet \\ {c})"],
    )?;
    let variables = definition_prefix(SOURCE, "VARIABLES", "vars ==")?;
    require_tokens("VARIABLES", variables, &VARIABLES)?;
    let record = definition_body(SOURCE, "RecordAccepted")?;
    require_tokens("RecordAccepted", record, &RECORD_FIELDS)?;
    let authorized = definition_body(SOURCE, "Authorized")?;
    require_tokens(
        "Authorized",
        authorized,
        &[
            "approvals \\in SUBSET active",
            "approvals \\cap revoked = {}",
            "WeightOf(approvals) >= threshold",
        ],
    )?;
    for (action, tokens) in ACTIONS {
        require_tokens(action, definition_body(SOURCE, action)?, tokens)?;
    }
    for (property, tokens) in PROPERTIES {
        require_tokens(property, definition_body(SOURCE, property)?, tokens)?;
    }
    let safety = definition_body(SOURCE, "Safety")?;
    for (property, _) in PROPERTIES {
        require_tokens("Safety", safety, &[property])?;
    }

    Ok(SpecificationEvidence {
        actions: u64::try_from(ACTIONS.len()).map_err(|_| FormalCheckError::ArithmeticOverflow)?,
        properties: u64::try_from(PROPERTIES.len())
            .map_err(|_| FormalCheckError::ArithmeticOverflow)?,
    })
}

fn definition_prefix<'a>(
    source: &'a str,
    start_marker: &str,
    end_marker: &str,
) -> Result<&'a str, FormalCheckError> {
    let start = source.find(start_marker).ok_or_else(|| {
        FormalCheckError::Specification(format!("missing TLA+ section {start_marker}"))
    })?;
    let after_start = &source[start..];
    let end = after_start.find(end_marker).ok_or_else(|| {
        FormalCheckError::Specification(format!("unterminated TLA+ section {start_marker}"))
    })?;
    Ok(&after_start[..end])
}

fn definition_body<'a>(source: &'a str, name: &str) -> Result<&'a str, FormalCheckError> {
    let plain_marker = format!("{name} ==");
    let parameterized_marker = format!("{name}(");
    let start = source
        .find(&plain_marker)
        .or_else(|| source.find(&parameterized_marker))
        .ok_or_else(|| {
            FormalCheckError::Specification(format!("missing TLA+ definition {name}"))
        })?;
    let definition = &source[start..];
    let separator = definition.find("==").ok_or_else(|| {
        FormalCheckError::Specification(format!("invalid TLA+ definition {name}"))
    })?;
    let body = &definition[separator + 2..];
    let end = body.find("\n\n").ok_or_else(|| {
        FormalCheckError::Specification(format!("unterminated TLA+ definition {name}"))
    })?;
    Ok(&body[..end])
}

fn require_tokens(section: &str, body: &str, tokens: &[&str]) -> Result<(), FormalCheckError> {
    if let Some(missing) = tokens.iter().find(|token| !body.contains(**token)) {
        return Err(FormalCheckError::Specification(format!(
            "TLA+ section {section} is missing semantic clause {missing:?}"
        )));
    }
    Ok(())
}

fn check_semantic_parity() -> Result<u64, FormalCheckError> {
    let initial = initial_state();
    let mut seen = BTreeSet::from([initial]);
    let mut queue = VecDeque::from([initial]);
    let mut cases = 0_u64;
    while let Some(state) = queue.pop_front() {
        for attempt in attempts(state) {
            let checker = apply_attempt(state, attempt);
            let portable = apply_portable_spec_attempt(state, attempt);
            cases = cases
                .checked_add(1)
                .ok_or(FormalCheckError::ArithmeticOverflow)?;
            if checker != portable {
                return Err(FormalCheckError::SemanticDivergence(format!(
                    "state={state:?}, attempt={attempt:?}, checker={checker:?}, portable={portable:?}"
                )));
            }
            if checker.accepted && seen.insert(checker.after) {
                if seen.len()
                    > usize::try_from(MAX_FORMAL_STATES)
                        .map_err(|_| FormalCheckError::ArithmeticOverflow)?
                {
                    return Err(FormalCheckError::StateBoundExceeded);
                }
                queue.push_back(checker.after);
            }
        }
    }
    if cases == 0 {
        return Err(FormalCheckError::Vacuous);
    }
    Ok(cases)
}

const fn initial_state() -> AbstractState {
    AbstractState {
        active: CONTROLLER_MASK,
        revoked: 0,
        threshold: 2,
        heads: 1,
        fork_visible: false,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AbstractState {
    active: u8,
    revoked: u8,
    threshold: u8,
    heads: u8,
    fork_visible: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbstractOperation {
    Add { controller: u8 },
    Revoke { controller: u8 },
    ChangePolicy { threshold: u8 },
    OpenFork,
    ResolveFork,
    Recover { replacement: u8, threshold: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Attempt {
    approvals: u8,
    predecessors: u8,
    operation: AbstractOperation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Outcome {
    before: AbstractState,
    after: AbstractState,
    attempt: Attempt,
    accepted: bool,
    recovery_replacement: u8,
}

fn attempts(state: AbstractState) -> Vec<Attempt> {
    let mut attempts = Vec::with_capacity(MAX_FORMAL_ATTEMPTS_PER_STATE);
    for approvals in 0..=CONTROLLER_MASK {
        for controller in 0..3 {
            let bit = 1_u8 << controller;
            if state.active & bit == 0 {
                attempts.push(Attempt {
                    approvals,
                    predecessors: state.heads,
                    operation: AbstractOperation::Add { controller: bit },
                });
            } else {
                attempts.push(Attempt {
                    approvals,
                    predecessors: state.heads,
                    operation: AbstractOperation::Revoke { controller: bit },
                });
            }
        }
        for threshold in 1..=MAX_POLICY_WEIGHT {
            attempts.push(Attempt {
                approvals,
                predecessors: state.heads,
                operation: AbstractOperation::ChangePolicy { threshold },
            });
        }
        attempts.push(Attempt {
            approvals,
            predecessors: state.heads,
            operation: if state.heads == 1 {
                AbstractOperation::OpenFork
            } else {
                AbstractOperation::ResolveFork
            },
        });
    }
    for replacement in 1..=CONTROLLER_MASK {
        for threshold in 1..=MAX_POLICY_WEIGHT {
            attempts.push(Attempt {
                approvals: 0,
                predecessors: state.heads,
                operation: AbstractOperation::Recover {
                    replacement,
                    threshold,
                },
            });
        }
    }
    attempts.push(Attempt {
        approvals: state.active,
        predecessors: if state.heads == 1 { 2 } else { 1 },
        operation: AbstractOperation::ChangePolicy {
            threshold: state.threshold,
        },
    });
    assert!(
        attempts.len() <= MAX_FORMAL_ATTEMPTS_PER_STATE,
        "bounded formal attempt inventory must fit MAX_FORMAL_ATTEMPTS_PER_STATE"
    );
    attempts
}

fn apply_attempt(before: AbstractState, attempt: Attempt) -> Outcome {
    apply_attempt_with_mutation(before, attempt, None)
}

fn apply_attempt_with_mutation(
    before: AbstractState,
    attempt: Attempt,
    mutation: Option<FormalMutation>,
) -> Outcome {
    let is_recovery = matches!(attempt.operation, AbstractOperation::Recover { .. });
    let expected_predecessors = if matches!(attempt.operation, AbstractOperation::ResolveFork) {
        before.heads
    } else {
        1
    };
    let predecessor_valid = attempt.predecessors == expected_predecessors
        || mutation == Some(FormalMutation::AcceptedEventHasTwoPredecessors);
    let head_valid = match attempt.operation {
        AbstractOperation::ResolveFork => before.heads == 2,
        AbstractOperation::Recover { .. }
            if mutation == Some(FormalMutation::RecoveryHidesFork) =>
        {
            before.heads == 1 || before.heads == 2
        }
        _ => before.heads == 1,
    };
    let approvals_are_known = if mutation == Some(FormalMutation::RevokedControllerAuthorizes) {
        attempt.approvals & !(before.active | before.revoked) == 0
    } else {
        attempt.approvals & !before.active == 0
    };
    let approvals_exclude_revoked = mutation == Some(FormalMutation::RevokedControllerAuthorizes)
        || attempt.approvals & before.revoked == 0;
    let required_weight = match attempt.operation {
        AbstractOperation::ChangePolicy { threshold }
            if mutation == Some(FormalMutation::PolicyAuthorizesItself) =>
        {
            threshold
        }
        _ => before.threshold,
    };
    let authorized = approvals_are_known
        && approvals_exclude_revoked
        && approval_weight(attempt.approvals) >= required_weight;
    let operation_valid = match attempt.operation {
        AbstractOperation::Add { controller } => {
            controller != 0
                && controller & !CONTROLLER_MASK == 0
                && controller.count_ones() == 1
                && controller & (before.active | before.revoked) == 0
        }
        AbstractOperation::Revoke { controller } => {
            controller & before.active != 0
                && approval_weight(before.active & !controller) >= before.threshold
        }
        AbstractOperation::ChangePolicy { threshold } => {
            threshold > 0
                && (threshold <= approval_weight(before.active)
                    || mutation == Some(FormalMutation::ThresholdBecomesUnsatisfied))
        }
        AbstractOperation::OpenFork | AbstractOperation::ResolveFork => true,
        AbstractOperation::Recover {
            replacement,
            threshold,
        } => {
            replacement != 0
                && replacement & !CONTROLLER_MASK == 0
                && replacement & before.revoked == 0
                && threshold > 0
                && threshold <= approval_weight(replacement)
        }
    };
    let accepted =
        predecessor_valid && head_valid && operation_valid && (is_recovery || authorized);
    let mut after = before;
    let mut replacement = 0;
    if accepted {
        match attempt.operation {
            AbstractOperation::Add { controller } => {
                after.active |= controller;
            }
            AbstractOperation::Revoke { controller } => {
                let candidate = before.active & !controller;
                after.active = candidate;
                after.revoked |= controller;
            }
            AbstractOperation::ChangePolicy { threshold } => {
                after.threshold = threshold;
            }
            AbstractOperation::OpenFork => {
                after.heads = 2;
                after.fork_visible = mutation != Some(FormalMutation::ForkIsHidden);
            }
            AbstractOperation::ResolveFork => {
                after.heads = 1;
                after.fork_visible = false;
            }
            AbstractOperation::Recover {
                replacement: candidate,
                threshold,
            } => {
                replacement = candidate;
                after.active = candidate;
                if mutation == Some(FormalMutation::RecoveryRetainsOldController) {
                    after.active |= before.active & !candidate;
                }
                after.revoked |= before.active & !after.active;
                after.threshold = threshold;
                after.heads = 1;
                after.fork_visible = false;
            }
        }
    }
    if !accepted {
        after = before;
        replacement = 0;
    }
    Outcome {
        before,
        after,
        attempt,
        accepted,
        recovery_replacement: replacement,
    }
}

/// Separately encoded executable semantics for the checked-in TLA+ transition predicates.
///
/// Keeping this evaluator structurally distinct from [`apply_attempt`] lets the bounded command
/// exhaustively compare accepted/rejected outcomes and successor states instead of relying on
/// source-marker checks alone.
fn apply_portable_spec_attempt(before: AbstractState, attempt: Attempt) -> Outcome {
    apply_portable_spec_attempt_with_mutation(before, attempt, None)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortableMutation {
    AuthorizationUsesCardinality,
    RecoveryResetsThreshold,
}

fn apply_portable_spec_attempt_with_mutation(
    before: AbstractState,
    attempt: Attempt,
    mutation: Option<PortableMutation>,
) -> Outcome {
    let submitted_weight = if mutation == Some(PortableMutation::AuthorizationUsesCardinality) {
        approval_cardinality(attempt.approvals)
    } else {
        approval_weight(attempt.approvals)
    };
    let approvals_are_authorized = attempt.approvals & !before.active == 0
        && attempt.approvals & before.revoked == 0
        && submitted_weight >= before.threshold;
    let expected_predecessors = if matches!(attempt.operation, AbstractOperation::ResolveFork) {
        before.heads
    } else {
        1
    };
    let operation_precondition = match attempt.operation {
        AbstractOperation::Add { controller } => {
            before.heads == 1
                && controller & CONTROLLER_MASK != 0
                && controller.count_ones() == 1
                && controller & (before.active | before.revoked) == 0
        }
        AbstractOperation::Revoke { controller } => {
            before.heads == 1
                && controller & before.active != 0
                && approval_weight(before.active & !controller) >= before.threshold
        }
        AbstractOperation::ChangePolicy { threshold } => {
            before.heads == 1 && threshold > 0 && threshold <= approval_weight(before.active)
        }
        AbstractOperation::OpenFork => before.heads == 1,
        AbstractOperation::ResolveFork => before.heads > 1,
        AbstractOperation::Recover {
            replacement,
            threshold,
        } => {
            before.heads == 1
                && replacement != 0
                && replacement & !CONTROLLER_MASK == 0
                && replacement & before.revoked == 0
                && threshold > 0
                && threshold <= approval_weight(replacement)
        }
    };
    let recovery = matches!(attempt.operation, AbstractOperation::Recover { .. });
    let accepted = attempt.predecessors == expected_predecessors
        && operation_precondition
        && (recovery || approvals_are_authorized);
    let mut after = before;
    let mut recovery_replacement = 0;
    if accepted {
        match attempt.operation {
            AbstractOperation::Add { controller } => after.active |= controller,
            AbstractOperation::Revoke { controller } => {
                after.active &= !controller;
                after.revoked |= controller;
            }
            AbstractOperation::ChangePolicy { threshold } => after.threshold = threshold,
            AbstractOperation::OpenFork => {
                after.heads = 2;
                after.fork_visible = true;
            }
            AbstractOperation::ResolveFork => {
                after.heads = 1;
                after.fork_visible = false;
            }
            AbstractOperation::Recover {
                replacement,
                threshold,
            } => {
                recovery_replacement = replacement;
                after.active = replacement;
                after.revoked |= before.active & !replacement;
                after.threshold = if mutation == Some(PortableMutation::RecoveryResetsThreshold) {
                    1
                } else {
                    threshold
                };
                after.heads = 1;
                after.fork_visible = false;
            }
        }
    }
    if !accepted {
        after = before;
        recovery_replacement = 0;
    }
    Outcome {
        before,
        after,
        attempt,
        accepted,
        recovery_replacement,
    }
}

fn check_outcome(
    outcome: &Outcome,
    evidence: &mut BTreeMap<FormalProperty, FormalPropertyEvidence>,
) -> Result<(), FormalViolation> {
    let policy_change = matches!(
        outcome.attempt.operation,
        AbstractOperation::ChangePolicy { .. }
    );
    let recovery = matches!(outcome.attempt.operation, AbstractOperation::Recover { .. });
    let expected_predecessors =
        if matches!(outcome.attempt.operation, AbstractOperation::ResolveFork) {
            outcome.before.heads
        } else {
            1
        };
    let threshold_adversarial = match outcome.attempt.operation {
        AbstractOperation::Revoke { controller } => {
            approval_weight(outcome.before.active & !controller) < outcome.before.threshold
        }
        AbstractOperation::ChangePolicy { threshold } => {
            threshold == 0 || threshold > approval_weight(outcome.before.active)
        }
        AbstractOperation::Recover {
            replacement,
            threshold,
        } => threshold == 0 || threshold > approval_weight(replacement),
        _ => false,
    };
    let rejected_policy_self_authorization = match outcome.attempt.operation {
        AbstractOperation::ChangePolicy { threshold } => {
            !outcome.accepted
                && approval_weight(outcome.attempt.approvals) < outcome.before.threshold
                && approval_weight(outcome.attempt.approvals) >= threshold
        }
        _ => false,
    };
    let evaluations = [
        (
            FormalProperty::RevokedControllersCannotAuthorize,
            !outcome.accepted || outcome.attempt.approvals & outcome.before.revoked == 0,
            outcome.before.revoked != 0,
            outcome.accepted && outcome.before.revoked != 0 && !recovery,
            !outcome.accepted && outcome.attempt.approvals & outcome.before.revoked != 0,
        ),
        (
            FormalProperty::PolicyChangesUsePreviousPolicy,
            !outcome.accepted
                || !policy_change
                || approval_weight(outcome.attempt.approvals) >= outcome.before.threshold,
            policy_change,
            outcome.accepted && policy_change,
            rejected_policy_self_authorization,
        ),
        (
            FormalProperty::ForksAreDetectable,
            (outcome.after.heads < 2 || outcome.after.fork_visible)
                && (!outcome.accepted
                    || outcome.before.heads < 2
                    || matches!(outcome.attempt.operation, AbstractOperation::ResolveFork)),
            outcome.before.heads > 1
                || matches!(
                    outcome.attempt.operation,
                    AbstractOperation::OpenFork | AbstractOperation::ResolveFork
                ),
            outcome.accepted
                && matches!(
                    outcome.attempt.operation,
                    AbstractOperation::OpenFork | AbstractOperation::ResolveFork
                ),
            !outcome.accepted
                && outcome.before.heads > 1
                && !matches!(outcome.attempt.operation, AbstractOperation::ResolveFork),
        ),
        (
            FormalProperty::ThresholdRequirementsPreserved,
            outcome.after.threshold > 0
                && outcome.after.threshold <= approval_weight(outcome.after.active)
                && outcome.after.active & outcome.after.revoked == 0,
            matches!(
                outcome.attempt.operation,
                AbstractOperation::Revoke { .. }
                    | AbstractOperation::ChangePolicy { .. }
                    | AbstractOperation::Recover { .. }
            ),
            outcome.accepted
                && matches!(
                    outcome.attempt.operation,
                    AbstractOperation::Revoke { .. }
                        | AbstractOperation::ChangePolicy { .. }
                        | AbstractOperation::Recover { .. }
                ),
            !outcome.accepted && threshold_adversarial,
        ),
        (
            FormalProperty::RecoveryDoesNotRetainOldControllers,
            !outcome.accepted
                || !matches!(outcome.attempt.operation, AbstractOperation::Recover { .. })
                || (outcome.after.active == outcome.recovery_replacement
                    && outcome.before.active
                        & !outcome.recovery_replacement
                        & !outcome.after.revoked
                        == 0),
            recovery,
            outcome.accepted && recovery,
            !outcome.accepted
                && recovery
                && match outcome.attempt.operation {
                    AbstractOperation::Recover {
                        replacement,
                        threshold,
                    } => {
                        replacement & outcome.before.revoked != 0
                            || threshold == 0
                            || threshold > approval_weight(replacement)
                            || outcome.before.heads > 1
                    }
                    _ => false,
                },
        ),
        (
            FormalProperty::AcceptedEventsHaveUniquePredecessor,
            !outcome.accepted || outcome.attempt.predecessors == expected_predecessors,
            true,
            outcome.accepted && outcome.attempt.predecessors == expected_predecessors,
            !outcome.accepted && outcome.attempt.predecessors != expected_predecessors,
        ),
    ];
    for (property, satisfied, antecedent, accepted, rejected) in evaluations {
        let property_evidence = evidence.get_mut(&property).ok_or_else(|| FormalViolation {
            property,
            witness: "missing property evidence".to_owned(),
        })?;
        property_evidence.evaluations =
            property_evidence
                .evaluations
                .checked_add(1)
                .ok_or_else(|| FormalViolation {
                    property,
                    witness: "property evaluation counter overflow".to_owned(),
                })?;
        if antecedent {
            property_evidence.antecedent_witnesses = property_evidence
                .antecedent_witnesses
                .checked_add(1)
                .ok_or_else(|| FormalViolation {
                    property,
                    witness: "property antecedent counter overflow".to_owned(),
                })?;
        }
        if accepted {
            property_evidence.accepted_witnesses = property_evidence
                .accepted_witnesses
                .checked_add(1)
                .ok_or_else(|| FormalViolation {
                    property,
                    witness: "property accepted-witness counter overflow".to_owned(),
                })?;
        }
        if rejected {
            property_evidence.rejected_witnesses = property_evidence
                .rejected_witnesses
                .checked_add(1)
                .ok_or_else(|| FormalViolation {
                    property,
                    witness: "property rejected-witness counter overflow".to_owned(),
                })?;
        }
        if !satisfied {
            return Err(FormalViolation {
                property,
                witness: format!("{outcome:?}"),
            });
        }
    }
    Ok(())
}

fn mutation_fixture(mutation: FormalMutation) -> (AbstractState, Attempt) {
    let base = initial_state();
    match mutation {
        FormalMutation::RevokedControllerAuthorizes => (
            AbstractState {
                active: 0b010,
                revoked: 0b001,
                threshold: 1,
                ..base
            },
            Attempt {
                approvals: 0b001,
                predecessors: 1,
                operation: AbstractOperation::ChangePolicy { threshold: 1 },
            },
        ),
        FormalMutation::PolicyAuthorizesItself => (
            base,
            Attempt {
                approvals: 0b010,
                predecessors: 1,
                operation: AbstractOperation::ChangePolicy { threshold: 1 },
            },
        ),
        FormalMutation::ForkIsHidden => (
            base,
            Attempt {
                approvals: 0b001,
                predecessors: 1,
                operation: AbstractOperation::OpenFork,
            },
        ),
        FormalMutation::ThresholdBecomesUnsatisfied => (
            AbstractState {
                active: 0b010,
                threshold: 1,
                ..base
            },
            Attempt {
                approvals: 0b010,
                predecessors: 1,
                operation: AbstractOperation::ChangePolicy { threshold: 2 },
            },
        ),
        FormalMutation::RecoveryRetainsOldController => (
            base,
            Attempt {
                approvals: 0,
                predecessors: 1,
                operation: AbstractOperation::Recover {
                    replacement: 0b001,
                    threshold: 2,
                },
            },
        ),
        FormalMutation::AcceptedEventHasTwoPredecessors => (
            base,
            Attempt {
                approvals: 0b001,
                predecessors: 2,
                operation: AbstractOperation::ChangePolicy { threshold: 2 },
            },
        ),
        FormalMutation::RecoveryHidesFork => (
            AbstractState {
                heads: 2,
                fork_visible: true,
                ..base
            },
            Attempt {
                approvals: 0,
                predecessors: 1,
                operation: AbstractOperation::Recover {
                    replacement: 0b001,
                    threshold: 2,
                },
            },
        ),
    }
}

fn check_transition_mutation_controls() -> Result<u64, FormalCheckError> {
    const MUTATIONS: [(FormalMutation, FormalProperty); 7] = [
        (
            FormalMutation::RevokedControllerAuthorizes,
            FormalProperty::RevokedControllersCannotAuthorize,
        ),
        (
            FormalMutation::PolicyAuthorizesItself,
            FormalProperty::PolicyChangesUsePreviousPolicy,
        ),
        (
            FormalMutation::ForkIsHidden,
            FormalProperty::ForksAreDetectable,
        ),
        (
            FormalMutation::ThresholdBecomesUnsatisfied,
            FormalProperty::ThresholdRequirementsPreserved,
        ),
        (
            FormalMutation::RecoveryRetainsOldController,
            FormalProperty::RecoveryDoesNotRetainOldControllers,
        ),
        (
            FormalMutation::AcceptedEventHasTwoPredecessors,
            FormalProperty::AcceptedEventsHaveUniquePredecessor,
        ),
        (
            FormalMutation::RecoveryHidesFork,
            FormalProperty::ForksAreDetectable,
        ),
    ];
    let mut rejected = 0_u64;
    for (mutation, expected) in MUTATIONS {
        match check_formal_mutation(mutation) {
            Err(violation) if violation.property == expected => {
                rejected = rejected
                    .checked_add(1)
                    .ok_or(FormalCheckError::ArithmeticOverflow)?;
            }
            result => {
                return Err(FormalCheckError::MutationControl(format!(
                    "transition mutation {mutation:?} expected {expected:?}, got {result:?}"
                )));
            }
        }
    }
    Ok(rejected)
}

fn check_asymmetric_weight_witnesses() -> Result<u64, FormalCheckError> {
    assert_eq!(
        approval_weight(0b001),
        MAX_CONTROLLER_WEIGHT,
        "bounded controller zero must carry the asymmetric weight-two authority"
    );
    let base = initial_state();
    let low_pair = Attempt {
        approvals: 0b110,
        predecessors: 1,
        operation: AbstractOperation::ChangePolicy { threshold: 2 },
    };
    let cases = [
        (
            Attempt {
                approvals: 0b001,
                ..low_pair
            },
            true,
        ),
        (low_pair, true),
        (
            Attempt {
                approvals: 0b010,
                ..low_pair
            },
            false,
        ),
        (
            Attempt {
                approvals: 0b010,
                operation: AbstractOperation::ChangePolicy { threshold: 1 },
                ..low_pair
            },
            false,
        ),
    ];
    let mut witnesses = 0_u64;
    for (attempt, accepted) in cases {
        let outcome = apply_attempt(base, attempt);
        if outcome.accepted != accepted || apply_portable_spec_attempt(base, attempt) != outcome {
            return Err(FormalCheckError::MutationControl(format!(
                "asymmetric authorization witness failed: {attempt:?}"
            )));
        }
        witnesses = witnesses
            .checked_add(1)
            .ok_or(FormalCheckError::ArithmeticOverflow)?;
    }
    let revoke_state = AbstractState {
        active: 0b011,
        threshold: 2,
        ..base
    };
    let revoke = Attempt {
        approvals: 0b001,
        predecessors: 1,
        operation: AbstractOperation::Revoke { controller: 0b001 },
    };
    let invalid_recovery = Attempt {
        approvals: 0,
        predecessors: 1,
        operation: AbstractOperation::Recover {
            replacement: 0b010,
            threshold: 2,
        },
    };
    for (state, attempt) in [(revoke_state, revoke), (base, invalid_recovery)] {
        if apply_attempt(state, attempt).accepted
            || apply_portable_spec_attempt(state, attempt).accepted
        {
            return Err(FormalCheckError::MutationControl(format!(
                "retained weighted threshold witness failed: {attempt:?}"
            )));
        }
        witnesses = witnesses
            .checked_add(1)
            .ok_or(FormalCheckError::ArithmeticOverflow)?;
    }
    Ok(witnesses)
}

fn check_portable_mutation_controls() -> Result<u64, FormalCheckError> {
    let base = initial_state();
    let cases = [
        (
            PortableMutation::AuthorizationUsesCardinality,
            base,
            Attempt {
                approvals: 0b001,
                predecessors: 1,
                operation: AbstractOperation::ChangePolicy { threshold: 2 },
            },
            FormalProperty::PolicyChangesUsePreviousPolicy,
        ),
        (
            PortableMutation::RecoveryResetsThreshold,
            base,
            Attempt {
                approvals: 0,
                predecessors: 1,
                operation: AbstractOperation::Recover {
                    replacement: 0b110,
                    threshold: 2,
                },
            },
            FormalProperty::ThresholdRequirementsPreserved,
        ),
    ];
    let mut rejected = 0_u64;
    for (mutation, state, attempt, property) in cases {
        let checker = apply_attempt(state, attempt);
        let portable = apply_portable_spec_attempt_with_mutation(state, attempt, Some(mutation));
        if checker == portable {
            return Err(FormalCheckError::MutationControl(format!(
                "portable mutation {mutation:?} was not detected for {property:?}"
            )));
        }
        rejected = rejected
            .checked_add(1)
            .ok_or(FormalCheckError::ArithmeticOverflow)?;
    }
    Ok(rejected)
}

const fn approval_weight(mask: u8) -> u8 {
    ((mask & 1) * MAX_CONTROLLER_WEIGHT) + ((mask >> 1) & 1) + ((mask >> 2) & 1)
}

const fn approval_cardinality(mask: u8) -> u8 {
    (mask & 1) + ((mask >> 1) & 1) + ((mask >> 2) & 1)
}

/// Concrete property violation with a bounded debug witness.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("formal property {property:?} failed: {witness}")]
pub struct FormalViolation {
    pub property: FormalProperty,
    pub witness: String,
}

/// Hermetic bounded-check configuration, exhaustion, encoding, or property failure.
#[derive(Debug, thiserror::Error)]
pub enum FormalCheckError {
    #[error("formal state bound exceeded")]
    StateBoundExceeded,
    #[error("formal transition bound exceeded")]
    TransitionBoundExceeded,
    #[error("formal exploration arithmetic overflow")]
    ArithmeticOverflow,
    #[error("formal exploration was vacuous")]
    Vacuous,
    #[error("checked-in TLA+ specification is invalid: {0}")]
    Specification(String),
    #[error("portable TLA+ semantics diverged from the bounded checker: {0}")]
    SemanticDivergence(String),
    #[error("formal mutation control failed: {0}")]
    MutationControl(String),
    #[error("formal report encoding failed: {0}")]
    Encoding(String),
    #[error(transparent)]
    Violation(#[from] FormalViolation),
}
