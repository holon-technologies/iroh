//! Pure pre-state account-event verification helpers.

use krikos_base::{PublicKey, Signature};

use crate::{
    AccountState, AlgorithmKind, AlgorithmSignature, AuthorizedEvent, CanonicalWire, ControllerId,
    FreshnessRequirement, IdentityError, ProviderMode,
};

/// Authority facts derived while validating one event envelope.
pub(crate) struct ValidatedEvent {
    provider_authority_time: Option<crate::Timestamp>,
}

impl ValidatedEvent {
    /// Deterministic provider-quorum signed-head time, when required by the rule.
    pub(crate) const fn provider_authority_time(&self) -> Option<crate::Timestamp> {
        self.provider_authority_time
    }
}

/// Opaque result proving one exact event intent met its authenticated pre-state threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedEventIntent {
    account_id: crate::AccountId,
    proposal_id: crate::ProposalId,
}

impl VerifiedEventIntent {
    /// Account whose current projected authority approved the intent.
    pub(crate) const fn account_id(self) -> crate::AccountId {
        self.account_id
    }

    /// Exact body-only proposal approved by the projected authority.
    pub(crate) const fn proposal_id(self) -> crate::ProposalId {
        self.proposal_id
    }
}

/// Verify a threshold-approved proposal intent against one exact authenticated pre-state.
pub(crate) fn verify_event_intent(
    pre_state: &AccountState,
    body: &crate::EventBody,
    approvals: &crate::EventIntentApprovals,
) -> Result<VerifiedEventIntent, IdentityError> {
    if body.account_id() != pre_state.account_id() {
        return Err(IdentityError::AccountMismatch);
    }
    if body.sequence() != pre_state.sequence().checked_next()? {
        return Err(IdentityError::InvalidSequence);
    }
    validate_body_predecessors(pre_state, body)?;
    if body.resulting_epoch() != pre_state.expected_epoch_for(body.operation())? {
        return Err(IdentityError::InvalidEpoch);
    }

    let proposal_id = body.proposal_id()?;
    if approvals.proposal_id() != proposal_id {
        return Err(IdentityError::InvalidRelationship {
            resource: "event intent proposal",
        });
    }
    let rule = pre_state
        .control_policy()
        .rule_for(body.operation().kind())
        .ok_or(IdentityError::AuthorizationDenied)?;
    if rule.delay().is_none()
        && !matches!(body.operation(), crate::AccountOperation::BeginRecovery(_))
    {
        return Err(IdentityError::InvalidRelationship {
            resource: "provider event intent without policy delay",
        });
    }

    match body.operation() {
        crate::AccountOperation::BeginRecovery(_) | crate::AccountOperation::CancelRecovery(_) => {
            validate_recovery_intent_authority(pre_state, body, approvals)?;
        }
        crate::AccountOperation::FinalizeRecovery(_) => {
            // Finalization is authorized by the pending recovery plus nested provider evidence,
            // never by an unrelated controller-intent threshold.
            return Err(IdentityError::AuthorizationDenied);
        }
        _ => validate_intent_threshold(
            pre_state,
            body,
            approvals,
            rule.eligible_controllers(),
            rule.required_weight(),
        )?,
    }

    Ok(VerifiedEventIntent {
        account_id: pre_state.account_id(),
        proposal_id,
    })
}

/// Verify guardian authority embedded in one exact recovery intent at one provider observation.
///
/// The provider observation time is bound into the resulting opaque append admission. Provider
/// receipts later establish quorum authority time and the event path re-verifies the same embedded
/// guardian set; this pre-admission check cannot replace that final validation.
pub(crate) fn verify_guardian_recovery_intent(
    pre_state: &AccountState,
    body: &crate::EventBody,
    observed_at: crate::Timestamp,
) -> Result<VerifiedEventIntent, IdentityError> {
    if body.account_id() != pre_state.account_id() {
        return Err(IdentityError::AccountMismatch);
    }
    if body.sequence() != pre_state.sequence().checked_next()? {
        return Err(IdentityError::InvalidSequence);
    }
    validate_body_predecessors(pre_state, body)?;
    if body.resulting_epoch() != pre_state.expected_epoch_for(body.operation())? {
        return Err(IdentityError::InvalidEpoch);
    }
    pre_state
        .control_policy()
        .rule_for(body.operation().kind())
        .ok_or(IdentityError::AuthorizationDenied)?;

    let (threshold_evidence, recovery_id, decision) = match body.operation() {
        crate::AccountOperation::BeginRecovery(begin) => (
            begin.threshold_evidence(),
            begin.recovery_id(),
            crate::GuardianApprovalDecision::Begin,
        ),
        crate::AccountOperation::CancelRecovery(cancel) => (
            cancel.threshold_evidence(),
            cancel.expected_pending_recovery(),
            crate::GuardianApprovalDecision::Cancel,
        ),
        _ => {
            return Err(IdentityError::InvalidRelationship {
                resource: "guardian recovery intent operation",
            });
        }
    };
    if threshold_evidence.recovery_policy_id() != pre_state.recovery_policy_id()
        || threshold_evidence.recovery_policy_version()
            != pre_state.recovery_policy().policy_version()
    {
        return Err(IdentityError::PolicyVersionMismatch);
    }
    if !matches!(
        pre_state.recovery_policy().authority(),
        crate::RecoveryAuthority::GuardianThreshold(_)
    ) {
        return Err(IdentityError::InvalidRelationship {
            resource: "guardian intent under controller recovery policy",
        });
    }
    let approvals = threshold_evidence
        .as_guardian_approvals()
        .ok_or(IdentityError::AuthorizationDenied)?;
    let context = crate::GuardianAuthorityContext::try_new(
        pre_state.account_id(),
        recovery_id,
        pre_state.recovery_policy_id(),
        pre_state.recovery_policy().policy_version(),
        pre_state.epoch(),
        decision,
        observed_at,
    )?;
    crate::verify_guardian_authority(pre_state.recovery_policy(), approvals, &context)?;
    Ok(VerifiedEventIntent {
        account_id: pre_state.account_id(),
        proposal_id: body.proposal_id()?,
    })
}

/// Validate envelope binding and weighted authorization against an immutable pre-state.
pub(crate) fn validate_event(
    lineage: &AccountState,
    authority: &AccountState,
    event: &AuthorizedEvent,
    expected_epoch: crate::Epoch,
) -> Result<ValidatedEvent, IdentityError> {
    let body = event.body();
    if body.account_id() != lineage.account_id() {
        return Err(IdentityError::AccountMismatch);
    }
    if body.sequence() != lineage.sequence().checked_next()? {
        return Err(IdentityError::InvalidSequence);
    }
    validate_predecessors(lineage, event)?;
    if body.resulting_epoch() != expected_epoch {
        return Err(IdentityError::InvalidEpoch);
    }

    let proposal_id = body.proposal_id()?;
    let evidence = event.admission_evidence();
    if evidence.proposal_id() != proposal_id {
        return Err(IdentityError::InvalidRelationship {
            resource: "projected event admission subject",
        });
    }
    if evidence.provider_policy_id() != authority.provider_policy_id() {
        return Err(IdentityError::PolicyVersionMismatch);
    }

    let rule = authority
        .control_policy()
        .rule_for(body.operation().kind())
        .ok_or(IdentityError::AuthorizationDenied)?;
    if matches!(
        body.operation(),
        crate::AccountOperation::BeginRecovery(_) | crate::AccountOperation::FinalizeRecovery(_)
    ) {
        authority.require_v1_recovery_crypto()?;
    }
    let provider_authority_time = validate_freshness(authority, event, rule)?;
    match body.operation() {
        crate::AccountOperation::BeginRecovery(_) | crate::AccountOperation::CancelRecovery(_) => {
            validate_recovery_authority(authority, event, provider_authority_time)?;
        }
        crate::AccountOperation::FinalizeRecovery(_) => {
            if !event.approvals().as_slice().is_empty() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "finalize recovery controller approvals",
                });
            }
        }
        _ => validate_approvals(authority, event, rule)?,
    }
    Ok(ValidatedEvent {
        provider_authority_time,
    })
}

fn validate_predecessors(
    lineage: &AccountState,
    event: &AuthorizedEvent,
) -> Result<(), IdentityError> {
    validate_body_predecessors(lineage, event.body())
}

fn validate_body_predecessors(
    lineage: &AccountState,
    body: &crate::EventBody,
) -> Result<(), IdentityError> {
    let predecessors = body.predecessors();
    if lineage.sequence() == crate::Sequence::GENESIS {
        if predecessors.genesis_anchor() != Some(lineage.genesis_anchor()) {
            return Err(IdentityError::InvalidPredecessor);
        }
        return Ok(());
    }
    if predecessors.event_heads() != Some(lineage.heads()) {
        return Err(IdentityError::InvalidPredecessor);
    }
    Ok(())
}

fn validate_freshness(
    authority: &AccountState,
    event: &AuthorizedEvent,
    rule: &crate::PolicyRule,
) -> Result<Option<crate::Timestamp>, IdentityError> {
    let evidence = event.admission_evidence();
    let mut valid_completion_receipts = Vec::new();
    let mut rule_provider_quorum = 0_usize;
    let mut provider_authority_time = None;
    match rule.freshness() {
        FreshnessRequirement::LatestKnown => {}
        FreshnessRequirement::ProviderQuorum(requirement) => {
            let receipts = evidence
                .freshness()
                .provider_receipts()
                .ok_or(IdentityError::FreshnessUnavailable)?;
            if evidence.freshness().provider_policy_id() != Some(authority.provider_policy_id()) {
                return Err(IdentityError::PolicyVersionMismatch);
            }
            let policy = match authority.provider_policy().mode() {
                ProviderMode::LocalOnly => return Err(IdentityError::FreshnessUnavailable),
                ProviderMode::Replicated(policy) => policy,
            };
            rule_provider_quorum = usize::from(requirement.required().get());
            let required =
                rule_provider_quorum.max(usize::from(policy.sufficient_threshold().get()));
            let maximum_age = requirement
                .maximum_age()
                .get()
                .min(policy.maximum_evidence_age().get());
            let mut stale_configured_receipt = false;
            for receipt in receipts.as_slice() {
                if receipt.entry().account_id() != authority.account_id() {
                    return Err(IdentityError::AccountMismatch);
                }
                let Some(provider) =
                    configured_provider(policy.providers(), receipt.provider_id())?
                else {
                    continue;
                };
                receipt.verify(provider)?;
                let entry_time = receipt.entry().observed_at().as_unix_millis();
                let head_time = receipt.signed_head().body().observed_at().as_unix_millis();
                let age = head_time.checked_sub(entry_time).ok_or(
                    IdentityError::InvalidRelationship {
                        resource: "provider head observation time",
                    },
                )?;
                if age > maximum_age {
                    stale_configured_receipt = true;
                    continue;
                }
                valid_completion_receipts.push(receipt);
            }
            if valid_completion_receipts.len() < required {
                return Err(if stale_configured_receipt {
                    IdentityError::StaleEvidence
                } else {
                    IdentityError::FreshnessUnavailable
                });
            }
            let mut authority_times = valid_completion_receipts
                .iter()
                .map(|receipt| receipt.signed_head().body().observed_at())
                .collect::<Vec<_>>();
            authority_times.sort_unstable();
            provider_authority_time = Some(authority_times[required - 1]);
        }
    }

    let requires_recovery_observation = matches!(
        event.body().operation(),
        crate::AccountOperation::BeginRecovery(_)
    ) || matches!(
        (
            event.body().operation(),
            authority.recovery_policy().authority(),
        ),
        (
            crate::AccountOperation::CancelRecovery(_),
            crate::RecoveryAuthority::GuardianThreshold(_),
        )
    );
    if requires_recovery_observation {
        return validate_recovery_intent_observation(
            authority,
            event,
            rule,
            rule_provider_quorum,
            provider_authority_time,
        );
    }

    match rule.delay() {
        None if evidence.delay().observed_at().is_none() => {}
        None => {
            return Err(IdentityError::InvalidRelationship {
                resource: "unexpected policy delay evidence",
            });
        }
        Some(delay) => {
            let delay_anchor = evidence
                .delay()
                .observed_at()
                .ok_or(IdentityError::FreshnessUnavailable)?;
            if evidence.delay().provider_policy_id() != Some(authority.provider_policy_id()) {
                return Err(IdentityError::PolicyVersionMismatch);
            }
            let policy = match authority.provider_policy().mode() {
                ProviderMode::LocalOnly => return Err(IdentityError::FreshnessUnavailable),
                ProviderMode::Replicated(policy) => policy,
            };
            let declared_delay_quorum = evidence
                .delay()
                .required_quorum()
                .ok_or(IdentityError::FreshnessUnavailable)?;
            let minimum_required =
                usize::from(policy.sufficient_threshold().get()).max(rule_provider_quorum);
            if usize::from(declared_delay_quorum.get()) < minimum_required {
                return Err(IdentityError::FreshnessUnavailable);
            }
            let required = minimum_required.max(usize::from(declared_delay_quorum.get()));
            let delay_receipts = evidence
                .delay()
                .provider_receipts()
                .ok_or(IdentityError::FreshnessUnavailable)?;
            let mut configured_delay_receipts = Vec::new();
            for receipt in delay_receipts.as_slice() {
                if receipt.entry().account_id() != authority.account_id() {
                    return Err(IdentityError::AccountMismatch);
                }
                let Some(provider) =
                    configured_provider(policy.providers(), receipt.provider_id())?
                else {
                    continue;
                };
                receipt.verify(provider)?;
                configured_delay_receipts.push(receipt);
            }
            if configured_delay_receipts.len() < required {
                return Err(IdentityError::FreshnessUnavailable);
            }
            let mut configured_delay_observations = configured_delay_receipts
                .iter()
                .map(|receipt| receipt.entry().observed_at())
                .collect::<Vec<_>>();
            configured_delay_observations.sort_unstable();
            if configured_delay_observations[required - 1] != delay_anchor {
                return Err(IdentityError::InvalidRelationship {
                    resource: "configured-provider delay observation anchor",
                });
            }
            validate_intent_approvals(authority, event, rule)?;
            let deadline = delay_anchor.checked_add(delay)?;
            let completion_receipts =
                if matches!(rule.freshness(), FreshnessRequirement::LatestKnown) {
                    configured_delay_receipts
                } else {
                    valid_completion_receipts
                };
            let mut elapsed_authority_times = completion_receipts
                .iter()
                .map(|receipt| receipt.signed_head().body().observed_at())
                .filter(|observed_at| *observed_at >= deadline)
                .collect::<Vec<_>>();
            if elapsed_authority_times.len() < required {
                return Err(IdentityError::DelayNotElapsed);
            }
            elapsed_authority_times.sort_unstable();
            provider_authority_time = Some(elapsed_authority_times[required - 1]);
        }
    }
    Ok(provider_authority_time)
}

fn validate_recovery_intent_observation(
    authority: &AccountState,
    event: &AuthorizedEvent,
    rule: &crate::PolicyRule,
    rule_provider_quorum: usize,
    provider_authority_time: Option<crate::Timestamp>,
) -> Result<Option<crate::Timestamp>, IdentityError> {
    // Begin uses this verified observation to start the mandatory recovery delay. Guardian Cancel
    // uses the same exact-proposal observation only to authenticate authority time; cancellation
    // itself never consumes or waits for a delay interval.
    let evidence = event.admission_evidence();
    let delay_anchor = evidence
        .delay()
        .observed_at()
        .ok_or(IdentityError::FreshnessUnavailable)?;
    if evidence.delay().provider_policy_id() != Some(authority.provider_policy_id()) {
        return Err(IdentityError::PolicyVersionMismatch);
    }
    let policy = match authority.provider_policy().mode() {
        ProviderMode::LocalOnly => return Err(IdentityError::FreshnessUnavailable),
        ProviderMode::Replicated(policy) => policy,
    };
    let declared_quorum = evidence
        .delay()
        .required_quorum()
        .ok_or(IdentityError::FreshnessUnavailable)?;
    let minimum_required =
        usize::from(policy.sufficient_threshold().get()).max(rule_provider_quorum);
    if usize::from(declared_quorum.get()) < minimum_required {
        return Err(IdentityError::FreshnessUnavailable);
    }
    let required = minimum_required.max(usize::from(declared_quorum.get()));
    let receipts = evidence
        .delay()
        .provider_receipts()
        .ok_or(IdentityError::FreshnessUnavailable)?;
    let mut configured_receipts = Vec::new();
    for receipt in receipts.as_slice() {
        if receipt.entry().account_id() != authority.account_id() {
            return Err(IdentityError::AccountMismatch);
        }
        let Some(provider) = configured_provider(policy.providers(), receipt.provider_id())? else {
            continue;
        };
        receipt.verify(provider)?;
        configured_receipts.push(receipt);
    }
    if configured_receipts.len() < required {
        return Err(IdentityError::FreshnessUnavailable);
    }
    let mut observations = configured_receipts
        .iter()
        .map(|receipt| receipt.entry().observed_at())
        .collect::<Vec<_>>();
    observations.sort_unstable();
    if observations[required - 1] != delay_anchor {
        return Err(IdentityError::InvalidRelationship {
            resource: "configured-provider recovery intent observation anchor",
        });
    }
    validate_intent_approvals(authority, event, rule)?;
    let mut authority_times = configured_receipts
        .iter()
        .map(|receipt| receipt.signed_head().body().observed_at())
        .collect::<Vec<_>>();
    authority_times.sort_unstable();
    let start_authority_time = authority_times[required - 1];
    Ok(Some(
        provider_authority_time.map_or(start_authority_time, |freshness_time| {
            freshness_time.max(start_authority_time)
        }),
    ))
}

pub(crate) fn configured_provider(
    providers: &[crate::ProviderDescriptor],
    provider_id: crate::ProviderId,
) -> Result<Option<&crate::ProviderDescriptor>, IdentityError> {
    for provider in providers {
        if provider.id()? == provider_id {
            return Ok(Some(provider));
        }
    }
    Ok(None)
}

fn validate_intent_approvals(
    authority: &AccountState,
    event: &AuthorizedEvent,
    rule: &crate::PolicyRule,
) -> Result<(), IdentityError> {
    let proposal_id = event.body().proposal_id()?;
    let delay = event.admission_evidence().delay();
    let receipts = event
        .admission_evidence()
        .delay()
        .provider_receipts()
        .ok_or(IdentityError::FreshnessUnavailable)?;
    if receipts.as_slice().iter().any(|receipt| {
        receipt.entry().subject() != crate::ProviderLogSubject::EventIntent(proposal_id)
    }) {
        return Err(IdentityError::InvalidRelationship {
            resource: "delayed intent receipt subject",
        });
    }

    let (selector, required_weight) = match event.body().operation() {
        crate::AccountOperation::BeginRecovery(_) | crate::AccountOperation::CancelRecovery(_) => {
            match authority.recovery_policy().authority() {
                crate::RecoveryAuthority::ControllerThreshold(threshold) => {
                    if delay.is_guardian_recovery() {
                        return Err(IdentityError::InvalidRelationship {
                            resource: "guardian delay evidence under controller recovery policy",
                        });
                    }
                    (threshold.selector(), threshold.required_weight())
                }
                crate::RecoveryAuthority::GuardianThreshold(_) => {
                    // The proposal ID already commits the embedded guardian approval set. The
                    // provider receipts bind that exact proposal; unrelated controller intent
                    // signatures are not recovery authority.
                    if !delay.is_guardian_recovery() {
                        return Err(IdentityError::InvalidRelationship {
                            resource: "guardian recovery delay evidence shape",
                        });
                    }
                    return Ok(());
                }
            }
        }
        _ => {
            if delay.is_guardian_recovery() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "guardian delay evidence for ordinary operation",
                });
            }
            (rule.eligible_controllers(), rule.required_weight())
        }
    };

    let intent_approvals = delay
        .intent_approvals()
        .ok_or(IdentityError::FreshnessUnavailable)?;
    if intent_approvals.proposal_id() != proposal_id {
        return Err(IdentityError::InvalidRelationship {
            resource: "delayed intent proposal",
        });
    }

    validate_intent_threshold(
        authority,
        event.body(),
        intent_approvals,
        selector,
        required_weight,
    )
}

fn validate_intent_threshold(
    authority: &AccountState,
    body: &crate::EventBody,
    intent_approvals: &crate::EventIntentApprovals,
    selector: &crate::ControllerSelector,
    required_weight: crate::RequiredWeight,
) -> Result<(), IdentityError> {
    let mut total_weight = 0_u64;
    let mut previous_signer = None;
    for approval in intent_approvals.as_slice() {
        let controller_id = approval.body().controller_id();
        if previous_signer == Some(controller_id) {
            return Err(IdentityError::DuplicateSigner);
        }
        previous_signer = Some(controller_id);
        let controller = approval_controller(authority, controller_id)?;
        if !controller
            .descriptor()
            .scope()
            .allows(body.operation().kind())
            || !selector.matches_controller(controller.descriptor())?
        {
            return Err(IdentityError::IneligibleController);
        }
        let keys = authority.verification_keys(controller_id)?;
        if keys.len() != approval.signatures().len() {
            return Err(IdentityError::InvalidSignature);
        }
        let signed_bytes = approval.body().to_canonical_bytes()?;
        for expected in &keys {
            let signature = approval
                .signatures()
                .iter()
                .find(|signature| {
                    signature.crypto_suite_id() == expected.crypto_suite_id
                        && signature.controller_key_id() == expected.controller_key_id
                })
                .ok_or(IdentityError::InvalidSignature)?;
            verify_algorithm_signature(
                expected.algorithm_code,
                &expected.public_key,
                signature.signature(),
                &signed_bytes,
            )?;
        }
        total_weight = total_weight
            .checked_add(u64::from(controller.descriptor().weight().get()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "event intent authorization weight",
            })?;
    }
    if total_weight < u64::from(required_weight.get()) {
        return Err(IdentityError::AuthorizationDenied);
    }
    Ok(())
}

fn validate_recovery_intent_authority(
    authority: &AccountState,
    body: &crate::EventBody,
    intent_approvals: &crate::EventIntentApprovals,
) -> Result<(), IdentityError> {
    let evidence = match body.operation() {
        crate::AccountOperation::BeginRecovery(begin) => begin.threshold_evidence(),
        crate::AccountOperation::CancelRecovery(cancel) => cancel.threshold_evidence(),
        _ => {
            return Err(IdentityError::InvalidRelationship {
                resource: "non-recovery event under recovery intent authority",
            });
        }
    };
    if evidence.recovery_policy_id() != authority.recovery_policy_id()
        || evidence.recovery_policy_version() != authority.recovery_policy().policy_version()
    {
        return Err(IdentityError::PolicyVersionMismatch);
    }

    match authority.recovery_policy().authority() {
        crate::RecoveryAuthority::ControllerThreshold(threshold) => {
            if evidence.as_guardian_approvals().is_some() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "guardian evidence for controller recovery intent",
                });
            }
            validate_intent_threshold(
                authority,
                body,
                intent_approvals,
                threshold.selector(),
                threshold.required_weight(),
            )
        }
        crate::RecoveryAuthority::GuardianThreshold(_) => {
            // Exact guardian membership and expiry require an authenticated authority time. This
            // pre-admission API intentionally has no caller-supplied time escape hatch.
            Err(IdentityError::FreshnessUnavailable)
        }
    }
}

fn validate_approvals(
    authority: &AccountState,
    event: &AuthorizedEvent,
    rule: &crate::PolicyRule,
) -> Result<(), IdentityError> {
    let mut total_weight = 0_u64;
    let mut previous_signer: Option<ControllerId> = None;
    for approval in event.approvals().as_slice() {
        let controller_id = approval.body().controller_id();
        if previous_signer == Some(controller_id) {
            return Err(IdentityError::DuplicateSigner);
        }
        previous_signer = Some(controller_id);
        let controller = approval_controller(authority, controller_id)?;
        if !controller
            .descriptor()
            .scope()
            .allows(event.body().operation().kind())
            || !rule
                .eligible_controllers()
                .matches_controller(controller.descriptor())?
        {
            return Err(IdentityError::IneligibleController);
        }
        verify_controller_approval(authority, approval)?;

        total_weight = total_weight
            .checked_add(u64::from(controller.descriptor().weight().get()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "controller authorization weight",
            })?;
    }

    if total_weight < u64::from(rule.required_weight().get()) {
        return Err(IdentityError::AuthorizationDenied);
    }
    Ok(())
}

fn approval_controller(
    authority: &AccountState,
    controller_id: ControllerId,
) -> Result<&crate::ProjectedController, IdentityError> {
    match authority.active_controller(controller_id) {
        Some(controller) => Ok(controller),
        None if authority.revoked_controller(controller_id).is_some() => {
            Err(IdentityError::RevokedController)
        }
        None => Err(IdentityError::UnknownController),
    }
}

pub(crate) fn verify_controller_approval(
    authority: &AccountState,
    approval: &crate::SignedControllerApproval,
) -> Result<(), IdentityError> {
    let controller_id = approval.body().controller_id();
    let signed_bytes = approval.body().to_canonical_bytes()?;
    let keys = authority.verification_keys(controller_id)?;
    if approval.signatures().len() != keys.len() {
        return Err(IdentityError::InvalidSignature);
    }
    for expected in &keys {
        let keyed_signature = approval
            .signatures()
            .iter()
            .find(|signature| {
                signature.crypto_suite_id() == expected.crypto_suite_id
                    && signature.controller_key_id() == expected.controller_key_id
            })
            .ok_or(IdentityError::InvalidSignature)?;
        if keyed_signature.signature().algorithm_code() != expected.algorithm_code {
            return Err(IdentityError::InvalidSignature);
        }
        verify_algorithm_signature(
            expected.algorithm_code,
            expected.public_key.as_slice(),
            keyed_signature.signature(),
            &signed_bytes,
        )?;
    }
    Ok(())
}

/// Verify direct checkpoint attestations under the authority that governs provider policy.
///
/// Checkpoint publication is not an account-state transition in v1, so it has no account-operation
/// codepoint of its own. The frozen v1 rule is to reuse the current `ChangeProviderPolicy` selector
/// and weighted threshold: the controllers allowed to choose the transparency set are the ones
/// allowed to authorize a directly published checkpoint to that set.
pub(crate) fn verify_checkpoint_approvals(
    authority: &AccountState,
    approvals: &crate::ControllerApprovals,
) -> Result<(), IdentityError> {
    let operation = crate::OperationKind::ChangeProviderPolicy;
    let rule = authority
        .control_policy()
        .rule_for(operation)
        .ok_or(IdentityError::AuthorizationDenied)?;
    let mut total_weight = 0_u64;
    let mut previous_signer = None;
    for approval in approvals.as_slice() {
        let controller_id = approval.body().controller_id();
        if previous_signer == Some(controller_id) {
            return Err(IdentityError::DuplicateSigner);
        }
        previous_signer = Some(controller_id);
        let controller = approval_controller(authority, controller_id)?;
        if !controller.descriptor().scope().allows(operation)
            || !rule
                .eligible_controllers()
                .matches_controller(controller.descriptor())?
        {
            return Err(IdentityError::IneligibleController);
        }
        verify_controller_approval(authority, approval)?;
        total_weight = total_weight
            .checked_add(u64::from(controller.descriptor().weight().get()))
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "checkpoint controller authorization weight",
            })?;
    }
    if total_weight < u64::from(rule.required_weight().get()) {
        return Err(IdentityError::AuthorizationDenied);
    }
    Ok(())
}

fn verify_ed25519(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), IdentityError> {
    let public_key: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| IdentityError::InvalidSignature)?;
    let public_key =
        PublicKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidSignature)?;
    let signature = Signature::try_from(signature).map_err(|_| IdentityError::InvalidSignature)?;
    public_key
        .verify(message, &signature)
        .map_err(|_| IdentityError::InvalidSignature)
}

fn validate_recovery_authority(
    authority: &AccountState,
    event: &AuthorizedEvent,
    provider_authority_time: Option<crate::Timestamp>,
) -> Result<(), IdentityError> {
    let (evidence, recovery_id, expected_decision, operation_kind) = match event.body().operation()
    {
        crate::AccountOperation::BeginRecovery(begin) => (
            begin.threshold_evidence(),
            begin.recovery_id(),
            crate::GuardianApprovalDecision::Begin,
            crate::OperationKind::BeginRecovery,
        ),
        crate::AccountOperation::CancelRecovery(cancel) => (
            cancel.threshold_evidence(),
            cancel.expected_pending_recovery(),
            crate::GuardianApprovalDecision::Cancel,
            crate::OperationKind::CancelRecovery,
        ),
        _ => return Ok(()),
    };
    if evidence.recovery_policy_id() != authority.recovery_policy_id()
        || evidence.recovery_policy_version() != authority.recovery_policy().policy_version()
    {
        return Err(IdentityError::PolicyVersionMismatch);
    }

    match authority.recovery_policy().authority() {
        crate::RecoveryAuthority::ControllerThreshold(threshold) => {
            if evidence.as_guardian_approvals().is_some() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "guardian evidence for controller recovery authority",
                });
            }
            let mut total = 0_u64;
            let mut previous_signer = None;
            for approval in event.approvals().as_slice() {
                let controller_id = approval.body().controller_id();
                if previous_signer == Some(controller_id) {
                    return Err(IdentityError::DuplicateSigner);
                }
                previous_signer = Some(controller_id);
                let controller = approval_controller(authority, controller_id)?;
                if threshold
                    .selector()
                    .matches_controller(controller.descriptor())?
                    && controller.descriptor().scope().allows(operation_kind)
                {
                    total = total
                        .checked_add(u64::from(controller.descriptor().weight().get()))
                        .ok_or(IdentityError::ArithmeticOverflow {
                            resource: "controller recovery weight",
                        })?;
                } else {
                    return Err(IdentityError::IneligibleController);
                }
                verify_controller_approval(authority, approval)?;
            }
            if total < u64::from(threshold.required_weight().get()) {
                return Err(IdentityError::AuthorizationDenied);
            }
            Ok(())
        }
        crate::RecoveryAuthority::GuardianThreshold(_) => {
            if !event.approvals().as_slice().is_empty() {
                return Err(IdentityError::InvalidRelationship {
                    resource: "guardian recovery controller approvals",
                });
            }
            let approvals = evidence
                .as_guardian_approvals()
                .ok_or(IdentityError::AuthorizationDenied)?;
            let authority_time =
                provider_authority_time.ok_or(IdentityError::FreshnessUnavailable)?;
            let context = crate::GuardianAuthorityContext::try_new(
                authority.account_id(),
                recovery_id,
                authority.recovery_policy_id(),
                authority.recovery_policy().policy_version(),
                authority.epoch(),
                expected_decision,
                authority_time,
            )?;
            crate::verify_guardian_authority(authority.recovery_policy(), approvals, &context)
                .map(|_| ())
        }
    }
}

pub(crate) fn verify_algorithm_signature(
    algorithm_code: u16,
    public_key: &[u8],
    signature: &AlgorithmSignature,
    message: &[u8],
) -> Result<(), IdentityError> {
    if signature.algorithm_code() != algorithm_code {
        return Err(IdentityError::InvalidSignature);
    }
    match algorithm_code {
        1 => verify_ed25519(public_key, signature.as_bytes(), message),
        code => Err(IdentityError::UnsupportedAlgorithm {
            kind: AlgorithmKind::Signature,
            code,
        }),
    }
}
