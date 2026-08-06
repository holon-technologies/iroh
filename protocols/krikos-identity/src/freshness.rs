//! Explicit checkpoint freshness decisions with monotonic caller tightening.

use crate::{
    AuthorizationContext, DurationMillis, FreshnessEvidence, FreshnessRequirement, IdentityError,
    ProviderMode, ProviderPolicy, ProviderPolicyId, ProviderQuorum, Timestamp,
};

/// Verified freshness basis for one exact account/checkpoint/epoch context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessDecision {
    context: AuthorizationContext,
    provider_policy_id: ProviderPolicyId,
    required_quorum: Option<ProviderQuorum>,
    maximum_age: Option<DurationMillis>,
    provider_observed_at: Option<Timestamp>,
}

impl FreshnessDecision {
    /// Exact account, epoch, and checkpoint to which the decision applies.
    pub const fn context(self) -> AuthorizationContext {
        self.context
    }

    /// Authenticated provider policy used by the decision.
    pub const fn provider_policy_id(self) -> ProviderPolicyId {
        self.provider_policy_id
    }

    /// Effective distinct-provider quorum, absent for latest-known-only evaluation.
    pub const fn required_quorum(self) -> Option<ProviderQuorum> {
        self.required_quorum
    }

    /// Effective age bound at the explicit verifier time, absent for latest-known-only evaluation.
    pub const fn maximum_age(self) -> Option<DurationMillis> {
        self.maximum_age
    }

    /// Deterministic quorum-th checkpoint observation time, if online evidence was required.
    pub const fn provider_observed_at(self) -> Option<Timestamp> {
        self.provider_observed_at
    }
}

/// Evaluate account and caller freshness requirements without permitting caller weakening.
///
/// Provider maximum age is measured from the signed checkpoint-log observation to the explicit
/// verifier time. A later tree head proves continued inclusion but cannot refresh the checkpoint's
/// original observation. The checkpoint's account-supplied metadata timestamp is never an
/// authority source. `LatestKnown` establishes only the exact locally trusted checkpoint context.
pub fn evaluate_freshness(
    context: AuthorizationContext,
    provider_policy: &ProviderPolicy,
    account_requirement: FreshnessRequirement,
    caller_requirement: FreshnessRequirement,
    evidence: &FreshnessEvidence,
    verified_at: Timestamp,
) -> Result<FreshnessDecision, IdentityError> {
    if evidence.checkpoint_id() != context.checkpoint_id() {
        return Err(IdentityError::InvalidRelationship {
            resource: "freshness decision checkpoint",
        });
    }
    let provider_policy_id = provider_policy.id()?;
    let requested = combine_requirements(account_requirement, caller_requirement);
    let Some((requested_quorum, requested_maximum_age)) = requested else {
        return Ok(FreshnessDecision {
            context,
            provider_policy_id,
            required_quorum: None,
            maximum_age: None,
            provider_observed_at: None,
        });
    };

    let replicated = match provider_policy.mode() {
        ProviderMode::LocalOnly => return Err(IdentityError::FreshnessUnavailable),
        ProviderMode::Replicated(replicated) => replicated,
    };
    if evidence.provider_policy_id() != Some(provider_policy_id) {
        return Err(IdentityError::PolicyVersionMismatch);
    }
    let receipts = evidence
        .provider_receipts()
        .ok_or(IdentityError::FreshnessUnavailable)?;
    let required = usize::from(
        requested_quorum
            .get()
            .max(replicated.sufficient_threshold().get()),
    );
    let maximum_age = DurationMillis::new(
        requested_maximum_age
            .get()
            .min(replicated.maximum_evidence_age().get()),
    );
    let required_quorum = ProviderQuorum::new(u16::try_from(required).map_err(|_| {
        IdentityError::ArithmeticOverflow {
            resource: "freshness decision provider quorum",
        }
    })?)?;
    let future_skew =
        u64::try_from(crate::limits::MAX_FUTURE_CLOCK_SKEW.as_millis()).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "freshness future clock skew milliseconds",
            }
        })?;
    let maximum_observation = verified_at.checked_add(DurationMillis::new(future_skew))?;
    let mut valid_times = Vec::new();
    let mut stale_configured = false;
    for receipt in receipts.as_slice() {
        if receipt.entry().account_id() != context.account_id() {
            return Err(IdentityError::AccountMismatch);
        }
        let Some(provider) = replicated
            .providers()
            .iter()
            .find(|provider| provider.id() == Ok(receipt.provider_id()))
        else {
            continue;
        };
        receipt.verify(provider)?;
        let entry_time = receipt.entry().observed_at().as_unix_millis();
        let head_time = receipt.signed_head().body().observed_at().as_unix_millis();
        if entry_time > maximum_observation.as_unix_millis()
            || head_time > maximum_observation.as_unix_millis()
        {
            stale_configured = true;
            continue;
        }
        let age = if verified_at.as_unix_millis() >= entry_time {
            verified_at.as_unix_millis() - entry_time
        } else {
            0
        };
        if age > maximum_age.get() {
            stale_configured = true;
            continue;
        }
        valid_times.push(receipt.entry().observed_at());
    }
    if valid_times.len() < required {
        return Err(if stale_configured {
            IdentityError::StaleEvidence
        } else {
            IdentityError::FreshnessUnavailable
        });
    }
    valid_times.sort_unstable();
    Ok(FreshnessDecision {
        context,
        provider_policy_id,
        required_quorum: Some(required_quorum),
        maximum_age: Some(maximum_age),
        provider_observed_at: Some(valid_times[required - 1]),
    })
}

fn combine_requirements(
    account: FreshnessRequirement,
    caller: FreshnessRequirement,
) -> Option<(ProviderQuorum, DurationMillis)> {
    match (account, caller) {
        (FreshnessRequirement::LatestKnown, FreshnessRequirement::LatestKnown) => None,
        (FreshnessRequirement::ProviderQuorum(requirement), FreshnessRequirement::LatestKnown)
        | (FreshnessRequirement::LatestKnown, FreshnessRequirement::ProviderQuorum(requirement)) => {
            Some((requirement.required(), requirement.maximum_age()))
        }
        (
            FreshnessRequirement::ProviderQuorum(account),
            FreshnessRequirement::ProviderQuorum(caller),
        ) => {
            let required = if account.required() >= caller.required() {
                account.required()
            } else {
                caller.required()
            };
            Some((
                required,
                DurationMillis::new(account.maximum_age().get().min(caller.maximum_age().get())),
            ))
        }
    }
}
