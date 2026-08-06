#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
spec="$repo_root/docs/identity/AccountControl.tla"

for marker in \
  'Init ==' \
  'Next ==' \
  'WeightOf(controllerSet) ==' \
  'RevokedControllersCannotAuthorize ==' \
  'PolicyChangesUsePreviousPolicy ==' \
  'ForksAreDetectable ==' \
  'ThresholdRequirementsPreserved ==' \
  'RecoveryDoesNotRetainOldControllers ==' \
  'AcceptedEventsHaveUniquePredecessor =='
do
  rg --fixed-strings --quiet "$marker" "$spec"
done

report=$(cargo +1.91.0 run \
  --quiet \
  --locked \
  --manifest-path "$repo_root/krikos-sim/Cargo.toml" \
  --bin identity-model-check)

printf '%s\n' "$report"
printf '%s\n' "$report" | rg --quiet '"states_explored": [1-9][0-9]*'
printf '%s\n' "$report" | rg --quiet '"transitions_explored": [1-9][0-9]*'
printf '%s\n' "$report" | rg --quiet '"tla_actions_validated": 6'
printf '%s\n' "$report" | rg --quiet '"tla_properties_validated": 6'
printf '%s\n' "$report" | rg --quiet '"semantic_parity_cases": [1-9][0-9]*'
printf '%s\n' "$report" | rg --quiet '"asymmetric_weight_witnesses": [1-9][0-9]*'
printf '%s\n' "$report" | rg --quiet '"transition_mutations_rejected": 7'
printf '%s\n' "$report" | rg --quiet '"portable_mutations_rejected": 2'

for property in \
  revoked_controllers_cannot_authorize \
  policy_changes_use_previous_policy \
  forks_are_detectable \
  threshold_requirements_preserved \
  recovery_does_not_retain_old_controllers \
  accepted_events_have_unique_predecessor
do
  printf '%s\n' "$report" | rg --quiet "\"$property\": [1-9][0-9]*"
done

for witness in \
  evaluations \
  antecedent_witnesses \
  accepted_witnesses \
  rejected_witnesses
do
  count=$(printf '%s\n' "$report" | rg --count "\"$witness\": [1-9][0-9]*")
  test "$count" -eq 6
done
