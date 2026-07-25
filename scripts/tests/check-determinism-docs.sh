#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
audit="$repo_root/docs/testing/determinism-audit.md"
simulation="$repo_root/docs/testing/simulation.md"
parity="$repo_root/docs/simulation/patchbay-parity.md"
canary="$repo_root/docs/testing/production-resource-canary.md"
fuzzing="$repo_root/docs/testing/fuzzing.md"

required=(
  "$audit|The authoritative stable review identity"
  "$audit|Production cryptographic entropy is intentionally outside"
  "$simulation|core client-side Tokio timers, and relay-server actor roots have been retired"
  "$simulation|The checked workflow and its seconds-long contract are definitions, not evidence"
  "$audit|The 2026-07-25 daily deterministic soak adds process wall-time measurement"
  "$audit|only an uploaded run report is execution evidence"
  "$audit|scheduled/manual GitHub-hosted Patchbay public smoke are checked service"
  "$parity|The scheduled/manual GitHub-hosted Patchbay smoke is a checked service definition, not execution"
  "$canary|This checked workflow definition is not itself execution evidence"
  "$canary|conserve exactly into admitted, rejected, or transport-failed"
  "$fuzzing|Each adapter rejects oversized input before expensive parsing"
)

for contract in "${required[@]}"; do
  file="${contract%%|*}"
  text="${contract#*|}"
  if ! grep -Fq -- "$text" "$file"; then
    printf 'testing documentation is missing current-state contract: %s\n' "$text" >&2
    exit 1
  fi
done

for retired_claim in \
  'Relay and remote-state actor timers still use direct Tokio/n0-future time' \
  'Paired application-exchange harness tasks and the endpoint shutdown watchdog remain'; do
  if grep -Fq -- "$retired_claim" "$audit"; then
    printf 'testing documentation reactivated a retired boundary: %s\n' "$retired_claim" >&2
    exit 1
  fi
done

printf '%s\n' 'determinism documentation consistency contract passed'
