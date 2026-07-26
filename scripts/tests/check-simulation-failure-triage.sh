#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
triage="$repo_root/scripts/triage-simulation-failures.sh"

if [[ ! -x "$triage" ]]; then
  echo "simulation failure triage tool is missing or not executable" >&2
  exit 1
fi
bash -n "$triage"

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
failure="$fixture_root/lane/epoch-00/failure-000001-seed-00000000000000000001"
mkdir -p "$failure"
signature_digest=1111111111111111111111111111111111111111111111111111111111111111
jq -n '{
  schema_version: 1,
  invariant: "authenticated_peer_identity",
  entities: ["client", "server"],
  terminal_class: "invariant_safety",
  causal_event_count: 1,
  causal_suffix_digest: "2222222222222222222222222222222222222222222222222222222222222222"
}' >"$failure/failure-signature.json"
jq -n --arg digest "$signature_digest" '{
  terminal_class: "invariant_safety",
  signature_digest: $digest
}' >"$failure/terminal-report.json"
jq -n --arg digest "$signature_digest" '{
  schema_version: 1,
  class: "product_correctness",
  evidence: $digest
}' >"$failure/operational-outcome.json"
jq -n '{
  schema_version: 3,
  files: {
    "operational-outcome.json":
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  },
  trace_chunks: 0,
  events_per_chunk: 64
}' >"$failure/failure-artifacts.json"
jq -n '{metadata: {id: "fixture"}}' >"$failure/scenario.json"
printf '%s\n' direct/deterministic-test >"$failure/lane-id.txt"
printf '%s\n' 1 >"$failure/seed-ordinal.txt"
printf '%064d\n' 1 >"$failure/seed.txt"
printf '%s\n' deterministic_test >"$failure/crypto-mode.txt"

aggregate="$fixture_root/aggregate.json"
jq -n '{
  schema_version: 1,
  seed_leases: [{
    schema_version: 2,
    policy_blake3: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    plan_blake3: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    lane_id: "direct/deterministic-test",
    seed_window: 1,
    epoch: 0,
    lane_index: 0,
    seed_start: 0,
    seed_end_exclusive: 1000000,
    consumed_runs: 2
  }]
}' >"$aggregate"

fake_sim="$fixture_root/fake-cargo-sim"
cat >"$fake_sim" <<'FAKE_SIM'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  explain)
    exit 0
    ;;
  run)
    scenario=$2
    shift 2
    artifacts=
    while (($# > 0)); do
      if [[ "$1" == --artifacts ]]; then
        artifacts=$2
        shift 2
      else
        shift
      fi
    done
    mkdir -p "$artifacts"
    cp "$(dirname "$scenario")/failure-signature.json" "$artifacts/"
    printf '%s\n' '{}' >"$artifacts/manifest.json"
    exit 70
    ;;
  replay)
    exit 0
    ;;
  minimize)
    output=${@: -3:1}
    mkdir -p "$output"
    cp "$failure_scenario" "$output/best.scenario.json"
    printf '%s\n' '{"status":"complete"}' >"$output/minimize.jsonl"
    exit 0
    ;;
esac
exit 64
FAKE_SIM
chmod +x "$fake_sim"
export failure_scenario="$failure/scenario.json"

output="$fixture_root/triage"
"$triage" \
  --artifacts "$fixture_root/lane" \
  --aggregate "$aggregate" \
  --sim-bin "$fake_sim" \
  --source-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --workflow-run-id 99 \
  --repository holon-technologies/iroh \
  --output "$output"

jq -e '
  .schema_version == 1
  and .status == "confirmed_product_failures"
  and .discovered_signatures == 1
  and .confirmed_signatures == 1
  and .replay_mismatches == 0
  and .minimization_failures == 0
' "$output/triage-summary.json" >/dev/null
record="$output/issue-records/$signature_digest.json"
minimized_scenario="$output/minimized/$signature_digest/best.scenario.json"
minimized_sha256=$(sha256sum "$minimized_scenario" | cut -d' ' -f1)
jq -e \
  --arg digest "$signature_digest" \
  --arg minimized_sha256 "$minimized_sha256" '
    .classification == "product_correctness"
    and .signature_digest == $digest
    and .source_revision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    and .workflow_run_id == 99
    and .lane == "direct/deterministic-test"
    and .seed_lease.seed_start == 0
    and .minimized_scenario_sha256 == $minimized_sha256
    and (.body | contains("<!-- iroh-sim-signature:" + $digest + " -->"))
    and (.body | contains("Exact replay: confirmed"))
    and (.body | contains("Minimization: signature-preserving"))
    and (.body | contains("Minimized scenario SHA-256: `" + $minimized_sha256 + "`"))
  ' "$record" >/dev/null
test -s "$minimized_scenario"

infra_output="$fixture_root/triage-infrastructure"
jq '.class = "infrastructure"' \
  "$failure/operational-outcome.json" >"$fixture_root/infrastructure-outcome.json"
mv "$fixture_root/infrastructure-outcome.json" "$failure/operational-outcome.json"
set +e
"$triage" \
  --artifacts "$fixture_root/lane" \
  --aggregate "$aggregate" \
  --sim-bin "$fake_sim" \
  --source-revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --workflow-run-id 99 \
  --repository holon-technologies/iroh \
  --output "$infra_output"
infra_status=$?
set -e
test "$infra_status" -eq 2
jq -e '
  .status == "triage_infrastructure_failure"
  and .confirmed_signatures == 0
  and .replay_mismatches == 1
' "$infra_output/triage-summary.json" >/dev/null
test ! -e "$infra_output/issue-records/$signature_digest.json"

echo "simulation failure replay and minimization triage contract passed"
