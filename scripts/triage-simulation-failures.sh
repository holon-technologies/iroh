#!/usr/bin/env bash

set -euo pipefail

artifact_root=
aggregate=
sim_bin=
source_revision=
workflow_run_id=
repository=
output=
maximum_signatures=16
minimization_attempts=512

usage() {
  printf '%s\n' \
    'Usage: triage-simulation-failures.sh --artifacts PATH --aggregate PATH --sim-bin PATH --source-revision HEX --workflow-run-id N --repository OWNER/REPO --output PATH'
}

while (($# > 0)); do
  case "$1" in
    --artifacts)
      artifact_root=$2
      shift 2
      ;;
    --aggregate)
      aggregate=$2
      shift 2
      ;;
    --sim-bin)
      sim_bin=$2
      shift 2
      ;;
    --source-revision)
      source_revision=$2
      shift 2
      ;;
    --workflow-run-id)
      workflow_run_id=$2
      shift 2
      ;;
    --repository)
      repository=$2
      shift 2
      ;;
    --output)
      output=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown simulation failure triage argument: %s\n' "$1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$artifact_root" || -z "$aggregate" || -z "$sim_bin" \
      || -z "$source_revision" || -z "$workflow_run_id" || -z "$repository" \
      || -z "$output" ]]; then
  echo "all simulation failure triage arguments are required" >&2
  usage >&2
  exit 64
fi
if [[ ! -d "$artifact_root" || -L "$artifact_root" \
      || ! -f "$aggregate" || -L "$aggregate" || ! -x "$sim_bin" ]]; then
  echo "simulation failure triage inputs are missing or unsafe" >&2
  exit 66
fi
if [[ ! "$source_revision" =~ ^[0-9a-f]{40}$ \
      || ! "$workflow_run_id" =~ ^[0-9]+$ \
      || ! "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "simulation failure triage identity is malformed" >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "SHA-256 tooling is required for minimized scenario provenance" >&2
  exit 66
fi
if [[ -e "$output" || -L "$output" ]]; then
  echo "simulation failure triage output must not already exist" >&2
  exit 73
fi
if ! jq -e '
  .schema_version == 1
  and (.seed_leases | type == "array" and length <= 384)
' "$aggregate" >/dev/null; then
  echo "simulation failure aggregate is malformed" >&2
  exit 65
fi

mkdir -p "$output/issue-records" "$output/minimized" "$output/logs"
mapfile -d '' signature_files < <(
  find "$artifact_root" -path '*/replay/*' -prune -o \
    -type f -name failure-signature.json -print0 | sort -z
)
declare -A seen_signatures=()
discovered=0
confirmed=0
replay_mismatches=0
minimization_failures=0
omitted=0

for signature_file in "${signature_files[@]}"; do
  failure_dir=$(dirname "$signature_file")
  terminal_report="$failure_dir/terminal-report.json"
  operational_outcome="$failure_dir/operational-outcome.json"
  artifact_index="$failure_dir/failure-artifacts.json"
  if [[ ! -f "$terminal_report" || -L "$terminal_report" \
        || ! -f "$operational_outcome" || -L "$operational_outcome" \
        || ! -f "$artifact_index" || -L "$artifact_index" \
        || -L "$signature_file" || -L "$failure_dir/scenario.json" ]]; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  if ! jq -e '
    .schema_version == 1
    and (.terminal_class | type == "string" and length > 0 and length <= 128)
    and (.causal_suffix_digest | type == "string" and test("^[0-9a-f]{64}$"))
  ' "$signature_file" >/dev/null; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  signature_digest=$(jq -er \
    '.signature_digest | select(type == "string" and test("^[0-9a-f]{64}$"))' \
    "$terminal_report" 2>/dev/null || true)
  if [[ -z "$signature_digest" ]]; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  if (( $(wc -c <"$operational_outcome") > 8192 )) \
    || ! jq -e \
      --arg digest "$signature_digest" '
        .schema_version == 1
        and .class == "product_correctness"
        and .evidence == $digest
      ' "$operational_outcome" >/dev/null \
    || ! jq -e '
      .schema_version == 3
      and (.files["operational-outcome.json"]
        | type == "string" and test("^[0-9a-f]{64}$"))
    ' "$artifact_index" >/dev/null; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  if [[ -n "${seen_signatures[$signature_digest]:-}" ]]; then
    continue
  fi
  seen_signatures[$signature_digest]=1
  discovered=$((discovered + 1))
  if ((discovered > maximum_signatures)); then
    omitted=$((omitted + 1))
    continue
  fi

  lane=$(tr -d '\n' <"$failure_dir/lane-id.txt")
  seed_ordinal=$(tr -d '\n' <"$failure_dir/seed-ordinal.txt")
  seed=$(tr -d '\n' <"$failure_dir/seed.txt")
  crypto=$(tr -d '\n' <"$failure_dir/crypto-mode.txt")
  if [[ ! "$lane" =~ ^(direct|discovery|mobility|nat|ready-order|relay)/(deterministic-test|production-provider)$ \
        || ! "$seed_ordinal" =~ ^[0-9]+$ \
        || ! "$seed" =~ ^[0-9a-f]{64}$ \
        || ( "$crypto" != deterministic_test && "$crypto" != production_provider ) \
        || ! "$failure_dir" =~ /epoch-([0-9][0-9])/ ]]; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  epoch=$((10#${BASH_REMATCH[1]}))
  seed_leases=$(jq -c \
    --arg lane "$lane" \
    --argjson epoch "$epoch" \
    '[.seed_leases[] | select(.lane_id == $lane and .epoch == $epoch)]' \
    "$aggregate")
  if [[ $(jq -r 'length' <<<"$seed_leases") -ne 1 ]]; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  seed_lease=$(jq -c '.[0]' <<<"$seed_leases")

  log_prefix="$output/logs/$signature_digest"
  if ! "$sim_bin" explain "$failure_dir" \
    >"$log_prefix-explain.log" 2>&1; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  replay_root="$failure_dir/replay"
  if [[ -e "$replay_root" || -L "$replay_root" ]]; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi
  replay_crypto=${crypto//_/-}
  set +e
  "$sim_bin" run "$failure_dir/scenario.json" \
    --seed "$seed" \
    --crypto "$replay_crypto" \
    --artifacts "$replay_root" \
    >"$log_prefix-run.log" 2>&1
  run_status=$?
  set -e
  if [[ "$run_status" -ne 0 && "$run_status" -ne 70 ]] \
    || [[ ! -f "$replay_root/failure-signature.json" ]] \
    || ! cmp -s "$signature_file" "$replay_root/failure-signature.json" \
    || ! "$sim_bin" replay "$replay_root/manifest.json" \
      >"$log_prefix-replay.log" 2>&1; then
    replay_mismatches=$((replay_mismatches + 1))
    continue
  fi

  minimized_root="$output/minimized/$signature_digest"
  if ! "$sim_bin" minimize "$replay_root/manifest.json" \
    --output "$minimized_root" \
    --max-attempts "$minimization_attempts" \
    >"$log_prefix-minimize.log" 2>&1 \
    || [[ ! -s "$minimized_root/best.scenario.json" ]]; then
    minimization_failures=$((minimization_failures + 1))
    continue
  fi

  minimized_scenario_sha256=$(sha256sum "$minimized_root/best.scenario.json" | cut -d' ' -f1)

  terminal_class=$(jq -r '.terminal_class' "$signature_file")
  title="[simulation] $terminal_class (${signature_digest:0:12})"
  lane_slug=${lane//\//-}
  replay_command="gh run download $workflow_run_id --repo $repository --name krikos-sim-soak-$lane_slug-$workflow_run_id"
  body=$(jq -nr \
    --arg marker "<!-- krikos-sim-signature:$signature_digest -->" \
    --arg source_revision "$source_revision" \
    --argjson workflow_run_id "$workflow_run_id" \
    --arg lane "$lane" \
    --arg seed_ordinal "$seed_ordinal" \
    --arg terminal_class "$terminal_class" \
    --arg minimized_scenario_sha256 "$minimized_scenario_sha256" \
    --arg replay_command "$replay_command" \
    --arg triage_artifact "krikos-sim-soak-triage-$workflow_run_id" \
    '$marker + "\n\n" +
     "A deterministic simulation product failure replayed exactly and minimized with its signature preserved.\n\n" +
     "- Source revision: `" + $source_revision + "`\n" +
     "- Workflow run: `" + ($workflow_run_id | tostring) + "`\n" +
     "- Lane: `" + $lane + "`\n" +
     "- Seed ordinal: `" + $seed_ordinal + "`\n" +
     "- Terminal class: `" + $terminal_class + "`\n" +
     "- Exact replay: confirmed\n" +
     "- Minimization: signature-preserving\n" +
     "- Minimized scenario SHA-256: `" + $minimized_scenario_sha256 + "`\n" +
     "- Corpus status: pending reviewed promotion\n\n" +
     "Download the source lane artifact:\n\n```text\n" + $replay_command + "\n```\n\n" +
     "The minimized scenario and logs are in artifact `" + $triage_artifact + "`."')
  jq -n \
    --arg signature_digest "$signature_digest" \
    --arg title "$title" \
    --arg body "$body" \
    --arg source_revision "$source_revision" \
    --arg minimized_scenario_sha256 "$minimized_scenario_sha256" \
    --argjson workflow_run_id "$workflow_run_id" \
    --arg lane "$lane" \
    --arg seed_ordinal "$seed_ordinal" \
    --argjson seed_lease "$seed_lease" \
    '{
      schema_version: 1,
      classification: "product_correctness",
      signature_digest: $signature_digest,
      title: $title,
      body: $body,
      labels: ["bug", "simulation"],
      source_revision: $source_revision,
      minimized_scenario_sha256: $minimized_scenario_sha256,
      workflow_run_id: $workflow_run_id,
      lane: $lane,
      seed_ordinal: $seed_ordinal,
      seed_lease: $seed_lease,
      replay: "confirmed_exact",
      minimization: "signature_preserving",
      corpus_status: "pending_promotion"
    }' >"$output/issue-records/$signature_digest.json"
  confirmed=$((confirmed + 1))
done

status=no_failures
exit_status=0
if ((replay_mismatches > 0 || minimization_failures > 0)); then
  status=triage_infrastructure_failure
  exit_status=2
elif ((confirmed > 0)); then
  status=confirmed_product_failures
fi
jq -n \
  --arg status "$status" \
  --argjson discovered_signatures "$discovered" \
  --argjson confirmed_signatures "$confirmed" \
  --argjson replay_mismatches "$replay_mismatches" \
  --argjson minimization_failures "$minimization_failures" \
  --argjson omitted_signatures "$omitted" \
  --argjson maximum_signatures "$maximum_signatures" \
  --argjson minimization_attempts "$minimization_attempts" \
  '{
    schema_version: 1,
    status: $status,
    discovered_signatures: $discovered_signatures,
    confirmed_signatures: $confirmed_signatures,
    replay_mismatches: $replay_mismatches,
    minimization_failures: $minimization_failures,
    omitted_signatures: $omitted_signatures,
    maximum_signatures: $maximum_signatures,
    minimization_attempts_per_signature: $minimization_attempts
  }' >"$output/triage-summary.json"

exit "$exit_status"
