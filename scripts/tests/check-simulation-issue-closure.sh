#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
guard="$repo_root/scripts/check-simulation-issue-closure.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT

repository=holon-technologies/iroh
revision=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
signature=1111111111111111111111111111111111111111111111111111111111111111
issue_url=https://github.com/holon-technologies/iroh/issues/42
corpus="$fixture_root/corpus"
entry="$corpus/regression-42"
mkdir -p "$entry"
printf '%s\n' '{"schema_version":3,"id":"regression-42"}' >"$entry/scenario.json"
scenario_sha256=$(sha256sum "$entry/scenario.json" | cut -d' ' -f1)
jq -n \
  --arg issue "$issue_url" \
  --arg signature "$signature" \
  --arg digest "$scenario_sha256" \
  '{
    schema_version: 2,
    id: "regression-42",
    scenario_file: "scenario.json",
    review_state: "reviewed",
    issue: $issue,
    promotion: {
      signature_digest: $signature,
      minimized_scenario_sha256: $digest,
      source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      workflow_run_id: 123,
      replay: "confirmed_exact",
      minimization: "signature_preserving"
    }
  }' >"$entry/metadata.json"

event="$fixture_root/event.json"
jq -n \
  --arg repository "$repository" \
  --arg issue "$issue_url" \
  --arg signature "$signature" \
  --arg digest "$scenario_sha256" \
  '{
    action: "closed",
    repository: {full_name: $repository, default_branch: "main"},
    issue: {
      number: 42,
      html_url: $issue,
      body: (
        "<!-- iroh-sim-signature:" + $signature + " -->\n\n" +
        "- Source revision: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`\n" +
        "- Workflow run: `123`\n" +
        "- Minimized scenario SHA-256: `" + $digest + "`"
      ),
      labels: [{name: "bug"}, {name: "simulation"}]
    }
  }' >"$event"

checks="$fixture_root/checks.json"
jq -n --arg revision "$revision" '{
  total_count: 2,
  check_runs: [
    {
      name: "Deterministic simulation contracts and corpus",
      head_sha: $revision,
      status: "completed",
      conclusion: "success",
      app: {slug: "github-actions"}
    },
    {
      name: "Deterministic simulation change gate",
      head_sha: $revision,
      status: "completed",
      conclusion: "success",
      app: {slug: "github-actions"}
    }
  ]
}' >"$checks"

fake_sim="$fixture_root/cargo-sim"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  '[[ "$1 $2 $3" == "corpus test "* ]]' \
  >"$fake_sim"
chmod +x "$fake_sim"

output="$fixture_root/accepted.json"
"$guard" \
  --event "$event" \
  --repository "$repository" \
  --revision "$revision" \
  --corpus "$corpus" \
  --checks "$checks" \
  --sim-bin "$fake_sim" \
  --output "$output"
jq -e \
  --arg signature "$signature" \
  --arg revision "$revision" '
    .schema_version == 1
    and .status == "closure_accepted"
    and .issue_number == 42
    and .corpus_entry == "regression-42"
    and .signature_digest == $signature
    and .revision == $revision
    and .required_checks == [
      "Deterministic simulation change gate",
      "Deterministic simulation contracts and corpus"
    ]
  ' "$output" >/dev/null

assert_rejected() {
  local name=$1
  local event_path=$2
  local checks_path=$3
  local corpus_path=$4
  local sim_path=$5
  local rejected_output="$fixture_root/$name.json"
  if "$guard" \
    --event "$event_path" \
    --repository "$repository" \
    --revision "$revision" \
    --corpus "$corpus_path" \
    --checks "$checks_path" \
    --sim-bin "$sim_path" \
    --output "$rejected_output"; then
    printf 'closure guard accepted invalid fixture: %s\n' "$name" >&2
    exit 1
  fi
  [[ ! -e "$rejected_output" ]] || {
    printf 'closure guard published acceptance for invalid fixture: %s\n' "$name" >&2
    exit 1
  }
}

missing_entry="$fixture_root/missing-entry"
mkdir "$missing_entry"
assert_rejected missing-corpus-entry "$event" "$checks" "$missing_entry" "$fake_sim"

bad_digest_corpus="$fixture_root/bad-digest-corpus"
cp -R "$corpus" "$bad_digest_corpus"
jq '.promotion.minimized_scenario_sha256 = ("f" * 64)' \
  "$bad_digest_corpus/regression-42/metadata.json" \
  >"$fixture_root/bad-metadata.json"
mv "$fixture_root/bad-metadata.json" "$bad_digest_corpus/regression-42/metadata.json"
assert_rejected digest-mismatch "$event" "$checks" "$bad_digest_corpus" "$fake_sim"

wrong_digest_event="$fixture_root/wrong-digest-event.json"
jq '.issue.body |= sub(
  "- Minimized scenario SHA-256: `[0-9a-f]{64}`";
  "- Minimized scenario SHA-256: `ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`"
)' "$event" >"$wrong_digest_event"
assert_rejected issue-digest-mismatch "$wrong_digest_event" "$checks" "$corpus" "$fake_sim"

failed_checks="$fixture_root/failed-checks.json"
jq '(.check_runs[] | select(.name == "Deterministic simulation contracts and corpus") | .conclusion) = "failure"' \
  "$checks" >"$failed_checks"
assert_rejected failed-required-check "$event" "$failed_checks" "$corpus" "$fake_sim"

duplicate_checks="$fixture_root/duplicate-checks.json"
jq '.total_count = 3 | .check_runs += [.check_runs[0]]' "$checks" >"$duplicate_checks"
assert_rejected duplicate-required-check "$event" "$duplicate_checks" "$corpus" "$fake_sim"

failing_sim="$fixture_root/failing-cargo-sim"
printf '%s\n' '#!/usr/bin/env bash' 'exit 74' >"$failing_sim"
chmod +x "$failing_sim"
assert_rejected corpus-failure "$event" "$checks" "$corpus" "$failing_sim"

wrong_signature_event="$fixture_root/wrong-signature-event.json"
jq '.issue.body = "<!-- iroh-sim-signature:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff -->"' \
  "$event" >"$wrong_signature_event"
assert_rejected signature-mismatch "$wrong_signature_event" "$checks" "$corpus" "$fake_sim"

echo "simulation issue closure guard contract passed"
