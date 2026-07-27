#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
collector="$repo_root/scripts/collect-latest-simulation-gap-selection.sh"

if [[ ! -x "$collector" ]]; then
  echo "latest simulation gap collector is missing or not executable" >&2
  exit 1
fi
bash -n "$collector"

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
mkdir -p "$fixture_root/bin" "$fixture_root/artifacts/51"
cat >"$fixture_root/bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "run list" ]]; then
  printf '%s\n' '[{"databaseId":51,"headSha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","createdAt":"2026-07-26T00:00:00Z"}]'
  exit 0
fi
if [[ "$1 $2" == "run download" ]]; then
  destination=${@: -1}
  mkdir -p "$destination"
  cp "$FAKE_GAP_ARTIFACTS/51/"*.json "$destination/"
  exit 0
fi
exit 64
FAKE_GH
chmod +x "$fixture_root/bin/gh"

policy=8e275709a3bb949f570c51abf184e023bb8a618f3d8aa8cbbfa737d9cdfe52c2
jq -n --arg policy "$policy" '{
  schema_version: 1,
  source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  workflow_run_id: 51,
  coverage: {schema_version: 2, policy_blake3: $policy}
}' >"$fixture_root/artifacts/51/daily-soak-aggregate.json"
jq -n --arg policy "$policy" '{
  schema_version: 1,
  policy_blake3: $policy,
  included_runs: [50, 51]
}' >"$fixture_root/artifacts/51/rolling-coverage.json"
jq -n --arg policy "$policy" '{
  schema_version: 1,
  policy_blake3: $policy,
  maximum_lanes: 12,
  lanes: [{lane: "nat/deterministic-test", priority: 1, gap_classes: ["pair"], gap_count: 1}],
  unassigned_gaps: []
}' >"$fixture_root/artifacts/51/gap-selection.json"

export PATH="$fixture_root/bin:$PATH"
export FAKE_GAP_ARTIFACTS="$fixture_root/artifacts"
output="$fixture_root/latest.json"
now_unix_secs=$(date -u -d '2026-07-26T01:00:00Z' '+%s')
"$collector" \
  --repository holon-technologies/iroh \
  --workflow simulation-daily-soak.yml \
  --policy-blake3 "$policy" \
  --now-unix-secs "$now_unix_secs" \
  --output "$output"
jq -e '
  .source_workflow_run_id == 51
  and .source_revision == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and .lanes == ["nat/deterministic-test"]
' "$output" >/dev/null

no_match="$fixture_root/no-match.json"
set +e
"$collector" \
  --repository holon-technologies/iroh \
  --workflow simulation-daily-soak.yml \
  --policy-blake3 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  --now-unix-secs "$now_unix_secs" \
  --output "$no_match"
no_match_status=$?
set -e
if [[ "$no_match_status" -ne 3 ]]; then
  echo "missing compatible gap evidence must request the bounded fallback" >&2
  exit 1
fi

echo "latest simulation gap collector contract passed"
