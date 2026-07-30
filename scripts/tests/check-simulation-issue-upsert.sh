#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
upsert="$repo_root/scripts/upsert-simulation-issues.sh"

if [[ ! -x "$upsert" ]]; then
  echo "simulation issue upsert tool is missing or not executable" >&2
  exit 1
fi
bash -n "$upsert"

fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
mkdir -p "$fixture_root/records" "$fixture_root/bin"
existing=1111111111111111111111111111111111111111111111111111111111111111
created=2222222222222222222222222222222222222222222222222222222222222222
write_record() {
  local digest=$1
  jq -n --arg digest "$digest" '{
    schema_version: 1,
    classification: "product_correctness",
    signature_digest: $digest,
    minimized_scenario_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
    title: ("[simulation] invariant_safety (" + ($digest[0:12]) + ")"),
    body: (
      "<!-- krikos-sim-signature:" + $digest + " -->\n\n" +
      "- Minimized scenario SHA-256: `3333333333333333333333333333333333333333333333333333333333333333`"
    ),
    labels: ["bug", "simulation"],
    source_revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    workflow_run_id: 99,
    lane: "direct/deterministic-test",
    seed_ordinal: "1",
    seed_lease: {},
    replay: "confirmed_exact",
    minimization: "signature_preserving",
    corpus_status: "pending_promotion"
  }' >"$fixture_root/records/$digest.json"
}
write_record "$existing"
write_record "$created"

cat >"$fixture_root/bin/gh" <<'FAKE_GH'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >>"$FAKE_GH_LOG"
printf '\n' >>"$FAKE_GH_LOG"
if [[ "$1 $2" == "issue list" ]]; then
  printf '%s\n' "$FAKE_GH_ISSUES"
  exit 0
fi
if [[ "$1 $2" == "issue create" ]]; then
  printf '%s\n' 'https://github.com/holon-technologies/iroh/issues/8'
  exit 0
fi
if [[ "$1 $2" == "issue edit" || "$1 $2" == "issue reopen" ]]; then
  exit 0
fi
exit 64
FAKE_GH
chmod +x "$fixture_root/bin/gh"
export PATH="$fixture_root/bin:$PATH"
export FAKE_GH_LOG="$fixture_root/gh.log"
export FAKE_GH_ISSUES="[{\"number\":7,\"state\":\"CLOSED\",\"title\":\"old\",\"body\":\"<!-- krikos-sim-signature:$existing -->\"}]"

summary="$fixture_root/upsert-summary.json"
"$upsert" \
  --records "$fixture_root/records" \
  --repository holon-technologies/iroh \
  --output "$summary"
jq -e '
  .schema_version == 1
  and .status == "success"
  and .processed == 2
  and .created == 1
  and .updated == 1
  and .reopened == 1
' "$summary" >/dev/null
if [[ $(grep -Fc 'issue list' "$FAKE_GH_LOG") -ne 2 ]]; then
  echo "issue automation must perform one bounded signature search per record" >&2
  exit 1
fi
grep -Fq -- "--search $existing\\ in:body" "$FAKE_GH_LOG"
grep -Fq -- "--search $created\\ in:body" "$FAKE_GH_LOG"
grep -Fq -- 'issue edit 7' "$FAKE_GH_LOG"
grep -Fq -- 'issue reopen 7' "$FAKE_GH_LOG"
if [[ $(grep -Fc 'issue create' "$FAKE_GH_LOG") -ne 1 ]]; then
  echo "issue automation must create exactly one new signature" >&2
  exit 1
fi

export FAKE_GH_ISSUES=$(jq -cn '[
  range(1; 101) as $number
  | {number: $number, state: "OPEN", title: "candidate", body: "unrelated"}
]')
truncated_summary="$fixture_root/truncated-summary.json"
set +e
"$upsert" \
  --records "$fixture_root/records" \
  --repository holon-technologies/iroh \
  --output "$truncated_summary"
truncated_status=$?
set -e
if [[ "$truncated_status" -ne 2 || -e "$truncated_summary" ]]; then
  echo "issue automation must fail closed when a signature search may be truncated" >&2
  exit 1
fi

echo "simulation issue create/update/reopen contract passed"
