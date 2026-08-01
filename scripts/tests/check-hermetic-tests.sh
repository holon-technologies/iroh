#!/usr/bin/env bash
# Test code must not configure n0-operated infrastructure.
#
# `presets::N0` attaches a PkarrPublisher, a PkarrResolver and a
# DnsAddressLookup pointed at dns.iroh.link, plus n0's default relays.
# `RelayMode::Default` does the same for relays alone. A test that uses either
# reaches third-party infrastructure on every developer machine and can be
# reddened by an outage n0 controls (see docs/adr/0003-*.md).
#
# This is a repeat offender. It has been fixed three times: once for the
# protocol tests that blocked on `online()`, once for eight krikos-blobs tests
# that merely configured N0 without blocking (one opened 17 connections to all
# four n0 relay regions and dns.iroh.link), and once for twelve krikos endpoint
# tests. Each pass fixed what it looked at and left the rest, because nothing
# checked. This is the check.
#
# Tests that genuinely exercise discovery need an exemption below, with a
# reason. Everything else should use `presets::Minimal` and set its own relay
# mode -- `RelayMode::Disabled`, or `RelayMode::Custom` with a relay from
# `krikos::test_utils::run_relay_server()`.
set -euo pipefail

cd "$(dirname "$0")/../.."

# Files allowed to configure n0 infrastructure, and why.
#
# Keep this list short. An entry is a promise that the test cannot do its job
# any other way -- not that converting it would be inconvenient.
declare -A EXEMPT=(
  ["krikos/tests/integration.rs"]="simple_endpoint_id_based_connection_transfer dials by endpoint ID, which requires a working publish/resolve round trip. It is a deliberate WAN integration test against n0 staging, and is the end-to-end proof of the product's headline capability."
)

# Test code only. Doc examples under src/ legitimately show presets::N0 to
# users, and are not run against real infrastructure by the test suite.
mapfile -t test_files < <(
  git ls-files \
    'krikos/tests/*.rs' \
    'krikos/src/**/tests.rs' \
    'krikos/src/tests.rs' \
    'protocols/*/tests/*.rs' \
    'protocols/*/src/**/tests.rs' \
    'protocols/*/src/tests.rs' \
  | sort -u
)

if [[ ${#test_files[@]} -eq 0 ]]; then
  echo "FAIL: found no test files to scan -- the glob is wrong, not the tree." >&2
  exit 1
fi

failed=0
used_exemptions=()

for file in "${test_files[@]}"; do
  # Strip whole-line comments so historical notes explaining a past conversion
  # do not trip the check; a real use is code, not prose.
  hits=$(grep -nE 'presets::N0|RelayMode::Default' "$file" \
    | grep -vE '^[0-9]+:[[:space:]]*(//|\*)' \
    || true)

  [[ -z "$hits" ]] && continue

  if [[ -v EXEMPT["$file"] ]]; then
    used_exemptions+=("$file")
    continue
  fi

  failed=1
  echo "FAIL: $file configures n0-operated infrastructure in test code:" >&2
  while IFS= read -r hit; do
    echo "    $file:$hit" >&2
  done <<<"$hits"
done

# An exemption that no longer matches anything is stale: it silently widens the
# allowed set for whoever edits that file next.
for file in "${!EXEMPT[@]}"; do
  found=0
  for used in ${used_exemptions[@]+"${used_exemptions[@]}"}; do
    [[ "$used" == "$file" ]] && found=1
  done
  if [[ $found -eq 0 ]]; then
    failed=1
    echo "FAIL: exemption for $file is unused -- remove it." >&2
  fi
done

if [[ $failed -ne 0 ]]; then
  cat >&2 <<'EOF'

Use presets::Minimal and set the relay mode explicitly:

    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)     // or RelayMode::Custom(relay_map)
        .bind()
        .await?

For a local relay, see krikos::test_utils::run_relay_server(). If the test
truly cannot work without n0 infrastructure, add it to EXEMPT in this script
with a reason.
EOF
  exit 1
fi

echo "ok: ${#test_files[@]} test files scanned, ${#EXEMPT[@]} documented exemption(s)"
