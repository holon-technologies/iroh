#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
inventory_check="$repo_root/scripts/check-v2-api-inventory.sh"
result_check="$repo_root/scripts/check-v2-semver-result.sh"
fixture_root=$(mktemp -d)
cleanup() {
  rm -r -- "$fixture_root"
}
trap cleanup EXIT

expected="$fixture_root/expected.txt"
actual="$fixture_root/actual.txt"
printf 'iroh-dns\tstruct_missing\tstruct iroh_dns::dns::DnsResolver\n' >"$expected"
cp "$expected" "$actual"
"$inventory_check" "$expected" "$actual" >/dev/null

printf 'iroh-dns\ttrait_missing\ttrait iroh_dns::dns::Resolver\n' >>"$actual"
if "$inventory_check" "$expected" "$actual" >/dev/null 2>&1; then
  printf '%s\n' 'undocumented legacy API break must fail the inventory gate' >&2
  exit 1
fi

: >"$actual"
if "$inventory_check" "$expected" "$actual" >/dev/null 2>&1; then
  printf '%s\n' 'removing a reviewed migration break must require inventory review' >&2
  exit 1
fi

"$result_check" legacy-inventory iroh-dns 100
if "$result_check" legacy-inventory iroh-dns 101 >/dev/null 2>&1; then
  printf '%s\n' 'legacy inventory must not hide tool or build failures' >&2
  exit 1
fi
"$result_check" post-cut iroh-dns 0
if "$result_check" post-cut iroh-dns 100 >/dev/null 2>&1; then
  printf '%s\n' 'post-cut semver incompatibility must fail' >&2
  exit 1
fi

printf '%s\n' 'v2 semver transition policy contract passed'
