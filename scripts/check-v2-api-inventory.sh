#!/usr/bin/env bash

set -euo pipefail

if (($# != 2)); then
  printf 'usage: %s EXPECTED ACTUAL\n' "$0" >&2
  exit 2
fi

expected=$1
actual=$2
for path in "$expected" "$actual"; do
  if [[ ! -f "$path" ]]; then
    printf 'API inventory file is missing: %s\n' "$path" >&2
    exit 66
  fi
done

expected_sorted=$(mktemp)
actual_sorted=$(mktemp)
cleanup() {
  rm -f -- "$expected_sorted" "$actual_sorted"
}
trap cleanup EXIT

normalize() {
  local source=$1
  local target=$2
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      if (split($0, fields, "\t") != 3 || fields[1] == "" || fields[2] == "" || fields[3] == "") {
        printf "malformed API inventory entry in %s at line %d: %s\n", FILENAME, FNR, $0 > "/dev/stderr"
        exit 2
      }
      print
    }
  ' "$source" | LC_ALL=C sort -u >"$target"
}

normalize "$expected" "$expected_sorted"
normalize "$actual" "$actual_sorted"
if ! cmp -s "$expected_sorted" "$actual_sorted"; then
  printf '%s\n' 'v2 intentional API-break inventory drifted:' >&2
  diff -u "$expected_sorted" "$actual_sorted" >&2 || true
  exit 1
fi

printf '%s\n' 'v2 intentional API-break inventory passed'
