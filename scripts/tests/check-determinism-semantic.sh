#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$repo_root/scripts/check-determinism-semantic.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p "$fixture_root/krikos/src" "$fixture_root/scripts"
# The Rust checker's SOURCE_ROOTS list is fixed; every root must exist below
# --root or it now errors loudly (a missing root must not silently narrow
# the scan). Only krikos/ carries fixture content -- the rest are
# present-but-empty so the fixture satisfies that floor check.
mkdir -p "$fixture_root/krikos-base" "$fixture_root/krikos-resolver" \
  "$fixture_root/krikos-dns" "$fixture_root/krikos-dns-server" \
  "$fixture_root/krikos-relay" "$fixture_root/krikos-runtime" \
  "$fixture_root/krikos-sim"
source_file="$fixture_root/krikos/src/lib.rs"
baseline="$fixture_root/scripts/determinism-boundaries.semantic.txt"

printf '%s\n' \
  'use std::time::SystemTime as WallClock;' \
  'const NOTE: &str = "tokio::spawn(async {})";' \
  'pub fn timestamp() { let _ = WallClock::now(); }' \
  > "$source_file"

"$checker" --update --root "$fixture_root" --baseline "$baseline"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

if ! grep -Fq $'clock-timer\tkrikos/src/lib.rs\ttimestamp\tstd::time::SystemTime::now\t1' "$baseline"; then
  echo "semantic checker did not resolve an aliased wall clock" >&2
  exit 1
fi
if grep -Fq 'spawn-task' "$baseline"; then
  echo "semantic checker treated string content as executable Rust" >&2
  exit 1
fi

sed -i '1i\\' "$source_file"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

printf '%s\n' \
  'use tokio::spawn as launch;' \
  'pub fn detached() { launch(async {}); }' \
  >> "$source_file"
if "$checker" --check --root "$fixture_root" --baseline "$baseline" >/dev/null 2>&1; then
  echo "semantic checker accepted an unclassified aliased spawn" >&2
  exit 1
fi

"$checker" --update --root "$fixture_root" --baseline "$baseline"
if ! grep -Fq $'spawn-task\tkrikos/src/lib.rs\tdetached\ttokio::spawn\t1' "$baseline"; then
  echo "semantic checker did not retain the aliased spawn identity" >&2
  exit 1
fi

printf '%s\n' 'pub fn malformed( {' >> "$source_file"
if "$checker" --check --root "$fixture_root" --baseline "$baseline" >/dev/null 2>&1; then
  echo "semantic checker accepted malformed Rust" >&2
  exit 1
fi

echo "semantic determinism checker contract passed"
