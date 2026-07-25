#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$repo_root/scripts/check-determinism-semantic.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p "$fixture_root/iroh/src" "$fixture_root/scripts"
source_file="$fixture_root/iroh/src/lib.rs"
baseline="$fixture_root/scripts/determinism-boundaries.semantic.txt"

printf '%s\n' \
  'use std::time::SystemTime as WallClock;' \
  'const NOTE: &str = "tokio::spawn(async {})";' \
  'pub fn timestamp() { let _ = WallClock::now(); }' \
  > "$source_file"

"$checker" --update --root "$fixture_root" --baseline "$baseline"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

if ! grep -Fq $'clock-timer\tiroh/src/lib.rs\ttimestamp\tstd::time::SystemTime::now\t1' "$baseline"; then
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
if ! grep -Fq $'spawn-task\tiroh/src/lib.rs\tdetached\ttokio::spawn\t1' "$baseline"; then
  echo "semantic checker did not retain the aliased spawn identity" >&2
  exit 1
fi

printf '%s\n' 'pub fn malformed( {' >> "$source_file"
if "$checker" --check --root "$fixture_root" --baseline "$baseline" >/dev/null 2>&1; then
  echo "semantic checker accepted malformed Rust" >&2
  exit 1
fi

echo "semantic determinism checker contract passed"
