#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$repo_root/scripts/check-determinism-boundaries.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p "$fixture_root/iroh/src" "$fixture_root/iroh-runtime/src" "$fixture_root/scripts"
baseline="$fixture_root/scripts/determinism-boundaries.txt"
source_file="$fixture_root/iroh/src/lib.rs"
runtime_source="$fixture_root/iroh-runtime/src/lib.rs"

printf '%s\n' 'pub fn deterministic() {}' > "$source_file"
printf '%s\n' 'pub fn runtime_capability() {}' > "$runtime_source"

"$checker" --update --root "$fixture_root" --baseline "$baseline"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

printf '%s\n' 'pub fn detached() { tokio::spawn(async {}); }' >> "$source_file"

if output=$("$checker" --check --root "$fixture_root" --baseline "$baseline" 2>&1); then
  echo "expected boundary check to reject an unclassified occurrence" >&2
  exit 1
fi

if [[ "$output" != *"new or changed occurrences"* ]]; then
  echo "boundary check did not explain the drift" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

"$checker" --update --root "$fixture_root" --baseline "$baseline"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

if ! grep -Fq $'spawn-task\tiroh/src/lib.rs:2\tpub fn detached() { tokio::spawn(async {}); }' "$baseline"; then
  echo "updated baseline does not contain the normalized occurrence" >&2
  exit 1
fi

printf '%s\n' 'pub fn wall_time() { let _ = SystemTime::now(); }' >> "$runtime_source"
if "$checker" --check --root "$fixture_root" --baseline "$baseline" >/dev/null 2>&1; then
  echo "expected boundary check to scan the iroh-runtime capability crate" >&2
  exit 1
fi

"$checker" --update --root "$fixture_root" --baseline "$baseline"
if ! grep -Fq $'clock-timer\tiroh-runtime/src/lib.rs:2\tpub fn wall_time() { let _ = SystemTime::now(); }' "$baseline"; then
  echo "updated baseline does not include iroh-runtime" >&2
  exit 1
fi

echo "determinism boundary checker contract passed"
