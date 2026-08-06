#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$repo_root/scripts/check-determinism-semantic.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p \
  "$fixture_root/krikos/src" \
  "$fixture_root/protocols/krikos-identity/src" \
  "$fixture_root/scripts"
# The Rust checker's SOURCE_ROOTS list is fixed; every root must exist below
# --root and contain at least one .rs file, or it now errors loudly
# (neither a missing root nor a present-but-empty root may silently narrow
# the scan). Krikos and the identity protocol carry the fixture content
# exercised below; the rest each get one trivial placeholder .rs file so they
# satisfy the per-root minimum without contributing any boundary
# occurrences.
placeholder_roots=(krikos-base krikos-resolver krikos-dns krikos-dns-server krikos-relay krikos-runtime krikos-sim)
for placeholder in "${placeholder_roots[@]}"; do
  mkdir -p "$fixture_root/$placeholder/src"
  printf '%s\n' '// placeholder crate root for the fixture' > "$fixture_root/$placeholder/src/lib.rs"
done
source_file="$fixture_root/krikos/src/lib.rs"
identity_source="$fixture_root/protocols/krikos-identity/src/lib.rs"
baseline="$fixture_root/scripts/determinism-boundaries.semantic.txt"

printf '%s\n' \
  'use std::time::SystemTime as WallClock;' \
  'const NOTE: &str = "tokio::spawn(async {})";' \
  'pub fn timestamp() { let _ = WallClock::now(); }' \
  > "$source_file"
printf '%s\n' \
  'pub fn secure_entropy(bytes: &mut [u8]) { let _ = getrandom::fill(bytes); }' \
  'pub fn secure_entropy_reference() { let _fill = getrandom::fill; }' \
  > "$identity_source"

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
if ! grep -Fq $'entropy-random\tprotocols/krikos-identity/src/lib.rs\tsecure_entropy\tgetrandom::fill\t1' "$baseline"; then
  echo "semantic checker did not scan identity or classify getrandom::fill" >&2
  exit 1
fi
if ! grep -Fq $'entropy-random\tprotocols/krikos-identity/src/lib.rs\tsecure_entropy_reference\tgetrandom::fill\t1' "$baseline"; then
  echo "semantic checker did not classify an entropy function used as a value" >&2
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

# A missing source root must be a hard error, not a silent narrowing of the
# scan (this is the Step Zero fix: SOURCE_ROOTS used to be pre-rename names
# and every candidate was silently absent).
rm -rf "$fixture_root/krikos-base"
if output=$("$checker" --check --root "$fixture_root" --baseline "$baseline" 2>&1); then
  echo "expected semantic checker to reject a missing source root" >&2
  exit 1
fi
if [[ "$output" != *"source root missing"* ]]; then
  echo "semantic checker did not name the missing source root" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi
mkdir -p "$fixture_root/krikos-base/src"
printf '%s\n' '// placeholder crate root for the fixture' > "$fixture_root/krikos-base/src/lib.rs"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

# A root that exists but holds zero .rs files is the same failure in
# different clothing (e.g. a botched `git mv` that left the destination
# directory behind but empty) and must also be a hard error, not silently
# treated as "nothing to scan here".
rm -f "$fixture_root/krikos-base/src/lib.rs"
if output=$("$checker" --check --root "$fixture_root" --baseline "$baseline" 2>&1); then
  echo "expected semantic checker to reject a present-but-empty source root" >&2
  exit 1
fi
if [[ "$output" != *"Rust file(s) (minimum"* ]]; then
  echo "semantic checker did not name the empty source root" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi
printf '%s\n' '// placeholder crate root for the fixture' > "$fixture_root/krikos-base/src/lib.rs"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

printf '%s\n' 'pub fn malformed( {' >> "$source_file"
if "$checker" --check --root "$fixture_root" --baseline "$baseline" >/dev/null 2>&1; then
  echo "semantic checker accepted malformed Rust" >&2
  exit 1
fi

echo "semantic determinism checker contract passed"
