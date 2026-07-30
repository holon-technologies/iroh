#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
checker="$repo_root/scripts/check-determinism-boundaries.sh"
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT

mkdir -p "$fixture_root/krikos/src" "$fixture_root/krikos-runtime/src" "$fixture_root/scripts"
# The checker's SOURCE_ROOTS list is fixed; every root must exist below
# --root and contain at least one .rs file, or the checker now errors
# loudly (neither a missing root nor a present-but-empty root may silently
# narrow the scan). Only krikos/ and krikos-runtime/ carry the fixture
# content the assertions below exercise -- the rest each get one trivial
# placeholder .rs file so they satisfy the per-root minimum without
# contributing any boundary occurrences.
placeholder_roots=(krikos-base krikos-resolver krikos-dns krikos-dns-server krikos-relay krikos-sim)
for placeholder in "${placeholder_roots[@]}"; do
  mkdir -p "$fixture_root/$placeholder/src"
  printf '%s\n' '// placeholder crate root for the fixture' > "$fixture_root/$placeholder/src/lib.rs"
done
baseline="$fixture_root/scripts/determinism-boundaries.txt"
source_file="$fixture_root/krikos/src/lib.rs"
runtime_source="$fixture_root/krikos-runtime/src/lib.rs"

printf '%s\n' 'pub fn deterministic() {}' > "$source_file"
printf '%s\n' 'pub fn runtime_capability() {}' > "$runtime_source"

"$checker" --update --root "$fixture_root" --baseline "$baseline"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

printf '%s\n' 'pub fn detached() { tokio::spawn(async {}); }' >> "$source_file"

if output=$("$checker" --check --root "$fixture_root" --baseline "$baseline" 2>&1); then
  echo "expected boundary check to reject an unclassified occurrence" >&2
  exit 1
fi

if [[ "$output" != *"CONTENT drift detected"* ]]; then
  echo "boundary check did not explain the drift" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi

# A genuinely new occurrence is content drift, not a line-number shift, so
# --update must refuse without the explicit override -- see the
# --allow-content-drift assertions below for that refusal itself.
if "$checker" --update --root "$fixture_root" --baseline "$baseline" >/dev/null 2>&1; then
  echo "expected --update to refuse an unreviewed content change without --allow-content-drift" >&2
  exit 1
fi

"$checker" --update --allow-content-drift --root "$fixture_root" --baseline "$baseline"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

if ! grep -Fq $'spawn-task\tkrikos/src/lib.rs:2\tpub fn detached() { tokio::spawn(async {}); }' "$baseline"; then
  echo "updated baseline does not contain the normalized occurrence" >&2
  exit 1
fi

printf '%s\n' 'pub fn wall_time() { let _ = SystemTime::now(); }' >> "$runtime_source"
if "$checker" --check --root "$fixture_root" --baseline "$baseline" >/dev/null 2>&1; then
  echo "expected boundary check to scan the krikos-runtime capability crate" >&2
  exit 1
fi

"$checker" --update --allow-content-drift --root "$fixture_root" --baseline "$baseline"
if ! grep -Fq $'clock-timer\tkrikos-runtime/src/lib.rs:2\tpub fn wall_time() { let _ = SystemTime::now(); }' "$baseline"; then
  echo "updated baseline does not include krikos-runtime" >&2
  exit 1
fi

# Pure line drift -- content identical, only the line number moved -- must
# be reported distinctly from content drift, and --update must accept it
# WITHOUT --allow-content-drift (nothing here needs review; it's the exact
# case a rustfmt reflow produces).
printf '%s\n' '' "$(cat "$runtime_source")" > "$runtime_source.tmp"
mv "$runtime_source.tmp" "$runtime_source"
if output=$("$checker" --check --root "$fixture_root" --baseline "$baseline" 2>&1); then
  echo "expected boundary check to reject a pure line shift against the baseline" >&2
  exit 1
fi
if [[ "$output" != *"LINE drift detected"* ]]; then
  echo "boundary check did not classify a pure line shift as line drift" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi
"$checker" --update --root "$fixture_root" --baseline "$baseline"
"$checker" --check --root "$fixture_root" --baseline "$baseline"


# A missing source root must be a hard error, not a silent narrowing of the
# scan (this is the Step Zero fix: SOURCE_ROOTS used to be pre-rename names
# and every candidate was silently absent).
rm -rf "$fixture_root/krikos-base"
if output=$("$checker" --check --root "$fixture_root" --baseline "$baseline" 2>&1); then
  echo "expected boundary check to reject a missing source root" >&2
  exit 1
fi
if [[ "$output" != *"source root(s) missing"* ]]; then
  echo "boundary check did not name the missing source root" >&2
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
  echo "expected boundary check to reject a present-but-empty source root" >&2
  exit 1
fi
if [[ "$output" != *"below the 1-file minimum"* ]]; then
  echo "boundary check did not name the empty source root" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi
printf '%s\n' '// placeholder crate root for the fixture' > "$fixture_root/krikos-base/src/lib.rs"
"$checker" --check --root "$fixture_root" --baseline "$baseline"

echo "determinism boundary checker contract passed"
