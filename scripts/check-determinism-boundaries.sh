#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scripts/check-determinism-boundaries.sh (--check|--update) [--root DIR] [--baseline FILE] [--allow-content-drift]

  --check                Compare source occurrences with the reviewed baseline.
  --update                Replace the baseline after reviewing and classifying drift.
  --allow-content-drift   Required with --update when the drift includes added,
                          removed, or altered occurrences (not just moved line
                          numbers). Without it, --update refuses to write a
                          baseline that would silently absorb a real content
                          change alongside routine line-number churn.
EOF
}

mode=
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline=
allow_content_drift=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allow-content-drift)
      allow_content_drift=1
      shift
      ;;
    --check|--update)
      if [[ -n "$mode" ]]; then
        echo "choose exactly one of --check or --update" >&2
        usage
        exit 2
      fi
      mode=$1
      shift
      ;;
    --root)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      repo_root=$2
      shift 2
      ;;
    --baseline)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      baseline=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$mode" ]]; then
  usage
  exit 2
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "determinism boundary check requires ripgrep (rg)" >&2
  exit 2
fi

repo_root=$(cd "$repo_root" && pwd)
if [[ -z "$baseline" ]]; then
  baseline="$repo_root/scripts/determinism-boundaries.txt"
fi

source_roots=()
missing_roots=()
for candidate in \
  krikos \
  krikos-base \
  krikos-resolver \
  krikos-dns \
  krikos-dns-server \
  krikos-relay \
  krikos-runtime \
  krikos-sim \
  protocols/krikos-identity; do
  if [[ -d "$repo_root/$candidate" ]]; then
    source_roots+=("$candidate")
  else
    missing_roots+=("$candidate")
  fi
done

if [[ ${#missing_roots[@]} -gt 0 ]]; then
  echo "determinism boundary source root(s) missing below $repo_root: ${missing_roots[*]}" >&2
  echo "a missing root would silently narrow the scan; fix the root list or the checkout" >&2
  exit 2
fi

if [[ ${#source_roots[@]} -eq 0 ]]; then
  echo "no Krikos source roots found below $repo_root" >&2
  exit 2
fi

# Every root above is a real Cargo package directory. Cargo requires a `[lib]` or
# `[[bin]]` entry point in at least one `.rs` file for such a package to
# build, so a root that exists but contains zero `.rs` files is never
# legitimate here -- only a symptom of a botched rename (e.g. a `git mv`
# that left the destination directory present but empty). A missing root
# and a present-but-empty root are the same failure in different clothing,
# so both are hard errors, not a skip.
min_files_per_root=1
empty_roots=()
for candidate in "${source_roots[@]}"; do
  found=$(find "$repo_root/$candidate" -type f -name '*.rs' | wc -l)
  if [[ "$found" -lt "$min_files_per_root" ]]; then
    empty_roots+=("$candidate ($found)")
  fi
done

if [[ ${#empty_roots[@]} -gt 0 ]]; then
  echo "determinism boundary source root(s) present but below the ${min_files_per_root}-file minimum below $repo_root: ${empty_roots[*]}" >&2
  echo "an existing-but-empty root would silently narrow the scan the same way a missing root would" >&2
  exit 2
fi

collected=$(mktemp)
sorted=$(mktemp)
trap 'rm -f "$collected" "$sorted"' EXIT

# Classifies the difference between two baseline-format files
# (category\tpath:line\tsource) into pure LINE drift -- same category, path,
# and source text, only the line number differs -- versus real CONTENT
# drift, where an occurrence was added, removed, or its source text
# changed. Comparing whole lines (as a plain `comm` would) can't tell these
# apart: a blank line inserted above a boundary reflows every subsequent
# line number in that file, so every one of those entries looks "added" at
# its new line and "removed" at its old line even though nothing about what
# runs actually changed. Conflating the two invites the reflex "CI says
# drift, run --update, push" for a change that silently altered behaviour --
# this already happened once during the rebrand, when a rustfmt reflow
# shifted two entries and the recovery was manual.
#
# Matching is per (category, path, source) key, multiset-aware: if a key
# occurs N times in the old file and M times in the new file, min(N, M)
# occurrences are treated as moved (paired arbitrarily among identical
# entries, since their content is indistinguishable) and any surplus on
# either side is real content added/removed.
classify_drift() {
  python3 - "$1" "$2" <<'PYEOF'
import sys
from collections import defaultdict


def load(path):
    entries = []
    with open(path) as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line:
                continue
            category, location, source = line.split("\t", 2)
            file_path, _, line_no = location.rpartition(":")
            entries.append((category, file_path, int(line_no), source))
    return entries


old = load(sys.argv[1])
new = load(sys.argv[2])


def key(entry):
    category, file_path, _line_no, source = entry
    return (category, file_path, source)


old_by_key = defaultdict(list)
for entry in old:
    old_by_key[key(entry)].append(entry[2])
new_by_key = defaultdict(list)
for entry in new:
    new_by_key[key(entry)].append(entry[2])

moved = []
content_added = []
content_removed = []

for k in sorted(set(old_by_key) | set(new_by_key)):
    old_lines = sorted(old_by_key.get(k, []))
    new_lines = sorted(new_by_key.get(k, []))
    matched = min(len(old_lines), len(new_lines))
    for i in range(matched):
        if old_lines[i] != new_lines[i]:
            moved.append((k, old_lines[i], new_lines[i]))
    for line_no in new_lines[matched:]:
        content_added.append((k, line_no))
    for line_no in old_lines[matched:]:
        content_removed.append((k, line_no))

if content_added or content_removed:
    verdict = "CONTENT_DRIFT"
elif moved:
    verdict = "LINE_DRIFT_ONLY"
else:
    verdict = "NO_DRIFT"
print(verdict)
for k, old_line, new_line in moved:
    category, file_path, source = k
    print(f"MOVED\t{category}\t{file_path}\t{old_line}\t{new_line}\t{source}")
for k, line_no in content_added:
    category, file_path, source = k
    print(f"ADDED\t{category}\t{file_path}:{line_no}\t{source}")
for k, line_no in content_removed:
    category, file_path, source = k
    print(f"REMOVED\t{category}\t{file_path}:{line_no}\t{source}")
PYEOF
}

collect() {
  local category=$1
  local pattern=$2

  (
    cd "$repo_root"
    rg -n --no-heading --color never --glob '*.rs' "$pattern" "${source_roots[@]}" || status=$?
    if [[ ${status:-0} -gt 1 ]]; then
      exit "$status"
    fi
  ) | awk -v category="$category" '
    {
      first = index($0, ":")
      rest = substr($0, first + 1)
      second_rel = index(rest, ":")
      path = substr($0, 1, first - 1)
      line = substr(rest, 1, second_rel - 1)
      source = substr(rest, second_rel + 1)
      gsub(/[[:space:]]+/, " ", source)
      sub(/^ /, "", source)
      sub(/ $/, "", source)
      printf "%s\t%s:%s\t%s\n", category, path, line, source
    }
  ' >> "$collected"
}

collect spawn-task 'tokio::spawn|tokio::task::spawn|n0_future::task::spawn|task::spawn|JoinSet|spawn_blocking|thread::spawn'
collect clock-timer 'tokio::time|n0_future::time|Instant::now|SystemTime::now|OffsetDateTime::now_utc|Timestamp::now'
collect entropy-random 'rand::random|rand::rng\(\)|thread_rng|OsRng|getrandom|with_jitter|SecretKey::generate|rng_seed'
collect network-environment 'UdpSocket|TcpListener::bind|resolve_host|lookup_|netmon::|interfaces::|portmapper'
collect external-state 'std::fs|tokio::fs|File::open|OpenOptions|std::env|env::var|Command::new|thread::spawn|spawn_blocking'
collect unordered-collection 'HashMap|HashSet|FxHashMap|FxHashSet|DashMap'

LC_ALL=C sort -u "$collected" > "$sorted"

if [[ "$mode" == "--update" ]]; then
  mkdir -p "$(dirname "$baseline")"
  if [[ -f "$baseline" ]] && ! cmp -s "$baseline" "$sorted"; then
    classification=$(classify_drift "$baseline" "$sorted")
    verdict=$(head -n 1 <<<"$classification")
    if [[ "$verdict" == "CONTENT_DRIFT" && "$allow_content_drift" -ne 1 ]]; then
      echo "REFUSING to update: this drift includes occurrences added, removed, or" >&2
      echo "altered, not just moved line numbers. Updating without review would let a" >&2
      echo "real behaviour change slip in disguised as routine baseline refresh." >&2
      tail -n +2 <<<"$classification" | awk -F'\t' '
        $1 == "MOVED"   { printf "  ~ %s\t%s\tline %s -> %s\t%s\n", $2, $3, $4, $5, $6 }
        $1 == "ADDED"   { printf "  + %s\t%s\t%s\n", $2, $3, $4 }
        $1 == "REMOVED" { printf "  - %s\t%s\t%s\n", $2, $3, $4 }
      ' >&2
      echo "review the change, classify it in docs/testing/determinism-audit.md, then rerun with:" >&2
      echo "  scripts/check-determinism-boundaries.sh --update --allow-content-drift" >&2
      exit 1
    fi
  fi
  baseline_tmp=$(mktemp "${baseline}.tmp.XXXXXX")
  cp "$sorted" "$baseline_tmp"
  mv "$baseline_tmp" "$baseline"
  echo "updated determinism boundary baseline: $baseline"
  exit 0
fi

if [[ ! -f "$baseline" ]]; then
  echo "determinism boundary baseline is missing: $baseline" >&2
  echo "review the audit, then run scripts/check-determinism-boundaries.sh --update" >&2
  exit 1
fi

if [[ -s "$baseline" ]] && ! awk -F '\t' '
  NF != 3 || $1 !~ /^[a-z-]+$/ || $2 !~ /:[0-9]+$/ || $3 == "" { exit 1 }
' "$baseline"; then
  echo "malformed determinism boundary baseline: $baseline" >&2
  exit 2
fi

if cmp -s "$baseline" "$sorted"; then
  echo "determinism boundary baseline is current"
  exit 0
fi

classification=$(classify_drift "$baseline" "$sorted")
verdict=$(head -n 1 <<<"$classification")
detail=$(tail -n +2 <<<"$classification")

case "$verdict" in
  LINE_DRIFT_ONLY)
    echo "determinism boundary LINE drift detected (content identical; only line numbers moved)" >&2
    echo "$detail" | awk -F'\t' '
      $1 == "MOVED" { printf "  ~ %s\t%s\tline %s -> %s\t%s\n", $2, $3, $4, $5, $6 }
    ' >&2
    echo "this looks like pure formatting drift (e.g. lines inserted or removed above a" >&2
    echo "boundary). If you have confirmed no behaviour changed, refresh the baseline:" >&2
    echo "  scripts/check-determinism-boundaries.sh --update" >&2
    ;;
  CONTENT_DRIFT)
    echo "determinism boundary CONTENT drift detected (an occurrence was added, removed, or altered)" >&2
    echo "$detail" | awk -F'\t' '
      $1 == "ADDED"   { printf "  + %s\t%s\t%s\n", $2, $3, $4 }
      $1 == "REMOVED" { printf "  - %s\t%s\t%s\n", $2, $3, $4 }
      $1 == "MOVED"   { printf "  ~ %s\t%s\tline %s -> %s\t%s\n", $2, $3, $4, $5, $6 }
    ' >&2
    echo "classify the drift in docs/testing/determinism-audit.md, then run:" >&2
    echo "  scripts/check-determinism-boundaries.sh --update --allow-content-drift" >&2
    ;;
  *)
    # classify_drift disagreeing with the cmp check above should be
    # impossible (cmp already proved the files differ byte-for-byte), but
    # fail loudly with the raw diff rather than silently treating it as
    # either drift class if it ever happens.
    echo "determinism boundary drift detected but could not be classified (verdict: $verdict)" >&2
    diff -u "$baseline" "$sorted" >&2 || true
    ;;
esac
exit 1
