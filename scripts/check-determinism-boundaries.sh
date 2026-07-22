#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scripts/check-determinism-boundaries.sh (--check|--update) [--root DIR] [--baseline FILE]

  --check     Compare source occurrences with the reviewed baseline.
  --update    Replace the baseline after reviewing and classifying drift.
EOF
}

mode=
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline=

while [[ $# -gt 0 ]]; do
  case "$1" in
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
for candidate in iroh iroh-base iroh-dns iroh-dns-server iroh-relay iroh-runtime iroh-sim; do
  if [[ -d "$repo_root/$candidate" ]]; then
    source_roots+=("$candidate")
  fi
done

if [[ ${#source_roots[@]} -eq 0 ]]; then
  echo "no Iroh source roots found below $repo_root" >&2
  exit 2
fi

collected=$(mktemp)
sorted=$(mktemp)
added=$(mktemp)
removed=$(mktemp)
trap 'rm -f "$collected" "$sorted" "$added" "$removed"' EXIT

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
collect external-state 'std::fs|tokio::fs|std::env|env::var|Command::new|thread::spawn|spawn_blocking'
collect unordered-collection 'HashMap|HashSet|FxHashMap|FxHashSet|DashMap'

LC_ALL=C sort -u "$collected" > "$sorted"

if [[ "$mode" == "--update" ]]; then
  mkdir -p "$(dirname "$baseline")"
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

LC_ALL=C comm -13 "$baseline" "$sorted" > "$added"
LC_ALL=C comm -23 "$baseline" "$sorted" > "$removed"

echo "determinism boundary drift detected" >&2
if [[ -s "$added" ]]; then
  echo "new or changed occurrences:" >&2
  sed 's/^/  + /' "$added" >&2
fi
if [[ -s "$removed" ]]; then
  echo "removed or changed occurrences:" >&2
  sed 's/^/  - /' "$removed" >&2
fi
echo "classify the drift in docs/testing/determinism-audit.md, then run:" >&2
echo "  scripts/check-determinism-boundaries.sh --update" >&2
exit 1
