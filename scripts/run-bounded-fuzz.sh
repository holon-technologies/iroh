#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seconds=30
selected_target=""
artifacts="$repo_root/target/fuzz-artifacts"
known_crash_seen=0
readonly fuzz_toolchain="${IROH_FUZZ_TOOLCHAIN:-nightly-2026-07-19}"
readonly artifact_file_limit=64
readonly artifact_byte_limit=67108864
readonly -a targets=(
  doh_extract
  pkarr_body
  relay_segmentation
  config_deserialize
  gossip_message
  app_manifest
  app_protocol_registration
  blob_ticket
  doc_ticket
)

usage() {
  cat <<'EOF'
Usage: scripts/run-bounded-fuzz.sh [--seconds N] [--target TARGET] [--artifacts DIR]

Runs one or all reviewed fuzz targets under explicit time, input, memory, and artifact bounds.
EOF
}

is_known_target() {
  local candidate="$1"
  local target

  for target in "${targets[@]}"; do
    if [[ "$target" == "$candidate" ]]; then
      return 0
    fi
  done
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --seconds)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      seconds="$2"
      shift 2
      ;;
    --target)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      selected_target="$2"
      shift 2
      ;;
    --artifacts)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      artifacts="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$seconds" =~ ^[0-9]+$ ]] || (( seconds < 1 || seconds > 3600 )); then
  printf '%s\n' '--seconds must be an integer from 1 through 3600' >&2
  exit 2
fi

if [[ -n "$selected_target" ]] && ! is_known_target "$selected_target"; then
  printf 'unknown fuzz target: %s\n' "$selected_target" >&2
  exit 2
fi

command -v cargo >/dev/null 2>&1 || {
  printf '%s\n' 'cargo is required' >&2
  exit 2
}

if ! cargo fuzz --help >/dev/null 2>&1; then
  printf '%s\n' 'cargo-fuzz is required: cargo install cargo-fuzz --locked' >&2
  exit 2
fi

fuzz_target=$(rustc "+$fuzz_toolchain" -vV | sed -n 's/^host: //p')
if [[ ! "$fuzz_target" =~ ^[A-Za-z0-9_.-]+$ ]]; then
  printf '%s rustc returned an invalid host target: %s\n' \
    "$fuzz_toolchain" "$fuzz_target" >&2
  exit 2
fi

mkdir -p "$artifacts"
artifacts="$(cd "$artifacts" && pwd)"
known_crashes_file="$repo_root/fuzz/known-crashes.md"

run_target() {
  local target="$1"
  local max_len=65535
  local source_corpus="$repo_root/fuzz/corpus/$target"
  local run_corpus
  local target_artifacts="$artifacts/$target"
  local file_count
  local byte_count

  case "$target" in
    pkarr_body)
      max_len=1104
      ;;
    relay_segmentation)
      # Ten framing-control bytes plus the production 64 KiB relay payload bound.
      max_len=65546
      ;;
  esac

  run_corpus="$(mktemp -d)"
  trap 'rm -rf "$run_corpus"' RETURN
  cp -a "$source_corpus/." "$run_corpus/"
  mkdir -p "$target_artifacts"

  local fuzz_log="$target_artifacts/fuzz-output.txt"
  local fuzz_status=0
  (
    cd "$repo_root"
    RUSTFLAGS="${IROH_FUZZ_RUSTFLAGS:--A deprecated}" \
      cargo "+$fuzz_toolchain" fuzz run --target "$fuzz_target" "$target" "$run_corpus" -- \
      "-max_total_time=$seconds" \
      -timeout=10 \
      -rss_limit_mb=2048 \
      "-max_len=$max_len" \
      "-artifact_prefix=$target_artifacts/" \
      -verbosity=0 \
      -print_final_stats=1
  ) 2>&1 | tee "$fuzz_log" || fuzz_status="${PIPESTATUS[0]}"

  if (( fuzz_status != 0 )); then
    # A Rust panic prints "panicked at <path>:<line>:<col>:" followed by the
    # panic message on the next line. Build a signature out of BOTH the
    # crate-relative location and the message, so a different panic at a
    # different location (even with the same message, e.g. another
    # "attempt to subtract with overflow" elsewhere) does not collide with
    # an unrelated one recorded in known-crashes.md.
    local location_line message_line crate_location signature
    location_line="$(grep -m1 'panicked at' "$fuzz_log" || true)"
    message_line=""
    if [[ -n "$location_line" ]]; then
      message_line="$(grep -m1 -A1 'panicked at' "$fuzz_log" | tail -1 | sed 's/^[[:space:]]*//')"
    fi
    crate_location="$(printf '%s\n' "$location_line" \
      | grep -m1 -oE '[A-Za-z0-9_.-]+-[0-9]+\.[0-9]+\.[0-9]+/src/[^[:space:]:]+:[0-9]+:[0-9]+' || true)"
    signature=""
    if [[ -n "$crate_location" && -n "$message_line" ]]; then
      signature="$crate_location: $message_line"
    fi

    if [[ -n "$signature" ]] && grep -qF -- "$signature" "$known_crashes_file" 2>/dev/null; then
      printf 'known crash reproduced for %s: %s\n' "$target" "$signature" >&2
      known_crash_seen=1
    else
      printf 'NEW crash for %s: %s\n' "$target" "${signature:-<no panic signature captured; see $fuzz_log>}" >&2
      exit 1
    fi
  fi

  file_count="$(find "$target_artifacts" -type f | wc -l)"
  byte_count="$(du -sb "$target_artifacts" | awk '{print $1}')"
  if (( file_count >= artifact_file_limit || byte_count > artifact_byte_limit )); then
    printf 'artifact budget exceeded for %s: files=%s bytes=%s\n' \
      "$target" "$file_count" "$byte_count" >&2
    exit 1
  fi

  printf 'target=%s seconds=%s max_len=%s artifact_files=%s artifact_bytes=%s\n' \
    "$target" "$seconds" "$max_len" "$file_count" "$byte_count" \
    > "$target_artifacts/run-summary.txt"

  file_count="$(find "$target_artifacts" -type f | wc -l)"
  byte_count="$(du -sb "$target_artifacts" | awk '{print $1}')"
  if (( file_count > artifact_file_limit || byte_count > artifact_byte_limit )); then
    printf 'artifact budget exceeded for %s after summary: files=%s bytes=%s\n' \
      "$target" "$file_count" "$byte_count" >&2
    exit 1
  fi
}

if [[ -n "$selected_target" ]]; then
  run_target "$selected_target"
else
  for target in "${targets[@]}"; do
    run_target "$target"
  done
fi

# 0 = clean, 1 = new crash (already exited above), 2 = only known crashes.
if (( known_crash_seen == 1 )); then
  exit 2
fi
exit 0
