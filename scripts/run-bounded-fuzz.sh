#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
seconds=30
selected_target=""
artifacts="$repo_root/target/fuzz-artifacts"
known_crash_seen=0
readonly fuzz_toolchain="${KRIKOS_FUZZ_TOOLCHAIN:-nightly-2026-07-19}"
readonly artifact_file_limit=64
readonly artifact_byte_limit=67108864
readonly mutable_corpus_file_limit=4096
readonly mutable_corpus_byte_limit=268435456
readonly fuzz_log_file_limit=1
readonly fuzz_log_byte_limit=16777216
readonly runtime_output_byte_limit=352321536
readonly preflight_headroom_bytes=1073741824
readonly watchdog_interval_seconds=0.25
readonly log_file_block_limit=32768
readonly fuzz_build_root="$repo_root/fuzz/target"
active_run_root=""
active_run_parent=""
active_campaign_pid=""
active_campaign_pgid=""
active_watchdog_pid=""
active_stage_file=""
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
  identity_foundation
  identity_schema
  identity_capability
  identity_merkle
  identity_state
  identity_pairing
  identity_sync
  identity_provider
  identity_semantics
)

process_alive() {
  local process_pid="$1"
  local process_state

  [[ "$process_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$process_pid" 2>/dev/null || return 1
  process_state="$(ps -o stat= -p "$process_pid" 2>/dev/null)"
  [[ -n "$process_state" && "$process_state" != Z* ]]
}

process_group_alive() {
  local campaign_pgid="$1"

  [[ "$campaign_pgid" =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 -- "-$campaign_pgid" 2>/dev/null || return 1
  ps -eo pgid=,stat= \
    | awk -v campaign_pgid="$campaign_pgid" \
      '$1 == campaign_pgid && $2 !~ /^Z/ { found = 1 } END { exit(found ? 0 : 1) }'
}

terminate_campaign() {
  local campaign_pgid="$1"

  [[ "$campaign_pgid" =~ ^[1-9][0-9]*$ ]] || return 0
  if process_group_alive "$campaign_pgid"; then
    kill -TERM -- "-$campaign_pgid" 2>/dev/null || true
  elif process_alive "$campaign_pgid"; then
    kill -TERM "$campaign_pgid" 2>/dev/null || true
  else
    return 0
  fi
  for _ in {1..20}; do
    if ! process_group_alive "$campaign_pgid" \
      && ! process_alive "$campaign_pgid"; then
      return 0
    fi
    sleep 0.05
  done
  if process_group_alive "$campaign_pgid"; then
    kill -KILL -- "-$campaign_pgid" 2>/dev/null || true
  fi
  kill -KILL "$campaign_pgid" 2>/dev/null || true
  for _ in {1..20}; do
    if ! process_group_alive "$campaign_pgid" \
      && ! process_alive "$campaign_pgid"; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

cleanup_active_run() {
  local campaign_pid="$active_campaign_pid"
  local campaign_pgid="$active_campaign_pgid"
  local watchdog_pid="$active_watchdog_pid"
  local run_root="$active_run_root"
  local run_parent="$active_run_parent"
  local stage_file="$active_stage_file"

  active_campaign_pid=""
  active_campaign_pgid=""
  active_watchdog_pid=""
  active_run_root=""
  active_run_parent=""
  active_stage_file=""
  if [[ -n "$campaign_pgid" ]]; then
    terminate_campaign "$campaign_pgid" || true
  fi
  if [[ -n "$campaign_pid" ]]; then
    wait "$campaign_pid" 2>/dev/null || true
  fi
  if [[ -n "$campaign_pgid" ]]; then
    terminate_campaign "$campaign_pgid" || true
  fi
  if [[ "$watchdog_pid" =~ ^[1-9][0-9]*$ ]]; then
    kill -TERM "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
  fi
  if [[ -n "$stage_file" \
     && "$(basename -- "$stage_file")" =~ ^\.krikos-fuzz-stage\.[A-Za-z0-9]{10}$ ]]; then
    rm -f -- "$stage_file"
  fi
  if [[ -n "$run_root" \
     && "$(dirname -- "$run_root")" == "$run_parent" \
     && "$(basename -- "$run_root")" =~ ^krikos-fuzz\.[A-Za-z0-9]{10}$ \
     && -f "$run_root/.krikos-fuzz-run" ]]; then
    rm -rf -- "$run_root"
  fi
}

trap cleanup_active_run EXIT
trap 'cleanup_active_run; exit 130' INT
trap 'cleanup_active_run; exit 143' TERM

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

path_file_count() {
  local path="$1"

  if [[ ! -e "$path" ]]; then
    printf '%s\n' 0
    return 0
  fi
  find "$path" -ignore_readdir_race -type f -printf '.' | wc -c
}

path_byte_count() {
  local path="$1"
  local attempt output status bytes line
  local saw_disappearing unexpected

  if [[ ! -e "$path" ]]; then
    printf '%s\n' 0
    return 0
  fi
  for attempt in 1 2 3; do
    if output="$(LC_ALL=C du -sb -- "$path" 2>&1)"; then
      bytes="$(awk 'NR == 1 { print $1 }' <<<"$output")"
      if [[ ! "$bytes" =~ ^[0-9]+$ ]]; then
        printf 'du returned an invalid byte count for %s: %s\n' "$path" "$output" >&2
        return 1
      fi
      printf '%s\n' "$bytes"
      return 0
    else
      status=$?
    fi

    saw_disappearing=0
    unexpected=0
    while IFS= read -r line; do
      if [[ "$line" == du:\ cannot\ access\ *:\ No\ such\ file\ or\ directory ]]; then
        saw_disappearing=1
      elif [[ "$line" =~ ^[0-9]+[[:space:]] ]]; then
        # GNU du may still print a stale total after one descendant disappears.
        :
      else
        unexpected=1
      fi
    done <<<"$output"
    if (( saw_disappearing == 0 || unexpected == 1 )) || [[ ! -e "$path" ]]; then
      printf '%s\n' "$output" >&2
      return "$status"
    fi
  done

  printf 'could not measure %s after %s disappearing-entry retries\n' \
    "$path" "$attempt" >&2
  printf '%s\n' "$output" >&2
  return 1
}

file_byte_count() {
  local path="$1"

  if [[ ! -f "$path" ]]; then
    printf '%s\n' 0
    return 0
  fi
  stat -c '%s' -- "$path"
}

reject_managed_tree_symlinks() {
  local path="$1"
  local phase="$2"
  local failure_file="${3:-}"
  local attempt output line
  local saw_disappearing unexpected

  if [[ ! -e "$path" && ! -L "$path" ]]; then
    return 0
  fi

  for attempt in 1 2 3; do
    if output="$(LC_ALL=C find "$path" -ignore_readdir_race -type l -print -quit 2>&1)"; then
      if [[ -n "$output" ]]; then
        write_budget_failure "$failure_file" \
          "managed fuzz write tree contains a symlink $phase: $output"
        return 1
      fi
      return 0
    fi

    saw_disappearing=0
    unexpected=0
    while IFS= read -r line; do
      if [[ "$line" == "find: '$path/"*"': No such file or directory" ]]; then
        saw_disappearing=1
      else
        unexpected=1
      fi
    done <<<"$output"

    if (( saw_disappearing == 0 || unexpected == 1 )); then
      [[ -z "$output" ]] || printf '%s\n' "$output" >&2
      write_budget_failure "$failure_file" \
        "could not inspect managed fuzz tree $phase: $path"
      return 1
    fi
    # Cargo can remove a temporary descendant while find traverses target/.
    # Require a later complete traversal instead of accepting a partial scan.
  done

  [[ -z "$output" ]] || printf '%s\n' "$output" >&2
  write_budget_failure "$failure_file" \
    "could not inspect managed fuzz tree $phase: $path"
  return 1
}

reject_managed_artifact_aliases() {
  local path="$1"
  local phase="$2"
  local failure_file="${3:-}"
  local invalid

  invalid="$(find "$path" -ignore_readdir_race ! -type d ! -type f ! -type l -print -quit)" || {
    write_budget_failure "$failure_file" \
      "could not inspect managed fuzz artifact tree $phase: $path"
    return 1
  }
  if [[ -n "$invalid" ]]; then
    write_budget_failure "$failure_file" \
      "managed fuzz artifact tree contains a non-regular entry $phase: $invalid"
    return 1
  fi
  invalid="$(find "$path" -ignore_readdir_race -type f -links +1 -print -quit)" || {
    write_budget_failure "$failure_file" \
      "could not inspect managed fuzz artifact link counts $phase: $path"
    return 1
  }
  if [[ -n "$invalid" ]]; then
    write_budget_failure "$failure_file" \
      "managed fuzz artifact tree contains a multiply-linked regular file $phase: $invalid"
    return 1
  fi
}

reject_nonregular_artifact_output() {
  local path="$1"

  if [[ -e "$path" && ! -f "$path" ]]; then
    printf 'managed fuzz artifact output is not a regular file: %s\n' "$path" >&2
    return 1
  fi
}

ensure_managed_directory() {
  local path="$1"
  local label="$2"

  if [[ -L "$path" ]]; then
    printf 'managed fuzz write tree contains a symlink before setup: %s\n' "$path" >&2
    return 1
  fi
  if [[ -e "$path" && ! -d "$path" ]]; then
    printf '%s is not a directory: %s\n' "$label" "$path" >&2
    return 1
  fi
  mkdir -p -- "$path"
  if [[ ! -d "$path" || -L "$path" ]]; then
    printf '%s is not a safe managed directory: %s\n' "$label" "$path" >&2
    return 1
  fi
  reject_managed_tree_symlinks "$path" 'before setup'
}

free_byte_count() {
  local path="$1"
  local available_blocks

  available_blocks="$(df -Pk -- "$path" | awk 'NR == 2 { print $4 }')"
  if [[ ! "$available_blocks" =~ ^[0-9]+$ ]]; then
    printf 'could not determine free space for fuzz path: %s\n' "$path" >&2
    return 1
  fi
  printf '%s\n' "$(( available_blocks * 1024 ))"
}

preflight_free_space() {
  local path="$1"
  local available_bytes required_bytes

  available_bytes="$(free_byte_count "$path")"
  required_bytes=$(( runtime_output_byte_limit + preflight_headroom_bytes ))
  if (( available_bytes < required_bytes )); then
    printf 'insufficient free space for bounded fuzz run: path=%s available=%s required=%s\n' \
      "$path" "$available_bytes" "$required_bytes" >&2
    return 1
  fi
}

write_budget_failure() {
  local failure_file="$1"
  shift

  if [[ -n "$failure_file" ]]; then
    printf '%s\n' "$*" > "$failure_file"
  else
    printf '%s\n' "$*" >&2
  fi
}

check_runtime_budgets() {
  local phase="$1"
  local run_corpus="$2"
  local artifact_root="$3"
  local fuzz_log="$4"
  local failure_file="$5"
  local build_root="$6"
  local repository_root="$7"
  local corpus_files corpus_bytes artifact_files artifact_bytes log_files log_bytes aggregate_bytes
  local corpus_free_bytes artifact_free_bytes log_free_bytes build_free_bytes repository_free_bytes
  local log_root

  reject_managed_tree_symlinks "$run_corpus" "$phase" "$failure_file" || return 1
  reject_managed_tree_symlinks "$artifact_root" "$phase" "$failure_file" || return 1
  reject_managed_artifact_aliases "$artifact_root" "$phase" "$failure_file" || return 1
  reject_managed_tree_symlinks "$build_root" "$phase" "$failure_file" || return 1
  if [[ -n "$fuzz_log" ]]; then
    reject_managed_tree_symlinks "$fuzz_log" "$phase" "$failure_file" || return 1
  fi

  corpus_files="$(path_file_count "$run_corpus")"
  corpus_bytes="$(path_byte_count "$run_corpus")"
  artifact_files="$(path_file_count "$artifact_root")"
  artifact_bytes="$(path_byte_count "$artifact_root")"
  if [[ -f "$fuzz_log" ]]; then
    log_files=1
  else
    log_files=0
  fi
  log_bytes="$(file_byte_count "$fuzz_log")"
  aggregate_bytes=$(( corpus_bytes + artifact_bytes + log_bytes ))
  corpus_free_bytes="$(free_byte_count "$run_corpus")"
  artifact_free_bytes="$(free_byte_count "$artifact_root")"
  log_root="${fuzz_log:+$(dirname -- "$fuzz_log")}"
  if [[ -n "$log_root" ]]; then
    log_free_bytes="$(free_byte_count "$log_root")"
  else
    log_free_bytes="$artifact_free_bytes"
  fi
  build_free_bytes="$(free_byte_count "$build_root")"
  repository_free_bytes="$(free_byte_count "$repository_root")"

  if (( corpus_files > mutable_corpus_file_limit || corpus_bytes > mutable_corpus_byte_limit )); then
    write_budget_failure "$failure_file" \
      "mutable corpus budget exceeded $phase: files=$corpus_files bytes=$corpus_bytes"
    return 1
  fi
  if (( artifact_files > artifact_file_limit || artifact_bytes > artifact_byte_limit )); then
    write_budget_failure "$failure_file" \
      "artifact budget exceeded $phase: files=$artifact_files bytes=$artifact_bytes"
    return 1
  fi
  if (( log_files > fuzz_log_file_limit || log_bytes > fuzz_log_byte_limit )); then
    write_budget_failure "$failure_file" \
      "fuzz log budget exceeded $phase: files=$log_files bytes=$log_bytes"
    return 1
  fi
  if (( aggregate_bytes > runtime_output_byte_limit )); then
    write_budget_failure "$failure_file" \
      "aggregate runtime-output budget exceeded $phase: bytes=$aggregate_bytes"
    return 1
  fi
  if (( corpus_free_bytes < preflight_headroom_bytes \
     || artifact_free_bytes < preflight_headroom_bytes \
     || log_free_bytes < preflight_headroom_bytes \
     || build_free_bytes < preflight_headroom_bytes \
     || repository_free_bytes < preflight_headroom_bytes )); then
    write_budget_failure "$failure_file" \
      "free-space headroom exhausted $phase: corpus_free=$corpus_free_bytes artifact_free=$artifact_free_bytes log_free=$log_free_bytes build_free=$build_free_bytes repository_free=$repository_free_bytes required=$preflight_headroom_bytes"
    return 1
  fi
}

budget_watchdog() {
  local campaign_pid="$1"
  local campaign_pgid="$2"
  local run_corpus="$3"
  local artifact_root="$4"
  local fuzz_log="$5"
  local failure_file="$6"
  local build_root="$7"
  local repository_root="$8"
  local group_observed=0

  for _ in {1..100}; do
    if process_group_alive "$campaign_pgid"; then
      group_observed=1
      break
    fi
    process_alive "$campaign_pid" || break
    sleep 0.01
  done
  if (( group_observed == 0 )) && process_alive "$campaign_pid"; then
    write_budget_failure "$failure_file" \
      'fuzz campaign did not establish its isolated process group'
    terminate_campaign "$campaign_pgid" || true
    return 1
  fi

  while process_group_alive "$campaign_pgid"; do
    if ! check_runtime_budgets \
      'during execution' "$run_corpus" "$artifact_root" "$fuzz_log" "$failure_file" \
      "$build_root" "$repository_root"; then
      terminate_campaign "$campaign_pgid" || true
      return 1
    fi
    sleep "$watchdog_interval_seconds"
  done
  check_runtime_budgets \
    'after execution' "$run_corpus" "$artifact_root" "$fuzz_log" "$failure_file" \
    "$build_root" "$repository_root"
}

retain_bounded_artifact_file() {
  local source="$1"
  local destination="$2"
  local run_corpus="$3"
  local label="$4"
  local destination_parent source_bytes artifact_files artifact_bytes
  local staging_files staging_bytes corpus_bytes aggregate_bytes
  local artifact_free_bytes required_free_bytes staged_bytes

  if [[ ! -f "$source" || -L "$source" ]]; then
    printf 'retained %s source is not a regular file: %s\n' "$label" "$source" >&2
    return 1
  fi
  reject_managed_artifact_aliases "$artifacts" "before $label staging"
  reject_nonregular_artifact_output "$destination"
  source_bytes="$(file_byte_count "$source")"
  artifact_files="$(path_file_count "$artifacts")"
  artifact_bytes="$(path_byte_count "$artifacts")"
  staging_files=$(( artifact_files + 1 ))
  staging_bytes=$(( artifact_bytes + source_bytes ))
  if (( staging_files > artifact_file_limit )); then
    printf 'retained %s would exceed artifact file budget before staging: files=%s\n' \
      "$label" "$staging_files" >&2
    return 1
  fi
  if (( staging_bytes > artifact_byte_limit )); then
    printf 'retained %s would exceed artifact byte budget before staging: bytes=%s\n' \
      "$label" "$staging_bytes" >&2
    return 1
  fi
  corpus_bytes="$(path_byte_count "$run_corpus")"
  aggregate_bytes=$(( corpus_bytes + staging_bytes + source_bytes ))
  if (( aggregate_bytes > runtime_output_byte_limit )); then
    printf 'retained %s would exceed aggregate runtime-output budget before staging: bytes=%s\n' \
      "$label" "$aggregate_bytes" >&2
    return 1
  fi
  artifact_free_bytes="$(free_byte_count "$artifacts")"
  required_free_bytes=$(( preflight_headroom_bytes + source_bytes ))
  if (( artifact_free_bytes < required_free_bytes )); then
    printf 'insufficient artifact free space for retained %s staging: available=%s required=%s\n' \
      "$label" "$artifact_free_bytes" "$required_free_bytes" >&2
    return 1
  fi

  destination_parent="$(dirname -- "$destination")"
  active_stage_file="$(mktemp "$destination_parent/.krikos-fuzz-stage.XXXXXXXXXX")"
  cp --reflink=never -- "$source" "$active_stage_file"
  staged_bytes="$(file_byte_count "$active_stage_file")"
  if (( staged_bytes != source_bytes )); then
    printf 'retained %s staging changed byte length: source=%s staged=%s\n' \
      "$label" "$source_bytes" "$staged_bytes" >&2
    return 1
  fi
  check_runtime_budgets \
    "during $label staging" "$run_corpus" "$artifacts" "$source" "" \
    "$fuzz_build_root" "$repo_root"
  reject_nonregular_artifact_output "$destination"
  mv -Tf -- "$active_stage_file" "$destination"
  active_stage_file=""
  rm -f -- "$source"
  check_runtime_budgets \
    "after $label retention" "$run_corpus" "$artifacts" "" "" \
    "$fuzz_build_root" "$repo_root"
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

command -v setsid >/dev/null 2>&1 || {
  printf '%s\n' 'setsid is required for bounded fuzz process-group cleanup' >&2
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

ensure_managed_directory "$artifacts" 'fuzz artifact root'
artifacts="$(cd "$artifacts" && pwd -P)"
reject_managed_artifact_aliases "$artifacts" 'before setup'
ensure_managed_directory "$fuzz_build_root" 'fuzz build target root'
known_crashes_file="$repo_root/fuzz/known-crashes.md"

run_target() {
  local target="$1"
  local max_len=65535
  local source_corpus="$repo_root/fuzz/corpus/$target"
  local target_artifacts="$artifacts/$target"
  local run_corpus fuzz_log budget_failure_file
  local temp_parent fuzz_rustflags command_text quoted_command
  local start_seconds end_seconds wall_seconds fuzz_status watchdog_status
  local campaign_pid campaign_pgid
  local executed_units peak_rss_mb run_result
  local corpus_files corpus_bytes artifact_files artifact_bytes
  local summary summary_temp summary_stable summary_text
  local summary_base_files summary_base_bytes summary_bytes_guess summary_bytes_actual
  local summary_final_files summary_final_bytes summary_existing_files summary_existing_bytes
  local -a fuzz_command

  case "$target" in
    pkarr_body)
      max_len=1104
      ;;
    relay_segmentation)
      # Ten framing-control bytes plus the production 64 KiB relay payload bound.
      max_len=65546
      ;;
    identity_foundation)
      # Covers the complete bounded extension envelope plus framing overhead.
      max_len=131072
      ;;
    identity_schema)
      # One dispatch byte plus the largest canonical identity object.
      max_len=1048577
      ;;
    identity_capability)
      # Fixed evaluator controls; all constructed grants and chains remain protocol-bounded.
      max_len=64
      ;;
    identity_merkle)
      # One dispatch byte plus the global canonical-object bound.
      max_len=1048577
      ;;
    identity_state)
      # The evaluator model caps itself at sixteen transitions and two fork branches.
      max_len=64
      ;;
    identity_pairing)
      # One dispatch byte plus the pairing/proposal/presence canonical-object bound.
      max_len=262145
      ;;
    identity_sync)
      # One dispatch byte plus the exact synchronization-frame bound.
      max_len=4194305
      ;;
    identity_provider)
      # Bounded fault controls plus small persistent-provider mutation payloads.
      max_len=4096
      ;;
    identity_semantics)
      # One selector plus the largest algorithm-tagged leaf accepted by this target.
      max_len=8209
      ;;
  esac

  temp_parent="${TMPDIR:-/tmp}"
  [[ -d "$temp_parent" ]] || {
    printf 'temporary fuzz parent does not exist: %s\n' "$temp_parent" >&2
    exit 1
  }
  preflight_free_space "$temp_parent"
  preflight_free_space "$artifacts"
  preflight_free_space "$fuzz_build_root"
  preflight_free_space "$repo_root"
  reject_managed_tree_symlinks "$source_corpus" 'before reviewed-corpus copy'
  check_runtime_budgets \
    'before reviewed-corpus copy' "$source_corpus" "$artifacts" "" "" \
    "$fuzz_build_root" "$repo_root"

  active_run_parent="$(cd "$temp_parent" && pwd)"
  active_run_root="$(mktemp -d "$active_run_parent/krikos-fuzz.XXXXXXXXXX")"
  active_run_root="$(cd "$active_run_root" && pwd)"
  : > "$active_run_root/.krikos-fuzz-run"
  run_corpus="$active_run_root/corpus"
  fuzz_log="$active_run_root/fuzz-output.txt"
  budget_failure_file="$active_run_root/budget-failure.txt"
  mkdir -p "$run_corpus"
  cp -a "$source_corpus/." "$run_corpus/"
  reject_managed_tree_symlinks "$run_corpus" 'after reviewed-corpus copy'
  ensure_managed_directory "$target_artifacts" 'fuzz artifact target'
  reject_managed_artifact_aliases "$target_artifacts" 'before execution'
  reject_nonregular_artifact_output "$target_artifacts/fuzz-output.txt"
  reject_nonregular_artifact_output "$target_artifacts/run-summary.txt"
  check_runtime_budgets \
    'before execution' "$run_corpus" "$artifacts" "$fuzz_log" "" \
    "$fuzz_build_root" "$repo_root"

  fuzz_rustflags="${KRIKOS_FUZZ_RUSTFLAGS:--A deprecated}"
  fuzz_command=(
    cargo "+$fuzz_toolchain" fuzz run --target "$fuzz_target" "$target" "$run_corpus" --
      "-max_total_time=$seconds" \
      -timeout=10 \
      -rss_limit_mb=2048 \
      "-max_len=$max_len" \
      "-artifact_prefix=$target_artifacts/" \
      -verbosity=0 \
      -print_final_stats=1
  )
  printf -v command_text 'CARGO_TARGET_DIR=%q RUSTFLAGS=%q ' \
    "$fuzz_build_root" "$fuzz_rustflags"
  printf -v quoted_command '%q ' "${fuzz_command[@]}"
  command_text+="${quoted_command% }"

  start_seconds="$(date +%s)"
  setsid bash -o pipefail -c '
    repo_root=$1
    fuzz_rustflags=$2
    fuzz_log=$3
    log_file_block_limit=$4
    fuzz_build_root=$5
    shift 5
    cd "$repo_root"
    CARGO_TARGET_DIR="$fuzz_build_root" RUSTFLAGS="$fuzz_rustflags" "$@" 2>&1 \
      | (ulimit -f "$log_file_block_limit"; exec tee "$fuzz_log")
    campaign_status=${PIPESTATUS[0]}
    exit "$campaign_status"
  ' _ "$repo_root" "$fuzz_rustflags" "$fuzz_log" "$log_file_block_limit" \
    "$fuzz_build_root" \
    "${fuzz_command[@]}" &
  active_campaign_pid=$!
  active_campaign_pgid=$active_campaign_pid
  campaign_pid=$active_campaign_pid
  campaign_pgid=$active_campaign_pgid
  budget_watchdog \
    "$campaign_pid" "$campaign_pgid" "$run_corpus" "$artifacts" "$fuzz_log" \
    "$budget_failure_file" \
    "$fuzz_build_root" "$repo_root" &
  active_watchdog_pid=$!

  if wait "$campaign_pid"; then
    fuzz_status=0
  else
    fuzz_status=$?
  fi
  if process_group_alive "$campaign_pgid"; then
    write_budget_failure "$budget_failure_file" \
      'fuzz campaign left a live process-group descendant after leader exit'
    terminate_campaign "$campaign_pgid" || true
  fi
  if wait "$active_watchdog_pid"; then
    watchdog_status=0
  else
    watchdog_status=$?
  fi
  active_watchdog_pid=""
  if process_group_alive "$campaign_pgid"; then
    terminate_campaign "$campaign_pgid" || true
  fi
  if process_group_alive "$campaign_pgid"; then
    write_budget_failure "$budget_failure_file" \
      'fuzz campaign process group remained live after forced termination'
    watchdog_status=1
  else
    active_campaign_pid=""
    active_campaign_pgid=""
  fi
  end_seconds="$(date +%s)"
  wall_seconds=$(( end_seconds - start_seconds ))

  if [[ -s "$budget_failure_file" ]]; then
    cat "$budget_failure_file" >&2
    cleanup_active_run
    exit 1
  fi
  if (( watchdog_status != 0 )); then
    printf 'runtime budget watchdog failed for %s without a diagnostic\n' "$target" >&2
    cleanup_active_run
    exit 1
  fi

  executed_units="$(sed -n \
    's/^stat::number_of_executed_units:[[:space:]]*\([0-9][0-9]*\).*$/\1/p' \
    "$fuzz_log" | tail -1)"
  peak_rss_mb="$(sed -n \
    's/^stat::peak_rss_mb:[[:space:]]*\([0-9][0-9]*\).*$/\1/p' \
    "$fuzz_log" | tail -1)"
  [[ "$executed_units" =~ ^[0-9]+$ ]] || executed_units=unavailable
  [[ "$peak_rss_mb" =~ ^[0-9]+$ ]] || peak_rss_mb=unavailable
  retain_bounded_artifact_file \
    "$fuzz_log" "$target_artifacts/fuzz-output.txt" "$run_corpus" 'fuzz log'
  fuzz_log="$target_artifacts/fuzz-output.txt"

  run_result=clean
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
      run_result=known-crash
    else
      printf 'NEW crash for %s: %s\n' "$target" "${signature:-<no panic signature captured; see $fuzz_log>}" >&2
      cleanup_active_run
      exit 1
    fi
  fi

  summary="$target_artifacts/run-summary.txt"
  reject_managed_artifact_aliases "$target_artifacts" 'before summary retention'
  reject_nonregular_artifact_output "$summary"
  artifact_files="$(path_file_count "$artifacts")"
  artifact_bytes="$(path_byte_count "$artifacts")"
  if [[ -f "$summary" ]]; then
    summary_existing_files=1
    summary_existing_bytes="$(file_byte_count "$summary")"
  else
    summary_existing_files=0
    summary_existing_bytes=0
  fi
  summary_base_files=$(( artifact_files - summary_existing_files ))
  summary_base_bytes=$(( artifact_bytes - summary_existing_bytes ))
  summary_final_files=$(( summary_base_files + 1 ))
  summary_bytes_guess=0
  summary_temp="$(mktemp "$active_run_root/run-summary.XXXXXXXXXX")"

  summary_stable=0
  for _ in {1..8}; do
    corpus_files="$(path_file_count "$run_corpus")"
    corpus_bytes="$(path_byte_count "$run_corpus")"
    summary_final_bytes=$(( summary_base_bytes + summary_bytes_guess ))
    printf '%s\n' \
      "target=$target" \
      "result=$run_result" \
      "toolchain=$fuzz_toolchain" \
      "command=$command_text" \
      "seconds=$seconds" \
      "wall_seconds=$wall_seconds" \
      "max_len=$max_len" \
      "rss_limit_mb=2048" \
      "executed_units=$executed_units" \
      "peak_rss_mb=$peak_rss_mb" \
      "mutable_corpus_files=$corpus_files" \
      "mutable_corpus_bytes=$corpus_bytes" \
      "corpus_result=within-budget" \
      "artifact_files=$summary_final_files" \
      "artifact_bytes=$summary_final_bytes" \
      "artifact_result=within-budget" \
      > "$summary_temp"
    summary_bytes_actual="$(file_byte_count "$summary_temp")"
    if (( summary_bytes_actual == summary_bytes_guess )); then
      summary_stable=1
      break
    fi
    summary_bytes_guess="$summary_bytes_actual"
  done
  if (( summary_stable == 0 )); then
    printf 'run summary byte accounting did not converge for %s\n' "$target" >&2
    cleanup_active_run
    exit 1
  fi
  summary_text="$(<"$summary_temp")"
  retain_bounded_artifact_file \
    "$summary_temp" "$summary" "$run_corpus" 'run summary'
  artifact_files="$(path_file_count "$artifacts")"
  artifact_bytes="$(path_byte_count "$artifacts")"
  if (( artifact_files != summary_final_files || artifact_bytes != summary_final_bytes )); then
    printf 'run summary accounting changed after atomic retention for %s\n' "$target" >&2
    cleanup_active_run
    exit 1
  fi
  printf '%s\n' "$summary_text"
  cleanup_active_run
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
