#!/usr/bin/env bash
# shellcheck disable=SC2016 # Required entries are literal shell-source contracts.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runner="$repo_root/scripts/run-bounded-fuzz.sh"
ci_workflow="$repo_root/.github/workflows/ci.yml"
scheduled_workflow="$repo_root/.github/workflows/fuzz.yml"

# Third-party actions are pinned to a commit SHA with a trailing `# <ref>`
# comment (e.g. `actions/upload-artifact@<40-hex>  # v7`). Normalize both
# workflow files back to `actions/upload-artifact@v7` before matching
# contract literals below, so this check asserts on the human-readable ref
# rather than a SHA that Dependabot will rotate on every bump.
normalized_ci_workflow=$(mktemp)
normalized_scheduled_workflow=$(mktemp)
fixture_root=""
cleanup() {
  if [[ -n "$fixture_root" && -f "$fixture_root/fake-sleep-pid" ]]; then
    fake_sleep_pid=$(<"$fixture_root/fake-sleep-pid")
    if [[ "$fake_sleep_pid" =~ ^[0-9]+$ ]]; then
      kill -TERM "$fake_sleep_pid" 2>/dev/null || true
    fi
  fi
  rm -f "$normalized_ci_workflow" "$normalized_scheduled_workflow"
  if [[ -n "$fixture_root" && -f "$fixture_root/.fuzz-tooling-fixture" ]]; then
    rm -rf -- "$fixture_root"
  fi
}
trap cleanup EXIT
sed -E 's/@[0-9a-f]{40}[[:space:]]+#[[:space:]]*([^[:space:]]+)/@\1/' "$ci_workflow" > "$normalized_ci_workflow"
sed -E 's/@[0-9a-f]{40}[[:space:]]+#[[:space:]]*([^[:space:]]+)/@\1/' "$scheduled_workflow" > "$normalized_scheduled_workflow"
ci_workflow="$normalized_ci_workflow"
scheduled_workflow="$normalized_scheduled_workflow"

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

[[ -x "$runner" ]] || {
  printf '%s\n' 'bounded fuzz runner is missing or not executable' >&2
  exit 1
}

[[ -f "$repo_root/fuzz/Cargo.lock" ]] || {
  printf '%s\n' 'fuzz workspace lockfile is missing' >&2
  exit 1
}

for generated_dir in fuzz/target fuzz/artifacts; do
  # A trailing slash tells git the path is a directory, which matters for
  # directory-only gitignore patterns (e.g. `target/`). git can only infer
  # "this is a directory" from a trailing slash or from the path existing on
  # disk, and on a clean checkout these generated directories do not exist
  # yet, so the trailing slash must be explicit here rather than relying on
  # local build state.
  git -C "$repo_root" check-ignore -q "$generated_dir/" || {
    printf 'generated fuzz directory is not ignored: %s\n' "$generated_dir" >&2
    exit 1
  }
done

for fork in \
  '../vendor/hickory-server-0.26.1' \
  '../vendor/noq-1.1.0'; do
  grep -Fq -- "$fork" "$repo_root/fuzz/Cargo.toml" || {
    printf 'fuzz workspace does not use production fork: %s\n' "$fork" >&2
    exit 1
  }
done

for target in "${targets[@]}"; do
  [[ -f "$repo_root/fuzz/fuzz_targets/$target.rs" ]] || {
    printf 'missing fuzz target: %s\n' "$target" >&2
    exit 1
  }
  [[ -d "$repo_root/fuzz/corpus/$target" ]] || {
    printf 'missing reviewed corpus: %s\n' "$target" >&2
    exit 1
  }
  find "$repo_root/fuzz/corpus/$target" -type f -print -quit | grep -q . || {
    printf 'empty reviewed corpus: %s\n' "$target" >&2
    exit 1
  }
  grep -Fq -- "- $target" "$ci_workflow" || {
    printf 'pull-request fuzz matrix is missing target: %s\n' "$target" >&2
    exit 1
  }
  grep -Fq -- "- $target" "$scheduled_workflow" || {
    printf 'scheduled fuzz matrix is missing target: %s\n' "$target" >&2
    exit 1
  }
done

if rg -n 'selector[^[:cntrl:]]*%' "$repo_root"/fuzz/fuzz_targets/identity_*.rs >&2; then
  printf '%s\n' 'identity fuzz selectors must be append-only and must not use modulo remapping' >&2
  exit 1
fi

provider_selector_contracts=(
  '7|ProviderExportComponent'
  '8|ProviderExportComponentDescriptor'
  '9|ProviderGenerationExportChunk'
  'a|ProviderAuditExportChunk'
  'b|ProviderGenerationExportManifest'
  'c|ProviderAuditExportManifest'
  'd|ProviderRecoveryExportManifest'
  'e|ProviderCompactionManifest'
  'f|OpaqueProviderAnchorCommitment'
)
for contract in "${provider_selector_contracts[@]}"; do
  selector="${contract%%|*}"
  wire_type="${contract#*|}"
  grep -F -A2 -- "b'$selector' => {" \
    "$repo_root/fuzz/fuzz_targets/identity_provider.rs" \
    | grep -Fq -- "$wire_type::from_canonical_bytes(&input[1..])" || {
      printf 'provider fuzz selector %s does not decode %s\n' "$selector" "$wire_type" >&2
      exit 1
    }
done
grep -Fq -- "checked_sub(b'0').filter(|selector| *selector < 7)" \
  "$repo_root/fuzz/fuzz_targets/identity_provider.rs"

sync_selector_contracts=(
  '0|SyncRequest'
  '1|SyncFrame'
  '2|SyncCursor'
  '3|SyncResponse'
  '4|EndpointAuthorizationRequest'
  '5|AuthorizedSyncRequest'
  '6|AuthorizedProposalRequest'
  '7|AuthorizedCheckpointRequest'
  '8|IdentityProtocolAck'
  '9|IdentityProtocolReply'
)
for contract in "${sync_selector_contracts[@]}"; do
  selector="${contract%%|*}"
  wire_type="${contract#*|}"
  grep -F -A8 -- "$selector => {" \
    "$repo_root/fuzz/fuzz_targets/identity_sync.rs" \
    | grep -Fq -- "$wire_type::from_canonical_bytes(bytes)" || {
      printf 'sync fuzz selector %s does not decode %s\n' "$selector" "$wire_type" >&2
      exit 1
    }
done

if "$runner" --seconds 0 >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted an unbounded zero-second campaign' >&2
  exit 1
fi

if "$runner" --target not-a-target >/dev/null 2>&1; then
  printf '%s\n' 'runner accepted an unknown fuzz target' >&2
  exit 1
fi

grep -Fq -- '-rss_limit_mb=2048' "$runner"
grep -Fq -- 'artifact_file_limit=64' "$runner"
grep -Fq -- 'artifact_byte_limit=67108864' "$runner"
grep -Fq -- 'mutable_corpus_file_limit=4096' "$runner"
grep -Fq -- 'mutable_corpus_byte_limit=268435456' "$runner"
grep -Fq -- 'fuzz_log_file_limit=1' "$runner"
grep -Fq -- 'fuzz_log_byte_limit=16777216' "$runner"
grep -Fq -- 'runtime_output_byte_limit=352321536' "$runner"
grep -Fq -- 'preflight_headroom_bytes=1073741824' "$runner"
grep -Fq -- 'budget_watchdog' "$runner"
grep -Fq -- 'free-space headroom exhausted' "$runner"
grep -Fq -- 'trap cleanup_active_run EXIT' "$runner"
grep -Fq -- "trap 'cleanup_active_run; exit 130' INT" "$runner"
grep -Fq -- "trap 'cleanup_active_run; exit 143' TERM" "$runner"
grep -Fq -- 'stat::number_of_executed_units' "$runner"
grep -Fq -- 'stat::peak_rss_mb' "$runner"
grep -Fq -- '"executed_units=$executed_units"' "$runner"
grep -Fq -- '"peak_rss_mb=$peak_rss_mb"' "$runner"
grep -Fq -- '"wall_seconds=$wall_seconds"' "$runner"
grep -Fq -- '"command=$command_text"' "$runner"
grep -Fq -- 'corpus_result=within-budget' "$runner"
grep -Fq -- 'artifact_result=within-budget' "$runner"
grep -A3 '^    identity_schema)' "$runner" | grep -Fq -- 'max_len=1048577'
grep -A3 '^    identity_capability)' "$runner" | grep -Fq -- 'max_len=64'
grep -A3 '^    identity_merkle)' "$runner" | grep -Fq -- 'max_len=1048577'
grep -A3 '^    identity_state)' "$runner" | grep -Fq -- 'max_len=64'
grep -A3 '^    identity_pairing)' "$runner" | grep -Fq -- 'max_len=262145'
grep -A3 '^    identity_sync)' "$runner" | grep -Fq -- 'max_len=4194305'
grep -A3 '^    identity_provider)' "$runner" | grep -Fq -- 'max_len=4096'
grep -A3 '^    identity_semantics)' "$runner" | grep -Fq -- 'max_len=8209'
grep -Fq -- 'fuzz_toolchain="${KRIKOS_FUZZ_TOOLCHAIN:-nightly-2026-07-19}"' "$runner"
grep -Fq -- 'fuzz_target=$(rustc "+$fuzz_toolchain" -vV' "$runner"
grep -Fq -- 'cargo "+$fuzz_toolchain" fuzz run' "$runner"

for workflow in "$ci_workflow" "$scheduled_workflow"; do
  grep -Fq -- 'KRIKOS_FUZZ_TOOLCHAIN: "nightly-2026-07-19"' "$workflow" || {
    printf 'fuzz workflow does not select the reviewed nightly: %s\n' "$workflow" >&2
    exit 1
  }
  grep -Fq -- 'toolchain: nightly-2026-07-19' "$workflow" || {
    printf 'fuzz workflow does not install the reviewed nightly: %s\n' "$workflow" >&2
    exit 1
  }
done

workflow_contracts=(
  "$ci_workflow|fuzz_smoke:"
  "$ci_workflow|--seconds 1"
  "$ci_workflow|actions/upload-artifact@v7"
  "$ci_workflow|retention-days: 7"
  "$scheduled_workflow|schedule:"
  "$scheduled_workflow|workflow_dispatch:"
  "$scheduled_workflow|--seconds 300"
  "$scheduled_workflow|actions/upload-artifact@v7"
  "$scheduled_workflow|retention-days: 30"
)

for contract in "${workflow_contracts[@]}"; do
  file="${contract%%|*}"
  text="${contract#*|}"
  grep -Fq -- "$text" "$file" || {
    printf 'fuzz workflow is missing required contract: %s\n' "$text" >&2
    exit 1
  }
done

if grep -Eq '^[[:space:]]+pull_request:' "$scheduled_workflow"; then
  printf '%s\n' 'scheduled fuzz campaign must not duplicate the pull-request trigger' >&2
  exit 1
fi

# Exercise the runner with fake cargo/rustc/df/du commands. No fuzz binary is built or run.
fixture_root=$(mktemp -d)
: > "$fixture_root/.fuzz-tooling-fixture"
mkdir -p "$fixture_root/bin" "$fixture_root/tmp" "$fixture_root/artifacts"

cat > "$fixture_root/bin/rustc" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'rustc 1.91.0 (fixture)' 'host: x86_64-unknown-linux-gnu'
EOF

cat > "$fixture_root/bin/df" <<'EOF'
#!/usr/bin/env bash
path="${!#}"
if [[ "${MOCK_DF_MODE:-}" == low \
   || ( -n "${MOCK_DF_LOW_PATH:-}" && "$path" == "$MOCK_DF_LOW_PATH" ) \
   || ( -f "${MOCK_DF_RUNTIME_MARKER:-/nonexistent}" \
        && -n "${MOCK_DF_RUNTIME_LOW_PATH:-}" \
        && "$path" == "$MOCK_DF_RUNTIME_LOW_PATH" ) ]]; then
  printf '%s\n' \
    'Filesystem 1024-blocks Used Available Capacity Mounted on' \
    '/dev/mock 1024 1023 1 100% /mock'
else
  exec /usr/bin/df "$@"
fi
EOF

cat > "$fixture_root/bin/du" <<'EOF'
#!/usr/bin/env bash
path="${!#}"
if [[ -n "${MOCK_DU_RACE_PATH:-}" \
   && "$path" == "$MOCK_DU_RACE_PATH" \
   && ! -e "${MOCK_DU_RACE_MARKER:?}" ]]; then
  : > "$MOCK_DU_RACE_MARKER"
  printf "du: cannot access '%s/transient-entry': No such file or directory\n" \
    "$path" >&2
  exit 1
elif [[ "${MOCK_SOURCE_CORPUS_OVER_BUDGET:-}" == 1 \
   && "$path" == */fuzz/corpus/doh_extract ]]; then
  printf '268435457\t%s\n' "$path"
elif [[ "${MOCK_ARTIFACT_NEAR_LIMIT_MODE:-}" == summary \
   && "$path" == "${MOCK_ARTIFACT_ROOT:-/nonexistent}" \
   && -f "$path/doh_extract/fuzz-output.txt" ]]; then
  printf '67108860\t%s\n' "$path"
elif [[ -f "${MOCK_RUNTIME_MARKER:-/nonexistent}" \
   && -f "${MOCK_RUNTIME_PATH_FILE:-/nonexistent}" \
   && "$path" == "$(<"$MOCK_RUNTIME_PATH_FILE")" ]]; then
  printf '268435457\t%s\n' "$path"
else
  exec /usr/bin/du "$@"
fi
EOF

cat > "$fixture_root/bin/find" <<'EOF'
#!/usr/bin/env bash
path="${1:-}"
if [[ -n "${MOCK_FIND_RACE_PATH:-}" && "$path" == "$MOCK_FIND_RACE_PATH" ]]; then
  saw_ignore=0
  for argument in "$@"; do
    [[ "$argument" == -ignore_readdir_race ]] && saw_ignore=1
  done
  if (( saw_ignore == 0 )); then
    printf "find: '%s/transient-entry': No such file or directory\n" "$path" >&2
    exit 1
  fi
  if [[ -n "${MOCK_FIND_RACE_MARKER:-}" && ! -e "$MOCK_FIND_RACE_MARKER" ]]; then
    : > "$MOCK_FIND_RACE_MARKER"
    printf "find: '%s/transient-entry': No such file or directory\n" "$path" >&2
    /usr/bin/find "$@"
    exit 1
  fi
  if [[ "${MOCK_FIND_RACE_ALWAYS:-}" == 1 ]]; then
    printf "find: '%s/transient-entry': No such file or directory\n" "$path" >&2
    /usr/bin/find "$@"
    exit 1
  fi
fi
exec /usr/bin/find "$@"
EOF

cat > "$fixture_root/bin/cp" <<'EOF'
#!/usr/bin/env bash
destination="${!#}"
if [[ -n "${MOCK_STAGE_DEST_FILE:-}" \
   && "$(basename -- "$destination")" == .krikos-fuzz-stage.* ]]; then
  printf '%s\n' "$destination" > "$MOCK_STAGE_DEST_FILE"
fi
exec /usr/bin/cp "$@"
EOF

cat > "$fixture_root/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == fuzz && "${2:-}" == --help ]]; then
  exit 0
fi
if [[ "${2:-}" != fuzz || "${3:-}" != run ]]; then
  printf 'unexpected fake cargo invocation: %s\n' "$*" >&2
  exit 2
fi
printf '%s\n' started > "${MOCK_CARGO_STARTED:?}"
run_corpus="${7:?missing mutable corpus}"
case "${MOCK_FUZZ_MODE:-clean}" in
  clean)
    printf '%s\n' "${CARGO_TARGET_DIR:-}" > "${MOCK_CARGO_TARGET_DIR_FILE:?}"
    printf '%s\n' \
      'stat::number_of_executed_units: 17' \
      'stat::peak_rss_mb: 23'
    ;;
  grow-corpus)
    printf '%s\n' "$run_corpus" > "${MOCK_RUNTIME_PATH_FILE:?}"
    : > "${MOCK_RUNTIME_MARKER:?}"
    sleep 30 &
    sleep_pid=$!
    printf '%s\n' "$sleep_pid" > "${MOCK_SLEEP_PID_FILE:?}"
    wait "$sleep_pid"
    ;;
  exhaust-filesystem)
    : > "${MOCK_DF_RUNTIME_MARKER:?}"
    sleep 30 &
    sleep_pid=$!
    printf '%s\n' "$sleep_pid" > "${MOCK_SLEEP_PID_FILE:?}"
    wait "$sleep_pid"
    ;;
  symlink-corpus)
    ln -s "${MOCK_SYMLINK_OUTSIDE:?}" "$run_corpus/symlink-escape"
    sleep 30 &
    sleep_pid=$!
    printf '%s\n' "$sleep_pid" > "${MOCK_SLEEP_PID_FILE:?}"
    wait "$sleep_pid"
    ;;
  block)
    sleep 30 &
    sleep_pid=$!
    printf '%s\n' "$sleep_pid" > "${MOCK_SLEEP_PID_FILE:?}"
    wait "$sleep_pid"
    ;;
  orphan-descendant)
    sleep 30 </dev/null >/dev/null 2>&1 &
    sleep_pid=$!
    printf '%s\n' "$sleep_pid" > "${MOCK_SLEEP_PID_FILE:?}"
    printf '%s\n' \
      'stat::number_of_executed_units: 17' \
      'stat::peak_rss_mb: 23'
    ;;
  *)
    printf 'unknown fake fuzz mode: %s\n' "$MOCK_FUZZ_MODE" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$fixture_root/bin/"*

common_fixture_env=(
  "PATH=$fixture_root/bin:/usr/bin:/bin"
  "TMPDIR=$fixture_root/tmp"
  "MOCK_CARGO_STARTED=$fixture_root/cargo-started"
  "MOCK_RUNTIME_MARKER=$fixture_root/runtime-over-budget"
  "MOCK_RUNTIME_PATH_FILE=$fixture_root/runtime-path"
  "MOCK_SLEEP_PID_FILE=$fixture_root/fake-sleep-pid"
  "MOCK_DF_RUNTIME_MARKER=$fixture_root/filesystem-exhausted"
  "MOCK_DU_RACE_MARKER=$fixture_root/du-race-observed"
  "MOCK_CARGO_TARGET_DIR_FILE=$fixture_root/cargo-target-dir"
  "MOCK_SYMLINK_OUTSIDE=$fixture_root/outside-artifacts"
  "MOCK_STAGE_DEST_FILE=$fixture_root/stage-destination"
)

assert_fake_child_stopped() {
  local child_pid
  child_pid=$(<"$fixture_root/fake-sleep-pid")
  [[ "$child_pid" =~ ^[0-9]+$ ]] || {
    printf 'fake campaign recorded an invalid child PID: %s\n' "$child_pid" >&2
    exit 1
  }
  for _ in $(seq 1 100); do
    if ! kill -0 "$child_pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.02
  done
  printf 'runner leaked fake fuzz child PID: %s\n' "$child_pid" >&2
  exit 1
}

outside_artifacts="$fixture_root/outside-artifacts"
mkdir -p "$outside_artifacts"
rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts"
ln -s "$outside_artifacts" "$fixture_root/artifacts/doh_extract"
rm -f "$fixture_root/cargo-started"
if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/artifact-target-symlink.log" 2>&1; then
  printf '%s\n' 'runner followed a symlinked per-target artifact directory' >&2
  exit 1
fi
grep -Fq -- 'managed fuzz write tree contains a symlink' \
  "$fixture_root/artifact-target-symlink.log"
[[ ! -e "$fixture_root/cargo-started" ]] || {
  printf '%s\n' 'runner started cargo with a symlinked artifact target' >&2
  exit 1
}

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts/doh_extract"
ln -s "$outside_artifacts/run-summary.txt" \
  "$fixture_root/artifacts/doh_extract/run-summary.txt"
rm -f "$fixture_root/cargo-started"
if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/artifact-file-symlink.log" 2>&1; then
  printf '%s\n' 'runner followed a symlinked artifact output file' >&2
  exit 1
fi
grep -Fq -- 'managed fuzz write tree contains a symlink' \
  "$fixture_root/artifact-file-symlink.log"
[[ ! -e "$fixture_root/cargo-started" ]] || {
  printf '%s\n' 'runner started cargo with a symlinked artifact output' >&2
  exit 1
}

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts/doh_extract"
printf '%s\n' 'must remain intact' > "$outside_artifacts/hardlink-target.txt"
ln "$outside_artifacts/hardlink-target.txt" \
  "$fixture_root/artifacts/doh_extract/run-summary.txt"
rm -f "$fixture_root/cargo-started"
if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/artifact-hardlink.log" 2>&1; then
  printf '%s\n' 'runner accepted a multiply-linked artifact output file' >&2
  exit 1
fi
grep -Fq -- 'managed fuzz artifact tree contains a multiply-linked regular file' \
  "$fixture_root/artifact-hardlink.log"
grep -Fxq -- 'must remain intact' "$outside_artifacts/hardlink-target.txt"
[[ ! -e "$fixture_root/cargo-started" ]] || {
  printf '%s\n' 'runner started cargo with a multiply-linked artifact output' >&2
  exit 1
}

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts/doh_extract"
mkfifo "$fixture_root/artifacts/doh_extract/run-summary.txt"
rm -f "$fixture_root/cargo-started"
started_at=$(date +%s)
if timeout 3 env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/artifact-fifo.log" 2>&1; then
  printf '%s\n' 'runner accepted a non-regular artifact output file' >&2
  exit 1
fi
elapsed=$(( $(date +%s) - started_at ))
(( elapsed < 3 )) || {
  printf '%s\n' 'runner blocked on a pre-existing artifact FIFO' >&2
  exit 1
}
grep -Fq -- 'managed fuzz artifact tree contains a non-regular entry' \
  "$fixture_root/artifact-fifo.log"
[[ ! -e "$fixture_root/cargo-started" ]] || {
  printf '%s\n' 'runner started cargo with a non-regular artifact output' >&2
  exit 1
}

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts/doh_extract"
printf '%s\n' 'previous valid fuzz log' \
  > "$fixture_root/artifacts/doh_extract/fuzz-output.txt"
for padding_index in $(seq 1 63); do
  : > "$fixture_root/artifacts/doh_extract/padding-$padding_index"
done
rm -f "$fixture_root/cargo-started" "$fixture_root/stage-destination"
if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/log-retention-limit.log" 2>&1; then
  printf '%s\n' 'runner retained a fuzz log without transient file-budget headroom' >&2
  exit 1
fi
grep -Fq -- 'retained fuzz log would exceed artifact file budget before staging' \
  "$fixture_root/log-retention-limit.log"
grep -Fxq -- 'previous valid fuzz log' \
  "$fixture_root/artifacts/doh_extract/fuzz-output.txt"
if find "$fixture_root/artifacts" -name '.krikos-fuzz-stage.*' -print -quit | grep -q .; then
  printf '%s\n' 'rejected fuzz-log retention leaked a staging file' >&2
  exit 1
fi

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts/doh_extract"
printf '%s\n' 'previous valid summary' \
  > "$fixture_root/artifacts/doh_extract/run-summary.txt"
rm -f "$fixture_root/cargo-started" "$fixture_root/stage-destination"
if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  MOCK_ARTIFACT_NEAR_LIMIT_MODE=summary \
  MOCK_ARTIFACT_ROOT="$fixture_root/artifacts" \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/summary-retention-limit.log" 2>&1; then
  printf '%s\n' 'runner retained a summary without transient byte-budget headroom' >&2
  exit 1
fi
grep -Fq -- 'retained run summary would exceed artifact byte budget before staging' \
  "$fixture_root/summary-retention-limit.log"
grep -Fxq -- 'previous valid summary' \
  "$fixture_root/artifacts/doh_extract/run-summary.txt"
if find "$fixture_root/artifacts" -name '.krikos-fuzz-stage.*' -print -quit | grep -q .; then
  printf '%s\n' 'rejected summary retention leaked a staging file' >&2
  exit 1
fi

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts"
: > "$fixture_root/artifacts/doh_extract"
rm -f "$fixture_root/cargo-started"
if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/artifact-target-file.log" 2>&1; then
  printf '%s\n' 'runner accepted a non-directory artifact target root' >&2
  exit 1
fi
grep -Fq -- 'fuzz artifact target is not a directory' \
  "$fixture_root/artifact-target-file.log"
[[ ! -e "$fixture_root/cargo-started" ]] || {
  printf '%s\n' 'runner started cargo with a non-directory artifact target' >&2
  exit 1
}

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts"
for monitored_root in "$repo_root/fuzz/target" "$repo_root"; do
  rm -f "$fixture_root/cargo-started"
  if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
    MOCK_DF_LOW_PATH="$monitored_root" \
    "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
    >"$fixture_root/write-root-preflight.log" 2>&1; then
    printf 'runner ignored the write/build filesystem preflight: %s\n' \
      "$monitored_root" >&2
    exit 1
  fi
  grep -Fq -- 'insufficient free space for bounded fuzz run' \
    "$fixture_root/write-root-preflight.log"
  [[ ! -e "$fixture_root/cargo-started" ]] || {
    printf 'runner started cargo after write/build preflight failure: %s\n' \
      "$monitored_root" >&2
    exit 1
  }
done

rm -f "$fixture_root/cargo-started"
if env "${common_fixture_env[@]}" MOCK_DF_MODE=low \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/preflight.log" 2>&1; then
  printf '%s\n' 'runner ignored the free-space preflight' >&2
  exit 1
fi
grep -Fq -- 'insufficient free space for bounded fuzz run' "$fixture_root/preflight.log"
[[ ! -e "$fixture_root/cargo-started" ]] || {
  printf '%s\n' 'runner started cargo after free-space preflight failure' >&2
  exit 1
}

rm -f "$fixture_root/cargo-started"
if env "${common_fixture_env[@]}" MOCK_SOURCE_CORPUS_OVER_BUDGET=1 \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/source-corpus-preflight.log" 2>&1; then
  printf '%s\n' 'runner copied an oversized reviewed corpus' >&2
  exit 1
fi
grep -Fq -- \
  'mutable corpus budget exceeded before reviewed-corpus copy' \
  "$fixture_root/source-corpus-preflight.log"
[[ ! -e "$fixture_root/cargo-started" ]] || {
  printf '%s\n' 'runner started cargo after reviewed-corpus preflight failure' >&2
  exit 1
}
if find "$fixture_root/tmp" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
  printf '%s\n' 'reviewed-corpus preflight created a temporary copy' >&2
  exit 1
fi

rm -f "$fixture_root/cargo-started" "$fixture_root/runtime-over-budget" \
  "$fixture_root/runtime-path" "$fixture_root/fake-sleep-pid"
started_at=$(date +%s)
if timeout 8 env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=grow-corpus \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/watchdog.log" 2>&1; then
  printf '%s\n' 'runner ignored mutable-corpus growth during execution' >&2
  exit 1
fi
elapsed=$(( $(date +%s) - started_at ))
(( elapsed < 8 )) || {
  printf '%s\n' 'runtime budget watchdog did not terminate the fake campaign promptly' >&2
  exit 1
}
grep -Fq -- 'mutable corpus budget exceeded during execution' "$fixture_root/watchdog.log"
assert_fake_child_stopped
if find "$fixture_root/tmp" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
  printf '%s\n' 'runtime budget failure leaked its mutable corpus directory' >&2
  exit 1
fi

for monitored_root in "$repo_root/fuzz/target" "$repo_root"; do
  rm -f "$fixture_root/cargo-started" "$fixture_root/filesystem-exhausted" \
    "$fixture_root/fake-sleep-pid"
  started_at=$(date +%s)
  if timeout 8 env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=exhaust-filesystem \
    MOCK_DF_RUNTIME_LOW_PATH="$monitored_root" \
    "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
    >"$fixture_root/filesystem-watchdog.log" 2>&1; then
    printf 'runner ignored write/build filesystem exhaustion: %s\n' \
      "$monitored_root" >&2
    exit 1
  fi
  elapsed=$(( $(date +%s) - started_at ))
  (( elapsed < 8 )) || {
    printf 'write/build filesystem watchdog was not prompt: %s\n' \
      "$monitored_root" >&2
    exit 1
  }
  grep -Fq -- 'free-space headroom exhausted during execution' \
    "$fixture_root/filesystem-watchdog.log"
  assert_fake_child_stopped
  if find "$fixture_root/tmp" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
    printf 'filesystem budget failure leaked mutable corpus: %s\n' \
      "$monitored_root" >&2
    exit 1
  fi
done

rm -f "$fixture_root/cargo-started" "$fixture_root/fake-sleep-pid"
started_at=$(date +%s)
if timeout 8 env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=symlink-corpus \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/symlink-watchdog.log" 2>&1; then
  printf '%s\n' 'runner ignored a mutable-corpus symlink escape' >&2
  exit 1
fi
elapsed=$(( $(date +%s) - started_at ))
(( elapsed < 8 )) || {
  printf '%s\n' 'symlink watchdog did not terminate the fake campaign promptly' >&2
  exit 1
}
grep -Fq -- 'managed fuzz write tree contains a symlink' \
  "$fixture_root/symlink-watchdog.log"
assert_fake_child_stopped
if find "$fixture_root/tmp" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
  printf '%s\n' 'symlink budget failure leaked its mutable corpus directory' >&2
  exit 1
fi

rm -f "$fixture_root/cargo-started" "$fixture_root/runtime-over-budget" \
  "$fixture_root/runtime-path" "$fixture_root/fake-sleep-pid"
started_at=$(date +%s)
if timeout 8 env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=orphan-descendant \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/orphan-descendant.log" 2>&1; then
  printf '%s\n' 'runner accepted a live process-group descendant after campaign leader exit' >&2
  exit 1
fi
elapsed=$(( $(date +%s) - started_at ))
(( elapsed < 8 )) || {
  printf '%s\n' 'runner did not terminate an orphaned campaign descendant promptly' >&2
  exit 1
}
grep -Fq -- 'fuzz campaign left a live process-group descendant after leader exit' \
  "$fixture_root/orphan-descendant.log"
assert_fake_child_stopped
if find "$fixture_root/tmp" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
  printf '%s\n' 'orphan-descendant failure leaked its mutable corpus directory' >&2
  exit 1
fi

rm -f "$fixture_root/cargo-started" "$fixture_root/runtime-over-budget" \
  "$fixture_root/runtime-path" "$fixture_root/fake-sleep-pid"
env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=block \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/signal.log" 2>&1 &
runner_pid=$!
for _ in $(seq 1 100); do
  [[ -e "$fixture_root/cargo-started" && -e "$fixture_root/fake-sleep-pid" ]] && break
  sleep 0.02
done
[[ -e "$fixture_root/cargo-started" && -e "$fixture_root/fake-sleep-pid" ]] || {
  printf '%s\n' 'fake campaign did not start for signal cleanup test' >&2
  kill -TERM "$runner_pid" 2>/dev/null || true
  wait "$runner_pid" 2>/dev/null || true
  exit 1
}
kill -TERM "$runner_pid"
if wait "$runner_pid"; then
  printf '%s\n' 'runner reported success after SIGTERM' >&2
  exit 1
fi
assert_fake_child_stopped
if find "$fixture_root/tmp" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
  printf '%s\n' 'SIGTERM leaked the exact mutable corpus directory' >&2
  exit 1
fi

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts"
rm -f "$fixture_root/du-race-observed" "$fixture_root/cargo-started"
if ! env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  MOCK_DU_RACE_PATH="$fixture_root/artifacts" \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/du-race.log" 2>&1; then
  printf '%s\n' 'runner treated one disappearing du entry as a permanent traversal failure' >&2
  cat "$fixture_root/du-race.log" >&2
  exit 1
fi
[[ -f "$fixture_root/du-race-observed" ]] || {
  printf '%s\n' 'du race fixture did not exercise the disappearing-entry path' >&2
  exit 1
}

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts"
rm -f "$fixture_root/cargo-started" "$fixture_root/find-race-observed"
if ! env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  MOCK_FIND_RACE_PATH="$repo_root/fuzz/target" \
  MOCK_FIND_RACE_MARKER="$fixture_root/find-race-observed" \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/find-race.log" 2>&1; then
  printf '%s\n' 'runner treated a disappearing find entry as a permanent traversal failure' >&2
  cat "$fixture_root/find-race.log" >&2
  exit 1
fi
[[ -f "$fixture_root/find-race-observed" ]] || {
  printf '%s\n' 'find race fixture did not exercise the disappearing-entry path' >&2
  exit 1
}

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts"
rm -f "$fixture_root/cargo-started"
if env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  MOCK_FIND_RACE_PATH="$repo_root/fuzz/target" \
  MOCK_FIND_RACE_ALWAYS=1 \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/persistent-find-race.log" 2>&1; then
  printf '%s\n' 'runner accepted a persistently incomplete find traversal' >&2
  exit 1
fi
grep -Fq -- 'could not inspect managed fuzz tree before setup' \
  "$fixture_root/persistent-find-race.log"
if [[ -f "$fixture_root/cargo-started" ]]; then
  printf '%s\n' 'runner started cargo after persistently incomplete find traversals' >&2
  exit 1
fi

rm -rf -- "$fixture_root/artifacts"
mkdir -p "$fixture_root/artifacts"
rm -f "$fixture_root/cargo-started" "$fixture_root/runtime-over-budget" \
  "$fixture_root/runtime-path" "$fixture_root/fake-sleep-pid" \
  "$fixture_root/cargo-target-dir" "$fixture_root/stage-destination"
env "${common_fixture_env[@]}" MOCK_FUZZ_MODE=clean \
  "$runner" --seconds 1 --target doh_extract --artifacts "$fixture_root/artifacts" \
  >"$fixture_root/clean.log" 2>&1
summary="$fixture_root/artifacts/doh_extract/run-summary.txt"
grep -Fq -- 'toolchain=nightly-2026-07-19' "$summary"
grep -Fq -- 'executed_units=17' "$summary"
grep -Fq -- 'peak_rss_mb=23' "$summary"
grep -Eq -- '^wall_seconds=[0-9]+$' "$summary"
grep -Fq -- 'command=' "$summary"
grep -Fq -- 'mutable_corpus_files=' "$summary"
grep -Fq -- 'mutable_corpus_bytes=' "$summary"
grep -Fq -- 'corpus_result=within-budget' "$summary"
grep -Fq -- 'artifact_files=' "$summary"
grep -Fq -- 'artifact_bytes=' "$summary"
grep -Fq -- 'artifact_result=within-budget' "$summary"
[[ "$(<"$fixture_root/cargo-target-dir")" == "$repo_root/fuzz/target" ]] || {
  printf '%s\n' 'runner did not pin the monitored fuzz build target directory' >&2
  exit 1
}
[[ -f "$fixture_root/stage-destination" ]] || {
  printf '%s\n' 'runner did not stage retained output on the artifact filesystem' >&2
  exit 1
}
case "$(<"$fixture_root/stage-destination")" in
  "$fixture_root/artifacts/doh_extract/".krikos-fuzz-stage.*) ;;
  *)
    printf '%s\n' 'runner staged retained output outside the artifact target directory' >&2
    exit 1
    ;;
esac
if find "$fixture_root/artifacts" -name '.krikos-fuzz-stage.*' -print -quit | grep -q .; then
  printf '%s\n' 'successful retention leaked a staging file' >&2
  exit 1
fi

printf '%s\n' 'bounded fuzz tooling contract passed'
