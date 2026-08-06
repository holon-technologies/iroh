#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain="${KRIKOS_IDENTITY_TOOLCHAIN:-1.91.0}"
generated_root="$(mktemp -d)"
generated_vectors="$generated_root/vectors"
generated_provider_corpus="$generated_root/provider-corpus"
generated_sync_corpus="$generated_root/sync-corpus"
trap 'rm -rf "$generated_root"' EXIT

cargo "+$toolchain" run \
  --quiet \
  --locked \
  --manifest-path "$repo_root/Cargo.toml" \
  -p krikos-identity \
  --features net \
  --example generate_interop_vectors \
  -- "$generated_vectors"

diff --recursive --brief \
  "$repo_root/protocols/krikos-identity/tests/vectors" \
  "$generated_vectors"

python3 "$repo_root/scripts/generate-identity-provider-fuzz-corpus.py" \
  "$generated_vectors" \
  "$generated_provider_corpus"

for generated_seed in "$generated_provider_corpus"/*.bin; do
  cmp \
    "$repo_root/fuzz/corpus/identity_provider/$(basename "$generated_seed")" \
    "$generated_seed"
done

python3 "$repo_root/scripts/generate-identity-sync-fuzz-corpus.py" \
  "$generated_vectors" \
  "$generated_sync_corpus"

for generated_seed in "$generated_sync_corpus"/*.bin; do
  cmp \
    "$repo_root/fuzz/corpus/identity_sync/$(basename "$generated_seed")" \
    "$generated_seed"
done

cargo "+$toolchain" test \
  --quiet \
  --locked \
  --manifest-path "$repo_root/Cargo.toml" \
  -p krikos-identity \
  --no-default-features \
  --features net \
  --test interop_vectors \
  --test network_fuzz_corpus \
  --test provider_fuzz_corpus

printf '%s\n' 'identity interoperability vectors are deterministic and self-validating'
