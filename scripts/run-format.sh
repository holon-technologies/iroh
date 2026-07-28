#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
check=()

if (($# > 1)); then
  echo "usage: $0 [--check]" >&2
  exit 2
fi
if (($# == 1)); then
  if [[ "$1" != "--check" ]]; then
    echo "usage: $0 [--check]" >&2
    exit 2
  fi
  check=(--check)
fi

format_config=(
  --config "unstable_features=true"
  --config "imports_granularity=Crate,group_imports=StdExternalCrate,reorder_imports=true,format_code_in_doc_comments=true"
)

cd "$repo_root"
cargo fmt --all "${check[@]}" -- "${format_config[@]}"
cargo fmt --manifest-path iroh-sim/Cargo.toml --all "${check[@]}" -- "${format_config[@]}"
cargo fmt --manifest-path fuzz/Cargo.toml --all "${check[@]}" -- "${format_config[@]}"
