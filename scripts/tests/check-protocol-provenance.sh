#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

args=(
  --policy "$repo_root/protocols/upstream-baselines.toml"
  --repo-root "$repo_root"
)
if [[ "${1:-}" == "--remote" ]]; then
  args+=(--remote)
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--remote]" >&2
  exit 2
fi

python3 "$repo_root/scripts/check_protocol_provenance.py" "${args[@]}"
