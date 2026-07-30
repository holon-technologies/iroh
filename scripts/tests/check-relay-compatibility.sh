#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mode=${1:---golden}
baseline_commit=f2eb930dda3779c6d852b72f3712aacd6e573ab1
fixture="$repo_root/krikos-relay/tests/fixtures/compat/v1.0.3/wire.txt"
contract="$repo_root/docs/relay-compatibility.md"

case "$mode" in
  --golden|--live) ;;
  *)
    echo "usage: scripts/tests/check-relay-compatibility.sh [--golden|--live]" >&2
    exit 2
    ;;
esac

require_text() {
  local path=$1
  local expected=$2
  if ! grep -Fq -- "$expected" "$path"; then
    echo "relay compatibility contract missing '$expected' in ${path#"$repo_root/"}" >&2
    exit 1
  fi
}

for path in \
  "$contract" \
  "$fixture" \
  "$repo_root/krikos-relay/tests/wire_compat.rs" \
  "$repo_root/compat/relay-v1-interop/Cargo.toml" \
  "$repo_root/compat/relay-v1-interop/Cargo.lock"; do
  if [[ ! -f "$path" ]]; then
    echo "relay compatibility artifact missing: ${path#"$repo_root/"}" >&2
    exit 1
  fi
done

require_text "$contract" "$baseline_commit"
require_text "$contract" 'krikos-relay-v1'
require_text "$contract" 'krikos-relay-v2'
require_text "$contract" 'x-krikos-relay-client-auth-v1'
require_text "$contract" 'iroh-relay handshake v1 challenge signature'
require_text "$contract" '64 KiB'
require_text "$contract" '1 MiB'
require_text "$repo_root/compat/relay-v1-interop/Cargo.toml" "rev = \"$baseline_commit\""

if grep -Eq '^[a-z0-9_.]+=$' "$fixture"; then
  echo "relay compatibility fixture contains an empty value" >&2
  exit 1
fi
fixture_count=$(grep -Ec '^[a-z0-9_.]+=[0-9a-f]+$' "$fixture")
if ((fixture_count != 17)); then
  echo "relay compatibility fixture must contain exactly 17 entries (found $fixture_count)" >&2
  exit 1
fi

require_text "$repo_root/krikos-relay/src/http.rs" 'pub const RELAY_PATH: &str = "/relay";'
require_text "$repo_root/krikos-relay/src/http.rs" 'pub const RELAY_PROBE_PATH: &str = "/ping";'
require_text "$repo_root/krikos-relay/src/http.rs" '"x-krikos-relay-client-auth-v1"'
require_text "$repo_root/krikos-relay/src/protos/handshake.rs" \
  '"iroh-relay handshake v1 challenge signature"'
require_text "$repo_root/krikos-relay/src/protos/handshake.rs" \
  'b"iroh-relay handshake v1"'
require_text "$repo_root/krikos-relay/src/protos/relay.rs" \
  'pub const MAX_PACKET_SIZE: usize = 64 * 1024;'
require_text "$repo_root/krikos-relay/src/protos/relay.rs" \
  'pub(crate) const MAX_FRAME_SIZE: usize = 1024 * 1024;'

(
  cd "$repo_root"
  cargo test -p krikos-relay --test wire_compat
  cargo test -p krikos-relay --features server-ring,test-utils frames_match_v1_0_3_fixtures
  cargo test -p krikos-relay --features server-ring,test-utils frames_snapshot
)

if [[ "$mode" == "--live" ]]; then
  (
    cd "$repo_root"
    cargo run --locked --manifest-path compat/relay-v1-interop/Cargo.toml
  )
fi

echo "relay compatibility $mode checks passed against upstream v1.0.3 ($baseline_commit)"
