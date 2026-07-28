#!/usr/bin/env bash

set -euo pipefail

if (($# != 3)); then
  printf 'usage: %s (legacy-inventory|post-cut) PACKAGE STATUS\n' "$0" >&2
  exit 2
fi

mode=$1
package=$2
status=$3
if [[ ! "$status" =~ ^[0-9]+$ ]]; then
  printf 'invalid cargo-semver-checks status for %s: %s\n' "$package" "$status" >&2
  exit 2
fi

case "$mode" in
  legacy-inventory)
    # 100 is cargo-semver-checks' documented incompatibility result. The exact findings are checked
    # against the reviewed migration inventory after all packages have run.
    if ((status == 0 || status == 100)); then
      exit 0
    fi
    ;;
  post-cut)
    if ((status == 0)); then
      exit 0
    fi
    ;;
  *)
    printf 'unknown semver policy mode: %s\n' "$mode" >&2
    exit 2
    ;;
esac

printf 'cargo-semver-checks failed policy mode %s for %s with status %s\n' \
  "$mode" "$package" "$status" >&2
exit 1
