#!/usr/bin/env bash
# Asserts each vendored tree equals its crates.io package plus the checked-in
# patch. This makes the IROH-VENDOR.md provenance claim machine-checked rather
# than merely asserted.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

status=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

check() {
  local name=$1 ver=$2 normalize=$3
  local dir="vendor/$name-$ver" patch="vendor/$name-$ver.patch"

  echo "--- $name $ver"
  curl -sL "https://static.crates.io/crates/$name/$name-$ver.crate" -o "$work/$name.crate"
  tar xzf "$work/$name.crate" -C "$work"
  local pristine="$work/$name-$ver"

  if [[ "$normalize" == "normalize" ]]; then
    # Sequential on purpose: rustfmt follows `mod` declarations and reformats
    # declared submodules as a side effect of formatting their parent, even
    # when invoked on a single file. Running this with `xargs -P` lets a
    # direct per-file invocation race that side effect on the same file,
    # occasionally truncating it. One file per invocation, one invocation at
    # a time, avoids the race.
    find "$pristine" -name '*.rs' -type f -print0 \
      | xargs -0 -n 1 rustfmt --edition 2021
  fi

  if [[ -s "$patch" ]]; then
    git apply --directory="$pristine" --unsafe-paths "$patch" \
      || { echo "FAIL: $name patch does not apply cleanly" >&2; status=1; return; }
  fi

  if diff -ru "$pristine" "$dir" -x target -x .cargo-ok -x IROH-VENDOR.md >/dev/null; then
    echo "ok: $dir matches upstream + patch"
  else
    echo "FAIL: $dir differs from upstream + patch" >&2
    # `|| true` guards against SIGPIPE: under `pipefail`, `head` closing its
    # input early once satisfied would otherwise propagate a 141 exit and
    # abort the whole script via `set -e`, skipping the remaining checks.
    { diff -ru "$pristine" "$dir" -x target -x .cargo-ok -x IROH-VENDOR.md | head -40 >&2; } || true
    status=1
  fi
}

check rustls         0.23.41 normalize
check noq            1.1.0   raw
check hickory-server 0.26.1  raw

exit $status
