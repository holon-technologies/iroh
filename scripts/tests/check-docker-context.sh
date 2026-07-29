#!/usr/bin/env bash
# Asserts the Docker build context stays bounded.
#
# .dockerignore is a deny-all-then-allowlist. If a new workspace member or a
# new [patch.crates-io] vendor is added without a matching `!` entry, the
# image build fails loudly with a missing manifest. If the allowlist is
# widened carelessly, this test fails instead.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

limit_mb="${DOCKER_CONTEXT_LIMIT_MB:-200}"

# `head` intentionally closes the pipe once it has enough lines, well before
# the (slow, --no-cache) planner build finishes -- the context size is
# reported before any build step runs. That early close sends docker a
# SIGPIPE; disable pipefail for this one command so its 141 exit doesn't
# trip `set -e` on an outcome we intend.
set +o pipefail
out=$(docker build --no-cache --target planner -f docker/Dockerfile . 2>&1 | head -20)
set -o pipefail
echo "$out"

# Two builders report context size in two different formats, both using
# go-units decimal suffixes (B, kB, MB, GB, ...):
#   - legacy builder:  "Sending build context to Docker daemon  4.314MB"
#   - BuildKit:         "transferring context: 45.31MB" (printed once per
#                        progress update, so the size grows across repeated
#                        lines until the transfer finishes)
# Match case-insensitively and take the LAST match of either form: for
# BuildKit that's the final (largest) progress line; for the legacy builder
# there is only ever one match, so this is a no-op there.
matches=$(grep -oE 'Sending build context to Docker daemon[[:space:]]+[0-9.]+[A-Za-z]+|[Tt]ransferring context:[[:space:]]+[0-9.]+[A-Za-z]+' <<<"$out")
line=$(tail -n1 <<<"$matches")
[[ -n "$line" ]] || { echo "FAIL: could not parse context size" >&2; exit 1; }

raw=$(grep -oE '[0-9.]+[A-Za-z]+$' <<<"$line")
value=$(sed -E 's/^([0-9.]+).*/\1/' <<<"$raw")
unit=$(sed -E 's/^[0-9.]+//' <<<"$raw")

# Round up (ceiling), not truncate: a 200.5MB context must fail a 200MB
# limit, not silently pass because `int()` truncated it down to 200.
case "${unit,,}" in
  b)  mb=0 ;;
  kb) mb=$(awk -v v="$value" 'BEGIN{r=v/1024; i=int(r); if (r>i) i++; printf "%d", i}') ;;
  mb) mb=$(awk -v v="$value" 'BEGIN{r=v; i=int(r); if (r>i) i++; printf "%d", i}') ;;
  gb) mb=$(awk -v v="$value" 'BEGIN{r=v*1024; i=int(r); if (r>i) i++; printf "%d", i}') ;;
  *)  echo "FAIL: unknown unit $unit" >&2; exit 1 ;;
esac

echo "docker build context: ${mb} MB (limit ${limit_mb} MB)"
if (( mb > limit_mb )); then
  echo "FAIL: build context exceeds ${limit_mb} MB" >&2
  exit 1
fi
