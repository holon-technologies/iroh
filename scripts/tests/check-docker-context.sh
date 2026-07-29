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

# This daemon (legacy builder, no buildx/BuildKit plugin installed) reports:
# "Sending build context to Docker daemon  4.314MB" using go-units decimal
# suffixes (B, kB, MB, GB, ...). Match case-insensitively and take the last
# occurrence in case earlier build steps echo something similar.
line=$(grep -m1 -oE 'Sending build context to Docker daemon[[:space:]]+[0-9.]+[A-Za-z]+' <<<"$out" | tail -1)
[[ -n "$line" ]] || { echo "FAIL: could not parse context size" >&2; exit 1; }

raw=$(sed -E 's/.*Docker daemon[[:space:]]+([0-9.]+[A-Za-z]+)/\1/' <<<"$line")
value=$(sed -E 's/^([0-9.]+).*/\1/' <<<"$raw")
unit=$(sed -E 's/^[0-9.]+//' <<<"$raw")

case "${unit,,}" in
  b)  mb=0 ;;
  kb) mb=$(awk -v v="$value" 'BEGIN{printf "%d", v/1024}') ;;
  mb) mb=$(awk -v v="$value" 'BEGIN{printf "%d", v}') ;;
  gb) mb=$(awk -v v="$value" 'BEGIN{printf "%d", v*1024}') ;;
  *)  echo "FAIL: unknown unit $unit" >&2; exit 1 ;;
esac

echo "docker build context: ${mb} MB (limit ${limit_mb} MB)"
if (( mb > limit_mb )); then
  echo "FAIL: build context exceeds ${limit_mb} MB" >&2
  exit 1
fi
