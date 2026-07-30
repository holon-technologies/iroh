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

# Context size is a property of .dockerignore plus the working tree, not of
# any particular build stage -- it does not require building
# docker/Dockerfile at all. Measure it with a throwaway, single-stage
# Dockerfile instead of `docker/Dockerfile`'s real `planner` target: `FROM
# scratch` has no base image to pull, and the lone `COPY . .` is the very
# first (and only) instruction, so the context is transferred immediately
# with nothing to build first.
#
# This matters because `docker/Dockerfile`'s `planner` target sits behind a
# `chef` base stage (image pull, `apk add`, `cargo install cargo-chef`
# compiled from source). Under BuildKit -- the default builder on GitHub's
# `ubuntu-latest` runners -- context is loaded lazily, only when a COPY/ADD
# instruction actually needs it, so that base-stage work runs *before*
# context transfer is even reported; a `head`-based short-circuit on the
# real Dockerfile can't skip it. The throwaway Dockerfile has no base stage
# to build first, so it is fast under any builder by construction, not by
# relying on early-pipe-close timing.
#
# Generated in the system temp dir (never under $repo_root), so it can
# never be swept into the very build context it's used to measure, and
# removed on exit regardless of outcome.
probe_dockerfile=$(mktemp)
trap 'rm -f "$probe_dockerfile"' EXIT
printf 'FROM scratch\nCOPY . .\n' > "$probe_dockerfile"

# `head` intentionally closes the pipe once it has enough lines, well before
# the context-transfer progress output (particularly BuildKit's, which
# prints one line per progress update) finishes -- the final/largest size is
# still among the first lines since this Dockerfile has nothing else to do.
# That early close sends docker a SIGPIPE; disable pipefail for this one
# command so its 141 exit doesn't trip `set -e` on an outcome we intend.
set +o pipefail
out=$(docker build --no-cache -f "$probe_dockerfile" . 2>&1 | head -20)
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
