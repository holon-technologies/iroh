#!/usr/bin/env bash
# Asserts the Docker build context is both COMPLETE and BOUNDED.
#
# .dockerignore is a deny-all-then-allowlist. A missing `!` entry does NOT
# make the build fail loudly: it makes the context SMALLER, so the size
# check below would pass while a later `COPY` in the actual image build
# silently fails to find its files (or worse, cargo-chef silently builds a
# stale dependency graph missing a workspace member). This exact
# false-pass already hid six workspace members added by an upstream merge,
# and separately hid a missing `!bins/` entry. Guard against both
# directions:
#   1. Completeness: every top-level path the workspace build actually
#      needs has a matching allowlist entry, derived from the sources of
#      truth themselves so this can't silently drift out of date again.
#   2. Size: the allowlist doesn't get widened carelessly.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

dockerignore="$repo_root/.dockerignore"

# --- Completeness --------------------------------------------------------
#
# Required top-level context entries come from three sources of truth:
#   - cargo metadata: the top-level directory each workspace member lives
#     under (catches new/moved workspace members).
#   - the root Cargo.toml [patch.crates-io] table: the local path of each
#     patched crate (catches new/moved vendor patches).
#   - docker/Dockerfile and docker/Dockerfile.ci: every literal COPY
#     source that reads from the build context (catches new COPY
#     instructions like the release-binary staging directory). `COPY . .`
#     is skipped (it means "the whole context", not a specific entry) and
#     so is any `--from=<stage>` copy (it reads another build stage, not
#     the context).
#
# Cargo.toml and Cargo.lock are derived from cargo metadata's
# workspace_root. `.cargo/` is a fixed structural requirement (cargo
# config, e.g. registry/patch settings) not expressed anywhere in
# metadata, the patch table, or a COPY instruction, so it is asserted
# directly rather than derived.
required_entries=$(python3 - "$repo_root" <<'PYEOF'
import json, re, subprocess, sys, tomllib
from pathlib import Path

repo_root = Path(sys.argv[1])
required = set()

metadata = json.loads(subprocess.run(
    ["cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"],
    cwd=repo_root, capture_output=True, check=True, text=True,
).stdout)
workspace_root = Path(metadata["workspace_root"])

required.add(("file", "Cargo.toml"))
required.add(("file", "Cargo.lock"))
for pkg in metadata["packages"]:
    manifest = Path(pkg["manifest_path"])
    rel = manifest.parent.relative_to(workspace_root)
    required.add(("dir", rel.parts[0]))

cargo_toml = tomllib.loads((repo_root / "Cargo.toml").read_text())
for spec in cargo_toml.get("patch", {}).get("crates-io", {}).values():
    path = spec.get("path")
    if path:
        required.add(("dir", path.rstrip("/")))

copy_re = re.compile(r'^\s*COPY\s+(.*)$', re.IGNORECASE)
for dockerfile in ("docker/Dockerfile", "docker/Dockerfile.ci"):
    for line in (repo_root / dockerfile).read_text().splitlines():
        m = copy_re.match(line)
        if not m:
            continue
        args = m.group(1).split()
        if not args or args[0].startswith("--from="):
            continue
        src = args[0]
        if src in (".", "./"):
            continue
        top = src.split("/", 1)[0]
        kind = "file" if "." in top else "dir"
        required.add((kind, top))

for kind, name in sorted(required):
    print(f"{kind} {name}")
PYEOF
)

# Fixed structural requirement -- see comment above.
required_entries="${required_entries}
dir .cargo"

# --- Floor -----------------------------------------------------------------
#
# The completeness check below only proves the allowlist is a superset of
# whatever `required_entries` says. An empty (or near-empty) derivation
# would make that vacuously true -- "nothing required" reads as "everything
# satisfied" -- and the loop below would print an "ok" with a suspiciously
# small denominator instead of failing loudly. Guard against the derivation
# itself silently collapsing (a python exception swallowed by a bad
# heredoc, a renamed `cargo metadata` key, an accidentally-emptied `for`
# loop) by asserting the derived set is non-empty and at least as large as
# a floor computed independently: the number of workspace member packages
# `cargo metadata` reports directly, via its own separate invocation, not
# reused from the `required_entries` derivation above. `required_entries`
# is always a strict superset of the raw member count (it also carries
# Cargo.toml/Cargo.lock, patch paths, and Dockerfile COPY sources, and it
# de-duplicates members that share a top-level directory), so this bound
# holds today and remains meaningful if the workspace grows.
workspace_member_count=$(cargo metadata --no-deps --locked --format-version 1 \
  | python3 -c 'import json, sys; print(len(json.load(sys.stdin)["packages"]))')

if (( workspace_member_count <= 0 )); then
  echo "FAIL: cargo metadata reported $workspace_member_count workspace member(s); the floor itself is broken" >&2
  exit 1
fi

required_entry_count=$(grep -c . <<<"$required_entries")
if (( required_entry_count == 0 )); then
  echo "FAIL: derived allowlist requirement set is EMPTY -- this would make the completeness" >&2
  echo "  check below pass vacuously ('nothing required' read as 'everything satisfied')." >&2
  echo "  Something upstream of this point (cargo metadata, the [patch.crates-io] table," >&2
  echo "  or the Dockerfile COPY scan) broke silently. Fix the derivation." >&2
  exit 1
fi
if (( required_entry_count < workspace_member_count )); then
  echo "FAIL: derived allowlist requirement set has only $required_entry_count entries," >&2
  echo "  which is fewer than the $workspace_member_count workspace members cargo metadata" >&2
  echo "  reports independently. The derivation is under-counting; fix it before trusting" >&2
  echo "  the completeness check below." >&2
  exit 1
fi
echo "ok: derived requirement set has $required_entry_count entries, at or above the" \
     "$workspace_member_count-workspace-member floor"

missing=()
total=0
while read -r kind name; do
  [[ -n "$kind" ]] || continue
  total=$((total + 1))
  if [[ "$kind" == "dir" ]]; then
    pattern="^!${name}/?\$"
  else
    pattern="^!${name}\$"
  fi
  if ! grep -Eq "$pattern" "$dockerignore"; then
    missing+=("$name")
  fi
done <<<"$required_entries"

if ((${#missing[@]} > 0)); then
  echo "FAIL: .dockerignore is missing an allowlist entry for: ${missing[*]}" >&2
  echo "  Each of these is required by cargo metadata workspace members," >&2
  echo "  the [patch.crates-io] table in Cargo.toml, or a COPY instruction" >&2
  echo "  in docker/Dockerfile or docker/Dockerfile.ci. Add a matching" >&2
  echo "  '!<name>/' (or '!<name>' for a file) line to .dockerignore." >&2
  exit 1
fi

echo "ok: .dockerignore allowlist covers all $total required context entries"

# --- Size ------------------------------------------------------------------
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
