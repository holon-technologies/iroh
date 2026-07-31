#!/usr/bin/env bash
# Asserts that every `cargo chef cook` in docker/Dockerfile can actually
# resolve its dependency graph: every [patch.crates-io] path target in the
# root Cargo.toml must already be present -- via a context COPY or a
# `COPY --from=<earlier stage>` -- in the *same build stage*, before the
# `cargo chef cook` line runs in it.
#
# This is the exact defect class that let docker/Dockerfile go unbuilt and
# broken for its entire history: cargo-chef's recipe.json only embeds
# manifests for workspace *members* (see `cargo chef prepare`'s output).
# Path-patched crates that are deliberately excluded from the workspace
# (vendored forks, pulled in only via [patch.crates-io]) never make it into
# the recipe, so cargo reads their Cargo.toml directly off disk during
# dependency resolution at `cook` time -- and fails with an opaque
# "unable to update <path>" / "No such file or directory" if that path
# was never copied into the stage.
#
# Nothing in CI ever built docker/Dockerfile (docker.yaml builds
# Dockerfile.ci, which stages prebuilt binaries and never touches cargo
# chef), which is how a Dockerfile broken at the very first `docker build`
# went unnoticed. A full `docker build` of this file is a from-scratch
# release compile of the whole workspace and is too expensive to run on
# every PR (tens of minutes, much of it re-doing what cross_build /
# tests.yaml already compile) -- see the Commit 2 report for a measured
# wall-clock figure. This check is the cheap substitute: it costs a single
# TOML parse and a Dockerfile scan, runs in well under a second, and would
# have caught this exact defect on day one without compiling a single
# crate.
#
# It does NOT catch every possible way a Dockerfile can fail to build (that
# would require actually building it) -- only this specific, previously-real
# class: a `cook` step starved of a path dependency's manifest.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

dockerfile="docker/Dockerfile"

if output=$(python3 - "$repo_root" "$dockerfile" <<'PYEOF'
import re
import sys
import tomllib
from pathlib import Path

repo_root = Path(sys.argv[1])
dockerfile_rel = sys.argv[2]
dockerfile = repo_root / dockerfile_rel

cargo_toml = tomllib.loads((repo_root / "Cargo.toml").read_text())
patch_paths = sorted(
    spec["path"].rstrip("/")
    for spec in cargo_toml.get("patch", {}).get("crates-io", {}).values()
    if spec.get("path")
)

if not patch_paths:
    # No path patches at all -- nothing for this check to guard. Don't
    # fail vacuously-passed either; say so explicitly.
    print("OK\nno [patch.crates-io] path targets in root Cargo.toml -- nothing to check")
    sys.exit(0)

from_re = re.compile(r'^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$', re.IGNORECASE)
copy_re = re.compile(r'^\s*COPY\s+(.*)$', re.IGNORECASE)
cook_re = re.compile(r'^\s*RUN\s+.*\bcargo\s+chef\s+cook\b', re.IGNORECASE)

def covers(known, full_context, path):
    if full_context:
        return True
    for k in known:
        if path == k or path.startswith(k + "/"):
            return True
    return False

# stage name -> {"known": set[str], "full_context": bool}
stages = {}
current = None  # name of the stage currently being scanned
failures = []
cook_lines_seen = 0

for lineno, raw in enumerate(dockerfile.read_text().splitlines(), start=1):
    line = raw.split("#", 1)[0]
    if not line.strip():
        continue

    m = from_re.match(line)
    if m:
        base, name = m.group(1), m.group(2)
        base_state = stages.get(base, {"known": set(), "full_context": False})
        state = {"known": set(base_state["known"]), "full_context": base_state["full_context"]}
        current = name or base
        stages[current] = state
        continue

    if current is None:
        continue
    state = stages[current]

    m = copy_re.match(line)
    if m:
        args = m.group(1).split()
        if args and args[0].startswith("--from="):
            args = args[1:]
        # What matters for `cargo chef cook` (which resolves patch paths
        # relative to WORKDIR inside the container) is where COPY *lands*,
        # not where it read from -- track the destination, not the
        # source(s). With >2 args the last is always the destination
        # directory (COPY's multi-source form); with exactly 2 args it's a
        # src->dst rename/copy, and the same rule (last token) still picks
        # the destination.
        if len(args) >= 2:
            dst = args[-1]
            src0 = args[0]
            if src0 in (".", "./") and dst in (".", "./"):
                state["full_context"] = True
            else:
                state["known"].add(dst.rstrip("/"))
        continue

    if cook_re.match(line):
        cook_lines_seen += 1
        for p in patch_paths:
            if not covers(state["known"], state["full_context"], p):
                failures.append(
                    f"{dockerfile_rel}:{lineno}: stage '{current}' runs `cargo chef cook` "
                    f"without '{p}' (a [patch.crates-io] path target) present in this stage "
                    f"-- add a COPY for it before this line"
                )

# A Dockerfile with no `cargo chef cook` at all would otherwise make every
# loop above a no-op and fall through to the "OK" print below having
# checked nothing -- reporting success over an empty set. That's exactly
# the anti-pattern this whole check exists to catch one level up: deleting
# the cook step "fixes" a broken cook by discarding cargo-chef's caching
# entirely (see the Commit 2 report, 2.2). This is a *different* case from
# `not patch_paths` above (a legitimate "nothing to guard" when there are
# no path patches to worry about) -- here patch_paths is non-empty, so the
# absence of any cook line is itself the defect, not a reason to pass.
if cook_lines_seen == 0:
    print("FAIL")
    print(
        f"{dockerfile_rel}: no `cargo chef cook` line found anywhere in the file, but "
        f"root Cargo.toml has {len(patch_paths)} [patch.crates-io] path target(s) "
        f"({', '.join(patch_paths)}). cargo-chef's whole purpose is a cached dependency-only "
        f"build via `cargo chef cook`; a Dockerfile using cargo-chef's `prepare`/recipe.json "
        f"flow without a `cook` step has discarded the caching this file exists for -- that "
        f"is not a fix, it's the defect this check is guarding against. Restore a "
        f"`RUN cargo chef cook ...` step (with the patch paths COPY'd in before it)."
    )
    sys.exit(1)

if failures:
    print("FAIL")
    for f in failures:
        print(f)
    sys.exit(1)

print("OK")
print(f"every 'cargo chef cook' in {dockerfile_rel} has all {len(patch_paths)} "
      f"[patch.crates-io] path target(s) present in its stage: {', '.join(patch_paths)}")
PYEOF
); then
  echo "$output" | tail -n +2
else
  status=$?
  echo "$output" | tail -n +2 >&2
  exit "$status"
fi
