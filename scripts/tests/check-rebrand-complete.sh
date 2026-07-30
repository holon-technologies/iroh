#!/usr/bin/env bash
# Defines "done" for the Krikos rebrand (ADR-0002 / .superpowers plan Task 1)
# as a machine-checkable property instead of a judgement call over an
# 8,000+ line diff:
#
#   1. No tracked file's path or content contains the string `iroh`, in any
#      case, unless the path is covered by an exemption in
#      scripts/rename-map.toml.
#   2. Every exemption in that map actually matches at least one tracked
#      file. An exemption matching nothing is either a typo or dead weight;
#      either way it must fail loudly rather than silently widen the hole,
#      per the same defect class that has bitten this repository's other
#      hardcoded enumerations five times before (see docs/adr/0002).
#   3. `[[packages]]` in the map is ordered longest-`old_package`-first. A
#      textual-substitution consumer (apply-rebrand.sh, Task 3) that walks
#      the list in order must rewrite `iroh-dns-server` before `iroh-dns`
#      before `iroh`, or the shorter rule fires first and corrupts the
#      longer name. This is asserted here, not left as a comment, so the
#      ordering cannot silently drift.
#
# Reads only `git ls-files` and the working-tree content of those files, so
# it depends on nothing beyond what git tracks -- no build directory, no
# cargo metadata, no network. Safe to run from a fresh clone.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

python3 - "$repo_root" <<'PY'
import sys
import tomllib
from pathlib import Path

root = Path(sys.argv[1])
map_path = root / "scripts" / "rename-map.toml"
with map_path.open("rb") as fh:
    rename_map = tomllib.load(fh)

exemptions = rename_map.get("exemptions", [])
for i, exemption in enumerate(exemptions):
    if "path" not in exemption or "reason" not in exemption:
        print(f"FAIL: exemptions[{i}] in {map_path} is missing 'path' or 'reason'", file=sys.stderr)
        sys.exit(1)

TARGET = "iroh"  # the string this checker looks for; see rename-map.toml's
                  # self-exemption for why this file is allowed to say it.

# --- Path-segment-aware glob matching --------------------------------------
# Plain `fnmatch.fnmatchcase` treats `*` as ".*" in regex terms, so it happily
# crosses `/` -- `fnmatch.fnmatchcase("vendor/x/extra/src/y.rs",
# "vendor/*/src/**")` is True, silently widening every exemption written with
# a single `*` far beyond what it reads as. Matching is done segment-by-
# segment instead: `*` (and `?`, `[...]`) match within exactly one path
# segment via `fnmatch` applied to that segment alone (so it cannot itself
# cross a `/`), and a literal `**` segment matches zero or more whole path
# segments, standard recursive-glob style.
import fnmatch as _fnmatch


def _glob_match(path_parts: list[str], pattern_parts: list[str]) -> bool:
    if not pattern_parts:
        return not path_parts
    head, rest = pattern_parts[0], pattern_parts[1:]
    if head == "**":
        if _glob_match(path_parts, rest):
            return True
        if path_parts and _glob_match(path_parts[1:], pattern_parts):
            return True
        return False
    if not path_parts:
        return False
    if not _fnmatch.fnmatchcase(path_parts[0], head):
        return False
    return _glob_match(path_parts[1:], rest)


def glob_match(path: str, pattern: str) -> bool:
    return _glob_match(path.split("/"), pattern.split("/"))


# `git ls-files -z` is the sole enumeration of "what exists": nothing on disk
# that git doesn't track (build output, an ignored scratch dir, ...) is ever
# consulted, so a clean checkout behaves identically to a dirty local tree.
import subprocess

out = subprocess.run(
    ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
).stdout
all_files = [p for p in out.decode("utf-8").split("\0") if p]

# --- packages ordering: longest old_package first, asserted not assumed ---
packages = rename_map.get("packages", [])
ordering_violations: list[str] = []
for i, earlier in enumerate(packages):
    for later in packages[i + 1 :]:
        a, b = earlier.get("old_package", ""), later.get("old_package", "")
        if a and b and a != b and b.startswith(a):
            ordering_violations.append(
                f"'{a}' (entry {i}) is a strict prefix of '{b}' (a later entry) "
                "but appears earlier in [[packages]] -- a sequential "
                "longest-first substitution must process the longer name "
                "first, or it corrupts it (e.g. iroh -> krikos applied "
                "before iroh-dns-server -> krikos-dns-server would produce "
                "krikos-dns-server only by accident)."
            )

# --- Exemption usage: does each pattern match at least one tracked file? ---
exemption_used = {e["path"]: False for e in exemptions}
for f in all_files:
    for e in exemptions:
        if glob_match(f, e["path"]):
            exemption_used[e["path"]] = True

unused = [e for e in exemptions if not exemption_used[e["path"]]]

# --- Occurrence scan ---
def is_exempt(path: str) -> bool:
    return any(glob_match(path, e["path"]) for e in exemptions)


def is_binary(data: bytes) -> bool:
    # Same heuristic git itself uses: a NUL in the first chunk means binary.
    # Binary files are skipped for content search (and never crash the
    # scan); their path is still checked.
    return b"\x00" in data[:8192]


uncovered_by_file: dict[str, list[str]] = {}
total_occurrences = 0

for rel in all_files:
    exempt = is_exempt(rel)
    entries: list[str] = []

    if TARGET in rel.lower():
        if not exempt:
            entries.append("PATH: the file path itself contains 'iroh'")

    fpath = root / rel
    try:
        data = fpath.read_bytes()
    except OSError as exc:
        # A tracked path that can't be read (broken symlink, permissions,
        # deleted-but-not-staged) is reported, not crashed on.
        entries.append(f"ERROR: could not read file: {exc}")
        if not exempt:
            uncovered_by_file.setdefault(rel, []).extend(entries)
            total_occurrences += len(entries)
        continue

    if not is_binary(data):
        text = data.decode("utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if TARGET in line.lower():
                entries.append(f"{lineno}: {line.strip()}")

    if entries and not exempt:
        uncovered_by_file.setdefault(rel, []).extend(entries)
        total_occurrences += len(entries)

# --- Report ---
status = 0

if uncovered_by_file:
    print("=== Uncovered occurrences of 'iroh' (case-insensitive) ===")
    for rel in sorted(uncovered_by_file):
        print(f"\n{rel}")
        for entry in uncovered_by_file[rel]:
            print(f"  {entry}")
    print(
        f"\nTOTAL: {total_occurrences} uncovered occurrence(s) "
        f"across {len(uncovered_by_file)} file(s)"
    )
    status = 1
else:
    print("No uncovered occurrences of 'iroh' outside exempted paths.")

if unused:
    print("\n=== Unused exemptions (match zero tracked files) ===")
    for e in unused:
        print(f"  {e['path']}  (reason given: {e['reason']})")
    print(
        f"\nFAIL: {len(unused)} exemption(s) in {map_path.relative_to(root)} "
        "match no tracked file. A stale exemption silently widens the hole "
        "this checker exists to close -- fix the glob or remove the entry."
    )
    status = 1

if ordering_violations:
    print("\n=== [[packages]] ordering violations (must be longest-old_package-first) ===")
    for v in ordering_violations:
        print(f"  {v}")
    print(
        f"\nFAIL: {len(ordering_violations)} ordering violation(s) in "
        f"{map_path.relative_to(root)}. Reorder [[packages]] so no "
        "old_package is a strict prefix of a later entry's old_package."
    )
    status = 1

sys.exit(status)
PY
