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
#
# Reads only `git ls-files` and the working-tree content of those files, so
# it depends on nothing beyond what git tracks -- no build directory, no
# cargo metadata, no network. Safe to run from a fresh clone.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

python3 - "$repo_root" <<'PY'
import fnmatch
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

# `git ls-files -z` is the sole enumeration of "what exists": nothing on disk
# that git doesn't track (build output, an ignored scratch dir, ...) is ever
# consulted, so a clean checkout behaves identically to a dirty local tree.
import subprocess

out = subprocess.run(
    ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
).stdout
all_files = [p for p in out.decode("utf-8").split("\0") if p]

# --- Exemption usage: does each pattern match at least one tracked file? ---
exemption_used = {e["path"]: False for e in exemptions}
for f in all_files:
    for e in exemptions:
        if fnmatch.fnmatchcase(f, e["path"]):
            exemption_used[e["path"]] = True

unused = [e for e in exemptions if not exemption_used[e["path"]]]

# --- Occurrence scan ---
def is_exempt(path: str) -> bool:
    return any(fnmatch.fnmatchcase(path, e["path"]) for e in exemptions)


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

sys.exit(status)
PY
