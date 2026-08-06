#!/usr/bin/env bash
# Catches falsified upstream/crate references that scripts/tests/check-rebrand-complete.sh
# is structurally blind to.
#
# That checker only asks "does this file still say `iroh`?" -- it cannot tell a genuine
# upstream fact ("adapted from `iroh-util`") from a false one ("adapted from `krikos-util`"),
# because both are equally free of the string `iroh`. Three review rounds on the Krikos
# rebrand each found instances the previous round missed this way: a mechanical
# `iroh`->`krikos` sweep had rewritten quoted crate names inside prose/doc-comments into
# names that read as this fork's own packages but correspond to nothing real --
# `krikos-net`, `krikos-util`, `krikos-tor`, `krikos-net-report`, `krikos-willow`.
#
# This check is the general form of that hunt, run once instead of by inspection each time:
#
#   1. Collect every real package name in this repository -- every `[package]` `name =`
#      in every tracked Cargo.toml, including vendor/ and compat/ -- so the reference set is
#      derived, not hand-maintained. A hardcoded package list would itself be exactly the
#      kind of stale enumeration this repository has been bitten by before (see docs/adr/0002).
#   2. Scan every tracked `.md`/`.rs` file (outside fenced ``` code blocks, which are runnable
#      examples/output, not name claims) for a `krikos`-prefixed token written the way a real
#      crate name is written in prose: inside inline backticks (`` `krikos-x` ``), as the
#      root of a `::`/`/`-qualified backtick path (`` `krikos_x::Foo` ``, `` `krikos-x/feat` ``),
#      or as a markdown reference-link label (`[krikos-x]`).
#   3. Flag every such token whose `-`/`_`-normalized form is not a real package name and not
#      in the short, explicit, commented allowlist below.
#
# Deliberately narrower than a blind grep for `krikos-[a-z-]+`: CI concurrency-group names,
# artifact names, `/tmp/krikos-sim-*` example paths, cfg flags used as plain identifiers, and
# shell/Rust variable names are this fork's own invented naming, not a claim that a crate by
# that name exists, and flagging all of them would bury the real signal under ~70 lines of
# noise per run (measured during development of this check). Backtick/bracket-in-prose is
# exactly the syntactic shape every confirmed false positive above actually had.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

python3 - "$repo_root" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])

# --- Step 1: the real package set, derived from every tracked Cargo.toml --------------
out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True)
all_files = [p for p in out.stdout.decode("utf-8").split("\0") if p]

NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"', re.MULTILINE)
HEADER_RE = re.compile(r"^\s*\[+([^\[\]]+)\]+\s*$", re.MULTILINE)

real_packages = set()
for rel in all_files:
    if not rel.endswith("Cargo.toml"):
        continue
    text = (root / rel).read_text(encoding="utf-8", errors="replace")
    # Only the [package] table's name, not [dependencies]/[workspace.dependencies] entries
    # (which are OTHER crates' names, not this repository's own packages).
    in_package = False
    for line in text.splitlines():
        h = HEADER_RE.match(line)
        if h:
            in_package = h.group(1).strip() == "package"
            continue
        if in_package:
            m = NAME_RE.match(line)
            if m:
                real_packages.add(m.group(1))
                in_package = False

real_packages_norm = {p.replace("_", "-") for p in real_packages}

# --- Known non-package `krikos`-prefixed identifiers, referenced in backticks/brackets  ---
# for a real reason that isn't "this names a crate". Each entry is independently justified;
# an unjustified addition here defeats the check the same way an unjustified path/pattern
# exemption would defeat check-rebrand-complete.sh.
ALLOWLIST = {
    "krikos_docsrs": "this fork's own rustdoc-only cfg flag (Cargo.toml's [lints], .github/workflows/docs.yaml), not a crate",
    "krikos_blobs_docsrs": "krikos-blobs' own per-crate variant of the krikos_docsrs cfg flag above, not a crate",
    "krikos_loom": "this fork's own tokio-rs/loom-testing cfg flag (Cargo.toml's [lints]), not a crate",
    "krikos_ref": "a GitHub Actions workflow input/env name (the netsim runner's pinned ref), not a crate",
    "krikos-provider-generation-v1": "the redb provider-generation table family name, not a crate",
    "krikos-provider-prepared-v1": "the redb provider prepared-append table family name, not a crate",
    "krikos-provider-audit-metadata-v2": "the redb provider-audit metadata table name, not a crate",
    "krikos-provider-audit-records-v2": "the redb provider-audit record table name, not a crate",
    "krikos-provider-audit-v1": "the explicitly rejected legacy redb provider-audit table name, not a crate",
}

# --- Step 2/3: scan tracked .md/.rs files for backtick/bracket-quoted krikos tokens -------
TOKEN = r"krikos[-_][a-z0-9_-]+"
BACKTICK_RE = re.compile(r"`(" + TOKEN + r")`")
BACKTICK_PREFIX_RE = re.compile(r"`(" + TOKEN.rstrip("+") + r"*?)(?:::|/)")
BRACKET_RE = re.compile(r"\[(" + TOKEN + r")\]")
FENCE_RE = re.compile(r"^\s*(```|~~~)")

findings = {}
for rel in all_files:
    if not (rel.endswith(".md") or rel.endswith(".rs")):
        continue
    text = (root / rel).read_text(encoding="utf-8", errors="replace")
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        toks = set()
        for pat in (BACKTICK_RE, BACKTICK_PREFIX_RE, BRACKET_RE):
            for m in pat.finditer(line):
                tok = m.group(1)
                if re.fullmatch(TOKEN, tok):
                    toks.add(tok)
        for tok in toks:
            if tok.replace("_", "-") in real_packages_norm:
                continue
            if tok in ALLOWLIST:
                continue
            findings.setdefault(tok, []).append((rel, lineno, line.strip()))

if findings:
    print("=== krikos-prefixed tokens with no corresponding package (and no allowlist entry) ===")
    for tok in sorted(findings):
        print(f"\n`{tok}`:")
        for rel, lineno, line in findings[tok]:
            print(f"  {rel}:{lineno}: {line}")
    total = sum(len(v) for v in findings.values())
    print(
        f"\nFAIL: {len(findings)} unknown token(s), {total} occurrence(s). "
        "Each is either a falsified upstream/crate reference (fix the text to name the real "
        "thing) or a genuine non-package identifier that belongs in this script's ALLOWLIST "
        "(add it with a reason)."
    )
    sys.exit(1)

print(f"No unknown krikos-prefixed tokens ({len(real_packages)} real packages, "
      f"{len(ALLOWLIST)} allowlisted non-package identifiers).")
PY
