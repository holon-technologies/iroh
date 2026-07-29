# Repo Showcase Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make this repository defensible as a public showcase by fixing substrate hygiene and CI correctness, without touching crate names, versions, tags, or the README.

**Architecture:** Two independent workstreams. A (Tasks 1–6) fixes ignore files, vendored-fork provenance, GitHub language attribution, changelog provenance, and documentation rationale. B (Tasks 7–13) fixes branch protection, action pinning, dead automation, issue-dependent triage, fuzz alerting, correctness gates, and build caching. Every change is verified by the mechanism it affects, never by inspection.

**Tech Stack:** Rust (edition 2024, MSRV 1.91), Cargo workspaces, GitHub Actions, `cargo-deny`, `git-cliff`, `cargo-fuzz`, `sccache`, Docker (cargo-chef), `gh` CLI, `jq`.

## Global Constraints

- Do not rename crates, change `version`, create tags, or publish to any registry. Deferred to Project C.
- Do not rewrite `README.md` or restructure docs for public consumption. Deferred to Project D.
- Do not remove or alter `Copyright 2025 N0, INC.` anywhere. It is required attribution for Apache-2.0/MIT-derived code. The fork's copyright is added alongside, never substituted.
- Do not change production source behaviour in `iroh`, `iroh-base`, `iroh-relay`, `iroh-dns`, `iroh-dns-server`, `iroh-resolver`, `iroh-runtime`.
- Do not fix the `hickory-proto` TSIG fuzz crash. Add alerting only.
- `GOAL.md` stays at repo root, unchanged.
- MSRV is `1.91`. Workspace edition is `2024`. Vendored crates use `--edition 2021` for `rustfmt`.
- Every new CI gate must be observed failing on a deliberate violation before it is considered installed. A gate never seen failing is not a gate.
- Commit after every task. Use Conventional Commits.

---

## Task 1: Bound the Docker build context

**Files:**
- Modify: `.dockerignore`
- Test: `scripts/tests/check-docker-context.sh` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `scripts/tests/check-docker-context.sh`, invoked by Task 12's CI wiring.

**Background:** `docker/Dockerfile` runs `COPY . .` twice (cargo-chef planner at line 9, builder at line 25). `.dockerignore` is two lines (`docker`, `target`), so the context is the whole repo including `.git/` and all vendored trees — measured at 53 GB. The image builds only `iroh-relay` and `iroh-dns-server`.

- [ ] **Step 1: Write the failing test**

Create `scripts/tests/check-docker-context.sh`:

```bash
#!/usr/bin/env bash
# Asserts the Docker build context stays bounded.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

limit_mb=200

# Ask the daemon for the real context size by building only the first stage
# with a no-op target, then reading the reported context transfer.
size_bytes=$(
  tar --exclude-from=<(
    # Translate .dockerignore into tar excludes for a daemon-free estimate.
    grep -vE '^\s*(#|!|$)' .dockerignore || true
  ) -cf - . 2>/dev/null | wc -c
)
size_mb=$(( size_bytes / 1024 / 1024 ))

echo "docker build context estimate: ${size_mb} MB (limit ${limit_mb} MB)"
if (( size_mb > limit_mb )); then
  echo "FAIL: build context exceeds ${limit_mb} MB" >&2
  exit 1
fi
```

Make it executable: `chmod +x scripts/tests/check-docker-context.sh`

- [ ] **Step 2: Run it to verify it fails**

Run: `scripts/tests/check-docker-context.sh`
Expected: FAIL, reporting a context far above 200 MB.

Note: the `tar` estimate above is deliberately naive — it does not implement `!`-negation. That is why Step 3 uses a deny-all-then-allowlist form whose *negations* are what matter, and why Step 4 replaces this estimate with a real measurement. Do not ship the naive estimate as the final gate.

- [ ] **Step 3: Write the `.dockerignore`**

Replace `.dockerignore` entirely:

```
# Deny everything, then allow only what the workspace build needs.
# docker/Dockerfile does `COPY . .` for the cargo-chef planner and builder,
# so this allowlist is the sole bound on context size.
*

!Cargo.toml
!Cargo.lock
!.cargo/

!iroh/
!iroh-base/
!iroh-dns/
!iroh-dns-server/
!iroh-relay/
!iroh-resolver/
!iroh-runtime/
!tools/

# Only the two crates referenced by [patch.crates-io] in the root Cargo.toml.
# vendor/rustls-0.23.41 is patched in by iroh-sim and fuzz only, neither of
# which this image builds.
!vendor/hickory-server-0.26.1/
!vendor/noq-1.1.0/

# Re-exclude build output inside the directories allowed above.
**/target
```

- [ ] **Step 4: Replace the estimate with a real measurement**

Rewrite `scripts/tests/check-docker-context.sh` to measure what the daemon actually receives:

```bash
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

out=$(docker build --no-cache --target planner -f docker/Dockerfile . 2>&1 | head -5)
echo "$out"

# BuildKit reports: "transferring context: 12.34MB"
size=$(sed -nE 's/.*transferring context: ([0-9.]+)([KMG]?B).*/\1 \2/p' <<<"$out" | tail -1)
[[ -n "$size" ]] || { echo "FAIL: could not parse context size" >&2; exit 1; }

value=${size% *}
unit=${size#* }
case "$unit" in
  B)  mb=0 ;;
  KB) mb=$(awk -v v="$value" 'BEGIN{printf "%d", v/1024}') ;;
  MB) mb=$(awk -v v="$value" 'BEGIN{printf "%d", v}') ;;
  GB) mb=$(awk -v v="$value" 'BEGIN{printf "%d", v*1024}') ;;
  *)  echo "FAIL: unknown unit $unit" >&2; exit 1 ;;
esac

echo "docker build context: ${mb} MB (limit ${limit_mb} MB)"
if (( mb > limit_mb )); then
  echo "FAIL: build context exceeds ${limit_mb} MB" >&2
  exit 1
fi
```

- [ ] **Step 5: Run it to verify it passes**

Run: `scripts/tests/check-docker-context.sh`
Expected: PASS, reporting well under 200 MB.

- [ ] **Step 6: Verify the image still builds**

Run: `docker build -f docker/Dockerfile --target iroh-relay -t iroh-relay:ctx-test .`
Expected: SUCCESS. If it fails with a missing manifest or missing crate, add the corresponding `!` entry to `.dockerignore` and repeat.

Then: `docker build -f docker/Dockerfile --target iroh-dns-server -t iroh-dns:ctx-test .`
Expected: SUCCESS.

- [ ] **Step 7: Commit**

```bash
git add .dockerignore scripts/tests/check-docker-context.sh
git commit -m "fix(docker): bound build context with an allowlist ignore file

The context was the entire repository including .git and all vendored
trees. Replace the two-line .dockerignore with deny-all-then-allowlist
covering only workspace members and the two patched vendors the image
actually builds, and add a test asserting the context stays bounded."
```

---

## Task 2: Make `.gitignore` survive vendor version bumps

**Files:**
- Modify: `.gitignore`
- Delete: `compat/relay-v1-interop/.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks.

**Background:** `.gitignore` currently anchors six build directories, three pinned to exact vendored versions, so every vendor bump silently reintroduces an unignored `target/`.

- [ ] **Step 1: Confirm the defect**

Run:

```bash
mkdir -p vendor/rustls-0.99.0/target && touch vendor/rustls-0.99.0/target/probe
git status --porcelain vendor/rustls-0.99.0
```

Expected: `?? vendor/rustls-0.99.0/` — an unignored build directory, reproducing the bug.

- [ ] **Step 2: Rewrite `.gitignore`**

Replace the whole file:

```
# Build output at any depth. Do not anchor or version-pin these: vendored
# crates are bumped by directory rename, and an anchored rule silently
# stops matching when that happens.
target/

/fuzz/artifacts
/logs
iroh.config.toml

# Local scratch directory that the docs instruct users to write into.
/artifacts/

# Per-developer Claude Code settings. Repository cleanliness must not depend
# on an individual's ~/.config/git/ignore.
.claude/settings.local.json
.claude/*.local.json
```

Note `/.patchbay` is intentionally dropped — Task 9 deletes `patchbay.yml`.

- [ ] **Step 3: Verify the probe is now ignored**

Run: `git status --porcelain vendor/rustls-0.99.0`
Expected: no output.

- [ ] **Step 4: Verify nothing previously-tracked became ignored**

Run:

```bash
git ls-files | git check-ignore --stdin --no-index 2>/dev/null | head
```

Expected: no output. Any output means a tracked file is now ignored — stop and fix the rule.

- [ ] **Step 5: Clean up the probe and the redundant nested ignore**

```bash
rm -rf vendor/rustls-0.99.0
git rm -q compat/relay-v1-interop/.gitignore
```

- [ ] **Step 6: Verify the nested ignore was redundant**

Run:

```bash
mkdir -p compat/relay-v1-interop/target && touch compat/relay-v1-interop/target/probe
git status --porcelain compat/relay-v1-interop
rm -rf compat/relay-v1-interop/target
```

Expected: no output from `git status`.

- [ ] **Step 7: Commit**

```bash
git add .gitignore compat/relay-v1-interop/.gitignore
git commit -m "fix(git): ignore build output at any depth

Six anchored rules, three pinned to exact vendored versions, meant every
vendor bump silently reintroduced an unignored target directory. Collapse
to a single depth-matching rule and add the artifacts scratch directory
and per-developer Claude settings."
```

---

## Task 3: Restore vendored rustls and make provenance machine-checked

**Files:**
- Create: `vendor/rustls-0.23.41.patch`
- Create: `vendor/rustls-0.23.41/IROH-VENDOR.md`
- Create: `vendor/README.md`
- Create: `vendor/hickory-server-0.26.1.patch`
- Create: `vendor/noq-1.1.0.patch`
- Create: `scripts/tests/check-vendor-provenance.sh`
- Modify: every file under `vendor/rustls-0.23.41/src/`, `benches/`, `examples/` (restored)

**Interfaces:**
- Consumes: nothing.
- Produces: `scripts/tests/check-vendor-provenance.sh`, invoked by Task 12's CI wiring.

**Background:** Measured against the crates.io package, `vendor/rustls-0.23.41` differs in 81 source files. Normalizing the pristine package with default `rustfmt --edition 2021` reduces that to 12, so 69 files carry nothing but a reformat that overwrote rustls's upstream style. The 12 real files hold a ~529-line public-API patch. This is the only vendored tree with no `IROH-VENDOR.md`, and the change is security-relevant.

`noq-1.1.0` differs in 6 `.rs` files and `hickory-server-0.26.1` in 2, both matching their documented patches. Only rustls needs restoration.

Do not attempt to fix this by excluding `vendor/**` from `scripts/run-format.sh`. That script runs `cargo fmt --all` on the root and `iroh-sim` workspaces; the vendored trees are members of neither, so it did not cause this and excluding it changes nothing.

- [ ] **Step 1: Extract the semantic patch**

```bash
work=$(mktemp -d)
cd "$work"
curl -sL https://static.crates.io/crates/rustls/rustls-0.23.41.crate -o r.crate
tar xzf r.crate
cp -r rustls-0.23.41 norm
find norm -name '*.rs' -type f -print0 | xargs -0 -P 8 -n 1 rustfmt --edition 2021
cd - >/dev/null

V=vendor/rustls-0.23.41
FILES="src/common_state.rs src/crypto/mod.rs src/crypto/aws_lc_rs/mod.rs \
src/crypto/ring/mod.rs src/client/hs.rs src/client/tls12.rs src/client/tls13.rs \
src/client/ech.rs src/client/client_conn.rs src/server/hs.rs src/server/tls12.rs \
src/server/tls13.rs"

: > vendor/rustls-0.23.41.patch
for f in $FILES; do
  diff -u "$work/norm/$f" "$V/$f" \
    | sed "s|^--- .*|--- a/$f|; s|^+++ .*|+++ b/$f|" >> vendor/rustls-0.23.41.patch || true
done
wc -l vendor/rustls-0.23.41.patch
```

Expected: roughly 529 lines.

- [ ] **Step 2: Verify the patch is complete**

Confirm no thirteenth file carries a semantic change:

```bash
for f in $(cd "$work/norm" && find . -name '*.rs' -type f | sed 's|^\./||'); do
  [ -f "$V/$f" ] || continue
  cmp -s "$work/norm/$f" "$V/$f" || echo "$f"
done | sort > /tmp/actual.txt
printf '%s\n' $FILES | sort > /tmp/expected.txt
diff /tmp/expected.txt /tmp/actual.txt && echo "PATCH COMPLETE"
```

Expected: `PATCH COMPLETE`. If the lists differ, add the missing files to `FILES` and redo Step 1.

- [ ] **Step 3: Restore the tree from pristine plus patch**

```bash
rm -rf "$V"
cp -r "$work/norm" "$V"
rm -rf "$V/target"
git apply --directory=vendor/rustls-0.23.41 vendor/rustls-0.23.41.patch
```

- [ ] **Step 4: Verify the restore compiles and the simulator still passes**

```bash
cargo check --manifest-path iroh-sim/Cargo.toml --all-targets
```

Expected: SUCCESS. The 12-file patch is the entire public-API surface `iroh-sim` depends on; if this fails, the patch extraction in Step 1 was incomplete.

- [ ] **Step 5: Write `vendor/rustls-0.23.41/IROH-VENDOR.md`**

Match the format used by `vendor/noq-1.1.0/IROH-VENDOR.md`. Read that file first, then write:

```markdown
# Vendored rustls 0.23.41

## Upstream

`rustls` 0.23.41, exactly as published on crates.io, normalized with
`rustfmt --edition 2021` at default settings.

## Why this fork exists

`iroh-sim` requires deterministic, run-scoped cryptography so that a simulation
replays identically from a seed. Upstream rustls draws session identifiers and
`Random` values from an ambient source and does not expose which key-exchange
group a connection negotiated, both of which make replay impossible.

## The patch

`vendor/rustls-0.23.41.patch`, roughly 529 lines across 12 files:

- `KxState` holds `Arc<dyn SupportedKxGroup>` rather than a borrowed reference,
  so the negotiated group outlives the handshake.
- A public `negotiated_key_exchange_group()` accessor on the connection.
- `provider.secure_random` is threaded through session-ID and `Random`
  construction instead of an ambient source.

Files: `src/common_state.rs`, `src/crypto/mod.rs`, `src/crypto/aws_lc_rs/mod.rs`,
`src/crypto/ring/mod.rs`, `src/client/{hs,tls12,tls13,ech,client_conn}.rs`,
`src/server/{hs,tls12,tls13}.rs`.

## Scope

Simulator only. This crate is patched in by `iroh-sim/Cargo.toml` and `fuzz/`.
No production crate resolves it — production uses rustls from crates.io. See
`docs/superpowers/specs/2026-07-25-iroh-publishable-fork-boundary-design.md`
for why a renamed rustls fork is not viable.

## Update procedure

1. Download the new upstream package from crates.io.
2. Normalize it: `find . -name '*.rs' -print0 | xargs -0 -n1 rustfmt --edition 2021`.
3. Apply `vendor/rustls-0.23.41.patch`, resolving conflicts by hand.
4. Rename the directory and patch file to the new version and update
   `iroh-sim/Cargo.toml` and `fuzz/Cargo.toml`.
5. Run `scripts/tests/check-vendor-provenance.sh`.

## Why this cannot simply be removed

Deleting the patch removes deterministic replay from every simulation, which
is the property the simulator exists to provide.
```

- [ ] **Step 6: Generate patches for the other two vendors**

```bash
for spec in "hickory-server 0.26.1" "noq 1.1.0"; do
  set -- $spec; name=$1; ver=$2
  d=$(mktemp -d)
  curl -sL "https://static.crates.io/crates/$name/$name-$ver.crate" -o "$d/c.crate"
  tar xzf "$d/c.crate" -C "$d"
  diff -ru "$d/$name-$ver" "vendor/$name-$ver" \
    -x target -x .cargo-ok -x IROH-VENDOR.md \
    | sed "s|^--- $d/$name-$ver/|--- a/|; s|^+++ vendor/$name-$ver/|+++ b/|" \
    > "vendor/$name-$ver.patch" || true
  wc -l "vendor/$name-$ver.patch"
done
```

- [ ] **Step 7: Write the provenance guard**

Create `scripts/tests/check-vendor-provenance.sh`:

```bash
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
    find "$pristine" -name '*.rs' -type f -print0 \
      | xargs -0 -P 8 -n 1 rustfmt --edition 2021
  fi

  if [[ -s "$patch" ]]; then
    git apply --directory="$pristine" --unsafe-paths "$patch" \
      || { echo "FAIL: $name patch does not apply cleanly" >&2; status=1; return; }
  fi

  if diff -ru "$pristine" "$dir" -x target -x .cargo-ok -x IROH-VENDOR.md >/dev/null; then
    echo "ok: $dir matches upstream + patch"
  else
    echo "FAIL: $dir differs from upstream + patch" >&2
    diff -ru "$pristine" "$dir" -x target -x .cargo-ok -x IROH-VENDOR.md | head -40 >&2
    status=1
  fi
}

check rustls         0.23.41 normalize
check noq            1.1.0   raw
check hickory-server 0.26.1  raw

exit $status
```

Make it executable: `chmod +x scripts/tests/check-vendor-provenance.sh`

- [ ] **Step 8: Run the guard to verify it passes**

Run: `scripts/tests/check-vendor-provenance.sh`
Expected: three `ok:` lines, exit 0.

- [ ] **Step 9: Observe the guard failing**

```bash
echo "// deliberate drift" >> vendor/rustls-0.23.41/src/lock.rs
scripts/tests/check-vendor-provenance.sh; echo "exit=$?"
git checkout vendor/rustls-0.23.41/src/lock.rs
```

Expected: `FAIL: vendor/rustls-0.23.41 differs from upstream + patch`, `exit=1`. A gate never seen failing is not a gate.

- [ ] **Step 10: Write `vendor/README.md`**

```markdown
# Vendored dependencies

Three upstream crates are vendored because each carries a patch this project
requires and upstream has not accepted. Each directory is its crates.io package
plus the sibling `*.patch` file, and nothing else.

| Directory | Upstream | Patch | Scope |
|---|---|---|---|
| `noq-1.1.0/` | noq 1.1.0 | `noq-1.1.0.patch` | Production. Bounded event queues, per-poll budgets, connection-lifetime ownership. |
| `hickory-server-0.26.1/` | hickory-server 0.26.1 | `hickory-server-0.26.1.patch` | Production. Pre-spawn UDP-request and TCP-connection admission limits. |
| `rustls-0.23.41/` | rustls 0.23.41 | `rustls-0.23.41.patch` | Simulator only. Run-scoped entropy and key-exchange visibility for deterministic replay. |

Each directory's `IROH-VENDOR.md` documents the exact delta, the update
procedure, and why the patch cannot be dropped.

`scripts/tests/check-vendor-provenance.sh` asserts in CI that every directory
still equals upstream plus its patch, so the claim above cannot silently rot.

The rustls tree is normalized with `rustfmt --edition 2021` at default settings
before the patch is applied; the other two are byte-identical to their packages.
```

- [ ] **Step 11: Commit**

```bash
git add vendor/ scripts/tests/check-vendor-provenance.sh
git commit -m "fix(vendor): restore rustls to upstream plus a reviewable patch

The vendored rustls tree differed from crates.io in 81 files. Normalizing
pristine with default rustfmt reduced that to 12, so 69 files carried
nothing but a reformat that overwrote rustls's upstream style and buried
the real change.

The genuine patch is ~529 lines across 12 files: KxState holding
Arc<dyn SupportedKxGroup>, a public negotiated_key_exchange_group()
accessor, and secure_random threaded through session-ID and Random
construction. That is a public-API change to a TLS library and it was
the only vendored tree with no IROH-VENDOR.md.

Restore from pristine, check the patch in, document it, and add a CI
guard asserting every vendored tree equals upstream plus its patch."
```

---

## Task 4: Attribute vendored and generated code correctly

**Files:**
- Modify: `.gitattributes`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks.

**Background:** `.gitattributes` is one line covering shell-script line endings. 37% of tracked Rust is vendored but unmarked, so GitHub's language statistics attribute upstream's rustls, noq and hickory-server to this project.

- [ ] **Step 1: Measure the current attribution**

```bash
echo "vendored .rs lines:"; git ls-files 'vendor/**/*.rs' | xargs wc -l | tail -1
echo "first-party .rs lines:"; git ls-files '*.rs' | grep -v '^vendor/' | xargs wc -l | tail -1
```

Record both numbers; Step 4 confirms the ratio is what the fix should remove.

- [ ] **Step 2: Rewrite `.gitattributes`**

```
# Set line endings to LF, even on Windows. Otherwise, execution within CI fails.
# See https://help.github.com/articles/dealing-with-line-endings/
* text=auto eol=lf
*.sh text eol=lf

# Upstream code carrying a narrow patch. Not this project's work, and it should
# not appear in GitHub's language statistics or dominate diff review.
vendor/** linguist-vendored

# Machine-generated. Excluded from language statistics and collapsed in diffs.
CHANGELOG.md linguist-generated
CHANGELOG_old.md linguist-generated
**/Cargo.lock linguist-generated
docs/testing/resource-canary/** linguist-generated
```

- [ ] **Step 3: Verify no file content changed**

Run: `git status --porcelain`
Expected: only `.gitattributes` modified. `text=auto eol=lf` must not rewrite working-tree files; if other files appear, the repo has CRLF content and you should stop and report rather than mass-convert in this task.

- [ ] **Step 4: Verify the attributes apply**

```bash
git check-attr linguist-vendored -- vendor/rustls-0.23.41/src/lib.rs
git check-attr linguist-generated -- CHANGELOG.md Cargo.lock
git check-attr linguist-generated -- docs/testing/resource-canary/2026-07-24/run.json
```

Expected: `linguist-vendored: set` for the first, `linguist-generated: set` for the rest.

- [ ] **Step 5: Commit**

```bash
git add .gitattributes
git commit -m "chore(git): mark vendored and generated files for linguist

37% of tracked Rust is vendored upstream code carrying a narrow patch,
but it was unmarked, so GitHub attributed it to this project. Also marks
both changelogs, all lockfiles, and the committed resource-canary samples
as generated, and applies the LF policy repo-wide rather than to shell
scripts alone."
```

---

## Task 5: Retarget changelog provenance off upstream

**Files:**
- Modify: `cliff.toml:41-43`
- Move: `CHANGELOG.md`, `CHANGELOG_old.md` → `docs/history/`
- Create: `CHANGELOG.md` (pointer)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks.

**Background:** `cliff.toml`'s postprocessors rewrite every commit reference to `https://github.com/n0-computer/iroh`, so the first person to run `git cliff` gets a changelog full of links to upstream issues. Cutting a release section and tagging are deferred to Project C.

- [ ] **Step 1: Observe the defect**

Run: `git cliff --unreleased 2>/dev/null | grep -o 'n0-computer/iroh[^)]*' | head -5`
Expected: several upstream URLs. If `git cliff` is not installed: `cargo install git-cliff --locked`.

- [ ] **Step 2: Retarget the postprocessors**

In `cliff.toml`, replace lines 41–43:

```toml
postprocessors = [
  { pattern = '<REPO>', replace = "https://github.com/holon-technologies/iroh" },
  { pattern = "\\(#([0-9]+)\\)", replace = "([#${1}](https://github.com/holon-technologies/iroh/issues/${1}))"},
]
```

- [ ] **Step 3: Verify the fix**

Run: `git cliff --unreleased 2>/dev/null | grep -c 'n0-computer'`
Expected: `0`.

Run: `git cliff --unreleased 2>/dev/null | grep -c 'holon-technologies'`
Expected: greater than 0.

- [ ] **Step 4: Relocate the historical changelogs**

```bash
mkdir -p docs/history
git mv CHANGELOG.md docs/history/CHANGELOG.md
git mv CHANGELOG_old.md docs/history/CHANGELOG_old.md
```

- [ ] **Step 5: Leave a root pointer**

Create `CHANGELOG.md`:

```markdown
# Changelog

Release notes for this fork begin at 2.0.0 and are generated by
[git-cliff](https://git-cliff.org) from Conventional Commits.

Historical changelogs inherited from upstream `n0-computer/iroh`, covering
releases prior to this fork, are preserved at:

- [`docs/history/CHANGELOG.md`](docs/history/CHANGELOG.md)
- [`docs/history/CHANGELOG_old.md`](docs/history/CHANGELOG_old.md)

Copyright for those entries remains with their original authors.
```

- [ ] **Step 6: Update the linguist paths from Task 4**

The `.gitattributes` entries now point at moved files. Replace those two lines:

```
docs/history/CHANGELOG.md linguist-generated
docs/history/CHANGELOG_old.md linguist-generated
```

Verify: `git check-attr linguist-generated -- docs/history/CHANGELOG.md`
Expected: `linguist-generated: set`.

- [ ] **Step 7: Check for dangling references**

```bash
grep -rn "CHANGELOG_old\|CHANGELOG.md" --include='*.md' --include='*.toml' --include='*.yml' --include='*.yaml' --include='*.sh' . \
  | grep -v '^./docs/history/' | grep -v '^./CHANGELOG.md'
```

Fix any path that still assumes the root location.

- [ ] **Step 8: Commit**

```bash
git add -A cliff.toml CHANGELOG.md docs/history .gitattributes
git commit -m "fix(changelog): retarget git-cliff at this fork and archive upstream history

cliff.toml rewrote every commit reference to n0-computer/iroh, so running
git cliff produced a changelog of links to upstream issues. Move the 372 KB
of inherited history under docs/history/ with a root pointer that keeps
upstream attribution explicit."
```

---

## Task 6: Promote durable rationale, then remove the planning tree

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/testing/determinism-audit.md`
- Create: `docs/README.md`
- Delete: `docs/superpowers/`

**Interfaces:**
- Consumes: `vendor/*/IROH-VENDOR.md` from Task 3.
- Produces: nothing consumed by later tasks.

**Background:** `docs/superpowers/` holds 29 planning artifacts (448 KB) containing load-bearing architecture rationale that exists nowhere else — notably the publishable-fork-boundary design and the deterministic-simulation architecture. This task promotes that rationale and then deletes the tree. It removes this plan and its spec too, so it must run last.

- [ ] **Step 1: Inventory what is load-bearing**

```bash
ls docs/superpowers/specs/ docs/superpowers/plans/ docs/superpowers/audits/
grep -rln "fork boundary\|publishable\|deterministic\|entropy\|rustls" docs/superpowers/specs/
```

For each spec, decide: is its rationale already stated in `docs/architecture.md`, `docs/testing/deterministic-simulation-architecture.md`, or a `vendor/*/IROH-VENDOR.md`? Record the ones that are not.

- [ ] **Step 2: Promote the fork-boundary rationale**

`docs/superpowers/specs/2026-07-25-iroh-publishable-fork-boundary-design.md` explains why `noq` and `hickory-server` became renamed packages while `rustls` could not — because Noq, Tokio-Rustls and other transitive dependencies resolve the package named `rustls`, so a differently-named fork would coexist as a distinct crate and make public rustls types incompatible at integration boundaries.

Add that reasoning to `docs/architecture.md` under a new `## Vendored dependency boundary` section, cross-linking `vendor/README.md`.

- [ ] **Step 3: Fix the stale determinism audit**

`docs/testing/determinism-audit.md` cites source paths deleted by the v2 hard cut (`b433041dce`). Find them:

```bash
grep -oE '`[a-z0-9/_.-]+\.rs`' docs/testing/determinism-audit.md | tr -d '`' | sort -u | while read -r p; do
  [ -e "$p" ] || echo "MISSING: $p"
done
```

Update each missing path to its v2 location, or delete the claim if the code no longer exists.

- [ ] **Step 4: Write `docs/README.md`**

```markdown
# Documentation

## Architecture and contracts

- [Architecture contract](architecture.md) — crate ownership boundaries, the v2 hard cut, and the vendored dependency boundary.
- [Relay compatibility contract](relay-compatibility.md) — V1/V2 wire protocol guarantees.
- [Transports](../TRANSPORTS.md) — the transport registry.

## Testing

- [Testing strategy](testing/simulation.md) — how deterministic gates and exploratory campaigns divide the work.
- [Deterministic simulation architecture](testing/deterministic-simulation-architecture.md) — how the simulator achieves seed-reproducible runs.
- [Determinism audit](testing/determinism-audit.md) — the boundary inventory.
- [Fuzzing](testing/fuzzing.md) — the bounded fuzz campaign.
- [Production resource canary](testing/production-resource-canary.md).

## Simulation operations

- [Operations](simulation/operations.md) — running, replaying, and minimizing.
- [Relay parity](simulation/relay-parity.md) and [Patchbay parity](simulation/patchbay-parity.md).

## Release

- [v2 migration guide](release/v2-migration.md).
- [v2 release checklist](release/v2-release-checklist.md).

## History

- [Inherited upstream changelogs](history/) — releases prior to this fork.

Project goals and current testing status live in [`GOAL.md`](../GOAL.md) at the
repository root.
```

- [ ] **Step 5: Verify no promoted rationale was lost**

Before deleting, confirm each key claim survives elsewhere:

```bash
for claim in "differently named fork" "secure_random" "KxState" "bounded event queues" "admission limits"; do
  printf '%s: ' "$claim"
  grep -rl "$claim" docs/ vendor/*/IROH-VENDOR.md --include='*.md' 2>/dev/null \
    | grep -v '^docs/superpowers/' | tr '\n' ' '
  echo
done
```

Expected: every claim resolves to at least one file outside `docs/superpowers/`. Any empty line means promotion is incomplete — go back to Step 2.

- [ ] **Step 6: Delete the planning tree**

```bash
git rm -r -q docs/superpowers/
```

- [ ] **Step 7: Check for dangling links**

```bash
grep -rn "superpowers/" --include='*.md' --include='*.toml' --include='*.yml' --include='*.yaml' . || echo "no dangling references"
```

Expected: `no dangling references`. Fix any that remain.

Then verify every relative link in `docs/` resolves:

```bash
grep -rhoE '\]\(([^)]+\.md)\)' docs/ README.md | sed -E 's/\]\((.*)\)/\1/' | sort -u | while read -r l; do
  case "$l" in http*) continue;; esac
  [ -e "docs/$l" ] || [ -e "$l" ] || echo "BROKEN: $l"
done
```

Expected: no output.

- [ ] **Step 8: Commit**

```bash
git add -A docs/
git commit -m "docs: promote durable rationale and remove the planning tree

29 planning artifacts held load-bearing rationale that existed nowhere
else — notably why rustls could not be renamed while noq and
hickory-server could. Promote that into the architecture contract and the
vendor documentation, correct the determinism audit's references to
sources deleted by the v2 hard cut, add a docs index, and drop the tree."
```

---

## Task 7: Make `main` require a full green CI run

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: a status context named `ci-ok`, referenced by the ruleset change in Step 6.

**Background:** The `main` ruleset requires 2 of roughly 20 checks and does not require a pull request at all, so `main` is directly writable and almost entirely ungated. This is the most serious finding in the audit.

The jobs currently in `ci.yml` are: `tests`, `fuzz_smoke`, `simulation_contracts`, `simulation_gate`, `cross_build`, `android`, `cross_test`, `wasm_test`, `check_semver`, `check_external_types`, `check_fmt`, `check_docs`, `clippy_check`, `check_optional_deps`, `msrv`, `cargo_deny`, `netsim-integration-tests`, `codespell`.

- [ ] **Step 1: Confirm the current state**

```bash
gh api repos/holon-technologies/iroh/rulesets --jq '.[] | {id, name, target}'
gh api repos/holon-technologies/iroh/rulesets/19774422 \
  --jq '.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context'
```

Record the two required contexts.

- [ ] **Step 2: Add the aggregate job**

Append to the end of `.github/workflows/ci.yml`:

```yaml
  ci-ok:
    name: CI OK
    # This is the sole required status check for `main`. Every job above must
    # appear in `needs`, so adding a job makes it required by construction.
    # `scripts/tests/check-ci-aggregate.sh` asserts that invariant.
    if: always()
    needs:
      - tests
      - fuzz_smoke
      - simulation_contracts
      - simulation_gate
      - cross_build
      - android
      - cross_test
      - wasm_test
      - check_semver
      - check_external_types
      - check_fmt
      - check_docs
      - clippy_check
      - check_optional_deps
      - msrv
      - cargo_deny
      - netsim-integration-tests
      - codespell
    timeout-minutes: 5
    runs-on: ubuntu-latest
    steps:
      - name: Assert every dependency succeeded or was skipped
        run: |
          failed=$(jq -r 'to_entries[] | select(.value.result != "success" and .value.result != "skipped") | "\(.key): \(.value.result)"' <<'JSON'
          ${{ toJSON(needs) }}
          JSON
          )
          if [ -n "$failed" ]; then
            echo "Failing dependencies:" >&2
            echo "$failed" >&2
            exit 1
          fi
          echo "All CI jobs succeeded or were skipped."
```

Note: `skipped` is accepted because several jobs carry a `flaky-test` label guard and legitimately skip.

- [ ] **Step 3: Write the invariant guard**

Create `scripts/tests/check-ci-aggregate.sh`:

```bash
#!/usr/bin/env bash
# Asserts every job in ci.yml appears in ci-ok's `needs` list. Without this,
# a new job silently escapes the required status check.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root"

jobs=$(yq -r '.jobs | keys[] | select(. != "ci-ok")' .github/workflows/ci.yml | sort)
needs=$(yq -r '.jobs["ci-ok"].needs[]' .github/workflows/ci.yml | sort)

if ! diff <(echo "$jobs") <(echo "$needs") >/dev/null; then
  echo "FAIL: ci-ok needs does not match the job list" >&2
  echo "  '<' = job defined but not required; '>' = listed in needs but not defined" >&2
  diff <(echo "$jobs") <(echo "$needs") >&2
  exit 1
fi
echo "ok: ci-ok covers all $(echo "$jobs" | wc -l) jobs"
```

Make it executable: `chmod +x scripts/tests/check-ci-aggregate.sh`

If `yq` is unavailable, install it: `sudo snap install yq` or use the Go binary from `mikefarah/yq`.

- [ ] **Step 4: Run the guard**

Run: `scripts/tests/check-ci-aggregate.sh`
Expected: `ok:` and exit 0.

- [ ] **Step 5: Observe it failing**

```bash
yq -i '.jobs.probe_job.runs-on = "ubuntu-latest"' .github/workflows/ci.yml
scripts/tests/check-ci-aggregate.sh; echo "exit=$?"
git checkout .github/workflows/ci.yml
```

Expected: FAIL, `exit=1`. Then re-apply Steps 2–3 if the checkout reverted them — commit first if you prefer.

- [ ] **Step 6: Commit, open a PR, and let `ci-ok` run**

```bash
git add .github/workflows/ci.yml scripts/tests/check-ci-aggregate.sh
git commit -m "ci: add ci-ok aggregate gate covering every job

main required 2 of ~20 checks and did not require a pull request at all.
This job depends on every other job in ci.yml so that a single required
context covers the whole suite and new jobs are required by construction.
check-ci-aggregate.sh asserts the needs list stays complete."
```

Push the branch, open a pull request, and wait for `ci-ok` to appear and pass. **Do not change the ruleset until `ci-ok` has been observed green at least once** — requiring a context that has never reported makes `main` unmergeable.

- [ ] **Step 7: Update the ruleset**

Only after `ci-ok` is green:

```bash
gh api -X PUT repos/holon-technologies/iroh/rulesets/19774422 --input - <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["merge", "squash", "rebase"]
      } },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [ { "context": "CI OK" } ]
      } }
  ]
}
JSON
```

- [ ] **Step 8: Verify the gate holds**

```bash
gh api repos/holon-technologies/iroh/rulesets/19774422 --jq '.rules[].type'
```
Expected: `deletion`, `non_fast_forward`, `pull_request`, `required_status_checks`.

Then confirm direct pushes are rejected:

```bash
git checkout main && git pull
echo "# probe" >> README.md && git add README.md && git commit -m "probe: verify branch protection"
git push origin main; echo "exit=$?"
git reset --hard origin/main
```

Expected: push REJECTED with a protected-branch error, non-zero exit.

---

## Task 8: Pin third-party actions to commit SHAs

**Files:**
- Modify: every file in `.github/workflows/` and `.github/actions/` using a third-party action

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks.

**Background:** No action is pinned to a commit SHA, and `dtolnay/rust-toolchain@master` tracks a mutable branch. `release.yml`'s `supply_chain` job holds attestation-signing and repository-write tokens, so it is the highest-value target.

The third-party (non-`actions/*`) actions in use are: `agenthunt/conventional-commit-checker-action@v2.0.1`, `anchore/sbom-action@v0`, `android-actions/setup-android@v4`, `docker/build-push-action@v7`, `docker/login-action@v4`, `docker/setup-buildx-action@v4`, `docker/setup-qemu-action@v4`, `dtolnay/rust-toolchain@master`, `dtolnay/rust-toolchain@stable`, `EmbarkStudios/cargo-deny-action@v2`, `mozilla-actions/sccache-action@v0.0.10`, `msys2/setup-msys2@v2`, `nttld/setup-ndk@v1`, `peaceiris/actions-gh-pages@v4`, `peter-evans/create-or-update-comment@v5`, `peter-evans/find-comment@v4`, `reactivecircus/android-emulator-runner@v2`, `taiki-e/install-action@{v2,cargo-make,cross,nextest}`.

- [ ] **Step 1: Resolve each reference to a SHA**

```bash
resolve() {
  local repo=$1 ref=$2
  local sha
  sha=$(gh api "repos/$repo/commits/$ref" --jq .sha 2>/dev/null) || { echo "SKIP $repo@$ref"; return; }
  echo "$repo@$sha # $ref"
}
grep -rhoE "uses: [a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+@[a-zA-Z0-9._-]+" .github/workflows/ .github/actions/ \
  | sed 's/uses: //' | sort -u | while IFS='@' read -r repo ref; do resolve "$repo" "$ref"; done
```

Record the mapping. Note `taiki-e/install-action@cargo-make`, `@cross` and `@nextest` are *tags*, not versions — resolve each separately.

- [ ] **Step 2: Pin `release.yml` first**

Edit `.github/workflows/release.yml`, replacing each `uses:` with the SHA form and a version comment:

```yaml
      - uses: anchore/sbom-action@<sha>  # v0
      - uses: actions/attest@<sha>  # v4
```

Apply the same to every action in that file, `actions/*` included — the `supply_chain` job's token scope makes exceptions unjustifiable there.

- [ ] **Step 3: Verify `release.yml` still parses and runs**

```bash
gh workflow view release.yml
gh workflow run release.yml --ref "$(git rev-parse --abbrev-ref HEAD)" 2>&1 | head -3 || true
```

If the workflow is tag-triggered only and cannot be dispatched, validate syntax instead:

```bash
python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml')); print('valid yaml')"
```

- [ ] **Step 4: Replace the mutable `master` reference**

`dtolnay/rust-toolchain@master` appears in `ci.yml` (msrv job), `fuzz.yml`, and others. It is the single most dangerous reference in the repo because the branch is mutable. Pin every occurrence to a SHA.

```bash
grep -rln "dtolnay/rust-toolchain@master" .github/
```

- [ ] **Step 5: Pin the remaining workflows**

Work through the rest of `.github/workflows/` and `.github/actions/`. Leave `uses: ./...` local references unchanged.

- [ ] **Step 6: Verify no unpinned third-party action remains**

```bash
grep -rhoE "uses: [a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+@[a-zA-Z0-9._-]+" .github/workflows/ .github/actions/ \
  | grep -vE "@[0-9a-f]{40}" | sort -u
```

Expected: no output.

- [ ] **Step 7: Confirm Dependabot will maintain the pins**

`.github/dependabot.yml` already declares the `github-actions` ecosystem, which bumps SHA pins and preserves the trailing version comment. Verify:

```bash
grep -A3 "github-actions" .github/dependabot.yml
```

Expected: a `package-ecosystem: "github-actions"` entry with a schedule.

- [ ] **Step 8: Commit**

```bash
git add .github/
git commit -m "ci: pin third-party actions to commit SHAs

No action was pinned, and dtolnay/rust-toolchain@master tracked a mutable
branch while release.yml's supply_chain job holds attestation-signing and
repo-write tokens. Pin every third-party action to a 40-character SHA with
a trailing version comment; the already-configured github-actions
Dependabot ecosystem maintains them."
```

---

## Task 9: Remove dead automation and fix the permanently-skipped preview

**Files:**
- Delete: `.github/ansible/`, `.github/workflows/patchbay.yml`
- Modify: `.github/workflows/docs.yaml:26`, `.github/workflows/docs.yaml:38`
- Modify: `.github/workflows/netsim.yml`, `.github/workflows/netsim_runner.yaml`
- Modify: `.github/workflows/cleanup.yaml`
- Modify: workflows using `actions/download-artifact@v7`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks.

**Background:** `.github/ansible/` redeploys n0-operated infrastructure. `patchbay.yml` targets a self-hosted runner label this fork has no runners for; its runs queue up to 24 hours before auto-cancel. `docs.yaml`'s guard `!github.event.pull_request.head.repo.fork` is always false-y for this repo *because the repo is itself a fork*, so Docs Preview never runs.

- [ ] **Step 1: Confirm the dead runs**

```bash
gh run list --workflow=patchbay.yml --limit 5 --json status,conclusion,createdAt
gh run list --workflow=docs.yaml --limit 5 --json status,conclusion,createdAt
```

Expected: `patchbay.yml` runs cancelled after long queueing; `docs.yaml` jobs skipped.

- [ ] **Step 2: Delete the dead automation**

```bash
git rm -r -q .github/ansible/
git rm -q .github/workflows/patchbay.yml
```

Confirm `patchbay-hosted-smoke.yml` survives and is runnable:

```bash
grep -n "runs-on" .github/workflows/patchbay-hosted-smoke.yml
```

Expected: `ubuntu-latest` or another hosted label — not a self-hosted one.

- [ ] **Step 3: Fix the Docs Preview guard**

In `.github/workflows/docs.yaml`, replace the condition at line 26:

```yaml
    if: ${{ (github.event_name == 'pull_request' || github.event_name == 'workflow_dispatch') && github.event.pull_request.head.repo.full_name == github.repository }}
```

This is the same-repo test the original guard intended: run for branches in this repository, skip for pull requests from external forks whose tokens lack write access.

- [ ] **Step 4: Refresh the stale nightly pin**

`docs.yaml:38` pins `toolchain: nightly-2025-10-09`. Align it with the newest nightly already used elsewhere in the repo:

```bash
grep -rhoE "nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}" .github/ | sort -u
```

Set `docs.yaml` to the newest of those, and record the value — Task 12 consolidates all three into one workflow-level variable.

- [ ] **Step 5: Remove dead MSRV variables and fix the copied header**

```bash
grep -n 'MSRV: "1.66"' .github/workflows/netsim.yml .github/workflows/netsim_runner.yaml
```

Delete those lines — the workspace MSRV is 1.91 and these are unused.

In `.github/workflows/cleanup.yaml`, correct the header comment and concurrency group, both copied from `beta.yaml`. Line 1 reads `# Run tests using the beta Rust compiler`, which describes a different workflow, and line 12 reads `group: beta-${{ github.workflow }}-${{ github.ref }}`, which collides with `beta.yaml`'s group and can cancel unrelated runs.

```yaml
# Weekly cleanup of the generated documentation branch.

name: Cleanup
```

and

```yaml
concurrency:
  group: cleanup-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

- [ ] **Step 6: Reconcile artifact action versions on v8**

```bash
grep -rn "download-artifact@v7" .github/workflows/
```

Change each to `v8` so upload and download stay in lockstep and Dependabot groups them.

Note: if Task 8 already pinned these to SHAs, resolve the v8 SHA instead and keep the `# v8` comment.

- [ ] **Step 7: Verify all workflows still parse**

```bash
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
  python3 -c "import yaml,sys; yaml.safe_load(open('$f'))" || echo "INVALID: $f"
done
echo "parse check complete"
```

Expected: no `INVALID:` lines.

- [ ] **Step 8: Verify Docs Preview now runs**

Push the branch and open a pull request. Then:

```bash
gh run list --workflow=docs.yaml --limit 1 --json status,conclusion,headBranch
```

Expected: a run that is not skipped, producing a preview.

- [ ] **Step 9: Commit**

```bash
git add -A .github/
git commit -m "ci: remove dead automation and fix the permanently-skipped docs preview

.github/ansible redeployed n0-operated infrastructure. patchbay.yml
targeted a self-hosted runner this fork has no runners for, queueing up to
24 hours before auto-cancel. docs.yaml guarded on head.repo.fork, which is
always true here because the repository is itself a fork, so the preview
never ran; the intended test is head.repo.full_name == github.repository.

Also drops the unused MSRV 1.66 variables, fixes cleanup.yaml's copied
header, and aligns artifact actions on v8."
```

---

## Task 10: Stop simulation triage from silently discarding failures

**Files:**
- Modify: `.github/workflows/simulation-daily-soak.yml`
- Modify: `.github/ISSUE_TEMPLATE/bug_report.md:6`
- Create: `scripts/tests/check-issues-enabled.sh`

**Interfaces:**
- Consumes: nothing.
- Produces: `scripts/tests/check-issues-enabled.sh`, invoked as a preflight step.

**Background:** Simulation failure triage calls `scripts/upsert-simulation-issues.sh`, but Issues are disabled on this fork, so the whole triage lifecycle is a silent no-op — failures are detected and then discarded. A triage path that reports success while discarding findings is worse than none.

- [ ] **Step 1: Confirm Issues are disabled**

```bash
gh api repos/holon-technologies/iroh --jq '.has_issues'
```
Expected: `false`.

- [ ] **Step 2: Enable Issues**

```bash
gh api -X PATCH repos/holon-technologies/iroh -f has_issues=true
gh api repos/holon-technologies/iroh --jq '.has_issues'
```
Expected: `true`.

- [ ] **Step 3: Retarget the issue template's project field**

`.github/ISSUE_TEMPLATE/bug_report.md:6` reads `projects: ["n0-computer/1"]`, which points at upstream's project board. Either retarget it at a holon-technologies board or remove the line. If no board exists, remove it:

```bash
sed -i '/^projects: \["n0-computer\/1"\]$/d' .github/ISSUE_TEMPLATE/bug_report.md
grep -n "n0-computer" .github/ISSUE_TEMPLATE/bug_report.md || echo "clean"
```

- [ ] **Step 4: Write the preflight guard**

Create `scripts/tests/check-issues-enabled.sh`:

```bash
#!/usr/bin/env bash
# The simulation triage lifecycle writes GitHub Issues. If Issues are disabled,
# every failure is detected and then silently discarded, and the workflow still
# reports success. Fail loudly instead.
set -euo pipefail

repo="${GITHUB_REPOSITORY:-holon-technologies/iroh}"

has_issues=$(gh api "repos/$repo" --jq '.has_issues')
if [[ "$has_issues" != "true" ]]; then
  echo "FAIL: Issues are disabled on $repo, so simulation triage cannot record failures." >&2
  echo "Enable Issues, or replace the triage mechanism. Do not leave it as a no-op." >&2
  exit 1
fi
echo "ok: Issues are enabled on $repo"
```

Make it executable: `chmod +x scripts/tests/check-issues-enabled.sh`

- [ ] **Step 5: Wire it in as a preflight**

In `.github/workflows/simulation-daily-soak.yml`, add as the first step of the job that runs `upsert-simulation-issues.sh`:

```yaml
      - name: Preflight — Issues must be enabled
        env:
          GH_TOKEN: ${{ github.token }}
        run: scripts/tests/check-issues-enabled.sh
```

- [ ] **Step 6: Run the guard both ways**

```bash
scripts/tests/check-issues-enabled.sh; echo "exit=$?"
```
Expected: `ok:`, `exit=0`.

Then observe it failing:

```bash
gh api -X PATCH repos/holon-technologies/iroh -f has_issues=false >/dev/null
scripts/tests/check-issues-enabled.sh; echo "exit=$?"
gh api -X PATCH repos/holon-technologies/iroh -f has_issues=true >/dev/null
```
Expected: `FAIL:`, `exit=1`, then restored to enabled.

- [ ] **Step 7: Commit**

```bash
git add .github/ scripts/tests/check-issues-enabled.sh
git commit -m "ci: fail loudly when simulation triage cannot record failures

Triage called upsert-simulation-issues.sh while Issues were disabled on
this fork, so every detected failure was discarded and the workflow still
reported success. Enable Issues, retarget the template's upstream project
field, and add a preflight assertion so this cannot regress into silence."
```

---

## Task 11: Restore signal from the fuzz campaign

**Files:**
- Modify: `.github/workflows/fuzz.yml`
- Modify: `scripts/run-bounded-fuzz.sh`
- Create: `fuzz/known-crashes.md`

**Interfaces:**
- Consumes: `scripts/tests/check-issues-enabled.sh` from Task 10.
- Produces: nothing consumed by later tasks.

**Background:** The nightly campaign has been red for four or more consecutive nights on a genuine `hickory-proto` TSIG crash, with no notification. A permanently-red scheduled workflow trains everyone to ignore it, so a *new* crash would go unnoticed. Fixing the crash is explicitly out of scope; restoring signal is not.

- [ ] **Step 1: Confirm the failure and identify the crash**

```bash
gh run list --workflow=fuzz.yml --limit 8 --json conclusion,createdAt,displayTitle
gh run view "$(gh run list --workflow=fuzz.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --log-failed | head -60
```

Record which matrix target fails and the panic message.

- [ ] **Step 2: Record the known crash**

Create `fuzz/known-crashes.md`:

```markdown
# Known crashes

Crashes reproduced by the bounded fuzz campaign that are accepted as known and
tracked, so the campaign's signal stays meaningful. A campaign that is
permanently red teaches everyone to ignore it, which hides new crashes.

Each entry must have an owner and an exit condition. An entry with neither is
a bug being hidden, not a crash being tracked.

## hickory-proto TSIG panic

- **Target:** `<target from Step 1>`
- **First seen:** <date from Step 1>
- **Panic:** `<message from Step 1>`
- **Upstream:** not yet reported — file at https://github.com/hickory-dns/hickory-dns/issues
- **Owner:** <assign>
- **Exit condition:** upstream fix released and the vendored/declared
  hickory version bumped past it, then delete this entry.
- **Why not fixed here:** the panic is in `hickory-proto`, which this project
  does not vendor. `vendor/hickory-server-0.26.1` patches the server crate only.
```

- [ ] **Step 3: Add the exclusion mechanism**

`scripts/run-bounded-fuzz.sh` runs `cargo fuzz run` inside a subshell at lines 121–134. Under `set -euo pipefail` a crash propagates out of `run_target` and fails the script, with no way to tell a known crash from a new one.

Add near the top, after `artifacts` is resolved to an absolute path (line 95):

```bash
known_crashes_file="$repo_root/fuzz/known-crashes.md"
```

Then replace the subshell at lines 121–134 so the run's output is captured and its status inspected:

```bash
  local fuzz_log="$target_artifacts/fuzz-output.txt"
  local fuzz_status=0
  (
    cd "$repo_root"
    RUSTFLAGS="${IROH_FUZZ_RUSTFLAGS:--A deprecated}" \
      cargo "+$fuzz_toolchain" fuzz run --target "$fuzz_target" "$target" "$run_corpus" -- \
      "-max_total_time=$seconds" \
      -timeout=10 \
      -rss_limit_mb=2048 \
      "-max_len=$max_len" \
      "-artifact_prefix=$target_artifacts/" \
      -verbosity=0 \
      -print_final_stats=1
  ) 2>&1 | tee "$fuzz_log" || fuzz_status="${PIPESTATUS[0]}"

  if (( fuzz_status != 0 )); then
    # libFuzzer prints the panic on the line following "panicked at".
    local signature
    signature="$(grep -m1 -A1 "panicked at" "$fuzz_log" | tail -1 | sed 's/^[[:space:]]*//')"
    if [[ -n "$signature" ]] && grep -qF "$signature" "$known_crashes_file" 2>/dev/null; then
      printf 'known crash reproduced for %s: %s\n' "$target" "$signature" >&2
      known_crash_seen=1
    else
      printf 'NEW crash for %s: %s\n' "$target" "${signature:-<no panic line captured>}" >&2
      exit 1
    fi
  fi
```

Declare `known_crash_seen=0` alongside the other globals near line 7, and at the very end of the script — after the target loop — translate it into the campaign's exit status:

```bash
# 0 = clean, 1 = new crash (already exited above), 2 = only known crashes.
if (( known_crash_seen == 1 )); then
  exit 2
fi
```

Because `run_target` uses `trap ... RETURN` and runs in the same shell, `known_crash_seen` persists across targets.

- [ ] **Step 4: Add notification to `fuzz.yml`**

Add a job that runs after the matrix and reports genuine failures. Append to `.github/workflows/fuzz.yml`:

```yaml
  report:
    name: Report fuzz outcome
    needs: fuzz
    if: always() && needs.fuzz.result == 'failure'
    timeout-minutes: 10
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@v7
      - name: Preflight — Issues must be enabled
        env:
          GH_TOKEN: ${{ github.token }}
        run: scripts/tests/check-issues-enabled.sh
      - name: Open or update the fuzz failure issue
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          title="Bounded fuzz campaign failing"
          body="The nightly bounded fuzz campaign failed.

          Run: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}

          If this is a crash already listed in fuzz/known-crashes.md, the
          campaign script should have exited 2 rather than failing. A failure
          here means a NEW crash, or that the exclusion mechanism is broken."

          existing=$(gh issue list --search "$title in:title" --state open --json number --jq '.[0].number')
          if [ -n "$existing" ]; then
            gh issue comment "$existing" --body "$body"
          else
            gh issue create --title "$title" --body "$body" --label fuzz
          fi
```

Also update the campaign step so a known-crash exit of 2 does not fail the job:

```yaml
      - name: Run bounded campaign
        run: |
          set +e
          scripts/run-bounded-fuzz.sh \
            --seconds 300 \
            --target "${{ matrix.target }}" \
            --artifacts "$RUNNER_TEMP/fuzz-artifacts"
          rc=$?
          set -e
          # 0 = clean, 2 = only known crashes, anything else = new crash.
          if [ "$rc" -eq 2 ]; then
            echo "::warning::Known crash reproduced; see fuzz/known-crashes.md"
            exit 0
          fi
          exit "$rc"
```

- [ ] **Step 5: Verify the campaign now reports green on the known crash**

```bash
gh workflow run fuzz.yml
sleep 60
gh run list --workflow=fuzz.yml --limit 1 --json status,conclusion
```

Expected: eventually `success`, with a warning annotation naming the known crash.

- [ ] **Step 6: Observe the notification firing on a new crash**

Temporarily remove the known-crash entry so the campaign sees an unrecognised crash:

```bash
git stash push fuzz/known-crashes.md
gh workflow run fuzz.yml
```

Expected: the run fails and the `report` job opens an issue. Then restore: `git stash pop`.

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/fuzz.yml scripts/run-bounded-fuzz.sh fuzz/known-crashes.md
git commit -m "ci: restore signal from the bounded fuzz campaign

The campaign had been red for four or more consecutive nights on a
hickory-proto TSIG panic with no notification, which trains everyone to
ignore it and hides new crashes. Track the panic in fuzz/known-crashes.md
with an owner and an exit condition, let the script distinguish known
crashes (exit 2) from new ones (exit 1), and open an issue when a new
crash appears.

The panic itself is upstream in hickory-proto and is not fixed here."
```

---

## Task 12: Install the cheap correctness gates

**Files:**
- Create: `rust-toolchain.toml`
- Modify: `.github/workflows/ci.yml` (msrv job at 694–715, cargo_deny at 716–727)
- Modify: `deny.toml:2`
- Modify: `fuzz/Cargo.toml`, `fuzz/Cargo.lock`
- Modify: `scripts/run-bounded-fuzz.sh`

**Interfaces:**
- Consumes: `scripts/tests/check-docker-context.sh` (Task 1), `scripts/tests/check-vendor-provenance.sh` (Task 3), `scripts/tests/check-ci-aggregate.sh` (Task 7).
- Produces: a new `hygiene` job in `ci.yml`, which Task 7's `ci-ok` `needs` list must gain.

**Background:** There is no toolchain pin; the MSRV job claims all-features coverage without passing the flag and skips `iroh-sim` and `compat`; `fuzz/Cargo.lock` predates the `iroh-resolver` extraction and is never enforced; `compat/relay-v1-interop` only compiles on a weekly cron; `deny.toml` globally waives duplicate versions.

- [ ] **Step 1: Pin the toolchain**

Create `rust-toolchain.toml`:

```toml
# Pins the toolchain so local builds reproduce CI. Keep the channel at or above
# the workspace MSRV declared in Cargo.toml (rust-version = "1.91").
[toolchain]
channel = "1.91"
components = ["rustfmt", "clippy"]
```

Verify: `cargo --version` (from the repo root)
Expected: reports 1.91, not the ambient default.

- [ ] **Step 2: Fix and widen the MSRV job**

In `.github/workflows/ci.yml`, replace the `Check MSRV all features` step:

```yaml
      - name: Check MSRV all features
        run: |
          cargo "+$MSRV" check --workspace --all-targets --all-features

      - name: Check MSRV — simulator
        run: |
          cargo "+$MSRV" check --manifest-path iroh-sim/Cargo.toml --all-targets --all-features

      - name: Check MSRV — relay v1 interop
        run: |
          cargo "+$MSRV" check --manifest-path compat/relay-v1-interop/Cargo.toml --all-targets --all-features
```

- [ ] **Step 3: Declare the fuzz crate's MSRV and refresh its lockfile**

Add to `fuzz/Cargo.toml` under `[package]`:

```toml
rust-version = "1.91"
```

Then regenerate the lockfile:

```bash
cargo update --manifest-path fuzz/Cargo.toml -w
git diff --stat fuzz/Cargo.lock
```

Expected: a non-empty diff — it predates the `iroh-resolver` extraction.

- [ ] **Step 4: Make the fuzz lockfile load-bearing**

In `scripts/run-bounded-fuzz.sh`, add `--locked` to the `cargo fuzz` invocations. Read the script and locate each `cargo fuzz run` or `cargo fuzz build`, then append the flag.

Verify: `scripts/run-bounded-fuzz.sh --seconds 5 --target doh_extract --artifacts /tmp/fz`
Expected: SUCCESS, no lockfile-update message.

- [ ] **Step 5: Enumerate the duplicate dependency versions**

In `deny.toml`, change line 2:

```toml
multiple-versions = "warn"
```

Then: `cargo deny check bans 2>&1 | grep -c "multiple versions"`
Expected: roughly 20 warnings, now enumerated rather than silently waived.

- [ ] **Step 6: Add the hygiene job**

Append to `.github/workflows/ci.yml`, before `ci-ok`:

```yaml
  hygiene:
    name: Repo hygiene
    timeout-minutes: 20
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Install yq
        run: sudo snap install yq
      - name: Docker build context is bounded
        run: scripts/tests/check-docker-context.sh
      - name: Vendored trees match upstream plus patch
        run: scripts/tests/check-vendor-provenance.sh
      - name: ci-ok covers every job
        run: scripts/tests/check-ci-aggregate.sh
      - name: Excluded workspaces resolve with their lockfiles
        run: |
          cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >/dev/null
          cargo metadata --manifest-path iroh-sim/Cargo.toml --locked --format-version 1 >/dev/null
          cargo metadata --manifest-path compat/relay-v1-interop/Cargo.toml --locked --format-version 1 >/dev/null
      - name: Relay v1 interop still compiles
        run: cargo check --locked --manifest-path compat/relay-v1-interop/Cargo.toml
```

- [ ] **Step 7: Add `hygiene` to `ci-ok`**

In the `ci-ok` job's `needs` list added in Task 7, insert `- hygiene`.

Verify: `scripts/tests/check-ci-aggregate.sh`
Expected: `ok:`, exit 0.

- [ ] **Step 8: Consolidate the nightly toolchain pins**

```bash
grep -rn "nightly-[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}" .github/workflows/
```

Add a single workflow-level variable to each affected workflow's `env:` block and reference it, so the three pins bump together rather than drifting.

- [ ] **Step 9: Observe each gate failing**

```bash
# lockfile gate
sed -i 's/^version = 4$/version = 3/' fuzz/Cargo.lock
cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 >/dev/null; echo "exit=$?"
git checkout fuzz/Cargo.lock

# interop compile gate
echo "compile_error!(\"probe\");" >> compat/relay-v1-interop/src/lib.rs
cargo check --locked --manifest-path compat/relay-v1-interop/Cargo.toml; echo "exit=$?"
git checkout compat/relay-v1-interop/src/lib.rs
```

Expected: non-zero exit from both. If `src/lib.rs` does not exist, use the crate's actual root — check `compat/relay-v1-interop/Cargo.toml`.

- [ ] **Step 10: Commit**

```bash
git add rust-toolchain.toml deny.toml fuzz/ .github/workflows/ci.yml scripts/
git commit -m "ci: install the cheap correctness gates

Pins the toolchain so local builds reproduce CI. The MSRV job claimed
all-features coverage without passing the flag and never checked iroh-sim
or compat, both of which declare rust-version 1.91. fuzz/Cargo.lock
predated the iroh-resolver extraction and was never enforced. Relay v1
interop only compiled on a weekly cron, so API drift surfaced a week after
the change that caused it. deny.toml globally waived 20 duplicate version
groups; they are now enumerated.

Adds a hygiene job wiring up the Docker-context, vendor-provenance and
ci-ok-coverage checks from earlier tasks."
```

---

## Task 13: Cache the two required jobs

**Files:**
- Modify: `.github/workflows/ci.yml` (`simulation_contracts` at 76–158, `simulation_gate` at 159–222)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing consumed by later tasks.

**Background:** `simulation_contracts` and `simulation_gate` gate every pull request and are the only expensive jobs without build caching. The repo already has the machinery — `mozilla-actions/sccache-action` and a local `./.github/actions/sccache-probe` — used by the `msrv` job.

- [ ] **Step 1: Measure the current duration**

```bash
gh run list --workflow=ci.yml --limit 10 --json databaseId --jq '.[].databaseId' | while read -r id; do
  gh api "repos/holon-technologies/iroh/actions/runs/$id/jobs" \
    --jq '.jobs[] | select(.name | test("simulation_(contracts|gate)")) | "\(.name) \(.started_at) \(.completed_at)"'
done
```

Record the typical duration for comparison in Step 4.

- [ ] **Step 2: Add caching to both jobs**

For `simulation_contracts` and `simulation_gate`, add an `env:` block matching the `msrv` job's:

```yaml
    env:
      RUSTC_WRAPPER: "sccache"
      SCCACHE_GHA_ENABLED: "on"
```

And after the toolchain setup step in each, before the first `cargo` invocation:

```yaml
      - name: Install sccache
        uses: mozilla-actions/sccache-action@<sha>  # v0.0.10
        continue-on-error: true
      - uses: ./.github/actions/sccache-probe
```

Use the SHA resolved in Task 8. `continue-on-error: true` matches the existing usage — a cache outage must not fail a required job.

- [ ] **Step 3: Verify the workflow parses and the jobs still pass**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('valid yaml')"
```

Push and open a pull request. Confirm both jobs pass.

- [ ] **Step 4: Verify caching actually engages**

Push a second, trivial commit to the same pull request, then:

```bash
gh run list --workflow=ci.yml --limit 1 --json databaseId --jq '.[0].databaseId' | while read -r id; do
  gh run view "$id" --log | grep -iE "sccache|cache hit|compile requests" | head -20
done
```

Expected: a non-zero cache-hit rate on the second run, and a measurably shorter duration than Step 1. If the hit rate is zero, the `sccache-probe` step is misplaced — it must come after toolchain setup and before any `cargo` call.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: cache the two required simulation jobs

simulation_contracts and simulation_gate gate every pull request and were
the only expensive jobs without caching, using the same sccache machinery
the msrv job already relies on. Release builds keep cold caches for
reproducibility."
```

---

## Sequencing

Tasks 1–6 (workstream A) and 7–13 (workstream B) are independent and may proceed in parallel, with three ordering constraints:

1. **Task 7 Step 6 before Step 7.** `ci-ok` must be observed green before the ruleset requires it, or `main` becomes unmergeable.
2. **Task 12 depends on Tasks 1, 3, and 7** for the scripts its `hygiene` job invokes, and must add `hygiene` to `ci-ok`'s `needs`.
3. **Task 6 runs last.** It deletes `docs/superpowers/`, which contains this plan and its spec.

## Verification

Before declaring the work complete:

```bash
scripts/tests/check-docker-context.sh
scripts/tests/check-vendor-provenance.sh
scripts/tests/check-ci-aggregate.sh
scripts/tests/check-issues-enabled.sh
cargo fmt --all --check
scripts/run-format.sh --check
cargo deny check --workspace --all-features
git status --porcelain
```

Every command must exit 0 and `git status` must be clean. Then confirm on GitHub that a pull request cannot merge with any job failing, and that a direct push to `main` is rejected.
