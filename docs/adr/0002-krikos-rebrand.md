# ADR-0002: Rebrand the fork as Krikos and publish at 1.0.0

## Status

Accepted on 2026-07-30. The project owner chose the name, the rename scope, the launch version, and
the import-path policy.

This ADR settles the question [ADR-0001](0001-local-first-application-framework-monorepo.md)
explicitly left open: it "does not define ... a final public product/crate name."

## Scope

This decision covers the published identity of every package in this repository: package names,
library names, Rust import paths, directory names, the launch version, and the fork-provenance
statement that accompanies them.

It does not change any public API surface, wire protocol, relay compatibility guarantee, or
dependency direction. It does not decide the marketing site, the repository name, or whether the
GitHub organisation is renamed.

## Context

This repository is a hard fork of `n0-computer/iroh`. Seven packages are marked publishable and
every one of them carries a name that n0-computer already owns on crates.io:

| Package | crates.io owner |
|---|---|
| `iroh` | dignifiedquire, github:n0-computer:iroh-publisher |
| `iroh-base` | same |
| `iroh-dns` | same |
| `iroh-dns-server` | same |
| `iroh-relay` | same |
| `iroh-resolver` | dignifiedquire |
| `iroh-runtime` | unclaimed |

`cargo publish` for six of the seven would fail with a 403. No release is possible under the
current names, and the release pipeline contains no publish step that would have surfaced this.

A further eight packages are unpublished, including three protocol crates imported from upstream
release tags under `protocols/`, tracked by `docs/upstream/commit-maps/` and re-synced through the
runbook at `docs/framework/upstream-sync.md`.

## Decision

### The name

**Krikos** — Greek κρίκος, "link; ring of a chain". Chosen over `Isthmos`, `Diodos` and
`Syndesmos`. It is the aptest single word for a connection library, is six letters, carries no
English collision or negative connotation, and reads cleanly as an identifier. It sits under the
Holon name coherently: krikoi are the links that bind parts into a whole.

`krikos` and every `krikos-*` name were verified unclaimed on crates.io on 2026-07-30. **Absence is
not reservation.** The names must be claimed before this repository is made public; a public
showcase announcing an unclaimed name is an invitation to squatters.

### Rename scope: everything

Every package is renamed, including the imported protocol crates. The repository reads as one
coherent product rather than a mix of `krikos-*` and `iroh-*`.

The cost is accepted deliberately: every future upstream protocol sync must reapply the rename on
top of the import. `docs/framework/upstream-sync.md` gains a step for this, and the provenance
records in `docs/upstream/commit-maps/` continue to name the upstream packages, so the import's
origin stays traceable even though the local package name differs.

The vendored fork packages `iroh-hickory-server` and `iroh-noq` are renamed to `krikos-hickory-server`
and `krikos-noq`. These are Holon-published fork names, not upstream ones, so they fall inside the
rename.

**Nothing inside a vendored source tree is renamed.** `vendor/*/src` is byte-verified against the
upstream crates.io package by `scripts/tests/check-vendor-provenance.sh`. Only the package name in
each vendored `Cargo.toml` changes, and that change lives in the checked-in `vendor/*.patch`, which
is already the mechanism for every other Holon delta.

### Version: 1.0.0

Krikos launches at `1.0.0`, not the previously-discussed `0.1.0`.

`0.x` tells every consumer that minor releases may break, which contradicts the positioning this
work exists to support: a hardened networking library you can take a dependency on. The code is a
v2 iroh with a deterministic-simulation verification system around it, not a prototype. Launching
at `0.1.0` would also leave the codebase, migration guide and architecture contract describing "v2"
while the crate metadata said otherwise.

### Import paths change

Package name, library name and import path all become `krikos*`. `use iroh::Endpoint` becomes
`use krikos::Endpoint` across roughly 430 `use` statements.

The alternative — renaming the package while keeping `[lib] name = "iroh"` — would make migration
from upstream a one-line manifest change and would have produced a far smaller diff. It was
rejected because a crate whose package and library names disagree is a permanent source of
confusion, and because a fresh brand that still compiles as `iroh` is not a fresh brand.

## Alternatives rejected

- **`holon-iroh` / `iroh-holon` prefixes.** Provenance is legible from the name and discovery via
  "iroh" is preserved, but the suffix form reads like an official n0 sub-crate and risks implying an
  endorsement upstream has not given.
- **Keeping the `iroh` names and publishing anyway.** Not possible; the names are owned.
- **Git-dependency distribution with no rename.** Viable but abandons the "library you can depend
  on" positioning and leaves the README, badges and release machinery describing a crates.io
  presence that does not exist.
- **Renaming only the seven publishable crates.** Smallest change that unblocks publishing, but
  leaves a visibly mixed tree.

## Consequences

### Mechanical scale

547 tracked files contain the string `iroh`, across 8,560 lines. Twelve directories are renamed.
This is the largest single change the repository has taken, and it is almost entirely mechanical —
which makes it well suited to automated transformation followed by machine verification, and badly
suited to review by reading the diff.

### Verification assets that encode the old names

The rename invalidates several artefacts that this repository relies on as gates. Each must be
regenerated or updated, and each is a place where a silent, passing-but-wrong result is possible:

- `scripts/determinism-boundaries.txt` (1,078 lines) and
  `scripts/determinism-boundaries.semantic.txt` (689 lines) are **path-keyed inventories** —
  entries look like `iroh-dns-server/src/admission.rs:166`. Every directory rename invalidates
  them wholesale.
- `scripts/workspace-architecture.toml` encodes the dependency-direction policy by package name.
- Roughly sixty scripts under `scripts/` reference package or directory names.
- `check-vendor-provenance.sh` excludes a file named literally `IROH-VENDOR.md`.
- `check-v2-release-readiness.sh`, `verify-release-packages.sh`, `run-v2-semver-checks.sh` and the
  workflow contract checkers all assert on package names.

This repository has already been bitten five times by hardcoded lists going stale
(`.dockerignore`'s allowlist, `ci-ok`'s `needs`, five contract checkers broken by action SHA
pinning, `version_manifests`, and a hand-maintained nine-script verification list). The rename will
trip every remaining instance at once. That is a feature: it forces them all into the open in a
single change, verified by `scripts/tests/run-all-local-checks.sh`, which discovers checks from the
workflows rather than from a list.

### Upstream compatibility

Relay wire compatibility with upstream `v1.0.3` is unaffected — it is a protocol guarantee, not a
naming one. `compat/*-interop` crates continue to reference upstream packages by their upstream
names, because they exist to test against upstream.

### Migration

Downstream migration from upstream iroh is no longer a one-line manifest change. A migration guide
must state the package mapping and the import-path rewrite, and the existing
`docs/release/v2-migration.md` needs a companion section.

## Addendum: `post_cut_ref` advanced to the rebrand (2026-07-30)

`scripts/v2-api-baseline.toml`'s `post_cut_ref` freezes the public-API-surface baseline that
`scripts/run-v2-semver-checks.sh` compares every subsequent change against in `post-cut` mode. It
held `b433041dce6fcb1f45287e4602e7cab271bf81df` (the pre-rebrand v2 architecture-cut commit), so
comparing this rebrand's tip against it correctly reported two breaking changes in `krikos-dns`:

- `IROH_TXT_NAME` (a `pub const`) renamed to `KRIKOS_TXT_NAME`.
- `ParseError::NotAnIrohRecord` (a `pub enum` variant) renamed to `NotAKrikosRecord`.

Both are sanctioned by this ADR's decision that import paths, and therefore every public
identifier that embeds the old name, change (see "Import paths change" above) — the checker was
not wrong, it was comparing against a baseline that predates the decision it is now asked to
verify compliance with. The project owner decided to advance `post_cut_ref` to this rebrand, in
the same change that makes the rename official, rather than leave the check red indefinitely
waiting for a separate maintainer action.

**Value chosen and why:** `post_cut_ref` is now `ee634c133d7d46c67822312293021abeaf0a3d73`, the
last commit of this rebrand branch before the commit that changes this file — i.e. the commit at
which every rebrand fix (mechanical sweep, guard/policy updates, version bump, migration docs, the
CI-gap closure, and every review-round fix including this addendum's own predecessors) is already
landed and the workspace is green apart from this baseline itself. It is not the tip *after* this
addendum, because a commit cannot embed its own hash.

**Stability after merge — read before merging with anything other than a merge commit.** A commit
SHA is only guaranteed to keep resolving (`git rev-parse --verify`, which
`run-v2-semver-checks.sh` depends on) if something keeps it reachable. Right now it is reachable
because it is an ancestor of this open PR's head. Whether it stays reachable from `main` after
merge depends entirely on the merge method:

- **Merge commit:** every commit on the branch, including this one, becomes an ancestor of the new
  commit on `main`. The SHA stays resolvable indefinitely from a plain clone of `main`. Sound.
- **Squash merge or rebase merge:** GitHub (or `git rebase`) constructs a *new* commit for the same
  tree content; this branch's original commits, including `ee634c133d...`, are not reachable from
  `main` at all. They persist only as long as something else keeps them alive (a still-open PR
  ref, a reflog entry, absence of a `git gc --prune` sweep) — not a property this repository's
  future CI runs can rely on. A future `main`-only clone/checkout would fail to resolve the ref,
  and `run-v2-semver-checks.sh` would hard-fail with "semver baseline ref is missing" (exit 66) on
  every subsequent PR, not just report a false compatibility result.

**This PR must therefore be merged with a merge commit, not squash or rebase, or this value must
be replaced with the resulting `main` commit immediately after merging by whatever method is
actually used.** If the merge method is squash or rebase, advancing `post_cut_ref` inside this PR
was the wrong moment to do it — the sound fix in that case is a small follow-up commit on `main`,
after the merge, setting `post_cut_ref` to the actual commit that lands on `main`, not to any SHA
that only ever existed on the source branch.
