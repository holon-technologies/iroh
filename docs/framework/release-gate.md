# Framework release gate

`framework/release-gate.toml` blocks four packages from being published to a registry:

| Order | Package | Path |
|---|---|---|
| 1 | `krikos-blobs` | `protocols/krikos-blobs` |
| 2 | `krikos-gossip` | `protocols/krikos-gossip` |
| 3 | `krikos-docs` | `protocols/krikos-docs` |
| 4 | `krikos-app` | `framework/app` |

The first three are imported from upstream release tags (see
[the upstream sync runbook](upstream-sync.md)); `krikos-app` is this project's own
experimental application layer. All four carry `publish = false`.

## How the gate is enforced

`scripts/check-framework-release-gate.py` runs in CI in two modes:

- `--expect-closed` — the mode CI uses today. It fails if the gate has been opened, and
  it *also* fails if the closed state is internally inconsistent: `status` must be
  `"blocked"`, at least one approval must be outstanding, and the approvals table must
  contain exactly the four reviewed names as booleans.
- `--require-open` — fails unless `status` is not `"blocked"` and every approval is `true`.

While the gate is closed the script additionally pins the things a premature release
would have to disturb: the exact package order and identity, root workspace membership,
retention of `publish = false`, a coordinated workspace version, presence in
`CARGO_MAKE_WORKSPACE_SKIP_MEMBERS`, and exclusion from `scripts/verify-release-packages.sh`.

The gate is deliberately hard to open by accident. What follows is what opening it
*means*.

## The four approvals

Each approval is a decision a person makes and records, not a check a script computes.
The script enforces that the decision was recorded; this document states what the
decision is about and what evidence should exist before flipping the flag to `true`.

### `package_naming`

**Question.** Are these the names these packages will carry permanently, on the registry
and in every downstream `use` statement?

**Why it gates release.** A crates.io name cannot be reused for different content after
publication, and an import path change is a breaking change for every consumer.

**Evidence.** [ADR-0002](../adr/0002-krikos-rebrand.md) decided the `krikos-*` naming
scheme, its scope, and the 1.0.0 launch version.
`scripts/tests/check-rebrand-complete.sh` holds the tree at zero un-exempted
occurrences of the former names, and
`scripts/tests/check-rebrand-unknown-crates.sh` asserts every `krikos-<suffix>`
reference names a package that actually exists.

**Decided by.** The project owner, via ADR.

**State.** The decision of record exists. This approval is a matter of confirming it
still describes the four gated packages at release time.

### `registry_ownership`

**Question.** Does this project control these four names on the registry it will publish
to, under an account that will still exist and still have publish rights later?

**Why it gates release.** Publishing into a name you do not own is not possible;
publishing from an account that lapses strands the crate. Name squatting on
`krikos-*` by a third party between now and release would force a rename, which
re-opens `package_naming`.

**Evidence.** The four names owned by the Holon organisation on crates.io, with owner
rights held by more than one person, and the CI publish token scoped to them.

**Decided by.** The project owner, who holds the registry account.

**State.** Deliberately deferred. The names are not yet reserved.

### `public_api_baseline`

**Question.** Is the public API surface of these packages one this project is willing to
support under semantic versioning — and is it recorded, so later drift is visible as a
diff rather than discovered by a downstream build break?

**Why it gates release.** Publishing 1.0.0 is a promise that the surface will not break
within the major version. Three of these four packages inherited their API wholesale
from upstream at a pinned release tag; nobody on this project designed that surface, and
until it is recorded there is no baseline against which an accidental break can be
distinguished from a sanctioned one.

**The concrete gap.** `scripts/run-v2-semver-checks.sh` maintains exactly this kind of
baseline — but only for the seven core packages (`krikos`, `krikos-base`,
`krikos-runtime`, `krikos-resolver`, `krikos-dns`, `krikos-dns-server`,
`krikos-relay`), against a commit pinned in `scripts/v2-api-baseline.toml`, with
sanctioned breaks enumerated in `scripts/v2-api-breaks.txt`. **None of the four gated
packages are in that list.** They have no baseline because they are not in the harness.

**Evidence.** Each of the four packages added to the semver harness, with a pinned
baseline ref and a reviewed sanctioned-breaks list; a green run of that harness; and a
recorded review confirming the inherited surface is one this project intends to support
rather than one it merely happens to re-export.

**Decided by.** Whoever will answer the support requests — in practice the project
owner, on the basis of a semver-harness run covering all four.

**State.** Undefined before this document. No baseline exists for any of the four.

### `data_schema_support`

**Question.** What range of previously-written on-disk data does a published version
promise to open, and what happens when it meets data it cannot?

**Why it gates release.** These packages own durable user data. A user who stores blobs
or document replicas under 1.0.0 and upgrades to 1.1.0 must not find the store
unreadable. Unlike an API break, this one cannot be worked around by pinning a version
after the fact — the data is already written.

**What exists today.** The mechanisms are real but the policy is not:

- `krikos-blobs` versions its redb tables in their names (`blobs-0`, `tags-0`,
  `inline-data-0`, `inline-outboard-0`), so a schema change is expressible as a new
  table generation.
- `krikos-docs` has 17 table definitions and four numbered forward migrations in
  `src/store/fs/migrations.rs`, run by `run_migrations` on open.
- `krikos-gossip` persists nothing; it is in-memory only and this approval is
  vacuous for it.
- `krikos-app` persists an identity and a data root (`src/identity.rs`,
  `src/data_root.rs`).

So there is a forward-migration path in the one package that most needs it, and a
version-in-table-name convention in another. What is missing is a *stated commitment*:
how far back migrations must work, whether downgrade is supported at all, and what a
version that meets unreadable data must do.

**Evidence.** A written on-disk compatibility policy covering the three persisting
packages, stating at minimum: the supported upgrade range, whether downgrade is
supported (the honest answer is likely "no"), the required failure behaviour on
unrecognised schema versions (refuse and report, never silently discard), and a test
that opens a store written by the previous release.

**Decided by.** The project owner, on the basis of that written policy.

**State.** Undefined before this document. No policy is recorded, and no test opens a
store written by an earlier version.

## Opening the gate

Opening it is a deliberate, reviewed change:

1. Satisfy an approval and record its evidence, then set that flag to `true`.
2. When all four are `true`, set `status` to something other than `"blocked"`.
3. Switch CI from `--expect-closed` to `--require-open`.
4. Remove `publish = false`, drop the packages from
   `CARGO_MAKE_WORKSPACE_SKIP_MEMBERS`, and add them to
   `scripts/verify-release-packages.sh` — all of which the closed gate currently pins.

Steps 1 and 2 without steps 3 and 4 leave a gate that permits release without checking
it, so they belong in one change.
