# Upstream provenance

This directory preserves and adapts the `iroh-blobs` source history for the Holon Iroh monorepo.

## Pinned source

- Repository: <https://github.com/n0-computer/iroh-blobs>
- Release tag: `v0.103.0`
- Annotated tag object: `8a9c9995aa1cdf8beefb1450619f60f79fb17e36`
- Source commit: `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc`
- Import date: `2026-07-28`
- Expected license: `MIT OR Apache-2.0`
- Retained license files: `LICENSE-MIT`, `LICENSE-APACHE`
- Source tree fingerprint (`git ls-tree -r --full-tree` SHA-256):
  `4b2eb0eec9088f20c433a18a0ccf28b1a1e32994f5812183934ae0f5f60454d4`

## History rewrite

- Tool: official `git-filter-repo` tag `v2.47.0`
- Tool source commit: `6f79afc8c90c592a3052e6cc53c2ca8907515bca`
- Tool embedded version identifier: `a40bce548d2c`
- Operation: `--to-subdirectory-filter protocols/iroh-blobs`
- Rewritten release commit: `52c1bb6994d9d1d940dc3354eacb41176fb47096`
- Rewritten tree fingerprint (`git ls-tree -r --full-tree` SHA-256):
  `ff3c1b643ecb3ba08d80763b53f1b209cbe37fe548857595f6a946284bbc7b7b`
- Monorepo import merge: `3f46aadd998e04896056adca1e5232f5e1278056`
- Commit map: [`docs/upstream/commit-maps/iroh-blobs-v0.103.0.tsv`](../../docs/upstream/commit-maps/iroh-blobs-v0.103.0.tsv)
- Commit-map SHA-256:
  `aeda18e708cf606c3c95ac046c4e1a38adbb576d27d4133fc6af404bd69b2380`

The rewrite ran in disposable bare mirror `/tmp/iroh-blobs-import.Ef56wa/iroh-blobs.git`, never in
the active monorepo or a push target. The exact path is diagnostic only and is not required to
reproduce the import.

## Monorepo-owned cleanup

The dedicated cleanup immediately following the import merge:

- removes imported repository-level `.cargo`, `.config`, `.github`, `.gitignore`, `Makefile.toml`,
  `cliff.toml`, `code_of_conduct.md`, and `deny.toml` files;
- sets `publish = false` without adapting Rust source;
- excludes the standalone crate from the production workspace; and
- registers the imported state in the architecture and provenance policies.

Source, tests, examples, regression fixtures, design documentation, assets, changelog, licenses,
and the standalone `Cargo.lock` remain. The removed files are recoverable from the import merge.
The next porting commit may change Rust APIs and workspace metadata, but it must first freeze and
then preserve the imported wire, ticket, hash, range, and persistent-state behavior.

## Import validation

The following checks passed before the cleanup commit was finalized:

- the rewritten object database passed `git fsck --full`;
- all 92 release-tree paths were under `protocols/iroh-blobs/`;
- the source release maps to exactly the rewritten commit recorded above;
- `git log --follow -- protocols/iroh-blobs/src/lib.rs` reaches preserved upstream history;
- retained source, tests, examples, fixtures, design documents, lockfile, and licenses are byte-for-byte
  unchanged from the import merge;
- the root Cargo package set and first-party dependency graph are unchanged; and
- `cargo test --manifest-path protocols/iroh-blobs/Cargo.toml --locked` passed with 100 tests
  passed, two upstream-ignored tests, and 17 documentation tests passed.
