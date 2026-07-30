# Upstream provenance

This directory preserves the `iroh-docs` source history for the Holon Iroh monorepo.

## Pinned source

- Repository: <https://github.com/n0-computer/iroh-docs>
- Release tag: `v0.101.0`
- Annotated tag object: `39453262e639cb1004d493e4a82f9995bc4bb604`
- Source commit: `091e8cac47bbc49cdb84b0bfed227cc163b61dfe`
- Import date: `2026-07-28`
- Expected license: `MIT OR Apache-2.0`
- Retained license files: `LICENSE-MIT`, `LICENSE-APACHE`
- Source tree fingerprint (`git ls-tree -r --full-tree` SHA-256):
  `1f5748644408649691743a2b86b857f34a0880c2d9c82bbe1d0f6358ddfbb152`

## History rewrite

- Tool: official `git-filter-repo` tag `v2.47.0`
- Tool source commit: `6f79afc8c90c592a3052e6cc53c2ca8907515bca`
- Tool embedded version identifier: `a40bce548d2c`
- Operation: `--to-subdirectory-filter protocols/iroh-docs`
- Rewritten release commit: `cbd6fdc84e0a3ab359d9798d13d3871f168cb829`
- Rewritten tree fingerprint (`git ls-tree -r --full-tree` SHA-256):
  `8d688a34ffc915b9dd80da707ae5ae8cfb0a6f8fb1cad286e821e03e37f267dc`
- Monorepo import merge: `79bb8805bb0d5ff491ccf3e3c43a4c8956acbc09`
- Commit map: [`docs/upstream/commit-maps/iroh-docs-v0.101.0.tsv`](../../docs/upstream/commit-maps/iroh-docs-v0.101.0.tsv)
- Commit-map SHA-256:
  `68c41b8682aca29f7a23e06194b9b2472215f5768b92235b63d6fececf0ef13b`

The rewrite ran in disposable bare mirror `/tmp/iroh-docs-import.fqCUTa/iroh-docs.git`, never in
the active monorepo or a push target. The exact path is diagnostic only and is not required to
reproduce the import.

## Monorepo-owned cleanup

The dedicated cleanup immediately following the import merge:

- removes imported repository-level `.cargo`, `.config`, `.github`, `.gitignore`,
  `Makefile.toml`, `cliff.toml`, `code_of_conduct.md`, `deny.toml`, and `release.toml` files;
- normalizes the legacy `MIT/Apache-2.0` license spelling to the SPDX expression
  `MIT OR Apache-2.0` and sets `publish = false` without adapting Rust source;
- excludes the standalone crate from the production workspace; and
- registers the imported state in the architecture and provenance policies.

Source, tests, examples, property-test regressions, changelog, store migrations, licenses, and the
standalone `Cargo.lock` remain at this checkpoint. The removed repository-global files are
recoverable from the import merge.

## Import validation

The following checks passed before the cleanup commit was finalized:

- the rewritten object database passed `git fsck --full`;
- all 59 release-tree paths were under `protocols/iroh-docs/`;
- the source release maps to exactly the rewritten commit recorded above;
- retained source, tests, examples, regressions, migrations, changelog, lockfile, and licenses are
  byte-for-byte unchanged from the import merge;
- the root Cargo package set and first-party production graph are unchanged; and
- the upstream-locked client, GC, and sync integration suites passed 16 tests, with the three
  upstream-marked flaky sync tests left ignored.

The following port freezes persistent and wire compatibility before adapting the imported Rust
implementation to the local v2 endpoint, blobs, and gossip crates.

## v2 workspace port

The subsequent port keeps the crate private, changes its package version and metadata to the v2
workspace line, replaces crates.io Iroh, blobs, and gossip with the local workspace packages, and
removes the superseded standalone lockfile. The production dependency graph contains no Iroh 1.x
package; the former `iroh-tickets` dependency is replaced by a local codec that retains the exact
`doc` prefix, lowercase unpadded-base32 representation, postcard discriminator, capability bytes,
and endpoint-address encoding.

Compatibility fixtures preserve `/iroh-sync/1`, document tickets, signed entries, author and
namespace secrets, canonical entry-signing bytes, range reconciliation messages, redb table names,
and the v1→v2 plus redb 2.x tuple migrations. Existing redb migration behavior remains in place:
format migrations create `.backup-redb-v1` or `.backup-redb-v2-tuples` siblings before replacing
the live file, and repeated opens do not rerun a completed migration.

The port centralizes and enforces named limits for sync frames, reconciliation parts and entries,
tickets, peers, active documents, peer history, sessions, subscribers, pending content, actor/RPC
queues, transaction age, and graceful shutdown. Endpoint addresses are validated at ticket and
start-sync boundaries; oversized peer state and malicious frames are rejected without changing a
document's capability. The setup example's Cargo target is `docs-setup` so it remains unique in the
monorepo.
