# Upstream provenance

This directory preserves and adapts the `krikos-blobs` source history for the Holon Krikos monorepo.

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
- Operation: `--to-subdirectory-filter protocols/krikos-blobs`
- Rewritten release commit: `52c1bb6994d9d1d940dc3354eacb41176fb47096`
- Rewritten tree fingerprint (`git ls-tree -r --full-tree` SHA-256):
  `ff3c1b643ecb3ba08d80763b53f1b209cbe37fe548857595f6a946284bbc7b7b`
- Monorepo import merge: `3f46aadd998e04896056adca1e5232f5e1278056`
- Commit map: [`docs/upstream/commit-maps/krikos-blobs-v0.103.0.tsv`](../../docs/upstream/commit-maps/krikos-blobs-v0.103.0.tsv)
- Commit-map SHA-256:
  `aeda18e708cf606c3c95ac046c4e1a38adbb576d27d4133fc6af404bd69b2380`

The rewrite ran in disposable bare mirror `/tmp/krikos-blobs-import.Ef56wa/krikos-blobs.git`, never in
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
and the standalone `Cargo.lock` remained at this stage. The removed files are recoverable from the
import merge. The following port froze and preserved the imported wire, ticket, hash, range, and
persistent-state behavior before adapting the Rust implementation.

## Import validation

The following checks passed before the cleanup commit was finalized:

- the rewritten object database passed `git fsck --full`;
- all 92 release-tree paths were under `protocols/krikos-blobs/`;
- the source release maps to exactly the rewritten commit recorded above;
- `git log --follow -- protocols/krikos-blobs/src/lib.rs` reaches preserved upstream history;
- retained source, tests, examples, fixtures, design documents, lockfile, and licenses are byte-for-byte
  unchanged from the import merge;
- the root Cargo package set and first-party dependency graph are unchanged; and
- `cargo test --manifest-path protocols/krikos-blobs/Cargo.toml --locked` passed with 100 tests
  passed, two upstream-ignored tests, and 17 documentation tests passed.

## V2 port

The monorepo port keeps the crate private (`publish = false`) and makes it a root workspace member.
It adopts the workspace edition, MSRV, lints, repository metadata, dependency lockfile, and local
`krikos` v2 core. The imported standalone lockfile was removed after its release baseline was
validated; it remains recoverable from the import merge.

Compatibility is frozen by `tests/compat/v0_103_0.rs` and the filesystem metadata tests. The port
preserves:

- ALPN `/iroh-bytes/4`;
- request, range, hash, hash-sequence, `HashAndFormat`, and blob-ticket encodings;
- the v0.103 ticket prefix and lowercase unpadded-base32 representation; and
- redb entry-state type names, table names, and postcard payloads.

The Rust source hard cut replaces Krikos 1.x endpoint calls with the local v2 endpoint facade,
localizes the former `krikos-util` connection pool, and removes `iroh-tickets` from the production
graph while retaining its exact blob-ticket codec. Imported examples now use bounded v2
`EndpointAddr` construction; the old mDNS example documents direct-address discovery because the
external adapter still targets Krikos 1.x. The transfer example's Cargo target is
`blobs-transfer` so it cannot collide with the platform's `transfer` example in this workspace.

The port also adds named limits for decoded requests, range transitions and boundaries, multi-blob
requests, provider connections, store tasks, imports, downloads, child fan-out, RPC/progress
queues, connection-pool queues, and graceful shutdown. Invalid peer dimensions are rejected before
protocol work begins, while actor queues provide backpressure at their ownership boundaries.

The excluded `compat/iroh-blobs-v0-103-interop` driver links the crates.io v0.103.0 stack and local
v2 port in one diagnostic binary without adding Krikos 1.x to the production workspace. It verifies
direct QUIC blob transfers in both directions with per-phase timeouts. Run it through
`scripts/tests/check-blobs-v0-interop.sh`.
