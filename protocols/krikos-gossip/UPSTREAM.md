# Upstream provenance

This directory preserves the `krikos-gossip` source history for the Holon Krikos monorepo.

## Pinned source

- Repository: <https://github.com/n0-computer/iroh-gossip>
- Release tag: `v0.101.0`
- Annotated tag object: `fe1d26d46dd10d5004195bcbb3e4d1310ee3bc96`
- Source commit: `2ce78afe09d89d41d123f28eac19bdc831609cc8`
- Import date: `2026-07-28`
- Expected license: `MIT OR Apache-2.0`
- Retained license files: `LICENSE-MIT`, `LICENSE-APACHE`
- Source tree fingerprint (`git ls-tree -r --full-tree` SHA-256):
  `7e6d1114dacdea2074fb583ffaf5eba2515d033d4c589dc0809dc2b7786a92b0`

## History rewrite

- Tool: official `git-filter-repo` tag `v2.47.0`
- Tool source commit: `6f79afc8c90c592a3052e6cc53c2ca8907515bca`
- Tool embedded version identifier: `a40bce548d2c`
- Operation: `--to-subdirectory-filter protocols/krikos-gossip`
- Rewritten release commit: `b5cb4330e3fe5f2c61c8bebd42cf3220b1ace368`
- Rewritten tree fingerprint (`git ls-tree -r --full-tree` SHA-256):
  `3462a55691d1e925d262032096db61dd268d69ee984d085fa88eeabec7aa0f75`
- Monorepo import merge: `7c38757dbe0b2d3ee01e70e6492c6e42d3c4d662`
- Commit map: [`docs/upstream/commit-maps/iroh-gossip-v0.101.0.tsv`](../../docs/upstream/commit-maps/iroh-gossip-v0.101.0.tsv)
- Commit-map SHA-256:
  `7d2a96e8dd3c5ebc2b69d40859f8fa5e978fca327ab662ce33d4e3cfd494fdf4`

The rewrite ran in disposable bare mirror `/tmp/krikos-gossip-import.oOmChh/krikos-gossip.git`, never
in the active monorepo or a push target. The exact path is diagnostic only and is not required to
reproduce the import.

## Monorepo-owned cleanup

The dedicated cleanup immediately following the import merge:

- removes imported repository-level `.cargo`, `.config`, `.github`, `.gitignore`,
  `Makefile.toml`, `cliff.toml`, `code_of_conduct.md`, `deny.toml`, and `release.toml` files;
- normalizes the legacy `MIT/Apache-2.0` license spelling to the SPDX expression
  `MIT OR Apache-2.0` and sets `publish = false` without adapting Rust source;
- excludes the standalone crate from the production workspace; and
- registers the imported state in the architecture and provenance policies.

Source, tests, examples, simulations, changelog, licenses, and the standalone `Cargo.lock` remained
at the import checkpoint. The removed files are recoverable from the import merge.

## Import validation

The following checks passed before the cleanup commit was finalized:

- the rewritten object database passed `git fsck --full`;
- all 43 release-tree paths were under `protocols/krikos-gossip/`;
- the source release maps to exactly the rewritten commit recorded above;
- retained source, tests, examples, simulations, changelog, lockfile, and licenses are byte-for-byte
  unchanged from the import merge;
- the root Cargo package set and first-party production graph are unchanged;
- `cargo test --manifest-path protocols/krikos-gossip/Cargo.toml --locked` passed 19 unit tests and
  one documentation test; and
- `cargo test --manifest-path protocols/krikos-gossip/Cargo.toml --locked --features test-utils
  --test sim` passed all four simulator integration tests.

## v2 workspace port

The subsequent port freezes the v0.101 ALPN and postcard encodings, changes the package version and
workspace metadata to 2.0, replaces Krikos 1.x dependencies with the local v2 crates, joins the root
workspace, and removes the superseded standalone lockfile. Production code does not retain an
Krikos 1.x dependency.

The port adds named resource limits for protocol and network state and a live excluded interop
driver under `compat/iroh-gossip-v0-101-interop`. That driver forms a mixed-version mesh and
broadcasts in both directions between exact upstream iroh v1.0.3/upstream gossip v0.101.0 and the
local v2 stack. The setup example's Cargo target is `gossip-setup` so it remains unique in the
monorepo.
