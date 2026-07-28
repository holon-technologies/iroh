# Iroh 2.0 release checklist

This is the blocking release contract for `2.0.0`. An unchecked item means the
release is not ready. Preparing a candidate does not authorize publishing a
crate, tag, GitHub release, or container.

## Source and compatibility

- [ ] Every publishable crate manifest and internal dependency requirement uses
  `2.0.0`; `Cargo.lock` contains no stale Iroh `1.x` package.
- [ ] `CHANGELOG.md` and every publishable crate changelog have complete
  `Unreleased` entries, including the fallible constructors and
  `Clients::register`.
- [ ] The migration guide has been checked against the final public API diff
  from `v1.0.3`, and `scripts/v2-api-breaks.txt` exactly matches the retained
  cargo-semver-checks inventory.
- [ ] After the architecture cut is approved, `post_cut_ref` in
  `scripts/v2-api-baseline.toml` is the immutable 40-character cut commit; it
  is not a branch, tag, or dirty worktree.
- [ ] `scripts/run-v2-semver-checks.sh` reports no minor-level regressions
  against that post-cut baseline. The independent upstream `v1.0.3` relay-wire
  matrix remains green.
- [ ] `iroh-runtime` and `iroh-resolver` package successfully and their README/API
  documentation accurately describes each support boundary.
- [ ] `iroh-noq` `1.1.0-holon.1` and `iroh-hickory-server`
  `0.26.1-holon.1` retain their reviewed resource-bound tests, provenance,
  licenses, and exact dependency requirements.
- [ ] Production packages resolve one registry Rustls package; the isolated
  simulator resolves one locally patched Rustls package and owns all
  deterministic-provider implementation code.

## Deterministic and integration evidence

- [ ] Formatting, clippy, docs, MSRV, dependency policy, all feature variants,
  minimal versions, Windows, macOS, Android, Wasm, cross, and Wine jobs are
  green on the exact candidate commit.
- [ ] All four bounded fuzz smoke targets are green on the candidate.
- [ ] Deterministic simulation contracts, corpus, campaigns, replay, daily soak,
  and the five fixed-seed nightly scenarios are green.
- [ ] The GitHub-hosted Patchbay public-parity smoke is green.
- [ ] The full namespace Patchbay suite is green, or every unsupported case is
  documented with retained equivalent evidence and an owner-approved waiver.
- [ ] Netsim is green against the pinned Chuck commit and its report artifact is
  retained.
- [ ] The production resource canary is green and its signed manifest,
  saturation behavior, latency, RSS, file-descriptor, and task-count evidence
  have been reviewed.

## Package and binary dry runs

- [ ] `scripts/verify-release-packages.sh` succeeds in dependency order:
  `iroh-noq`, `iroh-hickory-server`, `iroh-base`, `iroh-runtime`, `iroh-resolver`,
  `iroh-dns`, `iroh-relay`, `iroh`, then `iroh-dns-server`. Source paths bootstrap archive
  creation only; the authoritative build uses normalized extracted packages
  exclusively, and no patch is written into a crate archive.
- [ ] Each packaged crate builds using only packaged content.
- [ ] The manually dispatched release workflow succeeds with
  `create_release=false` and `publish_containers=false` for an immutable
  40-character candidate commit SHA.
- [ ] All seven native release bundles pass `--version`, have verified SHA-256
  sidecars, and are retained as GitHub artifacts.
- [ ] Both multi-platform GHCR images build with publication disabled and use
  the exact retained musl binaries.
- [ ] The candidate retains an SPDX 2.3 SBOM, SHA-256 checksums, build
  provenance attestations for every archive and crate package, and an SBOM
  attestation. Every attestation names the exact candidate commit.

## Repository and publication authority

- [ ] Required checks and branch protection/rulesets are configured for the
  default branch by a repository owner.
- [ ] The candidate commit is reviewed, signed off, and unchanged after all
  required evidence is collected.
- [ ] A repository owner explicitly authorizes crates.io publication.
- [ ] The `iroh-noq` and `iroh-hickory-server` crates.io names are claimed by
  an authorized Holon publisher before dependent Iroh crates are published.
- [ ] A repository owner explicitly authorizes the immutable `v2.0.0` tag,
  draft GitHub release, and any GHCR publication.
- [ ] After publication, install and smoke tests pass from crates.io, release
  archives, and both container architectures before the draft is published.
