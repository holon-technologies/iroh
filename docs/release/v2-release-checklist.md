# Krikos v2 architecture release checklist

This is the blocking release contract for the v2 architecture cut's `1.0.0`
launch release ([ADR-0002](../adr/0002-krikos-rebrand.md) sets the launch
version at `1.0.0`, superseding the `2.0.0` this checklist originally
targeted before the rebrand; "v2" below still names the architecture
generation, not the crate SemVer). An unchecked item means the release is
not ready. Preparing a candidate does not authorize publishing a crate, tag,
GitHub release, or container.

## Source and compatibility

- [ ] Every publishable crate manifest and internal dependency requirement uses
  `1.0.0`; `Cargo.lock` contains no stale dependency requirement on a
  pre-rebrand package name (see the mapping in
  [`krikos-migration.md`](krikos-migration.md)).
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
- [ ] `krikos-runtime` and `krikos-resolver` package successfully and their README/API
  documentation accurately describes each support boundary.
- [ ] `krikos-noq` `1.1.0-holon.1` and `krikos-hickory-server`
  `0.26.1-holon.1` retain their reviewed resource-bound tests, provenance,
  licenses, and exact dependency requirements.
- [ ] Production packages resolve one registry Rustls package; the isolated
  simulator resolves one locally patched Rustls package and owns all
  deterministic-provider implementation code.

## Deterministic and integration evidence

- [ ] Formatting, clippy, docs, MSRV, dependency policy, all feature variants,
  minimal versions, Windows, macOS, Android, Wasm, cross, and Wine jobs are
  green on the exact candidate commit.
- [ ] All nine bounded fuzz smoke targets are green on the candidate: the five platform targets,
  application manifest and protocol registration, blob tickets, and document tickets.
- [ ] Deterministic simulation contracts, corpus, campaigns, replay, daily soak,
  and the five fixed-seed nightly scenarios are green.
- [ ] The local-first application model fixture, docs migration tests, direct and forced-relay
  two-node acceptance flow, blobs and gossip upstream interoperability, and exact-tag provenance
  checks are green.
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
  `krikos-noq`, `krikos-hickory-server`, `krikos-base`, `krikos-runtime`, `krikos-resolver`,
  `krikos-dns`, `krikos-relay`, `krikos`, then `krikos-dns-server`. Source paths bootstrap archive
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

## Experimental local-first framework gate

- [ ] `framework/release-gate.toml` remains blocked for the platform v2 release, and
  `scripts/check-framework-release-gate.py --expect-closed` proves all four packages retain
  `publish = false`.
- [ ] `scripts/check-framework-package-layout.sh` validates package contents and dependency order:
  `krikos-blobs`, `krikos-gossip`, `krikos-docs`, then `krikos-app`.
- [ ] While the gate is closed, the four packages remain outside the publishable package verifier
  and the external-type/semver baseline, but retain formatting, clippy, docs, tests, migrations,
  deterministic modeling, fuzzing, resource, integration, and compatibility coverage.
- [ ] Every imported upstream update follows `docs/framework/upstream-sync.md`: resolve an exact
  tag and commit, retain licenses and migrations, document the fork delta, and rerun bidirectional
  compatibility before integration.

## Repository and publication authority

- [ ] Required checks and branch protection/rulesets are configured for the
  default branch by a repository owner.
- [ ] The candidate commit is reviewed, signed off, and unchanged after all
  required evidence is collected.
- [ ] A repository owner explicitly authorizes crates.io publication.
- [ ] Before any experimental framework publication, a repository owner separately approves all
  four package names, registry ownership, public API baseline, and persistent-data schema support
  commitments and opens the machine-readable framework gate.
- [ ] The `krikos-noq` and `krikos-hickory-server` crates.io names are claimed by
  an authorized Holon publisher before dependent Krikos crates are published.
- [ ] A repository owner explicitly authorizes the immutable `v1.0.0` tag,
  draft GitHub release, and any GHCR publication.
- [ ] After publication, install and smoke tests pass from crates.io, release
  archives, and both container architectures before the draft is published.
