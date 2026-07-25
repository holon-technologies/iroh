# Iroh 2.0 release-closure audit — 2026-07-25

## Decision

The source tree is locally ready to become a `2.0.0` release candidate. The
release itself remains **blocked** until this work is committed, pushed, and
validated by the hosted candidate gates. No crate, tag, GitHub release, or
container publication is authorized by this audit.

This audit covers a dirty worktree based on
`96de37ab7191f58a72ee71abeafc7c11ecd9cf7a`. At audit time, local `main` and
`origin/main` both pointed to that commit and the worktree had 93 porcelain
status entries. Hosted results for that base commit do not validate the
uncommitted closure changes.

## Locally closed

| Area | Result | Evidence |
| --- | --- | --- |
| Version and package graph | Pass | Every publishable Iroh crate is `2.0.0`; internal requirements and production/simulator locks are consistent; the two vendored forks use their `-holon.1` identities. |
| Public API compatibility | Pass | `scripts/run-v2-semver-checks.sh` completed strict minor-level comparison with `v1.0.3` for `iroh`, `iroh-base`, `iroh-dns`, `iroh-dns-server`, and `iroh-relay`; each package passed all 196 applicable checks. |
| Release packages | Pass | `scripts/verify-release-packages.sh --allow-dirty` created, normalized, unpacked, and built all eight packages in dependency order without a hidden path or patch dependency. |
| Native binaries | Pass locally | Optimized GNU and static musl `x86_64` relay and DNS server binaries built and reported `2.0.0`. The hosted seven-target matrix remains required. |
| Containers | Pass locally | Both `linux/amd64` targets built from `docker/Dockerfile.ci` with Buildx and ran their `--version` smoke tests. Hosted `linux/arm64` evidence remains required. |
| Supply chain | Pass locally | The release workflow creates SHA-256 checksums, an SPDX 2.3 SBOM from the production lockfile, build provenance attestations, and an SBOM attestation. The pinned Syft 1.44.0 output passed the workflow's exact local schema check. |
| Formatting and workflow syntax | Pass | `scripts/run-format.sh --check`, every `scripts/tests/check-*.sh` contract, Actionlint, and ShellCheck for every changed/new shell script passed. |
| Strict lint | Pass | Root and simulator workspaces passed all-workspace, all-feature, all-target Clippy with warnings denied. |
| Test suites | Pass in isolated environment | Root and simulator all-feature/all-target test suites passed through `scripts/iroh-test-env`. Patchbay passed 46 cases with 13 explicitly ignored capability/reliability cases. |
| Deterministic testing | Pass | Boundary contracts, semantic contracts, campaigns, corpus/replay paths, fixed-seed nightly scenarios, bounded fuzz tooling, and daily soak/resource workflow contracts passed. |
| Resource hardening | Pass locally | Finite connection, request, task, session, body, retained-state, and shutdown limits are covered by regression and saturation tests. No unresolved Critical or High TigerStyle finding was found in this closure pass. |

A direct host invocation of `scripts/run-all-tests.sh` reached Patchbay and was
then rejected by the host's user-namespace `setgroups` boundary. The same
suite passed through the repository's isolated test environment. That is an
expected host capability boundary, not a skipped release requirement.

## External state observed

The following read-only observations were made on 2026-07-25:

- `holon-technologies/iroh` is public, its default branch is `main`, and the
  authenticated operator has repository administration permission.
- The repository has no rulesets and GitHub reports `main` as unprotected.
- Actions are enabled for all actions. Default workflow permissions are read
  only; actions may not approve pull-request reviews; SHA pinning is not
  repository-enforced.
- The repository has zero self-hosted runners, Actions secrets, Actions
  variables, and GitHub releases.
- crates.io returned `404` for both `iroh-noq` and
  `iroh-hickory-server`. The required fork namespaces are therefore not yet
  controlled by an authorized Holon publisher.
- [CI run 30155190396](https://github.com/holon-technologies/iroh/actions/runs/30155190396),
  [Patchbay run 30155190120](https://github.com/holon-technologies/iroh/actions/runs/30155190120),
  [Netsim run 30155190179](https://github.com/holon-technologies/iroh/actions/runs/30155190179),
  and [Wine run 30155190240](https://github.com/holon-technologies/iroh/actions/runs/30155190240)
  remained queued against the pre-closure base commit. Their results cannot be
  used as candidate evidence.
- The repeatedly failing project-board workflow is deleted by this worktree;
  the deletion does not take effect until the changes are pushed.

## Blocking candidate gates

These are release blockers, not implementation work that can be honestly
closed from a dirty local tree:

1. Create one reviewed immutable candidate commit and push it to the default
   branch.
2. Configure an owner-approved ruleset or branch protection policy with the
   final required hosted checks.
3. Obtain green hosted evidence on that exact commit for CI, MSRV, platforms,
   dependency policy, fuzz smoke, Patchbay public-parity and full namespace
   coverage, Netsim, Wine, deterministic nightly/soak, and the resource canary.
4. Claim and publish `iroh-noq` and `iroh-hickory-server` in dependency order
   under an authorized Holon crates.io account before publishing dependent
   crates.
5. Dispatch the release workflow against the exact 40-character commit SHA
   with release and container publication disabled. Retain and inspect all
   native bundles, crate packages, checksums, SBOM, and Sigstore bundles.
6. Obtain explicit owner authorization before crates.io publication, the
   immutable `v2.0.0` tag, draft GitHub release, or GHCR publication.
7. After publication, smoke-test crates.io installs, every release archive,
   and both container architectures before publishing the draft release.

Until all items in `docs/release/v2-release-checklist.md` are checked against
the same immutable revision, the correct release status is **not ready**.
