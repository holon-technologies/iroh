# V2 architecture-cut readiness — 2026-07-27

## Verdict

The architecture hard cut is implemented, locally verified, and committed at
`b433041dce6fcb1f45287e4602e7cab271bf81df`. It is **not yet release-ready** because the hosted and
privileged evidence below is still pending. This record does not authorize a tag, crate
publication, GitHub release, container publication, or infrastructure change.

Relay interoperability is retained against the sole approved upstream baseline, tag `v1.0.3` at
commit `f2eb930dda3779c6d852b72f3712aacd6e573ab1`. Golden protocol checks and live client/server
processes passed in both directions.

## Candidate identity

| Field | Value |
| --- | --- |
| Verification date | 2026-07-27; immutable baseline locked 2026-07-28 |
| Architecture-cut revision | `b433041dce6fcb1f45287e4602e7cab271bf81df` |
| Tree state | Architecture cut committed; baseline metadata recorded in a follow-up commit |
| Host | Linux 6.8.0-136-generic, x86_64 |
| Rust | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Cargo | `cargo 1.97.1 (c980f4866 2026-06-30)` |
| Rust API inventory baseline | Upstream `v1.0.3`; exact intentional v1-to-v2 findings audited |
| Post-cut Rust API baseline | `b433041dce6fcb1f45287e4602e7cab271bf81df` |

The architecture-cut revision now identifies the exact source changes under test. Hosted evidence
must be collected from the pushed branch containing that revision and its baseline-lock follow-up
before release readiness can be claimed.

## Implemented cut

- Added and enforced the production dependency graph, isolated simulator workspace, and exact TLS
  provider rules.
- Extracted generic DNS resolution to `iroh-resolver`; endpoint-record composition remains in
  `iroh-dns`, and relay no longer depends on endpoint DNS or pkarr concerns.
- Replaced partial simulation injection with one validated `SimulationEnvironment`.
- Split endpoint, socket, relay actor, relay server/HTTP, simulator CLI, runner, and scenario-model
  responsibilities behind narrow facades.
- Moved DNS-server black-box tests to package integration boundaries and retained private store
  tests beside their implementation.
- Added the intentional v1-to-v2 API inventory and post-cut semver transition policy.
- Added frozen and live relay compatibility gates for exact upstream `v1.0.3`.
- Corrected DNS-server shutdown so DNS, HTTP, and store cancellation begins atomically and all
  components share one absolute deadline.
- Prevented workspace feature unification from selecting the relay binary without an explicit
  provider bundle, while preserving provider-neutral library embedding.

The authoritative current design is in `docs/architecture.md`; wire obligations are in
`docs/relay-compatibility.md`; source migration is in `docs/release/v2-migration.md`.

## Local verification evidence

| Area | Command | Result |
| --- | --- | --- |
| Formatting | `cargo make format-check` | Pass |
| Diff hygiene | `git diff --check` | Pass |
| Architecture | `scripts/tests/check-workspace-architecture.sh` | Pass |
| Release source contracts | `scripts/tests/check-v2-release-readiness.sh`; `scripts/tests/check-release-fork-boundary.sh` | Pass |
| Semver policy source | `scripts/tests/check-v2-semver-policy.sh` | Pass |
| V1-to-v2 API audit | `scripts/run-v2-semver-checks.sh --allow-dirty` | Pass; the exact ten intentional resolver moves match `scripts/v2-api-breaks.txt` |
| Post-cut API stability | `scripts/run-v2-semver-checks.sh --allow-dirty` | Pass against `b433041dce6fcb1f45287e4602e7cab271bf81df`; no findings across all seven public crates |
| Workspace tests | `RUSTFLAGS='-D warnings --cfg skip_patchbay' cargo test --workspace --all-features` | Pass; Patchbay correctly excluded for its privileged lane |
| Simulator tests and benches | `cargo test --manifest-path iroh-sim/Cargo.toml --all-targets --all-features` | Pass |
| All-feature lint | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Pass |
| Default-feature lint | `cargo clippy --workspace --all-targets --lib --bins --tests --benches --examples -- -D warnings` | Pass |
| No-default-feature lint | `cargo clippy --workspace --no-default-features --all-targets --lib --bins --tests --benches --examples -- -D warnings` | Pass |
| Simulator lint | `cargo clippy --manifest-path iroh-sim/Cargo.toml --all-targets --all-features -- -D warnings` | Pass |
| Minimal native graph | `cargo check -p iroh --no-default-features` | Pass |
| TLS feature graph | `scripts/tests/check-relay-tls-features.sh` | Pass for provider-neutral, Ring-only, AWS-LC-only, and providerless-binary failure cases |
| Workspace docs | `cargo doc --workspace --all-features --no-deps --document-private-items` | Pass |
| Simulator docs | `cargo doc --manifest-path iroh-sim/Cargo.toml --all-features --no-deps --document-private-items` | Pass |
| External public types | `cargo make check-external-types` | Pass; warnings are retained hidden/unused allowlist diagnostics, with zero errors |
| Dependency policy | `cargo deny check` | Pass: advisories, bans, licenses, and sources |
| Determinism inventories | `scripts/check-determinism-boundaries.sh --check`; `scripts/check-determinism-semantic.sh --check` | Pass after reviewed classification update |
| Relay golden compatibility | `scripts/tests/check-relay-compatibility.sh` | Pass against exact upstream `v1.0.3` |
| Relay live compatibility | `scripts/tests/check-relay-compatibility.sh --live` | Pass current client→v1.0.3 server and v1.0.3 client→current server |
| Release packages | `scripts/verify-release-packages.sh --allow-dirty` | Pass; all nine archives extracted and rebuilt in dependency order |

An unmodified `cargo test --workspace --all-features` reached the Patchbay test binary and aborted
because this container cannot initialize a Linux user namespace (`write setgroups`). This is an
environment capability failure. Normal CI uses `--cfg skip_patchbay` for the ordinary workspace
lane and runs Patchbay separately after enabling unprivileged user namespaces; that privileged
lane was not reproduced locally.

## Evidence still required from the committed candidate

- Run the complete hosted feature/platform matrix on that same commit: MSRV, minimal versions,
  Windows, macOS, Android, Wasm, cross/Wine, and the configured default/all/no-default test jobs.
- Run and retain the privileged Patchbay suite/public-parity smoke, Netsim, bounded fuzz smoke,
  deterministic scheduled scenarios/soak, and production resource-canary evidence.
- Run the release workflow with publication disabled and retain package, binary, image, checksum,
  SBOM, and provenance artifacts tied to the exact candidate SHA.
- Obtain repository-owner review and explicit publication/tag/container authority separately.

Until those items are complete, the implementation is ready for review but the v2 release
checklist remains blocked.
