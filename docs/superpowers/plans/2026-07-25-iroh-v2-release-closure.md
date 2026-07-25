# Iroh v2 Release-Closure Plan

**User-visible goal:** make the current hardening and deterministic-simulation series genuinely
ready to become Iroh v2, with every known code, CI, packaging, distribution, migration, and
evidence loose end either closed or represented by a fail-closed external gate.

**Success criteria:** one immutable release-candidate revision has a clean worktree, green
GitHub-hosted CI on every supported platform, green realistic and deterministic integration lanes,
validated v2 package metadata and migration notes, reproducible release archives and container
images from a non-publishing dry run, current resource/soak evidence, and no unresolved
Critical/High TigerStyle finding.

**Scope:** CI defects, hosted-runner routing, Patchbay/netsim/Wine execution, deterministic
services, publishable-crate metadata, changelogs and migration guidance, binary/container release
automation, supply-chain outputs, release gates, and a final closure audit.

**Non-goals:** creating a tag, publishing crates, publishing a GitHub release or container image,
claiming unexecuted workflows passed, changing the approved resource limits, or expanding the v2
feature set merely because a future parity dimension remains capability-scoped.

**Chosen approach:** keep `Unreleased` package versions during closure; treat `2.0.0` as the target
because the approved fallible constructors are source-breaking. Replace fork-inaccessible
Blacksmith and self-hosted routing with free standard GitHub-hosted runners. Make release
automation build-only by default and require an explicit publish input plus least-privilege token
permissions. Prefer GitHub Release artifacts and GHCR over the unavailable `vorc` S3 bucket and
`n0computer` Docker namespace. Keep the full Patchbay matrix on its existing lane until a retained
hosted public-smoke artifact proves the namespace capability, then promote the full matrix.

**Global constraints:** the repository is public; standard GitHub-hosted runners are the default
free execution substrate. Existing user work in the dirty tree must be preserved. Configuration
changes use executable source contracts. Rust changes follow TigerStyle and repository lints.
External publication and repository-settings mutations require explicit authority and are not
performed by this plan.

**Resolved decisions:**

- The next stable line is v2, not a semver-invalid `1.0.4`.
- A workflow definition is not execution evidence.
- The dated production-capacity artifact remains historical evidence; the final candidate repeats
  the profile because evidence is source-revision bound.
- Double NAT, diverse home routers, and cross-schema replay migration are follow-up capabilities,
  not hidden release passes and not v2 blockers unless advertised.
- `iroh-runtime` is published before crates that depend on it and remains lockstep-versioned.
- Local workspace patches are not release dependencies. The production Noq and Hickory forks
  become explicit publishable packages, while the deterministic Rustls fork is isolated to the
  non-published simulator workspace. The complete proposed boundary is specified in
  `docs/superpowers/specs/2026-07-25-iroh-publishable-fork-boundary-design.md`.

**Assumptions and validation:**

- GitHub-hosted Linux supports the required user namespaces: validate first with the bounded
  Patchbay smoke.
- Netsim setup is compatible with a fresh hosted Ubuntu VM: validate with a manual hosted run and
  retained report before making it required.
- Linux ARM64 standard runners can build both GNU and musl artifacts: validate in the release
  dry-run matrix; retain cross-compilation as a fallback if the native image lacks a dependency.
- Crates.io ownership and GHCR publication authority will exist at release time: fail closed in the
  checklist until credentials and namespaces are confirmed.

### Task 1: Executable release-readiness source contract

**Resources:** `scripts/tests/check-v2-release-readiness.sh`, `.github/workflows/ci.yml`.

**Depends on:** none.

**Interfaces and state:** the contract inspects workflow, runner, fuzz, nightly-seed, packaging,
permission, and documentation invariants without publishing or requiring credentials.

**Implementation:** write the contract before fixes and observe RED for the current formatting,
implicit fuzz target, numeric YAML seeds, unavailable runner labels, and legacy release
dependencies. Register it in normal hosted CI.

**Failure and operations:** emit one actionable invariant per failure; never silently skip a
missing workflow or convert an external evidence requirement into a local pass.

**Validation:** contract RED for the known state, ShellCheck, then GREEN after Tasks 2–6.

### Task 2: Close current deterministic-tooling CI failures

**Resources:** `iroh/bench/src/canary/workloads.rs`, `scripts/run-bounded-fuzz.sh`,
`scripts/tests/check-fuzz-tooling.sh`, `.github/workflows/simulation-nightly.yml`, a nightly
workflow contract test.

**Depends on:** Task 1 contract clauses for these failures.

**Interfaces and state:** rustfmt import ordering is canonical; `cargo-fuzz` receives the nightly
compiler host triple explicitly; every replay seed crosses YAML and expression evaluation as a
64-character lowercase hexadecimal string.

**Implementation:** establish focused RED with `cargo make format-check`, the fuzz source contract,
and the nightly source contract. Apply the smallest format, target-selection, and quoting changes.

**Failure and operations:** reject an empty compiler host triple; preserve sanitizer coverage and
all existing time/input/memory/artifact bounds; prepare the artifact root before scenarios so
diagnostics survive an early failure.

**Validation:** focused contracts, `cargo make format-check`, ShellCheck, Actionlint, one-second
local fuzz smoke where available, and the named nightly scenarios.

### Task 3: Move portable CI and platform coverage to standard hosted runners

**Resources:** `.github/workflows/ci.yml`, `.github/workflows/tests.yaml`,
`.github/workflows/wine.yaml`, `.github/workflows/sccache-probe/action.yml`,
`.github/workflows/pick-runner.yml`.

**Depends on:** Task 1.

**Interfaces and state:** Linux jobs use `ubuntu-latest`; Windows jobs use `windows-latest`; Apple
Silicon jobs use `macos-latest`; Intel macOS uses `macos-15-intel`; caches use GHA storage on
ephemeral hosts. No active portable job references Blacksmith or a repository self-hosted label.

**Implementation:** remove picker dependencies from callers, simplify matrices to direct labels,
make sccache behavior depend on hosted OS rather than proprietary runner names, and retain the
picker only if an explicitly documented non-release consumer still uses it.

**Failure and operations:** keep existing timeouts and feature matrices; do not drop Windows,
Android, Wasm, FreeBSD cross-build, MSRV, docs, semver, or external-type coverage to reduce queue
pressure.

**Validation:** readiness contract, Actionlint, matrix inspection, and one complete hosted CI run.

### Task 4: Establish hosted realistic integration evidence

**Resources:** `.github/workflows/patchbay-hosted-smoke.yml`, `.github/workflows/patchbay.yml`,
`.github/workflows/netsim.yml`, `.github/workflows/netsim_runner.yaml`,
`.github/workflows/wine.yaml`, parity and operations runbooks.

**Depends on:** Tasks 2–3 and a committed hosted-smoke workflow.

**Interfaces and state:** the public Patchbay receipt/import/export/compare chain remains strict;
netsim uploads reports through GitHub artifacts without S3; Wine runs on hosted Ubuntu. The full
Patchbay matrix moves only after retained user-namespace evidence exists.

**Implementation:** push and manually dispatch the smoke, inspect retained evidence, then port and
run the full matrix. Replace netsim's unconditional AWS setup and broad permissions with hosted
setup, least privilege, and artifact-only reporting. Exercise Wine on `ubuntu-latest`.

**Failure and operations:** namespace/setup failure is infrastructure failure; parity differences,
netsim failures, and Wine test failures remain nonzero. Never require absent metrics secrets for a
release qualification run.

**Validation:** retained successful public smoke, full Patchbay report, netsim report, and Wine
run, all from the candidate revision.

### Task 5: Make release and container automation safe to dry-run

**Resources:** `.github/workflows/release.yml`, `.github/workflows/docker.yaml`,
`docker/Dockerfile.ci`, release source contract.

**Depends on:** Task 3.

**Interfaces and state:** workflow dispatch requires a validated `v2.*` version and exact source
revision; `publish` defaults false; archives are always Actions artifacts; publication uses a draft
GitHub release and `ghcr.io/holon-technologies/*` only when explicitly enabled. Required token
permissions are declared per job.

**Implementation:** replace legacy release creation and unpinned asset upload, remove S3 handoff,
use standard hosted x64/ARM64/macOS/Windows matrices, build checksums and SBOM/provenance metadata,
and build containers from retained release-job artifacts. Keep tag-trigger publication disabled
until the dry run succeeds.

**Failure and operations:** validate version/source consistency before building; a missing archive,
checksum, binary, or container input fails. Publishing requires explicit authority and never runs
from pull requests.

**Validation:** Actionlint, ShellCheck, source contract, local package/archive checks, and a
non-publishing workflow dispatch whose artifacts are manually inspected.

### Task 6: Complete v2 package and migration metadata

**Resources:** publishable `Cargo.toml` files, lockstep internal dependencies, production fork
packages, nested simulator workspace, `CHANGELOG.md`, crate changelogs, migration guide,
`release.toml` files, package-order and fork-boundary contracts.

**Depends on:** stable public API after Tasks 2–5.

**Interfaces and state:** the owned Noq and Hickory forks are published before their consumers;
`iroh-runtime` is published before Iroh crates that depend on it; all public Iroh crates use the
same target version; unpublished bench/sim/checker crates stay unpublished. Production packages
resolve public Rustls, while the nested simulator workspace alone applies the deterministic Rustls
patch. Every approved breaking constructor has before/after migration guidance.

**Implementation:** implement the approved publishable-fork boundary, verify package contents and
dependency closure, add missing crate changelog entries, document the v1-to-v2 migration, and
prepare—but do not perform—the lockstep version bump.

**Failure and operations:** crates.io namespace ownership and token presence remain explicit
external gates. Do not publish a dependent crate before its exact owned-fork and `iroh-runtime`
versions exist. A source-workspace build cannot substitute for package-graph verification.

**Validation:** `cargo metadata`, `cargo package --list`, `cargo package`/`cargo publish --dry-run`
where the registry permits, package extraction builds, and expected-major semver reports.

### Task 7: Run release-candidate correctness and durability evidence

**Resources:** all CI workflows, daily/weekly/nightly simulation services, fuzz campaigns,
Patchbay, netsim, Wine, resource canary, release artifacts.

**Depends on:** Tasks 2–6 on one immutable candidate revision.

**Interfaces and state:** every result names the same revision; artifacts retain seeds, reports,
manifests, checksums, and stable failure classes.

**Implementation:** run complete hosted CI, one nightly matrix, one four-hour daily soak, the
scheduled bounded fuzz matrix, realistic integration lanes, and the production-minimum resource
canary. Re-run failed deterministic seeds exactly and promote genuine defects into the permanent
corpus.

**Failure and operations:** infrastructure failures are triaged separately but still block the
release until rerun; flakes need a reproduced cause and regression test, not a retry-only waiver.

**Validation:** retained run URLs and artifact digests recorded in a dated v2 closure audit.

### Task 8: Final audit and external release authorization

**Resources:** new dated v2 closure audit, repository rules/settings checklist, release notes,
artifact inventory.

**Depends on:** all prior tasks.

**Interfaces and state:** audit maps every requirement to code and current evidence, records zero
unresolved Critical/High findings, and names any accepted Medium/Low residual risk.

**Implementation:** repeat TigerStyle and determinism audits, verify branch/tag protection and
required checks, confirm crates.io/GHCR ownership, review checksums/SBOMs, and request explicit
authorization for version bump, tag creation, crate publication, draft release publication, and
container publication.

**Failure and operations:** any missing authority, credential, namespace, required check, retained
artifact, or unexplained failure keeps release status blocked.

**Validation:** signed-off closure audit and an explicit user release instruction. No task in this
plan itself creates or publishes the release.
