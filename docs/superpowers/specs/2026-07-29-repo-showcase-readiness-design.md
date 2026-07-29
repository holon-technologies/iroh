# Repo Showcase Readiness: Substrate and CI Cleanup

- Status: Draft — pending review
- Defined: 2026-07-29

## Outcome

Make this repository defensible as a public showcase of a hardened, dependable networking
library. This design covers the two workstreams that do not depend on the pending rebrand:
substrate cleanup and CI correctness.

Success means:

- the Docker build context is bounded and the ignore files survive the repo's own documented
  maintenance procedures;
- every vendored fork carries reviewable provenance;
- GitHub attributes only first-party code to this project;
- the `main` branch cannot be modified without review and a full green CI run;
- no workflow in the tree is permanently red, permanently queued, or a silent no-op; and
- cheap correctness gates (toolchain pin, MSRV coverage, lockfile enforcement) exist where
  they are currently absent.

This design does not rebrand the crates, choose a version number, create tags, publish to any
registry, rewrite the README, or change any production source behaviour.

## Context

This repository is a hard fork of `n0-computer/iroh` maintained by holon-technologies. A
five-dimension audit produced 59 candidate findings; an adversarial verification pass confirmed
51 and refuted 8. This design acts only on confirmed findings within its two workstreams.

Four refuted findings are recorded here so they are not re-litigated:

- **Supply-chain scanning is not absent.** `cargo deny check --workspace --all-features
  -Dwarnings` runs the full RUSTSEC advisory database plus license, bans, and sources checks on
  every pull request, merge group, and push to `main` (`ci.yml:716-726`). Dependabot runs weekly
  across three ecosystems.
- **Dependabot is not configured to suppress security patches.** `ignore.update-types` gates
  version updates only. `.github/dependabot.yml` is byte-identical to upstream's.
- **The `cargo-deny` excluded-tree gap is 5 crates, not 98.** The larger figure came from diffing
  independently-resolved lockfiles that had drifted by patch releases. `rustls` is in the scanned
  root graph; the vendored `rustls` fork is simulator-only.
- **`GOAL.md`'s placement at repo root is a preference, not a defect.** Its content is current,
  internally consistent, and free of broken links, and it is the file that links the simulation
  documentation.

Repo-level GitHub security toggles reported as `disabled` are GitHub's defaults for forks, not a
deliberate weakening. Upstream `n0-computer/iroh` carries neither `SECURITY.md` nor `CODEOWNERS`.

## Non-Goals

- Renaming crates, reserving registry names, or publishing. That is Project C (rebrand).
- Rewriting `README.md`, restructuring the docs information architecture for public consumption,
  or documenting the simulation showcase. That is Project D, deliberately sequenced after the
  rebrand so it is written once in the final name.
- Reconciling the simulator's dependency graph with production's (73 crates diverge, including
  `tokio` and a forked `rustls`). Architectural; needs its own design.
- Standing up fork-owned staging relay and DNS infrastructure to replace the n0-operated endpoints
  CI currently depends on. A cost decision, not a cleanup.
- Fixing the `hickory-proto` TSIG fuzz crash. Product work. This design adds alerting so the
  failure stops being silent; it does not fix the crash.
- Removing or altering `Copyright 2025 N0, INC.` anywhere. That attribution is required for
  Apache-2.0/MIT-derived code. The fork's copyright is added alongside it, never substituted.

## Workstream A — Substrate cleanup

### A1. Ignore files

`.dockerignore` is two lines (`docker`, `target`) while the real build context is 53 GB.
`docker/Dockerfile` does `COPY . .` twice — once for the cargo-chef planner, once for the
builder — so the context is the entire repository, including `target/`, `.git/`, and all three
vendored trees.

Replace it with a deny-all-then-allowlist form derived from what the workspace build actually
needs: the root manifests, every workspace member, the two vendored crates referenced by
`[patch.crates-io]`, and the cargo configuration.

```
*
!Cargo.toml
!Cargo.lock
!.cargo/
!iroh/
!iroh-base/
!iroh-dns/
!iroh-dns-server/
!iroh-relay/
!iroh-resolver/
!iroh-runtime/
!tools/
!vendor/hickory-server-0.26.1/
!vendor/noq-1.1.0/
**/target
```

`vendor/rustls-0.23.41` is deliberately absent: it is patched in only by `iroh-sim` and `fuzz`,
neither of which the image builds. The trailing `**/target` re-excludes build output inside the
otherwise-allowed directories.

The allowlist is authoritative and must be extended when a new workspace member or patched vendor
appears. This is the intended failure mode: an over-broad context fails silently and expensively,
while a missing input fails loudly at build time.

`.gitignore` currently spells out six anchored build directories, three of them pinned to an exact
vendored version:

```
/target
/fuzz/target
/iroh-sim/target
/vendor/hickory-server-0.26.1/target
/vendor/noq-1.1.0/target
/vendor/rustls-0.23.41/target
```

Every vendor version bump silently reintroduces an ignored-directory gap, which contradicts the
repo's own documented vendor-update procedure. Collapse all six to a single depth-matching
`target/` rule, which covers present and future members without enumeration.

Retain `/fuzz/artifacts`, `/logs`, and `iroh.config.toml`, which are not `target` directories. Drop
`/.patchbay`, which becomes dead once B3 deletes `patchbay.yml`.

Add `/artifacts/` — an untracked, unignored scratch directory the docs actively instruct users to
write into — and `.claude/settings.local.json`, currently excluded only by one developer's personal
git configuration. Repository cleanliness must not depend on a single machine.

Delete the nested `compat/relay-v1-interop/.gitignore`, made redundant by the depth-matching rule.

### A2. Vendor provenance

`vendor/rustls-0.23.41` is a public-API fork of a TLS library and is the only vendored tree with
no `IROH-VENDOR.md`. Add one in the format the other two use: upstream base version, why the fork
exists, the exact delta, the update procedure, and the non-removal rationale.

Add `vendor/README.md` indexing all three vendored trees, and check in a `*.patch` per vendor so
each delta is reviewable without diffing against crates.io.

The audit reported this as a whitespace formatter touching a license file and some prose. Direct
comparison against the crates.io packages shows something more serious, and the remedy is
correspondingly different.

Measured against `rustls-0.23.41` from crates.io, the vendored tree differs in **81 source
files**. Normalizing the pristine package with default `rustfmt --edition 2021` reduces that to
**12**. So 69 files carry no change other than having been reformatted with default rustfmt,
which overwrote rustls's own upstream style.

The 12 files holding the genuine patch are `src/common_state.rs`, `src/crypto/mod.rs`,
`src/crypto/aws_lc_rs/mod.rs`, `src/crypto/ring/mod.rs`, `src/client/{hs,tls12,tls13,ech,
client_conn}.rs`, and `src/server/{hs,tls12,tls13}.rs`. The patch is roughly 529 diff lines: it
changes `KxState` to hold `Arc<dyn SupportedKxGroup>`, adds a public
`negotiated_key_exchange_group()` accessor, and threads `provider.secure_random` through session-ID
and `Random` construction.

That is a public-API change to a TLS library, and it is currently indistinguishable from
formatting noise in any diff — in the one vendored tree with no `IROH-VENDOR.md` at all. This is
the repo's least reviewable change and it sits in the security-critical dependency.

For contrast, `noq-1.1.0` differs in 6 `.rs` files and `hickory-server-0.26.1` in 2, both
consistent with their documented narrow patches. Only rustls has the problem.

The remedy is therefore not to exclude `vendor/**` from `scripts/run-format.sh`. That script runs
`cargo fmt --all` against the root and `iroh-sim` workspaces, neither of which has the vendored
trees as members, so it could not have caused this and excluding it would fix nothing. Instead:

1. Restore `vendor/rustls-0.23.41` to the pristine crates.io package.
2. Reapply only the 12-file semantic patch, checked in as `vendor/rustls-0.23.41.patch`.
3. Write `vendor/rustls-0.23.41/IROH-VENDOR.md` documenting the key-exchange and entropy changes.
4. Add a CI guard asserting each vendored tree equals upstream-package-plus-checked-in-patch.

The guard is the durable fix: it makes the provenance claim machine-checked rather than asserted,
and it prevents recurrence regardless of which tool caused the drift.

### A3. Repository attribution

`.gitattributes` is one line covering shell-script line endings. 37% of tracked Rust is vendored
but unmarked, so GitHub attributes it to this project. Add:

```
* text=auto eol=lf
vendor/** linguist-vendored
CHANGELOG.md linguist-generated
CHANGELOG_old.md linguist-generated
**/Cargo.lock linguist-generated
docs/testing/resource-canary/** linguist-generated
```

The last entry covers roughly 290 KB of committed `.ndjson` sample data.

### A4. Changelog provenance

`cliff.toml`'s postprocessors still rewrite every commit reference to upstream's issue tracker, so
the first person to run `git cliff` produces a changelog of links to n0-computer issues. Retarget
them at `holon-technologies/iroh`, with a note preserving upstream attribution for pre-fork
entries.

Move `CHANGELOG.md` (372 KB of upstream history) and `CHANGELOG_old.md` to `docs/history/`, leaving
a one-line pointer at root.

Cutting a release section and tagging are deferred to Project C, because both depend on the
rebrand's version decision.

### A5. Durable rationale

`docs/superpowers/` holds 29 planning artifacts (448 KB) containing load-bearing architecture
rationale that exists nowhere else — notably the publishable-fork-boundary design and the
deterministic-simulation architecture.

Promote that rationale into `docs/architecture.md` and the relevant `vendor/*/IROH-VENDOR.md`
files, then delete `docs/superpowers/`. Add `docs/README.md` as an index of what remains.

Two consequences to handle deliberately: `docs/testing/determinism-audit.md` cites source paths
deleted by the v2 hard cut and must be corrected during promotion; and this design document lives
in `docs/superpowers/specs/`, so it is removed by the work it describes, once that work is
complete and verified.

`GOAL.md` stays at repo root, unchanged.

## Workstream B — CI correctness

### B1. Branch protection

The `main` ruleset requires 2 of roughly 20 CI checks and does not require a pull request at all.
This is the most serious finding in the audit: `main` is directly writable and almost entirely
ungated.

Add an aggregate job to `ci.yml`:

```yaml
ci-ok:
  needs: [<every other job in ci.yml, enumerated at implementation time>]
  if: always()
  runs-on: ubuntu-latest
  steps:
    - run: |
        [ -z "$(echo '${{ toJSON(needs) }}' | jq -r '.[] | select(.result != "success")')" ]
```

The `needs` list is the one place this pattern can rot, so implementation must also add a check
that every job defined in `ci.yml` appears in it.

Make `ci-ok` the single required status context, so jobs added later are required by
construction rather than by remembering to update the ruleset. Add ruleset rules for
`pull_request` with at least one required review, `non_fast_forward`, and deletion protection.

### B2. Action pinning

No action is pinned to a commit SHA. Third-party actions run with attestation-signing and
repository-write tokens. Pin all non-`actions/*` actions to full 40-character SHAs with a trailing
`# vX.Y.Z` comment, starting with the `supply_chain` job in `release.yml`, which holds the most
dangerous token scope. Dependabot's already-configured `github-actions` ecosystem will bump the
SHAs and preserve the comments.

### B3. Dead and broken automation

- Delete `.github/ansible/`. It redeploys n0-operated infrastructure.
- Delete `patchbay.yml`. It targets a self-hosted runner label this fork has no runners for; its
  runs queue for up to 24 hours before auto-cancel. `patchbay-hosted-smoke.yml` remains and is
  runnable.
- Fix Docs Preview. The guard `github.event.pull_request.head.repo.fork` is always true because
  this repository is itself a fork, so the job is permanently skipped. The correct same-repo test
  is `github.event.pull_request.head.repo.full_name == github.repository`. Refresh the nightly pin
  at `docs.yaml:38`.
- Reconcile artifact-action major-version skew on v8 across all workflows.
- Remove the dead `MSRV: "1.66"` from `netsim.yml` and `netsim_runner.yaml`, and fix
  `cleanup.yaml`'s copied header and concurrency group.

### B4. Issue-dependent automation

Simulation failure triage calls `scripts/upsert-simulation-issues.sh`, but Issues are disabled on
this fork, so the entire triage lifecycle is a silent no-op — failures are detected and then
discarded.

Enable Issues on the repository and retarget the `ISSUE_TEMPLATE` project field. Add a preflight
assertion to `simulation-daily-soak.yml` that fails loudly if the repository has Issues disabled,
so this cannot regress into silence again.

If Issues are not to be enabled, the triage mechanism must be replaced rather than left in place;
a no-op triage path is worse than no triage path, because it reports success.

### B5. Fuzz alerting

The nightly fuzz campaign has been red for four or more consecutive nights on a genuine
`hickory-proto` TSIG crash, with no notification. Add a failure-notification path to `fuzz.yml`
using the same mechanism as the soak.

The crash itself is out of scope. Until it is fixed or upstreamed, record it as a known-crash
exclusion with a tracking link, so the campaign's signal is restored and a *new* crash is
distinguishable from the known one.

### B6. Cheap correctness gates

- Add `rust-toolchain.toml` at repo root pinning the channel with `components = ["rustfmt",
  "clippy"]`. There is currently no pin, and local toolchains run six minor versions ahead of the
  declared MSRV of 1.91.
- Add `--all-features` to the MSRV step, which currently claims all-features coverage without
  passing the flag, and extend the job to `iroh-sim/Cargo.toml` and
  `compat/relay-v1-interop/Cargo.toml`, both of which declare `rust-version = "1.91"` that is
  never verified. Add `rust-version` to `fuzz/Cargo.toml`.
- Regenerate `fuzz/Cargo.lock`, which predates the `iroh-resolver` extraction, and make it
  load-bearing by adding `--locked` to `scripts/run-bounded-fuzz.sh` and a
  `cargo metadata --manifest-path fuzz/Cargo.toml --locked` step in CI.
- Add a PR-time `cargo check --locked --manifest-path compat/relay-v1-interop/Cargo.toml` so
  relay API drift breaks the pull request that caused it, rather than the following week's cron.
- Set `multiple-versions = "warn"` in `deny.toml` (currently `"allow"`) so the 20 duplicate
  dependency groups are enumerated with owners and exit conditions instead of globally waived.

### B7. Build caching

`simulation_contracts` and `simulation_gate` are the two required jobs and the only expensive ones
without caching. Add `RUSTC_WRAPPER: sccache`, `SCCACHE_GHA_ENABLED: on`,
`mozilla-actions/sccache-action`, and the existing `./.github/actions/sccache-probe`. Release
builds keep cold caches for reproducibility.

## Sequencing

A and B are independent and can proceed in parallel, with two ordering constraints:

1. B1's aggregate `ci-ok` job must land and go green before the ruleset is changed to require it,
   or `main` becomes unmergeable.
2. A5's deletion of `docs/superpowers/` happens last, after promotion is verified.

## Testing

Each change is verified by the mechanism it affects, not by inspection:

- **A1**: `docker build` context size measured before and after; assert the reported context is
  bounded. Confirm a simulated vendor version bump leaves no unignored `target/`.
- **A2**: for each vendored tree, download the crates.io package at its pinned version, apply the
  checked-in `*.patch`, and assert the result is byte-identical to the vendored directory ignoring
  `.cargo-ok`, `IROH-VENDOR.md`, and `target/`. This runs in CI, not once by hand.
- **A3**: GitHub's language statistics after merge; vendored code must no longer be attributed.
- **A4**: run `git cliff` and confirm every emitted link targets `holon-technologies/iroh`.
- **A5**: link-check `docs/` for dangling references; confirm no promoted rationale was lost by
  grepping the deleted content's key claims against the surviving documents.
- **B1**: open a probe pull request and confirm it cannot merge with any job failing, and that
  direct pushes to `main` are rejected.
- **B3**: confirm Docs Preview produces a preview on a same-repo pull request.
- **B4**: confirm the preflight assertion fails when Issues are disabled.
- **B5**: force a fuzz failure and confirm the notification fires.
- **B6**: confirm each new gate fails on a deliberately introduced violation before it is
  considered installed. A gate that has never been observed failing is not a gate.

## Open questions carried to Project C

- Crate version: `0.1.0` signals a pre-1.0 API under Cargo semver, which contradicts the
  "dependable library" positioning chosen for the showcase. Resolve before tagging.
- The 132 inherited upstream tags. Default is to keep them for provenance.
- Whether `iroh-noq` and `iroh-hickory-server` remain the vendored fork package names under the
  new brand.
