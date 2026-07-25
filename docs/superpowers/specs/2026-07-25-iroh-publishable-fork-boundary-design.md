# Publishable Fork Boundary Design

## Outcome

Make every v2 production crate independently packageable from crates.io while preserving the
resource-hardening changes in Noq and Hickory and the deterministic, run-scoped cryptography used
by `iroh-sim`.

Success means:

- `cargo package` can verify every published crate without relying on the root workspace's local
  patches;
- downstream users receive the bounded Noq and Hickory implementations used by the release;
- production packages resolve the public Rustls crate and remain type-compatible with their
  transitive TLS dependencies;
- simulator builds retain the reviewed Rustls patch without changing production dependency
  resolution; and
- CI fails if those boundaries regress.

This design prepares publishable artifacts. It does not publish crates, reserve registry names,
create a release, tag a commit, or change the v2 public Iroh API.

## Current Blocker

The root workspace patches three crates from local paths:

- Noq adds bounded event queues, per-poll budgets, and connection-lifetime ownership;
- Hickory adds pre-spawn UDP-request and TCP-connection admission limits; and
- Rustls permits run-scoped simulator entropy and key-exchange components.

Cargo does not include a workspace's `[patch.crates-io]` section in a published dependency graph.
The package verifier therefore resolves upstream Noq 1.1.0, where the connection lifetime API used
by `iroh-relay` does not exist. Hickory has the same latent packaging problem. Removing either
production fork would discard required resource bounds.

Renaming and publishing the Rustls fork is not viable. Noq, Tokio-Rustls, and other transitive
dependencies resolve the package named `rustls`; a differently named fork would coexist as a
distinct crate, making public Rustls types incompatible at integration boundaries.

## Chosen Architecture

### Publishable production forks

Turn the two production-critical forks into explicitly named, upstream-traceable packages:

- package `iroh-noq`, version `1.1.0-holon.1`, library name `noq`;
- package `iroh-hickory-server`, version `0.26.1-holon.1`, library name `hickory_server`.

Iroh manifests use Cargo dependency aliases, so Rust source paths do not change:

```toml
noq = { package = "iroh-noq", version = "=1.1.0-holon.1", ... }
hickory-server = {
  package = "iroh-hickory-server",
  version = "=0.26.1-holon.1",
  ...
}
```

Exact versions prevent an unrelated fork revision from entering a release. The upstream-aligned
base plus Holon revision communicates provenance and supports a later `holon.2` without pretending
to be an upstream Noq or Hickory release.

Each fork receives:

- `publish = true`, the Holon repository URL, and the existing upstream license;
- a README and changelog that identify the exact upstream release and owned patch set;
- the existing `IROH-VENDOR.md` ownership and resource-bound contract;
- a complete include/exclude policy suitable for `cargo package`;
- focused tests for every added bound and lifetime behavior; and
- an entry in the package verifier before any Iroh crate that consumes it.

The names are absent from the current crates.io index, but absence is not reservation. Registry
ownership must be established before the release publication step. If either name cannot be
claimed, choose a replacement package name and update the aliases before merging the release
commit; do not fall back to a path or Git dependency.

### Simulator-only Rustls fork

Remove the Rustls patch from the root workspace. Make `iroh-sim` a nested, non-published workspace
with its own lockfile and this local patch:

```toml
[workspace]

[patch.crates-io]
rustls = { path = "../vendor/rustls-0.23.41" }
```

The root workspace excludes `iroh-sim`. Its production members therefore compile and package
against public Rustls. Commands targeting the simulator use
`--manifest-path iroh-sim/Cargo.toml`, causing the simulator's patch to govern its complete path
dependency graph, including `iroh`, `iroh-relay`, Noq, and Tokio-Rustls. This preserves one Rustls
crate identity within the simulator graph and retains deterministic, run-owned cryptography.

The deterministic entropy and X25519 provider implementation lives in `iroh-sim`, not `iroh`.
Iroh's hidden simulation environment accepts an already constructed provider, so the published
Iroh package contains no code that depends on patched Rustls field types. The simulator constructs
that provider under its patched dependency graph and passes it across the type-compatible boundary.

Because `iroh-sim` currently inherits root lints, its manifest copies the root Rust and Clippy lint
policy. The simulator workspace owns its lockfile. Root formatting, checks, tests, Clippy, and
documentation commands receive explicit simulator equivalents so exclusion does not reduce
coverage.

The excluded `fuzz` workspace keeps explicit path dependencies on the owned forks and patched
Rustls. Fuzzing is a non-published test environment, so this does not affect the production
package graph.

## Release and Verification Flow

Package verification proceeds in dependency order:

1. `iroh-noq`;
2. `iroh-hickory-server`;
3. `iroh-base`;
4. `iroh-runtime`;
5. `iroh-dns`;
6. `iroh-relay`;
7. `iroh`;
8. `iroh-dns-server`.

Before the forks exist in crates.io, verification uses a candidate-local Cargo source overlay
containing only the normalized packages produced by `cargo package`. Cargo requires unpublished
versioned dependencies to resolve before it will create later archives, so archive creation may
use the existing source paths as a bootstrap. That pass uses `--no-verify`; the authoritative
verification pass compiles only extracted `.crate` contents and must not use source-tree paths.
This models the registry dependency graph while allowing the complete unpublished release set to
be tested atomically.

A release-boundary contract rejects:

- root patches for Rustls, Noq, or Hickory;
- path or Git dependencies in a publishable crate;
- non-exact dependencies on either owned fork;
- missing fork provenance, licenses, changelogs, or package-verification order;
- simulator commands that still assume root-workspace membership; and
- a simulator workspace without its Rustls patch, lockfile, lint policy, and explicit CI coverage.

Validation includes:

- focused fork tests and package contents inspection;
- `cargo package` for the full candidate-local dependency graph;
- clean-directory builds of the packaged Iroh libraries and binaries;
- production `cargo tree` proof that public Rustls and the owned Noq/Hickory packages resolve once;
- simulator `cargo tree` proof that the patched Rustls resolves once;
- simulator deterministic replay tests under its nested manifest;
- root and simulator formatting, strict Clippy, tests, and documentation checks; and
- all workflow, shell, release-readiness, fuzz, and determinism contracts.

## Migration Sequence

1. Add a failing boundary contract for the intended package graph and simulator command form.
2. Convert and document the Noq and Hickory packages, then update every direct dependency alias.
3. Extend candidate-local package verification and prove the production package graph.
4. Split `iroh-sim` into its nested workspace and move only the Rustls patch into that workspace.
5. Mechanically migrate active scripts, workflows, Make tasks, and current operator documentation
   to `--manifest-path`; preserve historical plan documents unchanged.
6. Add explicit root-plus-simulator formatting, Clippy, test, and dependency-tree gates.
7. Run the complete release-readiness suite and inspect the package archives.

Each step remains buildable before the next. No registry publication occurs during implementation.

## Alternatives Rejected

- **Remove the Noq or Hickory forks:** loses production resource and ownership invariants.
- **Keep root path patches:** local builds pass but released crates resolve different code.
- **Use Git dependencies:** makes the release depend on mutable external repository availability
  and is not a self-contained crates.io package graph.
- **Publish a renamed Rustls fork:** creates incompatible duplicate Rustls crate identities.
- **Publish a replacement package named `rustls`:** requires ownership outside this repository and
  would misrepresent upstream provenance.
- **Leak deterministic providers into static storage:** weakens run-scoped ownership and masks
  lifecycle bugs.
- **Drop deterministic TLS replay:** removes an established simulator guarantee before v2.

## Rollback and Failure Handling

Before publication, the migration is reversible as one source change: restore simulator membership
and the root Rustls patch, then remove the fork aliases. After an owned fork is published, versions
are immutable; corrections use a new Holon revision and exact dependency updates.

If package verification, dependency-tree uniqueness, or deterministic replay fails, the release
remains blocked. No workflow may tag, publish, or mark `latest` merely because source-workspace
tests pass.
