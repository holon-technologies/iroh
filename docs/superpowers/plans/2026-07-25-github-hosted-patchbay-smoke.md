# GitHub-hosted Patchbay Public-Parity Smoke Plan

**Goal:** prove that the existing Patchbay public semantic-parity case can run on free standard
GitHub-hosted Linux capacity without weakening or replacing the full self-hosted suite.

**Success criteria:** a scheduled/manual `ubuntu-latest` workflow executes only
`nat::nat_none_x_none`, emits the immutable Patchbay receipt, imports and compares same-revision
semantic evidence, uploads diagnostics unconditionally, and fails distinctly when user namespaces,
the test, receipt production, or parity comparison fails.

**Scope:** one workflow, its executable source contract, CI registration, and current-state
Patchbay/determinism documentation.

**Non-goals:** moving the full Patchbay matrix, deleting the self-hosted workflow, changing Iroh or
Patchbay Rust behavior, adding double NAT, accepting a capability skip as parity, or treating a
checked workflow definition as execution evidence.

### Task 1: Executable hosted-workflow contract

**Resources:** `scripts/tests/check-patchbay-hosted-smoke-workflow.sh`.

**Interfaces and state:** require daily/manual triggers, standard hosted runner, concurrency one,
15-minute timeout, strict user-namespace preflight, one exact public test, same-revision parity
commands, unconditional seven-day artifact upload, and no self-hosted/PR trigger.

**Implementation:** write the source contract first and observe it fail because the workflow is
absent.

**Failure and operations:** reject silent namespace setup, broad Patchbay execution, paid/self-hosted
labels, and missing upload/reporting clauses.

**Validation:** execute the contract and preserve its initial RED evidence.

### Task 2: Bounded hosted smoke workflow

**Resources:** `.github/workflows/patchbay-hosted-smoke.yml`, `.github/workflows/ci.yml`.

**Interfaces and state:** daily/manual workflow; one `ubuntu-latest` job; concurrency one;
15-minute job timeout; explicit namespace preflight before threads; exact
`nat::nat_none_x_none` selection; existing receipt/import/export/compare interface; unconditional
diagnostic upload.

**Implementation:** follow the established Patchbay workflow commands but reduce the executed test
surface and keep the full self-hosted workflow unchanged. Register the source contract in normal
CI.

**Failure and operations:** namespace preflight failure is infrastructure failure. Missing receipt,
semantic skip/difference, or stale/wrong-source evidence remains nonzero. Artifact upload uses
`if: always()` and does not mask earlier failure.

**Validation:** contract GREEN, `actionlint`, and `git diff --check`.

### Task 3: Runbook and final verification

**Resources:** `docs/simulation/patchbay-parity.md`, `docs/testing/determinism-audit.md`,
`scripts/tests/check-determinism-docs.sh`, determinism inventories if affected.

**Interfaces and state:** document the hosted smoke as an evidence-producing probe, the self-hosted
suite as the full authority, and double NAT as the next realism expansion only after a retained
hosted success.

**Implementation:** update current-state language and its executable documentation contract.

**Failure and operations:** do not claim a hosted pass until GitHub retains a successful run.

**Validation:** workflow contract, docs contract, actionlint, ShellCheck, determinism checks,
formatting where applicable, and clean diff checks.
