# Identity stable-release gate

`krikos-identity` is a workspace member so its implementation can receive the full repository test
matrix, but it is not yet authorized for a stable registry release. The machine-readable policy is
[`../release-gate.toml`](../release-gate.toml), enforced by
[`../../../scripts/check-identity-release-gate.py`](../../../scripts/check-identity-release-gate.py).
This gate applies only to `krikos-identity`; it does not add a fifth package to the separate
four-package framework gate.

While the policy is `blocked`, the checker requires all of the following publication boundaries:

- the package remains a root workspace member and retains `publish = false`;
- `scripts/verify-release-packages.sh` excludes `krikos-identity` from its dependency-ordered
  publication set; and
- `Makefile.toml` keeps the crate in the `cargo-check-external-types` skip list until its public API
  baseline is approved.

CI and release preflight prove that state with:

```console
python3 scripts/check-identity-release-gate.py --expect-closed
```

`--require-open` fails closed and reports every outstanding approval.

## Approval checklist

Each approval is independent. Setting one to `true` requires at least one non-empty immutable or
repository-owned reference in the matching `evidence` array. An unavailable system, planned review,
or repository-owned self-test is not external evidence.

| Approval | Minimum evidence before approval | Decision authority |
| --- | --- | --- |
| `third_party_security_audit` | A named independent cryptographic and protocol audit covering the stable candidate, with all critical/high findings resolved or explicitly release-blocked and the report revision retained. | Security owner and repository owner. |
| `independently_maintained_interoperability` | A separately maintained implementation validates the public v1 fixtures, negative cases, and complete pairing, proposal, recovery, provider, and sync ceremonies in both directions. | Protocol owner and repository owner. |
| `production_provider_diversity` | Production evidence demonstrates the stable profile's provider quorum across independently administered infrastructure and failure domains, including a provider-loss drill. | Production operations owner and security owner. |
| `protocol_governance` | A published process owns wire changes, codepoint allocation, compatibility windows, vulnerability handling, and protocol-upgrade decisions. | Protocol owner and repository owner. |
| `public_api_semver_baseline` | An immutable public API/rustdoc baseline, SemVer policy, compatibility result, and release ownership are reviewed for the stable crate. | Crate owner and repository owner. |
| `persistent_schema_support` | The account and provider schemas have documented support windows, forward/rollback rules, migration fixtures, backup/restore drills, and an assigned operational owner. | Storage owner and repository owner. |

## Opening the gate

Opening is one coordinated, owner-reviewed publication change:

1. Record qualifying references in every `evidence` array, set all six approvals to `true`, and set
   `status = "open"`.
2. Remove `publish = false` (or replace it with explicit `publish = true`), add `krikos-identity`
   exactly once to the publishable package order after its dependencies, and remove
   `protocols/krikos-identity` from the external-types skip list. An empty or registry-restricting
   Cargo publish allowlist is not an open stable-release boundary.
3. Switch CI, release preflight, local aggregate, Makefile, and source-contract expectations from
   `--expect-closed` to `--require-open`; update the release checklist and package-order contract in
   the same change.
4. Run `python3 scripts/check-identity-release-gate.py --require-open` and the full stable-release
   verification matrix on the immutable candidate.

Flipping only the policy, only package metadata, or only automation leaves the checker red.
