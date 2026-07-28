# Upstream protocol sync runbook

This monorepo never follows an upstream default branch. Every sync starts from one exact release
tag and its resolved 40-character commit in `protocols/upstream-baselines.toml`. The imported
protocol packages and `iroh-app` remain unpublished while `framework/release-gate.toml` is blocked.

## Prepare and review a sync

1. Select an upstream release, resolve the tag (including an annotated tag's peeled commit), and
   record both values in a review branch. Do not change the existing record until the source is
   fetched and inspected.
2. Import the selected commit into its existing `protocols/<name>` prefix without flattening its
   history. Retain both licenses, `UPSTREAM.md`, fixtures, migrations, and changelog. Remove only
   repository-level automation/configuration listed in the reviewed cleanup delta.
3. Update the provenance record with the exact tag, commit, and state. Run
   `scripts/tests/check-protocol-provenance.sh --remote`; exit code 2 means infrastructure was
   unavailable and is not compatibility success.
4. Reapply the v2 ownership and resource-bound delta as explicit commits. Review dependency changes
   against `scripts/workspace-architecture.toml`; production packages must never gain simulator,
   fuzz, example, or integration-test dependencies.

## Required evidence

Run formatting, strict Clippy/rustdoc, the complete affected package tests, and these independent
compatibility lanes:

```console
scripts/tests/check-blobs-v0-interop.sh
scripts/tests/check-gossip-v0-interop.sh
scripts/tests/check-relay-compatibility.sh --golden
scripts/tests/check-relay-compatibility.sh --live
cargo test -p iroh-local-first-app-tests --test two_node
```

Replay old blob/docs stores and migrations whenever persistent code or dependency versions change.
Run the deterministic application fixture and bounded fuzz smoke when parsers, tickets, manifests,
task scheduling, or durable boundaries change. Record the source commit, candidate commit, commands,
and retained artifacts in the pull request.

If a wire fixture, old store, license, provenance record, architecture edge, or bidirectional
interop lane fails, stop the sync. Do not rewrite an already published tag or migration. Relay
compatibility remains pinned independently to upstream Iroh `v1.0.3`; a protocol sync cannot weaken
or silently replace that baseline.
