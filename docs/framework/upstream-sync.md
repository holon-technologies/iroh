# Upstream protocol sync runbook

This monorepo never follows an upstream default branch. Every sync starts from one exact release
tag and its resolved 40-character commit in `protocols/upstream-baselines.toml`. The imported
protocol packages and `krikos-app` remain unpublished while `framework/release-gate.toml` is blocked.

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
4. Reapply the Krikos rebrand to the freshly imported files. This is a standing cost
   [ADR-0002](../adr/0002-krikos-rebrand.md) accepted deliberately: `protocols/<name>` is a renamed
   directory (`protocols/krikos-blobs`, `protocols/krikos-gossip`, `protocols/krikos-docs`), but the
   commit just imported carries upstream's own, pre-rebrand package/library names in its manifest
   (`Cargo.toml`'s `name =` and `[lib] name =`) and its source (`use`/`extern crate` statements),
   because upstream has no reason to know this fork renamed anything. Run

   ```console
   scripts/apply-rebrand.sh --dry-run
   ```

   and read the `TOML:`/`RS:` lines it reports under the imported package's directory — those are
   the files the import reintroduced old-named identifiers into. `--dry-run` only reports; it does
   not write. Fix each flagged file by hand, using the exact old→new pairs recorded in
   [`scripts/rename-map.toml`](../../scripts/rename-map.toml) (the same source of truth
   `scripts/tests/check-rebrand-complete.sh` checks against) — do **not** run `apply-rebrand.sh
   --apply`: every directory in its move plan already has its new name from the original rebrand, so
   `--apply` hits its own "source directory does not exist" guard on the first entry and refuses to
   run, by design, rather than silently doing nothing. Re-run `--dry-run` until it reports zero
   changes for the touched files, then confirm with `scripts/tests/check-rebrand-complete.sh`
   (must exit 0) before continuing. The provenance record's upstream `name`/`source_url`/`tag`/
   `source_commit` fields in `protocols/upstream-baselines.toml` are themselves exempt from this and
   keep naming the real upstream package (see the file's own exemption note) — only the imported
   source files are rewritten.
5. Reapply the v2 ownership and resource-bound delta as explicit commits. Review dependency changes
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
cargo test -p krikos-local-first-app-tests --test two_node
```

Replay old blob/docs stores and migrations whenever persistent code or dependency versions change.
Run the deterministic application fixture and bounded fuzz smoke when parsers, tickets, manifests,
task scheduling, or durable boundaries change. Record the source commit, candidate commit, commands,
and retained artifacts in the pull request.

If a wire fixture, old store, license, provenance record, architecture edge, or bidirectional
interop lane fails, stop the sync. Do not rewrite an already published tag or migration. Relay
compatibility remains pinned independently to upstream `v1.0.3` (see
[`relay-compatibility.md`](../relay-compatibility.md) for the exact pinned commit); a protocol sync
cannot weaken or silently replace that baseline.
