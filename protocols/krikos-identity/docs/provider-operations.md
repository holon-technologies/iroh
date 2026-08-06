# Provider persistence and operations

The default `krikos-identity` feature set remains deterministic and database-free. Enable
`provider-store` to use the redb-backed provider generation, audit journal, and operational-effect
journal. `fs-store` independently enables the redb account source/checkpoint store. Production
operators normally enable both.

This runbook is the normative provider-portability appendix for v1. It fixes the portable
manifest/chunk schemas, provider-only registries, commitment preimages, and resource ceilings below.
The redb layouts are separately versioned implementation formats, not interchange formats. Completing
this repository appendix does not open the six external approvals in
[`release-gate.md`](release-gate.md).

## Provider portability profile v1

All structures in this section use the Postcard 1.1.3 rules in the crate
[`README`](../README.md). Field lists are in serialization order. `sequence<T, N>` is a Postcard
sequence with at most `N` items, `bytes<N>` is a Postcard byte string with at most `N` bytes, and
`option<T>` is Postcard's closed option. Every `format_version` in this appendix is `1`; another
value fails closed. Provider portability never serializes `usize`, maps, floats, or a Rust enum
ordinal.

`ProviderGenerationExport`, `ProviderAuditSnapshot`, and `ProviderRecoveryExport` are validated
aggregate API types rather than single unbounded wire messages. Their portable representations are,
respectively, a generation manifest plus generation chunks, an audit manifest plus audit chunks,
and a recovery manifest plus both committed chunk sets. Assemblers may receive chunks out of order;
an exact duplicate is idempotent, while a conflicting ordinal, missing range, overlap, gap, route
mismatch, count mismatch, byte mismatch, or commitment mismatch fails closed.

### Exact portable schemas

The generation components carry these exact item forms:

| Component | Canonical item |
| --- | --- |
| `Entries` | `ProviderLogEntryBody` canonical bytes |
| `LeafHashes` | `Digest` canonical bytes |
| `Receipts` | `InclusionReceipt` canonical bytes |
| `CheckpointBundles` | `(format_version: u16, bundle: (genesis: option<AccountGenesis>, prior_checkpoint_id: option<CheckpointId>, events: sequence<AuthorizedEvent, 256>, checkpoint: SignedCheckpoint, transition_event: option<AuthorizedEvent>))` |
| `CompactionManifests` | `ProviderCompactionManifest` canonical bytes |

An audit item is `(format_version: u16, record: (sequence: u64, head: SignedProviderHead,
consistency_proof: option<MerkleConsistencyProof>, status_code: u16))`. A chunk `payload` is the
canonical encoding of `sequence<bytes<4 MiB - 4 KiB>, 256>`; `item_payload_bytes` is the sum of the
inner canonical item lengths and deliberately excludes the sequence and byte-string length prefixes.

The validated aggregate API shapes, which are committed and split into the bounded messages below
rather than encoded as one interchange frame, are:

| Aggregate | Exact logical field order and types |
| --- | --- |
| `ProviderGenerationExport` | `(provider: ProviderDescriptor, log_id: ProviderLogId, key_version: ProviderKeyVersion, entries: sequence<ProviderLogEntryBody, 1048576>, leaf_hashes: sequence<Digest, 1048576>, latest_head: option<SignedProviderHead>, receipts: sequence<InclusionReceipt, 1048576>, checkpoint_bundles: sequence<ProviderCheckpointBundle, 1048576>, compaction_manifests: sequence<ProviderCompactionManifest, 256>)` |
| `ProviderAuditSnapshot` | `(revision: u64, provider: ProviderDescriptor, log_id: ProviderLogId, latest_head: option<SignedProviderHead>, equivocation: option<ProviderEquivocationEvidence>, records: sequence<ProviderAuditRecord, 65536>)` |
| `ProviderAuditRecord` | `(sequence: u64, head: SignedProviderHead, consistency_proof: option<MerkleConsistencyProof>, status: ProviderAuditStatus)`; portable items and commitments replace `status` with its `status_code: u16` below |
| `ProviderAuditArtifact` | `(sequence: u64, kind: ProviderAuditArtifactKind, accepted_head: SignedProviderHead, observed_head: SignedProviderHead)`; commitments replace `kind` with its `kind_code: u16` below |
| `ProviderRecoveryExport` | `(generation: ProviderGenerationExport, audit: ProviderAuditSnapshot, artifacts: sequence<ProviderAuditArtifact, 65536>, generation_commitment: Digest, audit_commitment: Digest, artifact_commitment: Digest, recovery_commitment: Digest)` |
| `ProviderRetentionItem` | `(leaf_index: u64, class: ProviderRetentionClass)`; inventory commitments replace `class` with its `class_code: u16` below |
| `ProviderRetentionInventory` | `(tree_size: u64, items: sorted unique sequence<ProviderRetentionItem, 8 * tree_size>, audit_artifacts: sorted unique sequence<ProviderAuditArtifact, 65536>)`; `tree_size <= 1048576`, item order is `(leaf_index, class_code)`, artifact order is `(sequence, kind_code)`, and the pair ceiling follows from the eight closed classes |

| Structure | Exact field order and types |
| --- | --- |
| `ProviderExportComponent` | `(format_version: u16, component_code: u16)` |
| `ProviderExportComponentDescriptor` | `(format_version: u16, component_code: u16, item_count: u64, chunk_count: u32, total_payload_bytes: u64, chunk_list_commitment: Digest)` |
| `ProviderGenerationExportChunk` | `(format_version: u16, provider_id: ProviderId, log_id: ProviderLogId, key_version: ProviderKeyVersion, generation_commitment: Digest, component_code: u16, ordinal: u32, start_index: u64, end_index: u64, item_payload_bytes: u64, payload: bytes<4 MiB - 2 KiB>)` |
| `ProviderAuditExportChunk` | `(format_version: u16, provider_id: ProviderId, log_id: ProviderLogId, audit_commitment: Digest, ordinal: u32, start_sequence: u64, end_sequence: u64, item_payload_bytes: u64, payload: bytes<4 MiB - 2 KiB>)` |
| `ProviderGenerationExportManifest` | `(format_version: u16, provider: ProviderDescriptor, log_id: ProviderLogId, key_version: ProviderKeyVersion, tree_size: u64, tree_root: Digest, latest_head: option<SignedProviderHead>, generation_commitment: Digest, total_payload_bytes: u64, components: sequence<ProviderExportComponentDescriptor, 5>)` |
| `ProviderAuditExportManifest` | `(format_version: u16, provider: ProviderDescriptor, log_id: ProviderLogId, latest_head: option<SignedProviderHead>, equivocation: option<ProviderEquivocationEvidence>, record_count: u64, chunk_count: u32, total_payload_bytes: u64, audit_commitment: Digest, artifact_count: u64, artifact_commitment: Digest, chunk_list_commitment: Digest)` |
| `ProviderRecoveryExportManifest` | `(format_version: u16, generation: ProviderGenerationExportManifest, audit: ProviderAuditExportManifest, generation_manifest_commitment: Digest, audit_manifest_commitment: Digest, generation_commitment: Digest, audit_commitment: Digest, artifact_commitment: Digest, recovery_commitment: Digest)` |
| `ProviderCompactionManifest` | `(format_version: u16, provider_id: ProviderId, log_id: ProviderLogId, key_version: ProviderKeyVersion, source_tree_size: u64, source_tree_root: Digest, archive_commitment: Digest, generation_commitment: Digest, audit_commitment: Digest, audit_artifact_commitment: Digest, inventory_commitment: Digest, retained_evidence_commitment: Digest, retained_ranges: sequence<ProviderRetainedRange, 4096>)` |
| `ProviderRetainedRange` | `(start: u64, end_exclusive: u64)` |
| `OpaqueProviderAnchorCommitment` | `(format_version: u16, commitment: [u8; 32])` |

Generation chunk offsets are zero-based half-open ranges. Audit sequences are one-based and audit
chunk ranges are half-open. Generation manifests contain exactly five descriptors in ascending
component-code order. Entry, leaf-hash, and receipt counts equal `tree_size`; checkpoint-bundle
count cannot exceed it. A recovery manifest requires the same provider, log, and latest head in its
generation and audit manifests, and binds both manifest commitments as well as all three semantic
aggregate commitments.

For each generation component, zero items requires zero chunks, zero payload bytes, and the exact
empty ordered-list commitment. A nonempty component requires
`ceil(item_count / 256) <= chunk_count <= item_count`; the sum across the five component streams is
at most 65,536 chunks. The audit manifest applies the same empty/nonempty and minimum-chunk rules to
its record stream. A nonempty audit manifest requires a latest head and nonzero payload bytes,
requires `artifact_count <= record_count`, and requires at least one derived artifact when terminal
equivocation is present. Its empty form has no head or equivocation and commits the canonical empty
snapshot, empty artifact list, and empty audit chunk list.

Rollback/equivocation artifacts are deterministically reconstructed from the authenticated audit
records; there is no separate caller-selected artifact chunk stream. `ProviderRetentionInventory`
is likewise a validated semantic commitment input rather than an unbounded standalone interchange
message. Its exact preimage and limits are fixed below.

### Closed provider registries

| Registry | Code | Meaning |
| --- | ---: | --- |
| Provider export component | 1 | `Entries` |
|  | 2 | `LeafHashes` |
|  | 3 | `Receipts` |
|  | 4 | `CheckpointBundles` |
|  | 5 | `CompactionManifests` |
| Provider audit status | 1 | accepted, `FirstObserved` |
|  | 2 | accepted, `TreeAdvanced` |
|  | 3 | accepted, `HeadRefreshed` |
|  | 4 | accepted, exact `Replay` |
|  | 5 | authenticated `Rollback` |
|  | 6 | authenticated `Equivocation` |
| Provider audit artifact kind | 1 | `Rollback` |
|  | 2 | `Equivocation` |
| Provider retention class | 1 | `CheckpointLineage` |
|  | 2 | `ControllerTombstone` |
|  | 3 | `DeviceTombstone` |
|  | 4 | `UnresolvedFork` |
|  | 5 | `CryptoMigration` |
|  | 6 | `Recovery` |
|  | 7 | `ProviderRotation` |
|  | 8 | `Equivocation` |

All unlisted values are invalid. `ProviderAnchorStatus` is an adapter return type and has no
portable codepoint registry.

### Commitment rule and exact preimages

The foundational provider objects use the same `domain || NUL || canonical bytes` construction
already defined by the crate profile:

| Domain | Active v1 use |
| --- | --- |
| `KRIKOS-ID/provider/v1` | `ProviderId` is BLAKE3-256 over the canonical `ProviderDescriptor` |
| `KRIKOS-ID/provider-policy/v1` | `ProviderPolicyId` is BLAKE3-256 over the canonical `ProviderPolicy` |
| `KRIKOS-ID/provider-log-entry/v1` | one provider Merkle leaf digest is BLAKE3-256 over the canonical `ProviderLogEntryBody` |
| `KRIKOS-ID/provider-head-signature/v1` | the provider signs `domain || 0x00 || canonical(ProviderHeadBody)` directly; this row is a signature message, not another hash |
| `KRIKOS-ID/merkle-node/v1` | an interior provider-log node is BLAKE3-256 over canonical `(left: Digest, right: Digest)` |
| `KRIKOS-ID/merkle-empty/v1` | the empty provider-log root is BLAKE3-256 over the empty payload |

The hash-domain registry also reserves `KRIKOS-ID/provider-log/v1` and
`KRIKOS-ID/provider-head/v1`, but no current production path derives a `ProviderLogId` or provider
head digest with those generic domains. Callers supply the explicit log ID and providers sign the
literal head-signature message above. The reserved domains must not be substituted for an active
v1 commitment. `KRIKOS-ID/anchor/v1` is also a reserved generic hash domain; the active opaque
provider anchor uses only `KRIKOS-ID/provider-anchor-commitment/v1` below.

Every commitment in the table below is BLAKE3-256 over
`ASCII(domain) || 0x00 || Postcard(preimage)`. Every domain is ASCII and ends in `/v1`; every
top-level preimage begins with `format_version: u16 = 1`. The implementation streams Postcard bytes
directly into BLAKE3 for large aggregates, which is byte-for-byte equivalent to encoding the whole
preimage first. A `Digest` result is tagged `Blake3_256`; the prepared-owner token and opaque anchor
store the same 32 hash bytes without an algorithm field at their immediate API boundary.

| Domain | Exact Postcard preimage after the NUL separator |
| --- | --- |
| `KRIKOS-ID/provider-generation-chunk/v1` | `(format_version, provider_id, log_id, key_version, generation_commitment, component_code, ordinal, start_index, end_index, item_payload_bytes, payload)` |
| `KRIKOS-ID/provider-generation-chunk-list/v1` | `(format_version, component_code, chunk_count, commitments)` in ordinal order |
| `KRIKOS-ID/provider-generation-manifest/v1` | the complete `ProviderGenerationExportManifest` schema above |
| `KRIKOS-ID/provider-audit-chunk/v1` | `(format_version, provider_id, log_id, audit_commitment, ordinal, start_sequence, end_sequence, item_payload_bytes, payload)` |
| `KRIKOS-ID/provider-audit-chunk-list/v1` | `(format_version, component_code = 0, chunk_count, commitments)` in ordinal order |
| `KRIKOS-ID/provider-audit-manifest/v1` | the complete `ProviderAuditExportManifest` schema above |
| `KRIKOS-ID/provider-recovery-manifest/v1` | the complete `ProviderRecoveryExportManifest` schema above |
| `KRIKOS-ID/provider-generation-export/v1` | `(format_version, provider, log_id, key_version, entries, leaf_hashes, latest_head, receipts, checkpoint_bundles, compaction_manifests)`; each checkpoint bundle is `(genesis, prior_checkpoint_id, events, checkpoint, transition_event)` |
| `KRIKOS-ID/provider-audit-artifact/v1` | `(format_version, sequence, kind_code, accepted_head, observed_head)` |
| `KRIKOS-ID/provider-audit-snapshot/v1` | `(format_version, revision, provider, log_id, latest_head, equivocation, records)`; each record is `(sequence, head, consistency_proof, status_code)` |
| `KRIKOS-ID/provider-audit-artifacts/v1` | `(format_version, artifact_commitments)` sorted by `(sequence, kind_code)` |
| `KRIKOS-ID/provider-recovery-export/v1` | `(format_version, generation_commitment, audit_commitment, artifact_commitment)` |
| `KRIKOS-ID/provider-retention-inventory/v1` | `(format_version, tree_size, items, audit_artifact_commitments)`; each item is `(leaf_index, class_code)` and artifacts are sorted by `(sequence, kind_code)` |
| `KRIKOS-ID/provider-retained-evidence/v1` | `(format_version, records, checkpoint_evidence, checkpoint_index, audit_artifact_commitment)`; a record is `(leaf_index, entry, receipt)`, checkpoint evidence is `(genesis, prior_checkpoint_id, events, checkpoint, transition_event)`, and an index is `(account_id, greatest_sequence, greatest_epoch, current_checkpoint_id, projection_heads, forked)` |
| `KRIKOS-ID/provider-anchor-commitment/v1` | `(format_version, manifest: ProviderCompactionManifest)` including every manifest field and retained range |
| `KRIKOS-ID/provider-prepared-owner/v1` | `(format_version, base_root, base_size, material, leaf_index, observed_at)` where `material` is the exact prepared generation material defined below |

For the prepared-owner preimage, `material` is `(entries, leaf_hashes, account_index, frontier,
nodes, checkpoint_bundles, checkpoint_index)` in that order. An account-index item is
`(account_id, leaf_indices)`, a frontier item is `(level: u8, root)`, a Merkle-node item is
`(start: u64, size: u64, root)`, and a checkpoint-index item is `(account_id, greatest_sequence,
greatest_epoch, current_checkpoint_id, projection_heads, forked)`. Checkpoint bundles use the exact
five-field bundle schema above. This is an authenticated internal v7 prepare format, not a public
interchange message.

The generation-export commitment covers the export state immediately before a newly authorized
compaction manifest is inserted, avoiding self-reference. Every later generation commitment covers
all already-durable manifests. The recovery commitment binds the complete generation, complete
audit journal, and the sorted derived attack artifacts; it is not a commitment to availability
alone.

### Portable and persistence bounds

| Resource | V1 ceiling |
| --- | ---: |
| Canonical generation or audit chunk | 4 MiB |
| Decoded items in one chunk | 256 |
| One unsplit canonical item | 4 MiB - 4 KiB |
| Encoded chunk payload | 4 MiB - 2 KiB |
| Generation or audit manifest | 64 KiB |
| Recovery manifest | 128 KiB |
| Total chunks in one generation manifest; audit chunks in one audit manifest | 65,536 |
| Entries, leaf hashes, receipts, or checkpoint bundles in the portable generation profile | 1,048,576 per component |
| Compaction manifests in one generation | 256 |
| Aggregate canonical generation item bytes | 512 MiB |
| Audit records / aggregate canonical audit item bytes | 65,536 / 256 MiB |
| Checkpoint-lineage events in one checkpoint-bundle item | 256 |
| Compaction manifest canonical bytes / retained ranges | 2 MiB / 4,096 |
| Retention inventory pairs / addressable leaves / non-leaf audit artifacts | `8 * tree_size` unique pairs / 1,048,576 leaves / 65,536 artifacts |
| Opaque anchor commitment canonical bytes / backend evidence | 64 bytes / 16 KiB |
| One redb provider generation / one committed or prepared blob | 65,536 entries / 512 MiB |
| Stored account-index records / leaf indices in one record | 65,536 / 65,536 |
| Stored checkpoint bundles / checkpoint-index records / projection heads in one index | 65,536 / 65,536 / 16 |
| Stored sealed retention-inventory pairs | 65,536 |
| Stored Merkle nodes / frontier nodes | 131,072 / 64 |
| Stored embedded provider audit bytes | 256 MiB |

All item, count, and aggregate byte arithmetic is checked. Active stores maintain exact
per-component canonical-byte accounting on append and replacement; active and complete-archive
redb stores reconstruct it authoritatively on restore or open. A locally sealed generation has no
complete portable export, so reopen installs an explicit empty read-only sentinel instead. Every
mutation path rejects that sealed payload with `ProviderArchiveRequired` before consulting the
sentinel. Thus a mutable generation that fits its native database but cannot be represented by the
portable profile is rejected before it can be committed, without pretending a compacted local
view is a complete export.

## Generation boundary

Each `RedbProviderStore` path owns exactly one `(ProviderDescriptor, ProviderLogId,
ProviderKeyVersion)` generation. Opening a path with a different tuple fails; the adapter never
rolls a log or signing key implicitly. Version 1 currently verifies only `ProviderKeyVersion::GENESIS`.
A key change therefore requires an account-authorized `ChangeProviderPolicy` transition, a new
descriptor/provider ID, a new log generation, and a new store path. An in-place key-version bump is
rejected. Retain the old path, its signed heads, export, compaction manifests, and audit evidence.
After restart, select a checkpoint only from the exact current account-authorized policy and
descriptor generation. A longer log from an old or forked generation never wins by length.

Use `ProviderGenerationRegistry` when more than one generation is open. Every lookup supplies an
exact `ProviderGenerationRoute` containing provider ID, log ID, and key version. Policy routing
also checks that the exact provider ID occurs in that policy revision. The registry has no
`current`, `latest`, or longest-log fallback, and it rejects a second store at an already registered
route instead of replacing the first one. A locally sealed generation and its immutable full
archive therefore remain explicit alternatives at the same address; the caller chooses which one
to register for the operation being performed.

An append has four durable phases:

1. A native redb transaction authenticates the committed generation and durably records a hidden
   prepared candidate containing the entry, leaf hashes, account index, append frontier, and nodes.
2. A second transaction derives and records the exact `Signing` head body before invoking the
   configured signer. A signing error retains that same bound body for `resume_append`; it never
   substitutes a new request after the signer may have observed the message.
3. The verified signer result is persisted as the exact `Signed` candidate before it becomes
   visible.
4. A final transaction compares the exact base root/size, commits the candidate entry,
   index, nodes, signed head, and inclusion receipt together, and removes the prepare record.

Only the final transaction changes public tree size. Reopen retains `Prepared` and `Signing`
candidates, authenticates every derived field, and promotes a durably `Signed` candidate without
calling the signer again. `cancel_prepared_append` can remove only a never-signed `Prepared`
candidate. Do not wrap the adapter in a process mutex as a substitute for redb transactions.
Concurrent callers may receive `ResourceBusy` while a durable candidate is owned and should use
the bounded retry policy.

Provider append authority is the opaque token returned by checkpoint or intent verification.
Abuse controls receive that token only so they can deny capacity; they cannot manufacture it.
Preserve `ProviderUnavailable`, `ProviderTimeout`, `ProviderRateLimited`, `InvalidProof`,
`ProviderRollback`, and `ProviderEquivocation` as distinct outcomes.

Admission capacity is charged from the exact canonical request bytes and rejects any request above
4 MiB before storage mutation. Checkpoint admissions retain the complete verified checkpoint bundle
needed to rebuild the fork-safe account index; intent admissions retain the exact approved intent.
Because `CheckpointId` commits only the checkpoint body, a duplicate leaf may carry another
independently valid controller-approval subset for the same exact lineage. The store merges those
approvals canonically in either arrival order without adding a leaf; a different lineage,
transition witness, or checkpoint body still fails closed.
The provider serves inclusion proofs for committed leaves, exact arbitrary-prefix consistency
proofs, and bounded account history. A current checkpoint is returned only when all currently known
heads for the account resolve to one exact authorized bundle; unresolved or asymmetric forks have
no synthetic winner.

## Persistent schema and crash boundary

### Provider generation store v7

The redb generation layout is store version `7`. The committed table is
`krikos-provider-generation-v1` at key `active`; the transient append table is
`krikos-provider-prepared-v1` at key `append`. The table names identify their original table
families, while the `StoredProviderWire.version` and `PreparedAppendWire.version` fields select the
current layout. Only version `7` is accepted. Version `6`, any other version, and malformed or
oversized stored values are explicit `StorageCorruption`; this adapter performs no implicit
migration or downgrade. Back up and migrate a previous store with tooling that names both schema
versions rather than opening it as v7.

The logical v7 prepare record is `(version, owner_token: [u8; 32], base_tree_size,
base_tree_root, requested_observed_at, leaf_index, material, stage)`. `stage` is exactly one of
`Prepared`, `Signing { body }`, or `Signed { head }`. It is a private store-versioned enum, not a
portable codepoint registry; changing its encoding requires another store version.

Before the `Prepared` candidate is written, the adapter performs exact portable preflight against
the authenticated cached accounting. A new leaf must be exactly one entry, one parallel leaf hash,
one exact placeholder receipt, and at most one appended checkpoint bundle; a duplicate-checkpoint
approval merge may replace exactly one receipt and at most one bundle without changing the entry or
leaf streams. The placeholder has the exact canonical receipt size because it uses the fixed-width
Ed25519 signature schema; it grants no authority and is replaced by the verified signer result.
Every count, item byte length, component total, and 512 MiB aggregate delta is checked before the
prepared transaction commits.

The prepared owner token is the exact `provider-prepared-owner/v1` commitment specified above. On
every `Prepared -> Signing -> Signed` replacement and on reopen, the adapter rechecks that token,
store version, base root and size, generation route, derived material and indices, bound head body,
signature when present, and the exact portable delta. A reopened `Prepared` or `Signing` candidate
remains pending; a reopened `Signed` candidate is promoted without calling the signer again.

Failure atomicity is at the redb transaction boundary:

- preflight, signer-body, signature, receipt, or base-CAS failure cannot change the committed tree;
- each prepared-stage replacement compares the exact retained candidate before replacing it;
- final promotion writes the complete committed state and removes the prepared value in one
  transaction; and
- in-memory portable accounting changes only after the redb commit succeeds.

A never-signed `Prepared` candidate may be cancelled. Once the exact head body reaches `Signing`,
the candidate may only be resumed with that body or promoted from its already verified `Signed`
state.

### Provider audit store v2

The normalized audit layout is version `2`:

| redb object | Exact layout |
| --- | --- |
| `krikos-provider-audit-metadata-v2`, key `journal` | `(version = 2, revision, provider, log_id, latest_head, equivocation)`; at most 64 KiB |
| `krikos-provider-audit-records-v2`, key `sequence: u64` | `(sequence, head, consistency_proof, status_code)`; at most 4 MiB per record |

The old monolithic table `krikos-provider-audit-v1` is detected and rejected as
`StorageCorruption`; there is no automatic v1-to-v2 migration. When creating a journal, a missing
metadata row is valid only if the record table is empty. Open, reopen, explicit snapshot load, and
export reconstruct the complete journal and require exactly the contiguous keys `1..=revision`, no
record beyond the declared revision, no gaps, no key/body sequence mismatch, at most 65,536 records,
valid status codepoints, valid provider signatures and consistency outcomes, and exact agreement
between metadata and the replayed latest head/equivocation state.

The observation hot path is constant-size with respect to prior journal length. `load_cursor`
returns only revision, provider, log ID, latest accepted head, and terminal equivocation evidence.
`compare_and_append` validates one exact successor and one portable audit-item delta, compares the
durable metadata revision, then inserts that single sequence record and updates metadata in one redb
transaction. A stale cross-instance CAS refreshes authoritative state and retries under the bounded
auditor policy. No partial record survives a failed CAS or failed commit, and the cache is updated
only after commit. Full historical replay remains mandatory at open/reopen and explicit full-load
boundaries, not on each observation.

## Bounds and recovery

- one redb provider generation: 65,536 operational entries (rotate explicitly before the cap);
- protocol Merkle generation: 1,048,576 leaves;
- account-history response: 256 records and 4 MiB;
- provider count per publication: 16;
- effect/audit retry budget: 8;
- operational audit markers per effect: 256;
- owned identity queue: 256; concurrent tasks: 64; graceful shutdown: 10 seconds.

### Active, locally sealed, and archived generations

`ProviderRecoveryExport` is the unit of full mirror and recovery. It binds the exact
`ProviderGenerationExport`, the complete `ProviderAuditSnapshot` for the same authenticated latest
head, sorted rollback/equivocation artifacts, and separate generation, audit, artifact, and
composite recovery commitments. Construct it with `export_recovery` or
`ProviderRecoveryExport::new`; a mismatched provider, log, head, journal, artifact, signature,
receipt, checkpoint authorization, or commitment fails validation.

Derive the mandatory compaction inventory with
`derive_provider_retention_inventory(&recovery_export)`. A caller may retain additional valid
leaf/class pairs, but cannot omit or relabel a mandatory pair; its non-leaf audit-artifact set must
equal the derived sorted set. `record_compaction_manifest` and `seal_after_verified_mirror` accept
only the exact inventory committed by an authorization produced from an exact source/mirror
comparison. The source and mirror recovery exports, including their audit records and artifacts,
must be equal.

Each manifest requires BLAKE3-256 for its source root and six component/aggregate commitments,
requires `archive_commitment = recovery_commitment(generation, audit, audit artifacts)`, and binds
the source route, root and size, original-index retained ranges, inventory, and retained records,
checkpoint evidence, checkpoint index, and artifacts. Retained ranges are sorted, non-overlapping,
non-empty half-open intervals within the source tree. The candidate manifest commits the export
state immediately before that manifest is inserted, avoiding self-reference; later manifests
commit all earlier manifests. Memory and redb retain at most 256 manifests, and redb records
sealing atomically.

Local sealing is irreversible and semantic. It preserves current checkpoint tips, every branch of
an unresolved fork, destructive tombstone/recovery/migration/provider-rotation material, mandatory
original-index receipts, and non-leaf rollback/equivocation audit artifacts. Benign superseded
history and full replay bundles are released locally. The locally sealed store is read-only:
append, resume, cancel, and further archive-style sealing return `ProviderArchiveRequired`.
Deep validated reopen authenticates the retained state and installs a never-consulted read-only
portable-accounting sentinel rather than attempting to reconstruct the deliberately unavailable
full export. Append and compaction-manifest recording reject the sealed state before portable-delta
preflight; an unexpected prepared record beside a sealed state is `StorageCorruption`.

A locally sealed store exposes `ProviderRetainedCheckpointEvidence` only for retained current
links. This is raw, structurally checked material: genesis or prior checkpoint ID, bounded events,
signed checkpoint, optional transition witness, and its original provider receipt. It is not a
`VerifiedCheckpoint`, cannot create a provider admission, and does not make the compaction manifest
an account-authority signature. Replay it with
`build_provider_checkpoint_bundle_from_genesis` or
`build_provider_checkpoint_bundle_from_prior` from independently trusted state. If the required
prior state was released, retrieve the full recovery archive. Full history, checkpoint bundles,
lineage pages, and generation export deliberately return `ProviderArchiveRequired` on the local
sealed store.

Install the full immutable copy with `MemoryProviderStore::restore_recovery` or
`RedbProviderStore::restore_recovery` at a dedicated archive path. An archive retains exact full
history, checkpoint replay bundles, audit journal, and audit artifacts. Exact repeated restore is
idempotent; any different existing generation is rejected without overwrite. Archives serve full
read APIs but reject append, resume, cancel, compaction-manifest recording, and sealing. This keeps
their exact recovery export immutable, including across redb reopen and repeated restore. Raw
evidence reconstructed from a local sealed generation cannot mutate an archive, and the exact-route
registry prevents it from being silently installed as a duplicate generation.

On corruption, stop writes and preserve the database bytes. Restore the exact composite recovery
export at a new archive path, verify its root, head, history, checkpoint replay, audit commitment,
and artifacts, and compare the old and mirror heads with the auditor. Reopen validation recomputes
entry and receipt bindings, leaf hashes, frontier/nodes, account index, head signature, key/log
address, manifest commitments/ranges/inventory, and sealed/archive state kind. A truncated or
corrupt component is `StorageCorruption`; do not normalize it into an empty log or automatically
roll back to an older head.

## Auditor

`DurableProviderAuditor` journals accepted heads and authenticated rollback/equivocation outcomes
with compare-and-swap revisions. Same-size/different-root evidence becomes terminal and survives
redb reopen. The example accepts bounded canonical files:

```text
cargo run -p krikos-identity --example provider_auditor -- \
  provider.bin older-head.bin newer-head.bin consistency-proof.bin evidence.bin
```

Auditors must compare heads obtained from independent peers or mirrors; neither provider is trusted.
For a same-size conflict the consistency proof is ignored, but the argument position remains
reserved when an evidence output path is supplied.

## Effect execution and protected writes

`OperationalEffectJournal` keys every substep by the account operation's stable `EffectId`. It
retains deterministic checkpoint build/authorization, the exact authorizing `ProviderPolicy`, exact
provider receipts and observation proofs, rotation completion, peer notification, retry, and
terminal audit phases.
`RedbOperationalEffectStore` survives every process restart. Same-phase progress is still a durable
mutation: each newly accepted receipt or observation is revisioned and audited even when it does not
cross a threshold. Reopen re-verifies the policy ID, configured descriptors, signatures, inclusion
proofs, consistency proofs, and threshold-derived stage instead of trusting the serialized phase.

Re-run the same step after a crash. Account checkpoint commits, provider receipts, rotations,
operation completion, and journal transitions are idempotent under the same stable effect ID. After
a retry, claim the effect under a new bounded lease/attempt and call `begin` again; the journal
retains authenticated checkpoint, receipt, observation, rotation, and notification substep progress
while binding the new lease. Terminal journal states are immutable except for an exact idempotent
replay. If operation completion commits before the journal transition, `complete_ready_effect`
reconciles the already-completed outbox record on reopen.

Replicated publication completion requires the `Observed` phase. A partial batch remains
`Authorized`, `Published`, or `Replicated` exactly as computed by `PublicationTracker`; threshold
shortfall is retryable and must never be relabelled. `LocalOnly` is the explicit exception: it
completes directly from policy-bound `Authorized` without synthetic provider receipts or observation
phases. Group-key rotation uses the revision-bound atomic `commit_group_key_rotation`, which keeps
protected application writes blocked until the exact current-epoch artifact and its operational
effect completion are durable.

## Metrics and privacy

Allowed metric dimensions are aggregate phase, stable error class, queue saturation, retry count,
and latency bucket. Never use account, event, checkpoint, device, controller, guardian, provider
relationship, lookup handle, or peer identifiers as metric labels. `OperationalMetricsSnapshot`
exposes only aggregate counts (`pending`, `completed`, `retry_scheduled`, `terminal_failures`, and
`publication_shortfalls`). Detailed identifiers belong only in access-controlled durable audit
records.

Anchor backends receive only `OpaqueProviderAnchorCommitment`. They may return bounded opaque
inclusion/status evidence, but chain selection, fees, tokens, and vendor semantics are outside this
crate and cannot authorize an account. The opaque value commits to the complete verified compaction
manifest, not only its archive digest. Backend evidence must be nonempty and at most 16 KiB. A
pending, included, or rejected anchor status never changes account authority, provider admission,
compaction authorization, or recovery validity.

## Provider verification commands

Run these focused Rust 1.91 gates after changing any schema, commitment, store layout, or recovery
rule. They are commands to execute and record in the current-tree verification report, not a claim
that repository tests replace independent interoperability or security review.

```console
cargo +1.91.0 test --locked -p krikos-identity --test provider_wire_formats
cargo +1.91.0 test --locked -p krikos-identity --lib audit::tests
cargo +1.91.0 test --locked -p krikos-identity --lib provider::compaction::tests
cargo +1.91.0 test --locked -p krikos-identity --features provider-store --lib \
  provider::redb::tests -- --test-threads=1
cargo +1.91.0 test --locked -p krikos-identity --features provider-store --lib \
  audit::redb::tests -- --test-threads=1
cargo +1.91.0 test --locked -p krikos-identity --features provider-store \
  --test provider_persistence
```

`provider_wire_formats` covers canonical manifest/chunk round trips, the 257-item multi-chunk
assembly path, out-of-order delivery, duplicate replay, truncation, gaps, overlaps, component swaps,
unknown versions/codepoints, count/byte tampering, and incomplete recovery finish. The provider and
audit redb unit suites cover store-v6 rejection, prepared-owner preimages, exact portable preflight
on reopen, failed-preflight non-mutation, signer resumption, audit-v1 rejection, v2 gap/extra-record
rejection, failed-CAS atomicity, and the 257-append no-prior-rescan canaries. The persistence suite
covers exact recovery/compaction commitments, continuation checkpoint evidence, immutable archive
restore, deep validated reopen of locally sealed state without reconstructing a missing full export,
sealed mutation denial, route isolation, concurrency, and terminal audit evidence.

The complete feature, documentation, workspace, vector, fuzz, simulator, packaging, and closed
release-policy gates remain listed in [`design-evidence.md`](design-evidence.md). Stable publication
still requires all six external approvals in [`release-gate.md`](release-gate.md).
