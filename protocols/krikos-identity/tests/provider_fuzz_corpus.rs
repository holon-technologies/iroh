use krikos_identity::{
    CanonicalWire, OpaqueProviderAnchorCommitment, ProviderAuditExportChunk,
    ProviderAuditExportManifest, ProviderCompactionManifest, ProviderExportComponent,
    ProviderExportComponentDescriptor, ProviderGenerationExportChunk,
    ProviderGenerationExportManifest, ProviderRecoveryExportManifest,
};

fn payload(seed: &[u8], selector: u8) -> &[u8] {
    assert_eq!(seed.first(), Some(&selector));
    &seed[1..]
}

fn assert_corpus_pair<T: CanonicalWire>(accepted: &[u8], malformed: &[u8], selector: u8) {
    assert!(T::from_canonical_bytes(payload(accepted, selector)).is_ok());
    assert!(T::from_canonical_bytes(payload(malformed, selector)).is_err());
}

#[test]
fn provider_interchange_corpus_keeps_append_only_ascii_selectors_and_fail_closed_seeds() {
    assert_corpus_pair::<ProviderExportComponent>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-07-provider-export-component-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-07-provider-export-component-malformed-truncated.bin"
        ),
        b'7',
    );
    assert_corpus_pair::<ProviderExportComponentDescriptor>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-08-provider-export-component-descriptor-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-08-provider-export-component-descriptor-malformed-truncated.bin"
        ),
        b'8',
    );
    assert_corpus_pair::<ProviderGenerationExportChunk>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-09-provider-generation-export-chunk-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-09-provider-generation-export-chunk-malformed-truncated.bin"
        ),
        b'9',
    );
    assert_corpus_pair::<ProviderAuditExportChunk>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0a-provider-audit-export-chunk-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0a-provider-audit-export-chunk-malformed-truncated.bin"
        ),
        b'a',
    );
    assert_corpus_pair::<ProviderGenerationExportManifest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0b-provider-generation-export-manifest-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0b-provider-generation-export-manifest-malformed-truncated.bin"
        ),
        b'b',
    );
    assert_corpus_pair::<ProviderAuditExportManifest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0c-provider-audit-export-manifest-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0c-provider-audit-export-manifest-malformed-truncated.bin"
        ),
        b'c',
    );
    assert_corpus_pair::<ProviderRecoveryExportManifest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0d-provider-recovery-export-manifest-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0d-provider-recovery-export-manifest-malformed-truncated.bin"
        ),
        b'd',
    );
    assert_corpus_pair::<ProviderCompactionManifest>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0e-provider-compaction-manifest-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0e-provider-compaction-manifest-malformed-truncated.bin"
        ),
        b'e',
    );
    assert_corpus_pair::<OpaqueProviderAnchorCommitment>(
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0f-opaque-provider-anchor-commitment-accepted.bin"
        ),
        include_bytes!(
            "../../../fuzz/corpus/identity_provider/selector-0f-opaque-provider-anchor-commitment-malformed-truncated.bin"
        ),
        b'f',
    );
}
