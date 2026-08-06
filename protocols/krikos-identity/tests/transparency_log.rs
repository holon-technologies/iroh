use krikos_identity::{Digest, HashAlgorithm, IdentityError, merkle::AppendOnlyMerkleLog};

fn digest(fill: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [fill; 32])
}

#[test]
fn append_log_proves_every_leaf_and_prefix_without_reordering() {
    let mut log = AppendOnlyMerkleLog::new();
    let empty_root = log.root().unwrap();
    let leaves = (1_u8..=17).map(digest).collect::<Vec<_>>();
    let mut prefix_roots = vec![empty_root];

    for (expected_index, leaf) in leaves.iter().copied().enumerate() {
        assert_eq!(log.append(leaf).unwrap(), expected_index as u64);
        prefix_roots.push(log.root().unwrap());
    }

    assert_eq!(log.leaf_hashes(), leaves);
    for (index, leaf) in leaves.iter().copied().enumerate() {
        log.inclusion_proof(index as u64)
            .unwrap()
            .verify_leaf_hash(leaf, log.root().unwrap())
            .unwrap();
    }
    for old_size in 0..=log.tree_size().unwrap() {
        log.consistency_proof(old_size)
            .unwrap()
            .verify(
                prefix_roots[usize::try_from(old_size).unwrap()],
                log.root().unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn append_log_rejects_out_of_range_queries_without_mutation() {
    let log = AppendOnlyMerkleLog::from_leaf_hashes(vec![digest(1), digest(2)]).unwrap();
    let before = log.clone();
    assert_eq!(log.inclusion_proof(2), Err(IdentityError::InvalidProof));
    assert_eq!(log.consistency_proof(3), Err(IdentityError::InvalidProof));
    assert_eq!(log, before);
}
