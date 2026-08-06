use krikos_identity::{
    CanonicalWire, Digest, HashAlgorithm, IdentityError,
    limits::MAX_MERKLE_SET_LEAVES,
    merkle::{
        MerkleConsistencyProof, MerkleInclusionProof, MerkleNeighbor, MerkleNonMembershipProof,
        MerkleSet, MerkleSetKey, MerkleSetLeaf, empty_merkle_root,
    },
};
use proptest::prelude::*;

fn digest(byte: u8) -> Digest {
    Digest::new(HashAlgorithm::Blake3_256, [byte; 32])
}

fn key(tag: u16, byte: u8) -> MerkleSetKey {
    MerkleSetKey::new(tag, digest(byte)).expect("nonzero test tag")
}

fn leaf(tag: u16, byte: u8, value: u8) -> MerkleSetLeaf {
    MerkleSetLeaf::new(key(tag, byte), digest(value))
}

#[test]
fn roots_are_domain_separated_deterministic_and_frozen() {
    let empty = MerkleSet::new(Vec::new()).expect("empty set");
    assert_eq!(empty.root().expect("empty root"), empty_merkle_root());
    assert_eq!(
        empty_merkle_root().to_string(),
        "b3:ac852bf31ef19b5d18fd8df40dcb4f07a8ea8066ca4094464f431618ebf339b7"
    );

    let one = MerkleSet::new(vec![leaf(7, 1, 11)]).expect("one leaf");
    let four = MerkleSet::new(vec![
        leaf(7, 4, 14),
        leaf(7, 1, 11),
        leaf(7, 3, 13),
        leaf(7, 2, 12),
    ])
    .expect("four leaves");

    assert_ne!(
        empty.root().expect("empty root"),
        one.root().expect("one root")
    );
    assert_eq!(
        one.root().expect("one root").to_string(),
        "b3:435255485d5bb197e19d080ab391a6ae80437d4fe0b70cff6e57bcefb8b8065e"
    );
    assert_eq!(
        four.root().expect("four root").to_string(),
        "b3:64fd4c0da68b4383eabf387c07a16c0bb155497da84406e5bedf245882ed1ef2"
    );
    assert_eq!(four.entries()[0].key(), key(7, 1));
    assert_eq!(four.entries()[3].key(), key(7, 4));
}

#[test]
fn frozen_roots_are_independently_staged_from_the_wire_profile() {
    fn raw_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(payload);
        *hasher.finalize().as_bytes()
    }

    fn digest_wire(bytes: [u8; 32]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(33);
        wire.push(1); // BLAKE3-256 registry codepoint as a minimal Postcard varint.
        wire.extend_from_slice(&bytes);
        wire
    }

    fn raw_leaf(id: u8, value: u8) -> [u8; 32] {
        let mut payload = vec![7]; // Type tag 7 as a minimal Postcard varint.
        payload.extend_from_slice(&digest_wire([id; 32]));
        payload.extend_from_slice(&digest_wire([value; 32]));
        raw_hash(b"KRIKOS-ID/merkle-leaf/v1", &payload)
    }

    fn raw_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut payload = digest_wire(left);
        payload.extend_from_slice(&digest_wire(right));
        raw_hash(b"KRIKOS-ID/merkle-node/v1", &payload)
    }

    let leaves = [
        raw_leaf(1, 11),
        raw_leaf(2, 12),
        raw_leaf(3, 13),
        raw_leaf(4, 14),
    ];
    let independently_staged = raw_node(
        raw_node(leaves[0], leaves[1]),
        raw_node(leaves[2], leaves[3]),
    );
    let production = MerkleSet::new(vec![
        leaf(7, 4, 14),
        leaf(7, 1, 11),
        leaf(7, 3, 13),
        leaf(7, 2, 12),
    ])
    .expect("set")
    .root()
    .expect("root");
    assert_eq!(production.as_bytes(), &independently_staged);
}

#[test]
fn set_rejects_duplicate_keys_and_zero_type_tags() {
    assert_eq!(
        MerkleSetKey::new(0, digest(1)),
        Err(IdentityError::ZeroValue {
            resource: "Merkle set leaf type tag"
        })
    );
    assert_eq!(
        MerkleSet::new(vec![leaf(1, 1, 10), leaf(1, 1, 20)]),
        Err(IdentityError::DuplicateElement {
            resource: "Merkle set leaf key"
        })
    );
    assert!(matches!(
        MerkleSet::new(vec![leaf(1, 1, 10); MAX_MERKLE_SET_LEAVES + 1]),
        Err(IdentityError::LimitExceeded {
            resource: "Merkle set leaves",
            actual,
            maximum: MAX_MERKLE_SET_LEAVES,
        }) if actual == MAX_MERKLE_SET_LEAVES + 1
    ));
}

#[test]
fn inclusion_proofs_verify_every_shape_and_reject_substitution() {
    for size in 1_u8..=17 {
        let entries = (0..size)
            .map(|index| leaf(1, index, index.wrapping_add(80)))
            .collect();
        let set = MerkleSet::new(entries).expect("unique set");
        let root = set.root().expect("root");

        for entry in set.entries() {
            let proof = set
                .inclusion_proof(entry.key())
                .expect("included leaf proof");
            proof.verify(entry, root).expect("valid proof");

            assert_eq!(
                proof.verify(&leaf(1, entry.key().id().as_bytes()[0], 250), root),
                Err(IdentityError::InvalidProof)
            );
            assert_eq!(
                proof.verify(entry, digest(250)),
                Err(IdentityError::InvalidProof)
            );
        }
    }
}

#[test]
fn inclusion_proof_shape_is_exact_and_wire_decode_is_bounded() {
    assert_eq!(
        MerkleInclusionProof::new(1, 1, Vec::new()),
        Err(IdentityError::InvalidProof)
    );
    assert_eq!(
        MerkleInclusionProof::new(0, 1, vec![digest(1)]),
        Err(IdentityError::InvalidProof)
    );
    assert!(matches!(
        MerkleInclusionProof::new(0, u64::MAX, vec![digest(1); 65]),
        Err(IdentityError::LimitExceeded {
            resource: "Merkle audit path",
            actual: 65,
            maximum: 64
        })
    ));

    let set = MerkleSet::new((0..9).map(|index| leaf(2, index, index + 1)).collect())
        .expect("unique set");
    let proof = set.inclusion_proof(key(2, 7)).expect("proof");
    let bytes = proof.to_canonical_bytes().expect("encode proof");
    assert_eq!(
        MerkleInclusionProof::from_canonical_bytes(&bytes).expect("decode proof"),
        proof
    );
}

#[test]
fn non_membership_proves_empty_boundaries_and_adjacency() {
    let empty = MerkleSet::new(Vec::new()).expect("empty set");
    let empty_proof = empty.non_membership_proof(key(1, 9)).expect("empty proof");
    empty_proof
        .verify(key(1, 9), empty.root().expect("root"))
        .expect("empty non-membership");

    let set =
        MerkleSet::new(vec![leaf(1, 20, 1), leaf(1, 40, 2), leaf(1, 60, 3)]).expect("unique set");
    let root = set.root().expect("root");
    for missing in [10, 30, 50, 70] {
        let query = key(1, missing);
        let proof = set.non_membership_proof(query).expect("missing proof");
        proof.verify(query, root).expect("valid non-membership");

        let bytes = proof.to_canonical_bytes().expect("encode proof");
        let decoded = MerkleNonMembershipProof::from_canonical_bytes(&bytes).expect("decode proof");
        assert_eq!(decoded, proof);
    }

    assert_eq!(
        set.non_membership_proof(key(1, 40)),
        Err(IdentityError::InvalidRelationship {
            resource: "Merkle non-membership query is present"
        })
    );
}

#[test]
fn non_membership_rejects_non_adjacent_or_wrong_boundary_neighbors() {
    let set =
        MerkleSet::new(vec![leaf(1, 20, 1), leaf(1, 40, 2), leaf(1, 60, 3)]).expect("unique set");
    let root = set.root().expect("root");

    let first = MerkleNeighbor::new(
        set.entries()[0],
        set.inclusion_proof(key(1, 20)).expect("proof"),
    )
    .expect("neighbor");
    let last = MerkleNeighbor::new(
        set.entries()[2],
        set.inclusion_proof(key(1, 60)).expect("proof"),
    )
    .expect("neighbor");
    assert_eq!(
        MerkleNonMembershipProof::new(3, Some(first.clone()), Some(last.clone())),
        Err(IdentityError::InvalidProof)
    );

    let wrong_low_boundary =
        MerkleNonMembershipProof::new(3, None, Some(last)).expect_err("not first leaf");
    assert_eq!(wrong_low_boundary, IdentityError::InvalidProof);

    let wrong_high_boundary =
        MerkleNonMembershipProof::new(3, Some(first), None).expect_err("not last leaf");
    assert_eq!(wrong_high_boundary, IdentityError::InvalidProof);

    let valid = set.non_membership_proof(key(1, 30)).expect("proof");
    assert_eq!(
        valid.verify(key(1, 30), digest(99)),
        Err(IdentityError::InvalidProof)
    );
    valid.verify(key(1, 30), root).expect("valid proof");
}

#[test]
fn consistency_proofs_cover_every_prefix_and_tree_shape() {
    for new_size in 0_u8..=65 {
        let entries: Vec<_> = (0..new_size)
            .map(|index| leaf(11, index, index.wrapping_add(90)))
            .collect();
        let new_set = MerkleSet::new(entries).expect("new set");
        let new_root = new_set.root().expect("new root");

        for old_size in 0..=new_size {
            let old_set = MerkleSet::new(new_set.entries()[..usize::from(old_size)].to_vec())
                .expect("old prefix");
            let old_root = old_set.root().expect("old root");
            let proof = new_set
                .consistency_proof(u64::from(old_size))
                .expect("consistency proof");
            proof
                .verify(old_root, new_root)
                .expect("prefix is consistent");

            let bytes = proof.to_canonical_bytes().expect("encode proof");
            assert_eq!(
                MerkleConsistencyProof::from_canonical_bytes(&bytes).expect("decode proof"),
                proof
            );

            if old_size != 0 {
                assert_eq!(
                    proof.verify(digest(0xfe), new_root),
                    Err(IdentityError::InvalidProof)
                );
            }
            if old_size == new_size || old_size != 0 {
                assert_eq!(
                    proof.verify(old_root, digest(0xfd)),
                    Err(IdentityError::InvalidProof)
                );
            }
        }
    }
}

#[test]
fn consistency_proof_shape_and_tampering_fail_closed() {
    assert_eq!(
        MerkleConsistencyProof::new(2, 1, Vec::new()),
        Err(IdentityError::InvalidProof)
    );
    assert!(matches!(
        MerkleConsistencyProof::new(1, u64::MAX, vec![digest(1); 65]),
        Err(IdentityError::LimitExceeded {
            resource: "Merkle consistency path",
            actual: 65,
            maximum: 64,
        })
    ));

    let set =
        MerkleSet::new((0..13).map(|index| leaf(12, index, index + 1)).collect()).expect("set");
    assert_eq!(set.consistency_proof(14), Err(IdentityError::InvalidProof));
    let proof = set.consistency_proof(7).expect("proof");
    let mut tampered_path = proof.audit_path().to_vec();
    tampered_path[0] = digest(0xfc);
    let tampered = MerkleConsistencyProof::new(7, 13, tampered_path).expect("same shape");
    let old = MerkleSet::new(set.entries()[..7].to_vec()).expect("old set");
    assert_eq!(
        tampered.verify(old.root().expect("old root"), set.root().expect("new root")),
        Err(IdentityError::InvalidProof)
    );
}

proptest! {
    #[test]
    fn arbitrary_unique_sets_prove_all_members_and_gaps(mut ids in prop::collection::vec(any::<u8>(), 0..32)) {
        ids.sort_unstable();
        ids.dedup();
        let set = MerkleSet::new(
            ids.iter().map(|id| leaf(9, *id, id.wrapping_add(1))).collect()
        ).expect("unique set");
        let root = set.root().expect("root");

        for entry in set.entries() {
            set.inclusion_proof(entry.key())
                .expect("member proof")
                .verify(entry, root)
                .expect("member verifies");
        }

        if let Some(missing) = (0_u8..=u8::MAX).find(|candidate| !ids.contains(candidate)) {
            let query = key(9, missing);
            set.non_membership_proof(query)
                .expect("non-member proof")
                .verify(query, root)
                .expect("non-member verifies");
        }
    }
}
