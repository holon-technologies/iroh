//! Deterministic Merkle trees and sorted-set proofs.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    Digest, IdentityError,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_MERKLE_LOG_LEAVES, MAX_MERKLE_PROOF_HASHES, MAX_MERKLE_SET_LEAVES},
    schema::BoundedVec,
    types::{HashDomain, hash_bytes},
};

/// Canonical sort key for one leaf in a typed Merkle set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MerkleSetKey {
    type_tag: u16,
    id: Digest,
}

impl MerkleSetKey {
    /// Construct a key from a nonzero application-defined type tag and typed identifier digest.
    pub const fn new(type_tag: u16, id: Digest) -> Result<Self, IdentityError> {
        if type_tag == 0 {
            return Err(IdentityError::ZeroValue {
                resource: "Merkle set leaf type tag",
            });
        }
        Ok(Self { type_tag, id })
    }

    /// Stable application-defined leaf type tag.
    pub const fn type_tag(self) -> u16 {
        self.type_tag
    }

    /// Identifier that orders this leaf within its type.
    pub const fn id(self) -> Digest {
        self.id
    }
}

impl<'de> Deserialize<'de> for MerkleSetKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            type_tag: u16,
            id: Digest,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.type_tag, wire.id).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for MerkleSetKey {
    const RESOURCE: &'static str = "Merkle set key bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Canonical `(type_tag, id, value_hash)` leaf committed by a sorted Merkle set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MerkleSetLeaf {
    key: MerkleSetKey,
    value_hash: Digest,
}

impl MerkleSetLeaf {
    /// Construct a leaf from its unique sort key and the digest of its typed value.
    pub const fn new(key: MerkleSetKey, value_hash: Digest) -> Self {
        Self { key, value_hash }
    }

    /// Canonical leaf sort key.
    pub const fn key(&self) -> MerkleSetKey {
        self.key
    }

    /// Digest of the leaf's typed value.
    pub const fn value_hash(&self) -> Digest {
        self.value_hash
    }

    fn hash(&self) -> Result<Digest, IdentityError> {
        let payload = encode_wire(&(self.key.type_tag(), self.key.id(), self.value_hash))?;
        Ok(hash_bytes(HashDomain::MerkleLeaf, &payload))
    }
}

impl CanonicalCodec for MerkleSetLeaf {
    const RESOURCE: &'static str = "Merkle set leaf bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Bounded append-order Merkle tree for one versioned provider-log generation.
///
/// Unlike [`MerkleSet`], this structure preserves insertion order. The supplied leaf hashes
/// must already use their protocol-owned leaf domain; only interior nodes and the empty root are
/// derived here. Durable providers rotate `ProviderLogId` before this in-memory generation bound.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppendOnlyMerkleLog {
    leaf_hashes: Vec<Digest>,
}

impl AppendOnlyMerkleLog {
    /// Construct an empty append-only tree.
    pub const fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
        }
    }

    /// Restore one complete bounded generation in its exact append order.
    pub fn from_leaf_hashes(leaf_hashes: Vec<Digest>) -> Result<Self, IdentityError> {
        if leaf_hashes.len() > MAX_MERKLE_LOG_LEAVES {
            return Err(IdentityError::limit(
                "provider Merkle log leaves",
                leaf_hashes.len(),
                MAX_MERKLE_LOG_LEAVES,
            ));
        }
        Ok(Self { leaf_hashes })
    }

    /// Number of leaves currently committed by this generation.
    pub const fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    /// Whether this generation has no leaves.
    pub const fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    /// Exact append-ordered leaf hashes.
    pub fn leaf_hashes(&self) -> &[Digest] {
        &self.leaf_hashes
    }

    /// Append one protocol-domain-separated leaf hash and return its zero-based index.
    pub fn append(&mut self, leaf_hash: Digest) -> Result<u64, IdentityError> {
        if self.leaf_hashes.len() == MAX_MERKLE_LOG_LEAVES {
            return Err(IdentityError::limit(
                "provider Merkle log leaves",
                self.leaf_hashes.len().saturating_add(1),
                MAX_MERKLE_LOG_LEAVES,
            ));
        }
        let index = u64::try_from(self.leaf_hashes.len()).map_err(|_| {
            IdentityError::ArithmeticOverflow {
                resource: "provider Merkle log leaf index",
            }
        })?;
        self.leaf_hashes.push(leaf_hash);
        Ok(index)
    }

    /// Number of leaves represented on the wire by this generation.
    pub fn tree_size(&self) -> Result<u64, IdentityError> {
        u64::try_from(self.leaf_hashes.len()).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider Merkle log tree size",
        })
    }

    /// Root of the exact append prefix currently retained.
    pub fn root(&self) -> Result<Digest, IdentityError> {
        tree_hash(&self.leaf_hashes)
    }

    /// Build an exact bounded inclusion proof for one append index.
    pub fn inclusion_proof(&self, leaf_index: u64) -> Result<MerkleInclusionProof, IdentityError> {
        let tree_size = self.tree_size()?;
        if leaf_index >= tree_size {
            return Err(IdentityError::InvalidProof);
        }
        let index = usize::try_from(leaf_index).map_err(|_| IdentityError::ArithmeticOverflow {
            resource: "provider Merkle log leaf index",
        })?;
        let mut audit_path = Vec::new();
        append_inclusion_path(&self.leaf_hashes, index, &mut audit_path)?;
        MerkleInclusionProof::new(leaf_index, tree_size, audit_path)
    }

    /// Prove that `old_size` is an exact append-only prefix of the current generation.
    pub fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Result<MerkleConsistencyProof, IdentityError> {
        let new_size = self.tree_size()?;
        if old_size > new_size {
            return Err(IdentityError::InvalidProof);
        }
        if old_size == 0 || old_size == new_size {
            return MerkleConsistencyProof::new(old_size, new_size, Vec::new());
        }
        let prefix_len =
            usize::try_from(old_size).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "provider Merkle log consistency prefix",
            })?;
        let mut audit_path = Vec::new();
        append_consistency_path(prefix_len, &self.leaf_hashes, true, &mut audit_path)?;
        MerkleConsistencyProof::new(old_size, new_size, audit_path)
    }
}

/// Canonical sorted, duplicate-free collection committed by a binary Merkle root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleSet {
    entries: Vec<MerkleSetLeaf>,
}

impl MerkleSet {
    /// Sort and validate a complete set of leaves.
    pub fn new(mut entries: Vec<MerkleSetLeaf>) -> Result<Self, IdentityError> {
        if entries.len() > MAX_MERKLE_SET_LEAVES {
            return Err(IdentityError::limit(
                "Merkle set leaves",
                entries.len(),
                MAX_MERKLE_SET_LEAVES,
            ));
        }
        entries.sort_unstable_by_key(MerkleSetLeaf::key);
        for pair in entries.windows(2) {
            if pair[0].key() == pair[1].key() {
                return Err(IdentityError::DuplicateElement {
                    resource: "Merkle set leaf key",
                });
            }
        }
        Ok(Self { entries })
    }

    /// Canonically ordered leaves.
    pub fn entries(&self) -> &[MerkleSetLeaf] {
        &self.entries
    }

    /// Derive the root using the fixed v1 empty, leaf, and interior-node domains.
    pub fn root(&self) -> Result<Digest, IdentityError> {
        let hashes = self.leaf_hashes()?;
        tree_hash(&hashes)
    }

    /// Build a bounded inclusion proof for an exact set key.
    pub fn inclusion_proof(
        &self,
        key: MerkleSetKey,
    ) -> Result<MerkleInclusionProof, IdentityError> {
        let index = self
            .entries
            .binary_search_by_key(&key, MerkleSetLeaf::key)
            .map_err(|_| IdentityError::InvalidRelationship {
                resource: "Merkle inclusion query is absent",
            })?;
        self.inclusion_proof_at(index)
    }

    /// Build an adjacent-neighbor proof that an exact set key is absent.
    pub fn non_membership_proof(
        &self,
        query: MerkleSetKey,
    ) -> Result<MerkleNonMembershipProof, IdentityError> {
        let insertion = match self
            .entries
            .binary_search_by_key(&query, MerkleSetLeaf::key)
        {
            Ok(_) => {
                return Err(IdentityError::InvalidRelationship {
                    resource: "Merkle non-membership query is present",
                });
            }
            Err(index) => index,
        };

        let tree_size =
            u64::try_from(self.entries.len()).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "Merkle tree size",
            })?;
        let predecessor = if insertion == 0 {
            None
        } else {
            Some(MerkleNeighbor::new(
                self.entries[insertion - 1],
                self.inclusion_proof_at(insertion - 1)?,
            )?)
        };
        let successor = if insertion == self.entries.len() {
            None
        } else {
            Some(MerkleNeighbor::new(
                self.entries[insertion],
                self.inclusion_proof_at(insertion)?,
            )?)
        };
        MerkleNonMembershipProof::new(tree_size, predecessor, successor)
    }

    /// Prove that the first `old_size` leaves are an exact prefix of this tree.
    pub fn consistency_proof(
        &self,
        old_size: u64,
    ) -> Result<MerkleConsistencyProof, IdentityError> {
        let new_size =
            u64::try_from(self.entries.len()).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "Merkle tree size",
            })?;
        if old_size > new_size {
            return Err(IdentityError::InvalidProof);
        }
        if old_size == 0 || old_size == new_size {
            return MerkleConsistencyProof::new(old_size, new_size, Vec::new());
        }

        let old_size =
            usize::try_from(old_size).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "Merkle consistency old size",
            })?;
        let hashes = self.leaf_hashes()?;
        let mut audit_path = Vec::new();
        append_consistency_path(old_size, &hashes, true, &mut audit_path)?;
        MerkleConsistencyProof::new(
            u64::try_from(old_size).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "Merkle consistency old size",
            })?,
            new_size,
            audit_path,
        )
    }

    fn inclusion_proof_at(&self, leaf_index: usize) -> Result<MerkleInclusionProof, IdentityError> {
        let hashes = self.leaf_hashes()?;
        let mut audit_path = Vec::new();
        append_inclusion_path(&hashes, leaf_index, &mut audit_path)?;
        let leaf_index =
            u64::try_from(leaf_index).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "Merkle leaf index",
            })?;
        let tree_size =
            u64::try_from(hashes.len()).map_err(|_| IdentityError::ArithmeticOverflow {
                resource: "Merkle tree size",
            })?;
        MerkleInclusionProof::new(leaf_index, tree_size, audit_path)
    }

    fn leaf_hashes(&self) -> Result<Vec<Digest>, IdentityError> {
        self.entries.iter().map(MerkleSetLeaf::hash).collect()
    }
}

/// Bottom-up bounded audit path for one exact leaf index and tree size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleInclusionProof {
    leaf_index: u64,
    tree_size: u64,
    audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
}

impl MerkleInclusionProof {
    /// Validate and construct an exact-shape inclusion proof.
    pub fn new(
        leaf_index: u64,
        tree_size: u64,
        audit_path: Vec<Digest>,
    ) -> Result<Self, IdentityError> {
        let audit_path = BoundedVec::new("Merkle audit path", audit_path)?;
        if tree_size == 0 || leaf_index >= tree_size {
            return Err(IdentityError::InvalidProof);
        }
        let expected = inclusion_path_length(leaf_index, tree_size)?;
        if audit_path.len() != expected {
            return Err(IdentityError::InvalidProof);
        }
        Ok(Self {
            leaf_index,
            tree_size,
            audit_path,
        })
    }

    /// Zero-based leaf index committed by the proof.
    pub const fn leaf_index(&self) -> u64 {
        self.leaf_index
    }

    /// Number of leaves in the committed tree.
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Bottom-up sibling hashes.
    pub fn audit_path(&self) -> &[Digest] {
        self.audit_path.as_slice()
    }

    /// Verify this exact leaf against an expected root.
    pub fn verify(&self, leaf: &MerkleSetLeaf, expected_root: Digest) -> Result<(), IdentityError> {
        self.verify_leaf_hash(leaf.hash()?, expected_root)
    }

    /// Verify a leaf hash produced by another protocol-owned Merkle leaf schema.
    ///
    /// Callers must domain-separate and canonically encode that leaf before invoking this
    /// structural proof verifier.
    pub fn verify_leaf_hash(
        &self,
        leaf_hash: Digest,
        expected_root: Digest,
    ) -> Result<(), IdentityError> {
        let mut path_index = 0_usize;
        let actual_root = root_from_inclusion(
            leaf_hash,
            self.leaf_index,
            self.tree_size,
            self.audit_path.as_slice(),
            &mut path_index,
        )?;
        if path_index != self.audit_path.len() || actual_root != expected_root {
            return Err(IdentityError::InvalidProof);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for MerkleInclusionProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            leaf_index: u64,
            tree_size: u64,
            audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.leaf_index, wire.tree_size, wire.audit_path.into_vec())
            .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for MerkleInclusionProof {
    const RESOURCE: &'static str = "Merkle inclusion proof bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Bounded proof that one Merkle tree is an exact append-only prefix of another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleConsistencyProof {
    old_size: u64,
    new_size: u64,
    audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
}

impl MerkleConsistencyProof {
    /// Validate and construct an exact-shape append-only consistency proof.
    pub fn new(
        old_size: u64,
        new_size: u64,
        audit_path: Vec<Digest>,
    ) -> Result<Self, IdentityError> {
        let audit_path = BoundedVec::new("Merkle consistency path", audit_path)?;
        if old_size > new_size {
            return Err(IdentityError::InvalidProof);
        }
        let expected = if old_size == 0 || old_size == new_size {
            0
        } else {
            consistency_path_length(old_size, new_size, true)?
        };
        if audit_path.len() != expected {
            return Err(IdentityError::InvalidProof);
        }
        Ok(Self {
            old_size,
            new_size,
            audit_path,
        })
    }

    /// Leaf count of the earlier tree.
    pub const fn old_size(&self) -> u64 {
        self.old_size
    }

    /// Leaf count of the later tree.
    pub const fn new_size(&self) -> u64 {
        self.new_size
    }

    /// RFC-6962-shaped sibling hashes under Krikos's BLAKE3 domains.
    pub fn audit_path(&self) -> &[Digest] {
        self.audit_path.as_slice()
    }

    /// Verify that `old_root` is an exact append-only prefix of `new_root`.
    pub fn verify(&self, old_root: Digest, new_root: Digest) -> Result<(), IdentityError> {
        if self.old_size == 0 {
            if old_root != empty_merkle_root()
                || !self.audit_path.is_empty()
                || (self.new_size == 0 && new_root != empty_merkle_root())
            {
                return Err(IdentityError::InvalidProof);
            }
            return Ok(());
        }
        if self.old_size == self.new_size {
            return if self.audit_path.is_empty() && old_root == new_root {
                Ok(())
            } else {
                Err(IdentityError::InvalidProof)
            };
        }

        let mut old_cursor = self.old_size - 1;
        let mut new_cursor = self.new_size - 1;
        while old_cursor & 1 == 1 {
            old_cursor >>= 1;
            new_cursor >>= 1;
        }

        let (mut old_hash, mut new_hash, mut path_index) = if old_cursor == 0 {
            (old_root, old_root, 0_usize)
        } else {
            let seed = self
                .audit_path
                .as_slice()
                .first()
                .copied()
                .ok_or(IdentityError::InvalidProof)?;
            (seed, seed, 1_usize)
        };

        while path_index < self.audit_path.len() {
            if new_cursor == 0 {
                return Err(IdentityError::InvalidProof);
            }
            let sibling = self.audit_path.as_slice()[path_index];
            if old_cursor & 1 == 1 || old_cursor == new_cursor {
                old_hash = node_hash(sibling, old_hash)?;
                new_hash = node_hash(sibling, new_hash)?;
                while old_cursor != 0 && old_cursor & 1 == 0 {
                    old_cursor >>= 1;
                    new_cursor >>= 1;
                }
            } else {
                new_hash = node_hash(new_hash, sibling)?;
            }
            old_cursor >>= 1;
            new_cursor >>= 1;
            path_index = path_index
                .checked_add(1)
                .ok_or(IdentityError::ArithmeticOverflow {
                    resource: "Merkle consistency path index",
                })?;
        }

        if new_cursor != 0 || old_hash != old_root || new_hash != new_root {
            return Err(IdentityError::InvalidProof);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for MerkleConsistencyProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            old_size: u64,
            new_size: u64,
            audit_path: BoundedVec<Digest, MAX_MERKLE_PROOF_HASHES>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.old_size, wire.new_size, wire.audit_path.into_vec())
            .map_err(de::Error::custom)
    }
}

impl CanonicalCodec for MerkleConsistencyProof {
    const RESOURCE: &'static str = "Merkle consistency proof bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// A disclosed adjacent leaf and its inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleNeighbor {
    leaf: MerkleSetLeaf,
    proof: MerkleInclusionProof,
}

impl MerkleNeighbor {
    /// Pair a disclosed leaf with its structurally validated inclusion proof.
    pub const fn new(
        leaf: MerkleSetLeaf,
        proof: MerkleInclusionProof,
    ) -> Result<Self, IdentityError> {
        Ok(Self { leaf, proof })
    }

    /// Disclosed neighboring leaf.
    pub const fn leaf(&self) -> &MerkleSetLeaf {
        &self.leaf
    }

    /// Inclusion proof for the disclosed leaf.
    pub const fn proof(&self) -> &MerkleInclusionProof {
        &self.proof
    }
}

impl<'de> Deserialize<'de> for MerkleNeighbor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            leaf: MerkleSetLeaf,
            proof: MerkleInclusionProof,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.leaf, wire.proof).map_err(de::Error::custom)
    }
}

/// Adjacent-neighbor proof that a key is absent from a sorted Merkle set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MerkleNonMembershipProof {
    tree_size: u64,
    predecessor: Option<MerkleNeighbor>,
    successor: Option<MerkleNeighbor>,
}

impl MerkleNonMembershipProof {
    /// Validate and construct an empty, boundary, or adjacent-neighbor proof.
    pub fn new(
        tree_size: u64,
        predecessor: Option<MerkleNeighbor>,
        successor: Option<MerkleNeighbor>,
    ) -> Result<Self, IdentityError> {
        validate_neighbor_shape(tree_size, predecessor.as_ref(), successor.as_ref())?;
        Ok(Self {
            tree_size,
            predecessor,
            successor,
        })
    }

    /// Number of leaves committed by the proof.
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Immediately preceding leaf, if the query is not below the first leaf.
    pub const fn predecessor(&self) -> Option<&MerkleNeighbor> {
        self.predecessor.as_ref()
    }

    /// Immediately succeeding leaf, if the query is not above the last leaf.
    pub const fn successor(&self) -> Option<&MerkleNeighbor> {
        self.successor.as_ref()
    }

    /// Verify absence of `query` against an expected sorted-set root.
    pub fn verify(&self, query: MerkleSetKey, expected_root: Digest) -> Result<(), IdentityError> {
        validate_neighbor_shape(
            self.tree_size,
            self.predecessor.as_ref(),
            self.successor.as_ref(),
        )?;
        if self.tree_size == 0 {
            return if expected_root == empty_merkle_root() {
                Ok(())
            } else {
                Err(IdentityError::InvalidProof)
            };
        }

        if let Some(predecessor) = &self.predecessor {
            predecessor.proof.verify(&predecessor.leaf, expected_root)?;
            if predecessor.leaf.key() >= query {
                return Err(IdentityError::InvalidProof);
            }
        }
        if let Some(successor) = &self.successor {
            successor.proof.verify(&successor.leaf, expected_root)?;
            if successor.leaf.key() <= query {
                return Err(IdentityError::InvalidProof);
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for MerkleNonMembershipProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            tree_size: u64,
            predecessor: Option<MerkleNeighbor>,
            successor: Option<MerkleNeighbor>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.tree_size, wire.predecessor, wire.successor).map_err(de::Error::custom)
    }
}

impl CanonicalCodec for MerkleNonMembershipProof {
    const RESOURCE: &'static str = "Merkle non-membership proof bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Root of the empty v1 Merkle tree under its distinct domain separator.
pub fn empty_merkle_root() -> Digest {
    hash_bytes(HashDomain::MerkleEmpty, &[])
}

fn validate_neighbor_shape(
    tree_size: u64,
    predecessor: Option<&MerkleNeighbor>,
    successor: Option<&MerkleNeighbor>,
) -> Result<(), IdentityError> {
    if tree_size == 0 {
        return if predecessor.is_none() && successor.is_none() {
            Ok(())
        } else {
            Err(IdentityError::InvalidProof)
        };
    }
    let predecessor_index = predecessor.map(|neighbor| neighbor.proof.leaf_index());
    let successor_index = successor.map(|neighbor| neighbor.proof.leaf_index());
    for neighbor in predecessor.into_iter().chain(successor) {
        if neighbor.proof.tree_size() != tree_size {
            return Err(IdentityError::InvalidProof);
        }
    }
    match (predecessor, successor, predecessor_index, successor_index) {
        (None, None, _, _) => Err(IdentityError::InvalidProof),
        (None, Some(_), _, Some(0)) => Ok(()),
        (Some(_), None, Some(index), _) if index == tree_size - 1 => Ok(()),
        (Some(left), Some(right), Some(left_index), Some(right_index)) => {
            if left_index.checked_add(1) != Some(right_index) || left.leaf.key() >= right.leaf.key()
            {
                return Err(IdentityError::InvalidProof);
            }
            Ok(())
        }
        _ => Err(IdentityError::InvalidProof),
    }
}

fn tree_hash(hashes: &[Digest]) -> Result<Digest, IdentityError> {
    match hashes.len() {
        0 => Ok(empty_merkle_root()),
        1 => Ok(hashes[0]),
        len => {
            let split = largest_power_of_two_less_than_usize(len);
            node_hash(tree_hash(&hashes[..split])?, tree_hash(&hashes[split..])?)
        }
    }
}

fn node_hash(left: Digest, right: Digest) -> Result<Digest, IdentityError> {
    let payload = encode_wire(&(left, right))?;
    Ok(hash_bytes(HashDomain::MerkleNode, &payload))
}

fn append_inclusion_path(
    hashes: &[Digest],
    leaf_index: usize,
    audit_path: &mut Vec<Digest>,
) -> Result<(), IdentityError> {
    if hashes.is_empty() || leaf_index >= hashes.len() {
        return Err(IdentityError::InvalidProof);
    }
    if hashes.len() == 1 {
        return Ok(());
    }
    let split = largest_power_of_two_less_than_usize(hashes.len());
    if leaf_index < split {
        append_inclusion_path(&hashes[..split], leaf_index, audit_path)?;
        audit_path.push(tree_hash(&hashes[split..])?);
    } else {
        append_inclusion_path(&hashes[split..], leaf_index - split, audit_path)?;
        audit_path.push(tree_hash(&hashes[..split])?);
    }
    Ok(())
}

fn append_consistency_path(
    old_size: usize,
    hashes: &[Digest],
    complete_subtree: bool,
    audit_path: &mut Vec<Digest>,
) -> Result<(), IdentityError> {
    if old_size == 0 || old_size > hashes.len() || hashes.is_empty() {
        return Err(IdentityError::InvalidProof);
    }
    if old_size == hashes.len() {
        if !complete_subtree {
            audit_path.push(tree_hash(hashes)?);
        }
        return Ok(());
    }

    let split = largest_power_of_two_less_than_usize(hashes.len());
    if old_size <= split {
        append_consistency_path(old_size, &hashes[..split], complete_subtree, audit_path)?;
        audit_path.push(tree_hash(&hashes[split..])?);
    } else {
        append_consistency_path(old_size - split, &hashes[split..], false, audit_path)?;
        audit_path.push(tree_hash(&hashes[..split])?);
    }
    Ok(())
}

fn root_from_inclusion(
    leaf_hash: Digest,
    leaf_index: u64,
    tree_size: u64,
    audit_path: &[Digest],
    path_index: &mut usize,
) -> Result<Digest, IdentityError> {
    if tree_size == 0 || leaf_index >= tree_size {
        return Err(IdentityError::InvalidProof);
    }
    if tree_size == 1 {
        return Ok(leaf_hash);
    }
    let split = largest_power_of_two_less_than_u64(tree_size);
    if leaf_index < split {
        let left = root_from_inclusion(leaf_hash, leaf_index, split, audit_path, path_index)?;
        let right = next_path_hash(audit_path, path_index)?;
        node_hash(left, right)
    } else {
        let right = root_from_inclusion(
            leaf_hash,
            leaf_index - split,
            tree_size - split,
            audit_path,
            path_index,
        )?;
        let left = next_path_hash(audit_path, path_index)?;
        node_hash(left, right)
    }
}

fn next_path_hash(audit_path: &[Digest], path_index: &mut usize) -> Result<Digest, IdentityError> {
    let hash = audit_path
        .get(*path_index)
        .copied()
        .ok_or(IdentityError::InvalidProof)?;
    *path_index = path_index
        .checked_add(1)
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "Merkle proof path index",
        })?;
    Ok(hash)
}

fn inclusion_path_length(mut leaf_index: u64, mut tree_size: u64) -> Result<usize, IdentityError> {
    let mut length = 0_usize;
    while tree_size > 1 {
        let split = largest_power_of_two_less_than_u64(tree_size);
        if leaf_index >= split {
            leaf_index -= split;
            tree_size -= split;
        } else {
            tree_size = split;
        }
        length = length
            .checked_add(1)
            .ok_or(IdentityError::ArithmeticOverflow {
                resource: "Merkle proof length",
            })?;
    }
    if leaf_index != 0 || length > MAX_MERKLE_PROOF_HASHES {
        return Err(IdentityError::InvalidProof);
    }
    Ok(length)
}

fn consistency_path_length(
    old_size: u64,
    new_size: u64,
    complete_subtree: bool,
) -> Result<usize, IdentityError> {
    if old_size == 0 || old_size > new_size || new_size == 0 {
        return Err(IdentityError::InvalidProof);
    }
    if old_size == new_size {
        return Ok(usize::from(!complete_subtree));
    }
    let split = largest_power_of_two_less_than_u64(new_size);
    let nested = if old_size <= split {
        consistency_path_length(old_size, split, complete_subtree)?
    } else {
        consistency_path_length(old_size - split, new_size - split, false)?
    };
    let length = nested
        .checked_add(1)
        .ok_or(IdentityError::ArithmeticOverflow {
            resource: "Merkle consistency proof length",
        })?;
    if length > MAX_MERKLE_PROOF_HASHES {
        return Err(IdentityError::InvalidProof);
    }
    Ok(length)
}

fn largest_power_of_two_less_than_u64(value: u64) -> u64 {
    debug_assert!(value > 1);
    1_u64 << (u64::BITS - (value - 1).leading_zeros() - 1)
}

fn largest_power_of_two_less_than_usize(value: usize) -> usize {
    debug_assert!(value > 1);
    1_usize << (usize::BITS - (value - 1).leading_zeros() - 1)
}

impl fmt::Display for MerkleSetKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.type_tag, self.id)
    }
}
