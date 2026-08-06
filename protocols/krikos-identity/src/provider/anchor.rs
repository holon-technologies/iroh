//! Chain-neutral opaque provider anchoring boundary.

use super::{ProviderCompactionManifest, provider_commitment};
use crate::{
    Digest, HashAlgorithm, IdentityError, StoreFuture,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
};
use serde::{Deserialize, Serialize};

const MAX_ANCHOR_EVIDENCE_BYTES: usize = 16 * 1024;
const PROVIDER_ANCHOR_COMMITMENT_DOMAIN: &[u8] = b"KRIKOS-ID/provider-anchor-commitment/v1";

/// Exact aggregate provider commitment exposed to an optional external anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueProviderAnchorCommitment([u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct OpaqueProviderAnchorCommitmentWire {
    format_version: u16,
    commitment: [u8; 32],
}

#[derive(Serialize)]
struct ProviderAnchorCommitmentPreimageWire<'a> {
    format_version: u16,
    manifest: &'a ProviderCompactionManifest,
}

impl OpaqueProviderAnchorCommitment {
    /// Derive the opaque commitment to one exact verified compaction manifest.
    pub fn from_compaction_manifest(
        manifest: &ProviderCompactionManifest,
    ) -> Result<Self, IdentityError> {
        manifest.validate_wire()?;
        let commitment = provider_commitment(
            PROVIDER_ANCHOR_COMMITMENT_DOMAIN,
            &ProviderAnchorCommitmentPreimageWire {
                format_version: 1,
                manifest,
            },
        )?;
        Ok(Self(*commitment.as_bytes()))
    }

    /// Exact opaque bytes; no account, device, guardian, or relationship identifier is exposed.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Algorithm-tagged digest form for local aggregate comparison.
    pub const fn digest(self) -> Digest {
        Digest::new(HashAlgorithm::Blake3_256, self.0)
    }
}

impl CanonicalCodec for OpaqueProviderAnchorCommitment {
    const RESOURCE: &'static str = "opaque provider anchor commitment bytes";
    const MAX_ENCODED_BYTES: usize = 64;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(&OpaqueProviderAnchorCommitmentWire {
            format_version: 1,
            commitment: self.0,
        })
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let wire: OpaqueProviderAnchorCommitmentWire = decode_wire(bytes)?;
        if wire.format_version != 1 {
            return Err(IdentityError::UnsupportedVersion {
                version: wire.format_version,
            });
        }
        Ok(Self(wire.commitment))
    }
}

/// Opaque backend evidence that commits to one exact aggregate provider commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAnchorEvidence {
    commitment: OpaqueProviderAnchorCommitment,
    opaque_bytes: Vec<u8>,
}

impl ProviderAnchorEvidence {
    /// Attach bounded vendor-neutral evidence to the exact submitted commitment.
    pub fn new(
        commitment: OpaqueProviderAnchorCommitment,
        opaque_bytes: Vec<u8>,
    ) -> Result<Self, IdentityError> {
        if opaque_bytes.is_empty() {
            return Err(IdentityError::EmptyCollection {
                resource: "provider anchor evidence",
            });
        }
        if opaque_bytes.len() > MAX_ANCHOR_EVIDENCE_BYTES {
            return Err(IdentityError::limit(
                "provider anchor evidence bytes",
                opaque_bytes.len(),
                MAX_ANCHOR_EVIDENCE_BYTES,
            ));
        }
        Ok(Self {
            commitment,
            opaque_bytes,
        })
    }

    /// Exact aggregate commitment authenticated by this evidence.
    pub const fn commitment(&self) -> OpaqueProviderAnchorCommitment {
        self.commitment
    }

    /// Bounded backend-defined status or inclusion bytes.
    pub fn opaque_bytes(&self) -> &[u8] {
        &self.opaque_bytes
    }
}

/// Typed status returned by an optional chain-neutral anchor backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAnchorStatus {
    /// Submission is known but not yet durably included.
    Pending,
    /// Exact commitment has bounded backend inclusion evidence.
    Included(ProviderAnchorEvidence),
    /// Backend rejected the commitment with a nonzero stable operator code.
    Rejected(u16),
}

/// Optional anchor backend that receives only an opaque aggregate commitment.
pub trait ProviderAnchor: Send + Sync {
    /// Submit one exact opaque aggregate commitment.
    fn submit(
        &self,
        commitment: OpaqueProviderAnchorCommitment,
    ) -> StoreFuture<'_, ProviderAnchorStatus>;

    /// Query status for one exact opaque aggregate commitment.
    fn status(
        &self,
        commitment: OpaqueProviderAnchorCommitment,
    ) -> StoreFuture<'_, ProviderAnchorStatus>;
}
