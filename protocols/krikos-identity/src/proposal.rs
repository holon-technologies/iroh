//! Non-authoritative device-authorization proposal produced by pairing.

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    AccountId, DeviceDescriptor, DeviceId, Digest, Extensions, HashAlgorithm, IdentityError,
    PairingConfirmationContext, PairingProofId, PairingTicketId, PairingTranscriptId,
    ProtocolVersion,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::MAX_ACCOUNT_EVENT_BYTES,
};

const DEVICE_AUTHORIZATION_PROPOSAL_ID_CONTEXT: &str =
    "KRIKOS-ID/device-authorization-proposal-id/v1";

/// Domain-separated identifier of a complete non-authoritative pairing proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceAuthorizationProposalId(Digest);

impl DeviceAuthorizationProposalId {
    /// Borrow the tagged digest.
    pub const fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl CanonicalCodec for DeviceAuthorizationProposalId {
    const RESOURCE: &'static str = "device authorization proposal identifier bytes";

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}

/// Complete pairing result submitted to later account-event construction.
///
/// This object is not account authority. Account policy still decides whether and how it becomes
/// an `AuthorizeDevice` event, and controllers sign that exact later event independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceAuthorizationProposal {
    protocol_version: ProtocolVersion,
    account_id: AccountId,
    proposed_device: DeviceDescriptor,
    proposed_device_id: DeviceId,
    ticket_id: PairingTicketId,
    transcript_id: PairingTranscriptId,
    proof_id: PairingProofId,
    confirmation: PairingConfirmationContext,
    extensions: Extensions,
}

impl DeviceAuthorizationProposal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_confirmed_pairing(
        account_id: AccountId,
        proposed_device: DeviceDescriptor,
        proposed_device_id: DeviceId,
        ticket_id: PairingTicketId,
        transcript_id: PairingTranscriptId,
        proof_id: PairingProofId,
        confirmation: PairingConfirmationContext,
    ) -> Result<Self, IdentityError> {
        if proposed_device.id()? != proposed_device_id {
            return Err(IdentityError::InvalidIdentifier {
                resource: "paired authorization proposal device",
            });
        }
        if confirmation.transcript_id() != transcript_id {
            return Err(IdentityError::InvalidRelationship {
                resource: "paired authorization proposal confirmation",
            });
        }
        let proposal = Self {
            protocol_version: ProtocolVersion::V1,
            account_id,
            proposed_device,
            proposed_device_id,
            ticket_id,
            transcript_id,
            proof_id,
            confirmation,
            extensions: Extensions::default(),
        };
        let encoded_len = encode_wire(&proposal)?.len();
        if encoded_len > MAX_ACCOUNT_EVENT_BYTES {
            return Err(IdentityError::limit(
                "device authorization proposal bytes",
                encoded_len,
                MAX_ACCOUNT_EVENT_BYTES,
            ));
        }
        Ok(proposal)
    }

    /// Domain-separated proposal identifier.
    pub fn proposal_id(&self) -> Result<DeviceAuthorizationProposalId, IdentityError> {
        Ok(DeviceAuthorizationProposalId(Digest::new(
            HashAlgorithm::Blake3_256,
            blake3::derive_key(
                DEVICE_AUTHORIZATION_PROPOSAL_ID_CONTEXT,
                &crate::CanonicalWire::to_canonical_bytes(self)?,
            ),
        )))
    }

    /// Account this proposal asks to extend.
    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// Complete proposed descriptor.
    pub const fn proposed_device(&self) -> &DeviceDescriptor {
        &self.proposed_device
    }

    /// Exact identifier derived from the descriptor.
    pub const fn proposed_device_id(&self) -> DeviceId {
        self.proposed_device_id
    }

    /// One-time ticket whose ceremony produced this proposal.
    pub const fn ticket_id(&self) -> PairingTicketId {
        self.ticket_id
    }

    /// Complete authenticated pairing transcript.
    pub const fn transcript_id(&self) -> PairingTranscriptId {
        self.transcript_id
    }

    /// Complete four-role possession proof.
    pub const fn proof_id(&self) -> PairingProofId {
        self.proof_id
    }

    /// Exact two-sided short-auth confirmation context.
    pub const fn confirmation(&self) -> PairingConfirmationContext {
        self.confirmation
    }
}

impl<'de> Deserialize<'de> for DeviceAuthorizationProposal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (
            protocol_version,
            account_id,
            proposed_device,
            proposed_device_id,
            ticket_id,
            transcript_id,
            proof_id,
            confirmation,
            extensions,
        ) = <(
            ProtocolVersion,
            AccountId,
            DeviceDescriptor,
            DeviceId,
            PairingTicketId,
            PairingTranscriptId,
            PairingProofId,
            PairingConfirmationContext,
            Extensions,
        )>::deserialize(deserializer)?;
        if protocol_version != ProtocolVersion::V1 {
            return Err(de::Error::custom(IdentityError::UnsupportedVersion {
                version: protocol_version.get(),
            }));
        }
        if proposed_device.id().map_err(de::Error::custom)? != proposed_device_id {
            return Err(de::Error::custom(IdentityError::InvalidIdentifier {
                resource: "paired authorization proposal device",
            }));
        }
        if confirmation.transcript_id() != transcript_id {
            return Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "paired authorization proposal confirmation",
            }));
        }
        extensions
            .validate_critical(&[])
            .map_err(de::Error::custom)?;
        if !extensions.as_slice().is_empty() {
            return Err(de::Error::custom(IdentityError::InvalidRelationship {
                resource: "device authorization proposal extensions",
            }));
        }
        Ok(Self {
            protocol_version,
            account_id,
            proposed_device,
            proposed_device_id,
            ticket_id,
            transcript_id,
            proof_id,
            confirmation,
            extensions,
        })
    }
}

impl CanonicalCodec for DeviceAuthorizationProposal {
    const RESOURCE: &'static str = "device authorization proposal bytes";
    const MAX_ENCODED_BYTES: usize = MAX_ACCOUNT_EVENT_BYTES;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        encode_wire(self)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        decode_wire(bytes)
    }
}
