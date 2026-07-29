//! Tickets for `iroh-docs` documents.

use std::{fmt, str::FromStr};

use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};

use crate::{
    Capability,
    limits::{LimitError, MAX_PEERS_PER_DOCUMENT, MAX_TICKET_BYTES},
};

/// An error parsing or validating a [`DocTicket`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The string does not start with the document-ticket prefix.
    #[error("wrong prefix, expected doc")]
    Kind,
    /// The ticket payload is not valid postcard data.
    #[error(transparent)]
    Postcard(#[from] postcard::Error),
    /// The ticket payload is not valid unpadded base32.
    #[error(transparent)]
    Encoding(#[from] data_encoding::DecodeError),
    /// The ticket does not contain addressing information.
    #[error("addressing info cannot be empty")]
    Empty,
    /// The ticket exceeded a resource limit.
    #[error(transparent)]
    Limit(#[from] LimitError),
    /// An endpoint address in the ticket exceeded its resource limits.
    #[error(transparent)]
    Address(#[from] iroh_base::AddressLimitError),
}

/// Contains both a key (either secret or public) to a document, and a list of peers to join.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DocTicket {
    /// either a public or private key
    pub capability: Capability,
    /// A list of nodes to contact.
    pub nodes: Vec<EndpointAddr>,
}

/// Wire format for [`DocTicket`].
///
/// In the future we might have multiple variants (not versions, since they
/// might be both equally valid), so this is a single variant enum to force
/// postcard to add a discriminator.
#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(DocTicket),
}

impl DocTicket {
    /// String prefix identifying document tickets.
    pub const KIND: &'static str = "doc";

    /// Encode this ticket to its v0.101-compatible binary representation.
    pub fn encode_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(self.clone());
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    /// Decode the v0.101-compatible binary representation.
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() > MAX_TICKET_BYTES {
            return Err(LimitError::new("ticket bytes", bytes.len(), MAX_TICKET_BYTES).into());
        }
        let res: TicketWireFormat = postcard::from_bytes(bytes)?;
        let TicketWireFormat::Variant0(res) = res;
        if res.nodes.is_empty() {
            return Err(ParseError::Empty);
        }
        res.validate()?;
        Ok(res)
    }

    /// Encode this ticket as lowercase, unpadded base32 with the `doc` prefix.
    pub fn encode_string(&self) -> String {
        let mut output = Self::KIND.to_owned();
        data_encoding::BASE32_NOPAD.encode_append(&self.encode_bytes(), &mut output);
        output.make_ascii_lowercase();
        output
    }

    /// Decode the canonical string representation.
    pub fn decode_string(value: &str) -> Result<Self, ParseError> {
        let Some(payload) = value.strip_prefix(Self::KIND) else {
            return Err(ParseError::Kind);
        };
        let maximum_encoded = MAX_TICKET_BYTES.saturating_mul(8).div_ceil(5);
        if payload.len() > maximum_encoded {
            return Err(LimitError::new("ticket text", payload.len(), maximum_encoded).into());
        }
        let bytes = data_encoding::BASE32_NOPAD.decode(payload.to_ascii_uppercase().as_bytes())?;
        Self::decode_bytes(&bytes)
    }

    /// Validate the ticket's untrusted peer addresses.
    pub fn validate(&self) -> Result<(), ParseError> {
        if self.nodes.len() > MAX_PEERS_PER_DOCUMENT {
            return Err(
                LimitError::new("ticket peers", self.nodes.len(), MAX_PEERS_PER_DOCUMENT).into(),
            );
        }
        for node in &self.nodes {
            node.validate()?;
        }
        Ok(())
    }

    /// Create a new validated document ticket.
    pub fn try_new(capability: Capability, peers: Vec<EndpointAddr>) -> Result<Self, ParseError> {
        let ticket = Self {
            capability,
            nodes: peers,
        };
        if ticket.nodes.is_empty() {
            return Err(ParseError::Empty);
        }
        ticket.validate()?;
        Ok(ticket)
    }

    /// Create a new document ticket from trusted application state.
    pub fn new(capability: Capability, peers: Vec<EndpointAddr>) -> Self {
        Self::try_new(capability, peers).expect("document ticket must satisfy resource limits")
    }
}

impl fmt::Display for DocTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.validate().is_err() {
            return Err(fmt::Error);
        }
        formatter.write_str(&self.encode_string())
    }
}

impl FromStr for DocTicket {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode_string(s)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::{Context, Result, ensure};
    use iroh::PublicKey;

    use super::*;
    use crate::NamespaceId;

    #[test]
    fn test_ticket_base32() {
        let node_id =
            PublicKey::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                .unwrap();
        let namespace_id = NamespaceId::from(
            &<[u8; 32]>::try_from(
                hex::decode("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
                    .unwrap(),
            )
            .unwrap(),
        );

        let ticket = DocTicket {
            capability: Capability::Read(namespace_id),
            nodes: vec![EndpointAddr::new(node_id)],
        };
        let s = ticket.to_string();
        let base32 = data_encoding::BASE32_NOPAD
            .decode(
                s.strip_prefix("doc")
                    .unwrap()
                    .to_ascii_uppercase()
                    .as_bytes(),
            )
            .unwrap();
        let expected = parse_hexdump("
            00 # variant
            01 # capability discriminator, 1 = read
            ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6 # namespace id, 32 bytes, see above
            01 # one node
            ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6 # node id, 32 bytes, see above
            00 # no addrs
        ").unwrap();
        assert_eq!(base32, expected);
    }

    /// Parses a commented multi line hexdump into a vector of bytes.
    ///
    /// This is useful to write wire level protocol tests.
    pub fn parse_hexdump(s: &str) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        for (line_number, line) in s.lines().enumerate() {
            let data_part = line.split('#').next().unwrap_or("");
            let cleaned: String = data_part.chars().filter(|c| !c.is_whitespace()).collect();

            ensure!(
                cleaned.len().is_multiple_of(2),
                "Non-even number of hex chars detected on line {}.",
                line_number + 1
            );

            for i in (0..cleaned.len()).step_by(2) {
                let byte_str = &cleaned[i..i + 2];
                let byte = u8::from_str_radix(byte_str, 16)
                    .with_context(|| format!("Invalid hex data on line {}.", line_number + 1))?;

                result.push(byte);
            }
        }

        Ok(result)
    }
}
