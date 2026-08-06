//! Canonical Postcard v1 encoding for protocol-owned wire types.

use serde::{Serialize, de::DeserializeOwned};

use crate::{IdentityError, limits::MAX_ENCODED_OBJECT_BYTES};

pub(crate) mod sealed {
    use super::IdentityError;

    pub trait CanonicalCodec: Sized {
        const RESOURCE: &'static str;
        const MAX_ENCODED_BYTES: usize = super::MAX_ENCODED_OBJECT_BYTES;

        fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError>;
        fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError>;
    }
}

/// Canonical encoding available only for protocol-owned, sealed wire types.
///
/// The v1 profile uses Postcard 1 and forbids maps, floats, `usize`, unordered
/// collections, trailing bytes, and non-minimal integer encodings in signed
/// structures. Implementations are sealed so arbitrary caller types cannot be
/// accidentally treated as signable protocol objects.
pub trait CanonicalWire: sealed::CanonicalCodec {
    /// Encode this value into its unique canonical v1 byte representation.
    fn to_canonical_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let encoded = self.encode_canonical()?;
        if encoded.len() > Self::MAX_ENCODED_BYTES {
            return Err(IdentityError::limit(
                Self::RESOURCE,
                encoded.len(),
                Self::MAX_ENCODED_BYTES,
            ));
        }
        Ok(encoded)
    }

    /// Decode a bounded canonical v1 byte representation.
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() > Self::MAX_ENCODED_BYTES {
            return Err(IdentityError::limit(
                Self::RESOURCE,
                bytes.len(),
                Self::MAX_ENCODED_BYTES,
            ));
        }
        Self::decode_canonical(bytes)
    }
}

impl<T: sealed::CanonicalCodec> CanonicalWire for T {}

pub(crate) fn encode_wire<T: Serialize>(value: &T) -> Result<Vec<u8>, IdentityError> {
    postcard::to_stdvec(value).map_err(|_| IdentityError::InvalidEncoding)
}

pub(crate) fn decode_wire<T>(bytes: &[u8]) -> Result<T, IdentityError>
where
    T: DeserializeOwned + Serialize,
{
    let (value, remaining) =
        postcard::take_from_bytes::<T>(bytes).map_err(|_| IdentityError::InvalidEncoding)?;
    if !remaining.is_empty() {
        return Err(IdentityError::NonCanonical);
    }
    let canonical = encode_wire(&value)?;
    if canonical != bytes {
        return Err(IdentityError::NonCanonical);
    }
    Ok(value)
}
