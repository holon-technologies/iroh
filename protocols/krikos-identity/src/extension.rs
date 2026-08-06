//! Bounded forward-compatible extension fields.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de, ser::SerializeSeq};

use crate::{
    IdentityError,
    codec::{decode_wire, encode_wire, sealed::CanonicalCodec},
    limits::{MAX_EXTENSION_VALUE_BYTES, MAX_EXTENSIONS, MAX_TOTAL_EXTENSION_BYTES},
};

/// One opaque, signed extension field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Extension {
    code: u32,
    critical: bool,
    value: Vec<u8>,
}

impl Extension {
    /// Construct a bounded extension.
    pub fn new(code: u32, critical: bool, value: Vec<u8>) -> Result<Self, IdentityError> {
        if code == 0 {
            return Err(IdentityError::InvalidExtensionCode { code });
        }
        if value.len() > MAX_EXTENSION_VALUE_BYTES {
            return Err(IdentityError::limit(
                "extension value bytes",
                value.len(),
                MAX_EXTENSION_VALUE_BYTES,
            ));
        }
        Ok(Self {
            code,
            critical,
            value,
        })
    }

    /// Stable extension registry code.
    pub const fn code(&self) -> u32 {
        self.code
    }

    /// Whether an implementation must understand this field to accept its object.
    pub const fn is_critical(&self) -> bool {
        self.critical
    }

    /// Opaque canonical extension value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    fn into_wire(self) -> ExtensionWire {
        ExtensionWire {
            code: self.code,
            critical: self.critical,
            value: BoundedBytes(self.value),
        }
    }
}

/// Sorted, duplicate-free extension fields on one extensible object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    /// Validate, sort, and construct an extension set.
    pub fn new(mut extensions: Vec<Extension>) -> Result<Self, IdentityError> {
        if extensions.len() > MAX_EXTENSIONS {
            return Err(IdentityError::limit(
                "extension fields",
                extensions.len(),
                MAX_EXTENSIONS,
            ));
        }
        extensions.sort_unstable_by_key(Extension::code);
        Self::from_sorted(extensions)
    }

    /// Borrow the canonical sorted fields.
    pub fn as_slice(&self) -> &[Extension] {
        &self.0
    }

    /// Reject critical fields not present in a sorted bounded known-code registry.
    pub fn validate_critical(&self, known_codes: &[u32]) -> Result<(), IdentityError> {
        if known_codes.len() > MAX_EXTENSIONS {
            return Err(IdentityError::limit(
                "known extension codes",
                known_codes.len(),
                MAX_EXTENSIONS,
            ));
        }
        if known_codes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(IdentityError::NonCanonical);
        }
        for extension in &self.0 {
            if extension.critical && known_codes.binary_search(&extension.code).is_err() {
                return Err(IdentityError::UnknownCriticalExtension {
                    code: extension.code,
                });
            }
        }
        Ok(())
    }

    fn from_sorted(extensions: Vec<Extension>) -> Result<Self, IdentityError> {
        if extensions.len() > MAX_EXTENSIONS {
            return Err(IdentityError::limit(
                "extension fields",
                extensions.len(),
                MAX_EXTENSIONS,
            ));
        }
        for pair in extensions.windows(2) {
            if pair[0].code == pair[1].code {
                return Err(IdentityError::DuplicateExtension { code: pair[0].code });
            }
            if pair[0].code > pair[1].code {
                return Err(IdentityError::NonCanonical);
            }
        }
        let mut total = 0usize;
        for extension in &extensions {
            total = total.checked_add(extension.value.len()).ok_or(
                IdentityError::ArithmeticOverflow {
                    resource: "total extension bytes",
                },
            )?;
            if total > MAX_TOTAL_EXTENSION_BYTES {
                return Err(IdentityError::limit(
                    "total extension bytes",
                    total,
                    MAX_TOTAL_EXTENSION_BYTES,
                ));
            }
        }
        Ok(Self(extensions))
    }
}

impl CanonicalCodec for Extensions {
    const RESOURCE: &'static str = "extension bytes";
    const MAX_ENCODED_BYTES: usize = MAX_TOTAL_EXTENSION_BYTES + MAX_EXTENSIONS * 16;

    fn encode_canonical(&self) -> Result<Vec<u8>, IdentityError> {
        let wire = ExtensionList(
            self.0
                .clone()
                .into_iter()
                .map(Extension::into_wire)
                .collect(),
        );
        encode_wire(&wire)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self, IdentityError> {
        let wire: ExtensionList = decode_wire(bytes)?;
        let extensions = wire
            .0
            .into_iter()
            .map(|wire| Extension::new(wire.code, wire.critical, wire.value.0))
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_sorted(extensions)
    }
}

impl<'de> Deserialize<'de> for Extensions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ExtensionList::deserialize(deserializer)?;
        let extensions = wire
            .0
            .into_iter()
            .map(|wire| Extension::new(wire.code, wire.critical, wire.value.0))
            .collect::<Result<Vec<_>, _>>()
            .map_err(de::Error::custom)?;
        Self::from_sorted(extensions).map_err(de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct ExtensionWire {
    code: u32,
    critical: bool,
    value: BoundedBytes,
}

struct ExtensionList(Vec<ExtensionWire>);

impl Serialize for ExtensionList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for extension in &self.0 {
            sequence.serialize_element(extension)?;
        }
        sequence.end()
    }
}

impl<'de> Deserialize<'de> for ExtensionList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = ExtensionList;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "at most {MAX_EXTENSIONS} extension fields")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|hint| hint > MAX_EXTENSIONS)
                {
                    return Err(de::Error::invalid_length(MAX_EXTENSIONS + 1, &self));
                }
                let mut extensions =
                    Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_EXTENSIONS));
                while let Some(extension) = sequence.next_element()? {
                    if extensions.len() == MAX_EXTENSIONS {
                        return Err(de::Error::invalid_length(MAX_EXTENSIONS + 1, &self));
                    }
                    extensions.push(extension);
                }
                Ok(ExtensionList(extensions))
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}

#[derive(Serialize)]
struct BoundedBytes(Vec<u8>);

impl<'de> Deserialize<'de> for BoundedBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = BoundedBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_EXTENSION_VALUE_BYTES} extension bytes"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|hint| hint > MAX_EXTENSION_VALUE_BYTES)
                {
                    return Err(de::Error::invalid_length(
                        MAX_EXTENSION_VALUE_BYTES + 1,
                        &self,
                    ));
                }
                let mut bytes = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(MAX_EXTENSION_VALUE_BYTES),
                );
                while let Some(byte) = sequence.next_element()? {
                    if bytes.len() == MAX_EXTENSION_VALUE_BYTES {
                        return Err(de::Error::invalid_length(
                            MAX_EXTENSION_VALUE_BYTES + 1,
                            &self,
                        ));
                    }
                    bytes.push(byte);
                }
                Ok(BoundedBytes(bytes))
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}
