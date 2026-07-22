//! Addressing for iroh endpoints.
//!
//! This module contains some common addressing types for iroh.  An endpoint is uniquely
//! identified by the [`EndpointId`] but that does not make it addressable on the network layer.
//! For this the addition of a [`RelayUrl`] and/or direct addresses are required.
//!
//! The primary way of addressing an endpoint is by using the [`EndpointAddr`].

use std::{collections::BTreeSet, fmt, net::SocketAddr};

use data_encoding::HEXLOWER;
use n0_error::stack_error;
use serde::de::VariantAccess as _;
use serde::{Deserialize, Serialize, de};

use crate::{EndpointId, PublicKey, RelayUrl};

/// Network-level addressing information for an iroh endpoint.
///
/// This combines an endpoint's identifier with network-level addressing information of how to
/// contact the endpoint.
///
/// To establish a network connection to an endpoint both the [`EndpointId`] and one or more network
/// paths are needed.  The network paths can come from various sources:
///
/// - An [Address Lookup] service which can provide routing information for a given [`EndpointId`].
///
/// - A [`RelayUrl`] of the endpoint's [home relay], this allows establishing the connection via
///   the Relay server and is very reliable.
///
/// - One or more *IP based addresses* on which the endpoint might be reachable.  Depending on the
///   network location of both endpoints it might not be possible to establish a direct
///   connection without the help of a [Relay server].
///
/// This structure will always contain the required [`EndpointId`] and will contain an optional
/// number of other addressing information.  It is a generic addressing type used whenever a connection
/// to other endpoints needs to be established.
///
/// [Address Lookup]: https://docs.rs/iroh/*/iroh/index.html#address-lookup
/// [home relay]: https://docs.rs/iroh/*/iroh/relay/index.html
/// [Relay server]: https://docs.rs/iroh/*/iroh/index.html#relay-servers
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointAddr {
    /// The endpoint's identifier.
    pub id: EndpointId,
    /// The endpoint's addresses.
    pub addrs: BTreeSet<TransportAddr>,
}

/// Default maximum opaque bytes in one [`CustomAddr`].
pub const MAX_CUSTOM_ADDR_BYTES: usize = 512;
/// Default maximum UTF-8 bytes in one relay URL.
pub const MAX_RELAY_URL_BYTES: usize = 2_048;
/// Default maximum transport addresses supplied for one endpoint.
pub const MAX_ENDPOINT_ADDRS: usize = 34;
/// Default maximum accounted bytes in one [`EndpointAddr`].
pub const MAX_ENDPOINT_ADDR_BYTES: usize = 16 * 1_024;

/// Limits applied when constructing endpoint addressing from untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressLimits {
    /// Maximum opaque bytes in one custom transport address.
    pub max_custom_addr_bytes: usize,
    /// Maximum UTF-8 bytes in one relay URL.
    pub max_relay_url_bytes: usize,
    /// Maximum transport address items supplied for one endpoint.
    pub max_endpoint_addrs: usize,
    /// Maximum accounted bytes in one endpoint address.
    pub max_endpoint_addr_bytes: usize,
}

impl Default for AddressLimits {
    fn default() -> Self {
        Self {
            max_custom_addr_bytes: MAX_CUSTOM_ADDR_BYTES,
            max_relay_url_bytes: MAX_RELAY_URL_BYTES,
            max_endpoint_addrs: MAX_ENDPOINT_ADDRS,
            max_endpoint_addr_bytes: MAX_ENDPOINT_ADDR_BYTES,
        }
    }
}

/// An endpoint address exceeded a configured input bound.
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum AddressLimitError {
    #[error("custom address contains {actual} bytes, maximum is {maximum}")]
    CustomAddrBytes { actual: usize, maximum: usize },
    #[error("endpoint address contains more than {maximum} address items")]
    EndpointAddrCount { maximum: usize },
    #[error("relay URL contains {actual} bytes, maximum is {maximum}")]
    RelayUrlBytes { actual: usize, maximum: usize },
    #[error("endpoint address accounts for {actual} bytes, maximum is {maximum}")]
    EndpointAddrBytes { actual: usize, maximum: usize },
}

/// Available address types.
#[derive(
    derive_more::Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[non_exhaustive]
pub enum TransportAddr {
    /// A relay server address.
    #[debug("Relay({_0})")]
    Relay(RelayUrl),
    /// An IP based address.
    Ip(SocketAddr),
    /// Custom transport address
    Custom(CustomAddr),
}

impl TransportAddr {
    /// Whether this is a transport address via a relay server.
    pub fn is_relay(&self) -> bool {
        matches!(self, Self::Relay(_))
    }

    /// Whether this is an IP transport address.
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    /// Whether this is a custom transport address.
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relay(url) => write!(f, "relay:{url}"),
            Self::Ip(addr) => write!(f, "ip:{addr}"),
            Self::Custom(addr) => write!(f, "custom:{addr}"),
        }
    }
}

impl EndpointAddr {
    /// Validate this address against the default untrusted-input limits.
    ///
    /// This is required at system boundaries while the public fields retained for 1.x source
    /// compatibility still allow callers to construct an out-of-policy value.
    pub fn validate(&self) -> Result<(), AddressLimitError> {
        self.validate_with_limits(AddressLimits::default())
    }

    /// Validate this address using explicit input limits.
    pub fn validate_with_limits(&self, limits: AddressLimits) -> Result<(), AddressLimitError> {
        Self::try_from_parts_with_limits(self.id, self.addrs.iter().cloned(), limits).map(|_| ())
    }

    /// Creates a new [`EndpointAddr`] with no network level addresses.
    ///
    /// This still is usable with e.g. an address lookup service to establish a connection,
    /// depending on the situation.
    pub fn new(id: PublicKey) -> Self {
        EndpointAddr {
            id,
            addrs: Default::default(),
        }
    }

    /// Creates a new [`EndpointAddr`] from its parts.
    #[deprecated(note = "use EndpointAddr::try_from_parts for bounded construction")]
    pub fn from_parts(id: PublicKey, addrs: impl IntoIterator<Item = TransportAddr>) -> Self {
        Self {
            id,
            addrs: addrs.into_iter().collect(),
        }
    }

    /// Creates a bounded [`EndpointAddr`] from untrusted parts.
    pub fn try_from_parts(
        id: PublicKey,
        addrs: impl IntoIterator<Item = TransportAddr>,
    ) -> Result<Self, AddressLimitError> {
        Self::try_from_parts_with_limits(id, addrs, AddressLimits::default())
    }

    /// Creates an [`EndpointAddr`] using explicit input limits.
    pub fn try_from_parts_with_limits(
        id: PublicKey,
        addrs: impl IntoIterator<Item = TransportAddr>,
        limits: AddressLimits,
    ) -> Result<Self, AddressLimitError> {
        let mut retained = BTreeSet::new();
        let mut accounted_bytes = id.as_bytes().len();

        for (index, addr) in addrs.into_iter().enumerate() {
            if index >= limits.max_endpoint_addrs {
                return Err(n0_error::e!(AddressLimitError::EndpointAddrCount {
                    maximum: limits.max_endpoint_addrs,
                }));
            }
            let addr_bytes = validate_transport_addr(&addr, limits)?;
            if retained.insert(addr) {
                accounted_bytes = accounted_bytes.saturating_add(addr_bytes);
                if accounted_bytes > limits.max_endpoint_addr_bytes {
                    return Err(n0_error::e!(AddressLimitError::EndpointAddrBytes {
                        actual: accounted_bytes,
                        maximum: limits.max_endpoint_addr_bytes,
                    }));
                }
            }
        }

        Ok(Self {
            id,
            addrs: retained,
        })
    }

    /// Adds a [`RelayUrl`] address.
    pub fn with_relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.addrs.insert(TransportAddr::Relay(relay_url));
        self
    }

    /// Adds an IP based address.
    pub fn with_ip_addr(mut self, addr: SocketAddr) -> Self {
        self.addrs.insert(TransportAddr::Ip(addr));
        self
    }

    /// Adds a list of addresses.
    pub fn with_addrs(mut self, addrs: impl IntoIterator<Item = TransportAddr>) -> Self {
        for addr in addrs.into_iter() {
            self.addrs.insert(addr);
        }
        self
    }

    /// Returns true if only an [`EndpointId`] is present.
    pub fn is_empty(&self) -> bool {
        self.addrs.is_empty()
    }

    /// Returns an iterator over the IP addresses of this endpoint address.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Ip(addr) => Some(addr),
            _ => None,
        })
    }

    /// Returns an iterator over the relay URLs of this endpoint address.
    ///
    ///  In practice this is expected to be zero or one home relay for all known cases currently.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Relay(url) => Some(url),
            _ => None,
        })
    }
}

impl<'de> Deserialize<'de> for EndpointAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct UncheckedEndpointAddr {
            id: EndpointId,
            #[serde(deserialize_with = "deserialize_transport_addrs")]
            addrs: BTreeSet<TransportAddr>,
        }

        let unchecked = UncheckedEndpointAddr::deserialize(deserializer)?;
        Self::try_from_parts(unchecked.id, unchecked.addrs).map_err(de::Error::custom)
    }
}

fn deserialize_transport_addrs<'de, D>(deserializer: D) -> Result<BTreeSet<TransportAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct TransportAddrsVisitor;

    impl<'de> de::Visitor<'de> for TransportAddrsVisitor {
        type Value = BTreeSet<TransportAddr>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_ENDPOINT_ADDRS} bounded transport addresses"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_ENDPOINT_ADDRS)
            {
                return Err(de::Error::custom("endpoint address count exceeds limit"));
            }

            let limits = AddressLimits::default();
            let mut addrs = BTreeSet::new();
            let mut supplied = 0usize;
            let mut accounted_bytes = 32usize;
            while let Some(addr) = sequence.next_element::<TransportAddr>()? {
                supplied = supplied.saturating_add(1);
                if supplied > limits.max_endpoint_addrs {
                    return Err(de::Error::custom("endpoint address count exceeds limit"));
                }
                let addr_bytes =
                    validate_transport_addr(&addr, limits).map_err(de::Error::custom)?;
                if addrs.insert(addr) {
                    accounted_bytes = accounted_bytes.saturating_add(addr_bytes);
                    if accounted_bytes > limits.max_endpoint_addr_bytes {
                        return Err(de::Error::custom(
                            "endpoint address byte size exceeds limit",
                        ));
                    }
                }
            }
            Ok(addrs)
        }
    }

    deserializer.deserialize_seq(TransportAddrsVisitor)
}

fn validate_transport_addr(
    addr: &TransportAddr,
    limits: AddressLimits,
) -> Result<usize, AddressLimitError> {
    let bytes = match addr {
        TransportAddr::Relay(url) => {
            let actual = url.as_str().len();
            if actual > limits.max_relay_url_bytes {
                return Err(n0_error::e!(AddressLimitError::RelayUrlBytes {
                    actual,
                    maximum: limits.max_relay_url_bytes,
                }));
            }
            1usize.saturating_add(actual)
        }
        TransportAddr::Ip(SocketAddr::V4(_)) => 1 + 4 + 2,
        TransportAddr::Ip(SocketAddr::V6(_)) => 1 + 16 + 2,
        TransportAddr::Custom(addr) => {
            let actual = addr.data().len();
            if actual > limits.max_custom_addr_bytes {
                return Err(n0_error::e!(AddressLimitError::CustomAddrBytes {
                    actual,
                    maximum: limits.max_custom_addr_bytes,
                }));
            }
            1usize.saturating_add(8).saturating_add(actual)
        }
    };
    Ok(bytes)
}

impl From<EndpointId> for EndpointAddr {
    fn from(endpoint_id: EndpointId) -> Self {
        EndpointAddr::new(endpoint_id)
    }
}

/// A custom transport address consisting of a transport id and opaque address data.
///
/// This is a generic address type that allows external crates to implement custom
/// transports for iroh.
///
/// Transport ids are freely chosen u64 numbers. A registry for well-known transport ids
/// is maintained at <https://github.com/n0-computer/iroh/blob/main/TRANSPORTS.md>.
/// New addresses created through fallible parsing or [`CustomAddr::try_from_parts`] are limited to
/// [`MAX_CUSTOM_ADDR_BYTES`]. The legacy infallible constructor remains temporarily available for
/// source compatibility and is deprecated.
///
/// # String encoding
///
/// Used by [`Display`] and [`FromStr`] implementations.
/// Format: `<id>_<data>` where `<id>` is the transport id as lowercase hex (no `0x`
/// prefix, no leading zeros) and `<data>` is the address bytes as lowercase hex,
/// separated by `_`.
///
/// # Binary encoding
///
/// Used by [`Self::to_vec`] and [`Self::from_bytes`].
/// Format: 8-byte little-endian `u64` transport id, followed by raw address data bytes.
/// The minimum valid length is 8 bytes (id only with empty data).
///
/// [`Display`]: std::fmt::Display
/// [`FromStr`]: std::str::FromStr
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CustomAddr {
    /// The transport id.
    id: u64,
    /// Opaque address data for this transport.
    data: CustomAddrBytes,
}

impl fmt::Display for CustomAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}_{}", self.id, HEXLOWER.encode(self.data.as_bytes()))
    }
}

impl std::str::FromStr for CustomAddr {
    type Err = CustomAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((id_str, data_str)) = s.split_once('_') else {
            return Err(CustomAddrParseError::MissingSeparator);
        };
        let Ok(id) = u64::from_str_radix(id_str, 16) else {
            return Err(CustomAddrParseError::InvalidId);
        };
        let Ok(data) = HEXLOWER.decode(data_str.as_bytes()) else {
            return Err(CustomAddrParseError::InvalidData);
        };
        Self::try_from_parts(id, &data).map_err(|_| CustomAddrParseError::DataTooLong {
            maximum: MAX_CUSTOM_ADDR_BYTES,
        })
    }
}

/// Error returned when parsing a [`CustomAddr`] from its string encoding fails.
///
/// Parsing a string into a [`CustomAddr`] represents just the first part of
/// validation. Even if the string is well-formed, the resulting [`CustomAddr`] might
/// still have an invalid data size or format for the transport type.
#[stack_error(derive)]
#[allow(missing_docs)]
pub enum CustomAddrParseError {
    /// Missing `_` separator between id and data.
    #[error("missing '_' separator")]
    MissingSeparator,
    /// Invalid hex-encoded id.
    #[error("invalid id")]
    InvalidId,
    /// Invalid hex-encoded data.
    #[error("invalid data")]
    InvalidData,
    /// Opaque address data exceeds the supported input limit.
    #[error("address data exceeds {maximum} bytes")]
    DataTooLong { maximum: usize },
}

#[derive(Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum CustomAddrBytes {
    Inline { size: u8, data: [u8; 30] },
    Heap(Box<[u8]>),
}

impl<'de> Deserialize<'de> for CustomAddrBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Variant {
            Inline,
            Heap,
        }

        struct CustomAddrBytesVisitor;

        impl<'de> de::Visitor<'de> for CustomAddrBytesVisitor {
            type Value = CustomAddrBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded CustomAddrBytes value")
            }

            fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
            where
                A: de::EnumAccess<'de>,
            {
                let (variant, access) = data.variant::<Variant>()?;
                match variant {
                    Variant::Inline => {
                        access.struct_variant(&["size", "data"], InlineCustomAddrBytesVisitor)
                    }
                    Variant::Heap => access
                        .newtype_variant::<BoundedHeapCustomAddrBytes>()
                        .map(|bounded| bounded.0),
                }
            }
        }

        deserializer.deserialize_enum(
            "CustomAddrBytes",
            &["Inline", "Heap"],
            CustomAddrBytesVisitor,
        )
    }
}

struct InlineCustomAddrBytesVisitor;

impl<'de> de::Visitor<'de> for InlineCustomAddrBytesVisitor {
    type Value = CustomAddrBytes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an inline custom address byte array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let size: u8 = sequence
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let data: [u8; 30] = sequence
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        inline_custom_addr_bytes(size, data).map_err(de::Error::custom)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Size,
            Data,
        }

        let mut size = None;
        let mut data = None;
        while let Some(field) = map.next_key::<Field>()? {
            match field {
                Field::Size => {
                    if size.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("size"));
                    }
                }
                Field::Data => {
                    if data.replace(map.next_value()?).is_some() {
                        return Err(de::Error::duplicate_field("data"));
                    }
                }
            }
        }
        let size = size.ok_or_else(|| de::Error::missing_field("size"))?;
        let data = data.ok_or_else(|| de::Error::missing_field("data"))?;
        inline_custom_addr_bytes(size, data).map_err(de::Error::custom)
    }
}

fn inline_custom_addr_bytes(size: u8, data: [u8; 30]) -> Result<CustomAddrBytes, &'static str> {
    if usize::from(size) > data.len() {
        return Err("inline custom address size exceeds storage");
    }
    Ok(CustomAddrBytes::Inline { size, data })
}

struct BoundedHeapCustomAddrBytes(CustomAddrBytes);

impl<'de> Deserialize<'de> for BoundedHeapCustomAddrBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct HeapVisitor;

        impl<'de> de::Visitor<'de> for HeapVisitor {
            type Value = BoundedHeapCustomAddrBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "at most {MAX_CUSTOM_ADDR_BYTES} custom address bytes"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|size| size > MAX_CUSTOM_ADDR_BYTES)
                {
                    return Err(de::Error::custom("custom address data exceeds limit"));
                }
                let mut bytes = Vec::with_capacity(
                    sequence.size_hint().unwrap_or(0).min(MAX_CUSTOM_ADDR_BYTES),
                );
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == MAX_CUSTOM_ADDR_BYTES {
                        return Err(de::Error::custom("custom address data exceeds limit"));
                    }
                    bytes.push(byte);
                }
                Ok(BoundedHeapCustomAddrBytes(CustomAddrBytes::Heap(
                    bytes.into_boxed_slice(),
                )))
            }
        }

        deserializer.deserialize_seq(HeapVisitor)
    }
}

impl fmt::Debug for CustomAddrBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            write!(f, "[{}]", HEXLOWER.encode(self.as_bytes()))
        } else {
            let bytes = self.as_bytes();
            match self {
                Self::Inline { .. } => write!(f, "Inline[{}]", HEXLOWER.encode(bytes)),
                Self::Heap(_) => write!(f, "Heap[{}]", HEXLOWER.encode(bytes)),
            }
        }
    }
}

impl From<(u64, &[u8])> for CustomAddr {
    fn from((id, data): (u64, &[u8])) -> Self {
        Self::from_parts_unchecked(id, data)
    }
}

impl CustomAddrBytes {
    fn len(&self) -> usize {
        match self {
            Self::Inline { size, .. } => *size as usize,
            Self::Heap(data) => data.len(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Inline { size, data } => &data[..*size as usize],
            Self::Heap(data) => data,
        }
    }

    fn copy_from_slice(data: &[u8]) -> Self {
        if data.len() <= 30 {
            let mut inline = [0u8; 30];
            inline[..data.len()].copy_from_slice(data);
            Self::Inline {
                size: data.len() as u8,
                data: inline,
            }
        } else {
            Self::Heap(data.to_vec().into_boxed_slice())
        }
    }
}

impl CustomAddr {
    /// Creates a new [`CustomAddr`] from a transport id and raw address data.
    #[deprecated(note = "use CustomAddr::try_from_parts for bounded construction")]
    pub fn from_parts(id: u64, data: &[u8]) -> Self {
        Self::from_parts_unchecked(id, data)
    }

    fn from_parts_unchecked(id: u64, data: &[u8]) -> Self {
        Self {
            id,
            data: CustomAddrBytes::copy_from_slice(data),
        }
    }

    /// Creates a bounded [`CustomAddr`] from untrusted raw address data.
    pub fn try_from_parts(id: u64, data: &[u8]) -> Result<Self, AddressLimitError> {
        let maximum = AddressLimits::default().max_custom_addr_bytes;
        if data.len() > maximum {
            return Err(n0_error::e!(AddressLimitError::CustomAddrBytes {
                actual: data.len(),
                maximum,
            }));
        }
        Ok(Self::from_parts_unchecked(id, data))
    }

    /// Returns the transport id.
    ///
    /// You can freely choose this. There is a table of reserved custom transport ids in
    /// <https://github.com/n0-computer/iroh/blob/main/TRANSPORTS.md>, where you could
    /// submit your transport for registration to get a reserved id.
    ///
    /// But this is only relevant if you care for interop.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the opaque address data for this transport.
    ///
    /// Below a certain size (currently 30 bytes) this is stored inline, otherwise on the heap.
    ///
    /// Note that there are no guarantees about the size of this data. When parsing custom
    /// addresses you must be prepared to handle unexpected sizes here.
    pub fn data(&self) -> &[u8] {
        self.data.as_bytes()
    }

    /// Serializes to the binary encoding.
    ///
    /// See [`CustomAddr`] docs for details on the encoding.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = vec![0u8; 8 + self.data.len()];
        out[..8].copy_from_slice(&self.id().to_le_bytes());
        out[8..].copy_from_slice(self.data());
        out
    }

    /// Parses from the binary encoding.
    ///
    /// See [`CustomAddr`] docs for details on the encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("data too short");
        }
        let id = u64::from_le_bytes(data[..8].try_into().expect("data length checked above"));
        let data = &data[8..];
        Self::try_from_parts(id, data).map_err(|_| "address data too long")
    }
}

impl<'de> Deserialize<'de> for CustomAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct UncheckedCustomAddr {
            id: u64,
            data: CustomAddrBytes,
        }

        let unchecked = UncheckedCustomAddr::deserialize(deserializer)?;
        Self::try_from_parts(unchecked.id, unchecked.data.as_bytes()).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[non_exhaustive]
    enum NewAddrType {
        /// Relays
        Relay(RelayUrl),
        /// IP based addresses
        Ip(SocketAddr),
        /// New addr type for testing
        Cool(u16),
    }

    #[test]
    fn test_roundtrip_new_addr_type() {
        let old = vec![
            TransportAddr::Ip("127.0.0.1:9".parse().unwrap()),
            TransportAddr::Relay("https://example.com".parse().unwrap()),
        ];
        let old_ser = postcard::to_stdvec(&old).unwrap();
        let old_back: Vec<TransportAddr> = postcard::from_bytes(&old_ser).unwrap();
        assert_eq!(old, old_back);

        let new = vec![
            NewAddrType::Ip("127.0.0.1:9".parse().unwrap()),
            NewAddrType::Relay("https://example.com".parse().unwrap()),
            NewAddrType::Cool(4),
        ];
        let new_ser = postcard::to_stdvec(&new).unwrap();
        let new_back: Vec<NewAddrType> = postcard::from_bytes(&new_ser).unwrap();

        assert_eq!(new, new_back);

        // serialize old into new
        let old_new_back: Vec<NewAddrType> = postcard::from_bytes(&old_ser).unwrap();

        assert_eq!(
            old_new_back,
            vec![
                NewAddrType::Ip("127.0.0.1:9".parse().unwrap()),
                NewAddrType::Relay("https://example.com".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn test_custom_addr_roundtrip() {
        // Small id, small data (e.g., Bluetooth MAC)
        let addr = CustomAddr::try_from_parts(1, &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6])
            .expect("test address is bounded");
        let s = addr.to_string();
        assert_eq!(s, "1_a1b2c3d4e5f6");
        let parsed: CustomAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);

        // Larger id, 32-byte data (e.g., Tor pubkey)
        let addr = CustomAddr::try_from_parts(42, &[0xab; 32]).expect("test address is bounded");
        let s = addr.to_string();
        assert_eq!(
            s,
            "2a_abababababababababababababababababababababababababababababababab"
        );
        let parsed: CustomAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);

        // Zero id, empty data
        let addr = CustomAddr::try_from_parts(0, &[]).expect("test address is bounded");
        let s = addr.to_string();
        assert_eq!(s, "0_");
        let parsed: CustomAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);

        // Large id
        let addr =
            CustomAddr::try_from_parts(0xdeadbeef, &[0x01, 0x02]).expect("test address is bounded");
        let s = addr.to_string();
        assert_eq!(s, "deadbeef_0102");
        let parsed: CustomAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_custom_addr_parse_errors() {
        // Missing separator
        assert!("abc123".parse::<CustomAddr>().is_err());

        // Invalid id (not hex)
        assert!("xyz_0102".parse::<CustomAddr>().is_err());

        // Invalid data (not hex)
        assert!("1_ghij".parse::<CustomAddr>().is_err());

        // Odd-length hex data
        assert!("1_abc".parse::<CustomAddr>().is_err());
    }

    #[test]
    #[allow(deprecated)] // Constructs an old oversized value to test bounded deserialization.
    fn oversized_custom_addr_is_rejected_at_untrusted_ingress() {
        let oversized = vec![0xab; 513];
        let encoded = format!("1_{}", HEXLOWER.encode(&oversized));
        assert!(
            encoded.parse::<CustomAddr>().is_err(),
            "string parsing must enforce the custom-address byte limit"
        );

        let mut binary = 1_u64.to_le_bytes().to_vec();
        binary.extend_from_slice(&oversized);
        assert!(
            CustomAddr::from_bytes(&binary).is_err(),
            "binary parsing must enforce the custom-address byte limit"
        );

        let legacy = CustomAddr::from_parts(1, &oversized);
        let serialized = postcard::to_stdvec(&legacy).unwrap();
        assert!(
            postcard::from_bytes::<CustomAddr>(&serialized).is_err(),
            "deserialization must reject legacy oversized values"
        );
    }

    #[test]
    #[allow(deprecated)] // Constructs an old oversized value to test bounded deserialization.
    fn endpoint_addr_deserialization_rejects_excessive_address_count() {
        let key = crate::SecretKey::generate().public();
        let addrs = (0..35)
            .map(|port| TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 10_000 + port))));
        let legacy = EndpointAddr::from_parts(key, addrs);
        let serialized = postcard::to_stdvec(&legacy).unwrap();

        assert!(
            postcard::from_bytes::<EndpointAddr>(&serialized).is_err(),
            "deserialization must reject excessive endpoint address counts"
        );
    }

    #[test]
    fn public_field_mutation_is_detected_by_validation() {
        let key = crate::SecretKey::generate().public();
        let mut addr = EndpointAddr::new(key);
        for port in 0..=MAX_ENDPOINT_ADDRS {
            addr.addrs.insert(TransportAddr::Ip(SocketAddr::from((
                [127, 0, 0, 1],
                40_000 + port as u16,
            ))));
        }
        assert!(matches!(
            addr.validate(),
            Err(AddressLimitError::EndpointAddrCount { .. })
        ));
    }

    #[test]
    fn fallible_constructors_enforce_all_default_address_limits() {
        assert!(CustomAddr::try_from_parts(1, &[0_u8; MAX_CUSTOM_ADDR_BYTES]).is_ok());
        assert!(CustomAddr::try_from_parts(1, &[0_u8; MAX_CUSTOM_ADDR_BYTES + 1]).is_err());

        let key = crate::SecretKey::generate().public();
        let maximum_count = (0..MAX_ENDPOINT_ADDRS).map(|port| {
            TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 20_000 + port as u16)))
        });
        assert!(EndpointAddr::try_from_parts(key, maximum_count).is_ok());
        let excessive_count = (0..=MAX_ENDPOINT_ADDRS).map(|port| {
            TransportAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 30_000 + port as u16)))
        });
        assert!(EndpointAddr::try_from_parts(key, excessive_count).is_err());

        let long_url: RelayUrl = format!("https://example.com/{}", "a".repeat(MAX_RELAY_URL_BYTES))
            .parse()
            .unwrap();
        assert!(
            EndpointAddr::try_from_parts(key, [TransportAddr::Relay(long_url)]).is_err(),
            "relay URL encoding must be bounded independently"
        );

        let byte_heavy = (0..MAX_ENDPOINT_ADDRS - 1).map(|id| {
            TransportAddr::Custom(CustomAddr::try_from_parts(id as u64, &[0; 512]).unwrap())
        });
        assert!(
            EndpointAddr::try_from_parts(key, byte_heavy).is_err(),
            "cumulative endpoint address bytes must be bounded"
        );
    }

    #[test]
    fn bounded_custom_addr_serde_preserves_existing_encoding() {
        for addr in [
            CustomAddr::try_from_parts(1, &[1, 2, 3]).unwrap(),
            CustomAddr::try_from_parts(2, &[7; 64]).unwrap(),
        ] {
            let encoded = postcard::to_stdvec(&addr).unwrap();
            let decoded: CustomAddr = postcard::from_bytes(&encoded).unwrap();
            assert_eq!(decoded, addr);
        }
    }
}
