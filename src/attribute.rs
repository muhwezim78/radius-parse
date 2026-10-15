//! Attributes: the type-length-value list that follows the header.
//!
//! An attribute on the wire is three fields:
//!
//! ```text
//!  0                   1                   2
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ...
//! |     Type      |    Length     |  Value ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ...
//! ```
//!
//! `Length` counts the type and length octets as well as the value, so a
//! valid attribute is at least 2 bytes and its value is `Length - 2` bytes.
//! Getting that `- 2` wrong in either direction is the classic RADIUS parser
//! bug, which is why [`Attributes`] is tested against both.

use core::fmt;
use core::net::Ipv4Addr;

use crate::error::ParseError;
use crate::packet::HEADER_LEN;

/// The `Type` octet of an attribute.
///
/// This is the subset that shows up in ISP authentication and accounting.
/// Everything else is preserved as [`AttributeType::Other`]; a parser that
/// rejected unknown attributes would break on every vendor that ships its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributeType {
    /// 1 — the login name being authenticated.
    UserName,
    /// 2 — the password, obscured with the shared secret and the authenticator.
    UserPassword,
    /// 3 — CHAP response.
    ChapPassword,
    /// 4 — IPv4 address of the NAS asking the question.
    NasIpAddress,
    /// 5 — physical port on the NAS.
    NasPort,
    /// 6 — the kind of service requested, e.g. Framed.
    ServiceType,
    /// 7 — framing to use, e.g. PPP.
    FramedProtocol,
    /// 8 — address to assign the user, or `255.255.255.254` to ask the NAS.
    FramedIpAddress,
    /// 9 — netmask for the user's address.
    FramedIpNetmask,
    /// 11 — name of an access filter to apply.
    FilterId,
    /// 12 — MTU to negotiate.
    FramedMtu,
    /// 18 — text the NAS should show the user.
    ReplyMessage,
    /// 24 — opaque blob echoed back in the next request.
    State,
    /// 25 — opaque blob the server wants back in accounting records.
    Class,
    /// 26 — vendor-specific attribute, itself a nested TLV.
    VendorSpecific,
    /// 27 — seconds before the session must be terminated.
    SessionTimeout,
    /// 28 — seconds of idle time before termination.
    IdleTimeout,
    /// 30 — the number the user dialled, or the AP's MAC in Wi-Fi.
    CalledStationId,
    /// 31 — the user's number, or their MAC in Wi-Fi.
    CallingStationId,
    /// 32 — string identifying the NAS, used when the IP is not stable.
    NasIdentifier,
    /// 40 — Start, Stop or Interim-Update (RFC 2866).
    AcctStatusType,
    /// 42 — octets received by the user this session (RFC 2866).
    AcctInputOctets,
    /// 43 — octets sent to the user this session (RFC 2866).
    AcctOutputOctets,
    /// 44 — unique id tying accounting records to one session (RFC 2866).
    AcctSessionId,
    /// 46 — seconds the session has been up (RFC 2866).
    AcctSessionTime,
    /// 49 — why the session ended (RFC 2866).
    AcctTerminateCause,
    /// 61 — the physical port type, e.g. Ethernet or Virtual.
    NasPortType,
    /// 80 — HMAC-MD5 over the packet, required for `CoA` (RFC 3579).
    MessageAuthenticator,
    /// Any other type, kept verbatim.
    Other(u8),
}

impl AttributeType {
    /// The wire value of this type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::UserName => 1,
            Self::UserPassword => 2,
            Self::ChapPassword => 3,
            Self::NasIpAddress => 4,
            Self::NasPort => 5,
            Self::ServiceType => 6,
            Self::FramedProtocol => 7,
            Self::FramedIpAddress => 8,
            Self::FramedIpNetmask => 9,
            Self::FilterId => 11,
            Self::FramedMtu => 12,
            Self::ReplyMessage => 18,
            Self::State => 24,
            Self::Class => 25,
            Self::VendorSpecific => 26,
            Self::SessionTimeout => 27,
            Self::IdleTimeout => 28,
            Self::CalledStationId => 30,
            Self::CallingStationId => 31,
            Self::NasIdentifier => 32,
            Self::AcctStatusType => 40,
            Self::AcctInputOctets => 42,
            Self::AcctOutputOctets => 43,
            Self::AcctSessionId => 44,
            Self::AcctSessionTime => 46,
            Self::AcctTerminateCause => 49,
            Self::NasPortType => 61,
            Self::MessageAuthenticator => 80,
            Self::Other(raw) => raw,
        }
    }
}

impl From<u8> for AttributeType {
    fn from(raw: u8) -> Self {
        match raw {
            1 => Self::UserName,
            2 => Self::UserPassword,
            3 => Self::ChapPassword,
            4 => Self::NasIpAddress,
            5 => Self::NasPort,
            6 => Self::ServiceType,
            7 => Self::FramedProtocol,
            8 => Self::FramedIpAddress,
            9 => Self::FramedIpNetmask,
            11 => Self::FilterId,
            12 => Self::FramedMtu,
            18 => Self::ReplyMessage,
            24 => Self::State,
            25 => Self::Class,
            26 => Self::VendorSpecific,
            27 => Self::SessionTimeout,
            28 => Self::IdleTimeout,
            30 => Self::CalledStationId,
            31 => Self::CallingStationId,
            32 => Self::NasIdentifier,
            40 => Self::AcctStatusType,
            42 => Self::AcctInputOctets,
            43 => Self::AcctOutputOctets,
            44 => Self::AcctSessionId,
            46 => Self::AcctSessionTime,
            49 => Self::AcctTerminateCause,
            61 => Self::NasPortType,
            80 => Self::MessageAuthenticator,
            other => Self::Other(other),
        }
    }
}

impl From<AttributeType> for u8 {
    fn from(ty: AttributeType) -> Self {
        ty.as_u8()
    }
}

/// One attribute, borrowing its value from the packet buffer.
///
/// No copy is made. The lifetime `'a` ties this to the buffer it was parsed
/// from, so the borrow checker will not let the value outlive the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attribute<'a> {
    typ: AttributeType,
    value: &'a [u8],
}

impl<'a> Attribute<'a> {
    /// The attribute's type.
    #[must_use]
    pub const fn typ(&self) -> AttributeType {
        self.typ
    }

    /// The raw value, without the type and length octets.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The value's length on the wire, including the two header octets.
    ///
    /// Always at least 2 and at most 255.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        self.value.len() + 2
    }

    /// The value as UTF-8 text.
    ///
    /// RFC 2865 calls these fields `text` and expects UTF-8, but nothing on
    /// the wire enforces it, so this can fail and the error is yours to
    /// handle.
    ///
    /// # Errors
    ///
    /// Returns [`core::str::Utf8Error`] if the value is not valid UTF-8.
    pub fn as_str(&self) -> Result<&'a str, core::str::Utf8Error> {
        core::str::from_utf8(self.value)
    }

    /// The value as a 32-bit integer, for the `integer` attribute types.
    ///
    /// Returns `None` unless the value is exactly 4 octets, which is the only
    /// encoding RFC 2865 defines for an integer.
    #[must_use]
    pub fn as_u32(&self) -> Option<u32> {
        let bytes: [u8; 4] = self.value.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    /// The value as an IPv4 address, for the `ipaddr` attribute types.
    ///
    /// Returns `None` unless the value is exactly 4 octets.
    #[must_use]
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        let bytes: [u8; 4] = self.value.try_into().ok()?;
        Some(Ipv4Addr::from(bytes))
    }
}

impl fmt::Display for Attribute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}({} bytes)", self.typ, self.value.len())
    }
}

/// Iterator over a packet's attributes.
///
/// Yields `Result`, because a malformed attribute part way through a packet
/// should not look the same as the end of the list. Once an error is yielded
/// the iterator stops: the remaining bytes cannot be trusted to be aligned to
/// an attribute boundary any more, so continuing would be guesswork.
#[derive(Debug, Clone)]
pub struct Attributes<'a> {
    rest: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> Attributes<'a> {
    pub(crate) const fn new(attribute_bytes: &'a [u8]) -> Self {
        Self {
            rest: attribute_bytes,
            offset: HEADER_LEN,
            failed: false,
        }
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub const fn remaining_bytes(&self) -> &'a [u8] {
        self.rest
    }
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Result<Attribute<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.rest.is_empty() {
            return None;
        }

        if self.rest.len() < 2 {
            self.failed = true;
            return Some(Err(ParseError::AttributeTruncated {
                offset: self.offset,
            }));
        }

        let typ = self.rest[0];
        let declared = self.rest[1];

        // Below 2 the attribute cannot cover its own header. Zero in
        // particular would leave `rest` unchanged and spin this iterator
        // forever, so it has to be rejected, not skipped.
        if declared < 2 {
            self.failed = true;
            return Some(Err(ParseError::AttributeLengthBelowMinimum {
                offset: self.offset,
                declared,
            }));
        }

        let declared_usize = usize::from(declared);
        if declared_usize > self.rest.len() {
            self.failed = true;
            return Some(Err(ParseError::AttributeOverrunsPacket {
                offset: self.offset,
                declared,
                remaining: self.rest.len(),
            }));
        }

        let (head, tail) = self.rest.split_at(declared_usize);
        self.rest = tail;
        self.offset += declared_usize;

        Some(Ok(Attribute {
            typ: AttributeType::from(typ),
            value: &head[2..],
        }))
    }
}

impl core::iter::FusedIterator for Attributes<'_> {}

#[cfg(test)]
mod tests {
    use super::{AttributeType, Attributes};
    use crate::error::ParseError;
    use crate::packet::HEADER_LEN;

    #[test]
    fn types_round_trip_through_the_wire_value() {
        for raw in 0u8..=255 {
            assert_eq!(AttributeType::from(raw).as_u8(), raw);
        }
    }

    #[test]
    fn empty_attribute_section_yields_nothing() {
        assert_eq!(Attributes::new(&[]).count(), 0);
    }

    #[test]
    fn value_is_length_minus_two() {
        // User-Name = "mark": type 1, length 6, four value octets.
        let bytes = [1u8, 6, b'm', b'a', b'r', b'k'];
        let attrs: Vec<_> = Attributes::new(&bytes).collect();
        assert_eq!(attrs.len(), 1);
        let attr = attrs[0].expect("well-formed attribute");
        assert_eq!(attr.typ(), AttributeType::UserName);
        assert_eq!(attr.value(), b"mark");
        assert_eq!(attr.as_str().unwrap(), "mark");
        assert_eq!(attr.wire_len(), 6);
    }

    #[test]
    fn a_two_byte_attribute_has_an_empty_value() {
        // Length 2 is legal and means "no value". An off-by-one in the
        // `- 2` would panic here instead.
        let bytes = [18u8, 2];
        let attr = Attributes::new(&bytes).next().unwrap().unwrap();
        assert_eq!(attr.typ(), AttributeType::ReplyMessage);
        assert!(attr.value().is_empty());
        assert_eq!(attr.wire_len(), 2);
    }

    #[test]
    fn walks_a_whole_list_in_order() {
        let bytes = [
            1u8, 6, b'm', b'a', b'r', b'k', // User-Name
            4, 6, 10, 0, 0, 1, // NAS-IP-Address = 10.0.0.1
            5, 6, 0, 0, 0, 7, // NAS-Port = 7
        ];
        let attrs: Vec<_> = Attributes::new(&bytes)
            .map(|a| a.expect("well-formed"))
            .collect();

        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].as_str().unwrap(), "mark");
        assert_eq!(
            attrs[1].as_ipv4().unwrap(),
            core::net::Ipv4Addr::new(10, 0, 0, 1)
        );
        assert_eq!(attrs[2].as_u32().unwrap(), 7);
    }

    #[test]
    fn zero_length_is_rejected_rather_than_looping() {
        let bytes = [1u8, 0, 0, 0];
        let mut iter = Attributes::new(&bytes);
        assert_eq!(
            iter.next(),
            Some(Err(ParseError::AttributeLengthBelowMinimum {
                offset: HEADER_LEN,
                declared: 0,
            }))
        );
        // And it stays stopped.
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn length_of_one_is_rejected() {
        let bytes = [1u8, 1, b'x'];
        assert_eq!(
            Attributes::new(&bytes).next(),
            Some(Err(ParseError::AttributeLengthBelowMinimum {
                offset: HEADER_LEN,
                declared: 1,
            }))
        );
    }

    #[test]
    fn an_attribute_running_past_the_end_is_rejected() {
        // Declares 20 bytes, only 4 are present.
        let bytes = [1u8, 20, b'm', b'a'];
        assert_eq!(
            Attributes::new(&bytes).next(),
            Some(Err(ParseError::AttributeOverrunsPacket {
                offset: HEADER_LEN,
                declared: 20,
                remaining: 4,
            }))
        );
    }

    #[test]
    fn a_stray_trailing_byte_is_reported_at_its_offset() {
        let bytes = [
            1u8, 6, b'm', b'a', b'r', b'k', // a good attribute
            5,    // and then one byte that cannot be one
        ];
        let results: Vec<_> = Attributes::new(&bytes).collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_eq!(
            results[1],
            Err(ParseError::AttributeTruncated {
                offset: HEADER_LEN + 6,
            })
        );
    }

    #[test]
    fn integer_accessors_reject_the_wrong_width() {
        // NAS-Port carrying 2 octets instead of 4.
        let bytes = [5u8, 4, 0, 7];
        let attr = Attributes::new(&bytes).next().unwrap().unwrap();
        assert_eq!(attr.value(), &[0, 7]);
        assert_eq!(attr.as_u32(), None);
        assert_eq!(attr.as_ipv4(), None);
    }
}
