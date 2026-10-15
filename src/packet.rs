//! The packet header and the entry point to parsing.

use core::fmt;

use crate::attribute::{Attribute, AttributeType, Attributes};
use crate::code::Code;
use crate::error::ParseError;

/// Size of the fixed header: code, identifier, length, authenticator.
pub const HEADER_LEN: usize = 20;

/// Smallest legal packet, from RFC 2865 section 3. A packet with no
/// attributes at all is still 20 bytes.
pub const MIN_PACKET_LEN: usize = 20;

/// Largest legal packet, from RFC 2865 section 3.
pub const MAX_PACKET_LEN: usize = 4096;

/// A parsed RADIUS packet, borrowing the buffer it came from.
///
/// Parsing performs no allocation and copies nothing: this struct holds a
/// handful of integers and two borrowed slices. The lifetime `'a` is the
/// buffer's, so a `Packet` cannot outlive the bytes it describes — which is
/// what you want when the bytes are a reused receive buffer.
///
/// ```
/// use radius_parse::{Code, Packet};
///
/// # fn main() -> Result<(), radius_parse::ParseError> {
/// let mut datagram = [0u8; 26];
/// datagram[0] = 1; // Access-Request
/// datagram[1] = 42; // Identifier
/// datagram[2..4].copy_from_slice(&26u16.to_be_bytes());
/// datagram[20..].copy_from_slice(&[1, 6, b'm', b'a', b'r', b'k']);
///
/// let packet = Packet::parse(&datagram)?;
/// assert_eq!(packet.code(), Code::AccessRequest);
/// assert_eq!(packet.identifier(), 42);
/// assert_eq!(packet.attributes().count(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    code: Code,
    identifier: u8,
    length: u16,
    authenticator: &'a [u8; 16],
    attribute_bytes: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Read a packet out of `buf`.
    ///
    /// The header is validated eagerly; attributes are not. Walking the
    /// attribute list is the caller's choice via [`Packet::attributes`],
    /// because a server that only needs the code and identifier — to match a
    /// response to a pending request, say — should not pay for parsing the
    /// rest.
    ///
    /// # Trailing bytes
    ///
    /// If `buf` is longer than the `Length` field declares, the surplus is
    /// ignored. RFC 2865 section 3 requires exactly this: "Octets outside the
    /// range of the Length field MUST be treated as padding and ignored on
    /// reception." It matters in practice because a UDP socket read gives you
    /// a buffer sized for the largest packet you might get, not for this one.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the buffer is shorter than the header, or if
    /// the `Length` field is out of range or longer than the buffer.
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        // Peel the header off as a fixed-size chunk and destructure it. The
        // array pattern proves to the compiler that `authenticator` is
        // exactly 16 bytes, so there is no fallible conversion and no panic
        // path anywhere in this function.
        let Some(header) = buf.first_chunk::<HEADER_LEN>() else {
            return Err(ParseError::HeaderTruncated { got: buf.len() });
        };
        let [code, identifier, len_hi, len_lo, authenticator @ ..] = header;

        let length = u16::from_be_bytes([*len_hi, *len_lo]);
        let declared = usize::from(length);

        if declared < MIN_PACKET_LEN {
            return Err(ParseError::LengthBelowMinimum { declared: length });
        }
        if declared > MAX_PACKET_LEN {
            return Err(ParseError::LengthAboveMaximum { declared: length });
        }
        if declared > buf.len() {
            return Err(ParseError::LengthExceedsBuffer {
                declared: length,
                available: buf.len(),
            });
        }

        Ok(Self {
            code: Code::from(*code),
            identifier: *identifier,
            length,
            authenticator,
            // Trailing bytes past `declared` are dropped here, not later.
            attribute_bytes: &buf[HEADER_LEN..declared],
        })
    }

    /// What kind of message this is.
    #[must_use]
    pub const fn code(&self) -> Code {
        self.code
    }

    /// The identifier, used to match a response to its request.
    #[must_use]
    pub const fn identifier(&self) -> u8 {
        self.identifier
    }

    /// The packet's declared total length in bytes, header included.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    /// Always `false`. A RADIUS packet is never zero-length; this exists
    /// because `len` without `is_empty` is a lint, and lying to the lint by
    /// renaming `len` would be worse.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// The 16-byte Request or Response Authenticator.
    ///
    /// This parser does not verify it. Verification needs the shared secret
    /// and an MD5 implementation, which is a separate concern from reading
    /// the wire format — keeping it out is what lets this crate stay
    /// dependency-free.
    #[must_use]
    pub const fn authenticator(&self) -> &'a [u8; 16] {
        self.authenticator
    }

    /// The raw attribute section, between the header and the declared end.
    #[must_use]
    pub const fn attribute_bytes(&self) -> &'a [u8] {
        self.attribute_bytes
    }

    /// Walk the attributes in wire order.
    #[must_use]
    pub const fn attributes(&self) -> Attributes<'a> {
        Attributes::new(self.attribute_bytes)
    }

    /// The first attribute of the given type, if the list is well-formed up to
    /// that point.
    ///
    /// Returns `Ok(None)` if the list parsed cleanly and held no such
    /// attribute, and `Err` if the list is malformed before one was found.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the attribute list is malformed.
    pub fn find(&self, wanted: AttributeType) -> Result<Option<Attribute<'a>>, ParseError> {
        for attribute in self.attributes() {
            let attribute = attribute?;
            if attribute.typ() == wanted {
                return Ok(Some(attribute));
            }
        }
        Ok(None)
    }
}

impl fmt::Display for Packet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} id={} len={}",
            self.code, self.identifier, self.length
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Packet, HEADER_LEN, MAX_PACKET_LEN};
    use crate::attribute::AttributeType;
    use crate::code::Code;
    use crate::error::ParseError;

    /// Build a packet whose `Length` field is set correctly.
    fn packet(code: u8, id: u8, attribute_bytes: &[u8]) -> Vec<u8> {
        let total = HEADER_LEN + attribute_bytes.len();
        let mut out = Vec::with_capacity(total);
        out.push(code);
        out.push(id);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&[0xaa; 16]);
        out.extend_from_slice(attribute_bytes);
        out
    }

    #[test]
    fn reads_a_bare_header() {
        let bytes = packet(1, 7, &[]);
        let p = Packet::parse(&bytes).expect("a 20-byte packet is legal");

        assert_eq!(p.code(), Code::AccessRequest);
        assert_eq!(p.identifier(), 7);
        assert_eq!(p.len(), 20);
        assert_eq!(p.authenticator(), &[0xaa; 16]);
        assert!(p.attribute_bytes().is_empty());
        assert_eq!(p.attributes().count(), 0);
    }

    #[test]
    fn length_is_read_big_endian() {
        // 0x0101 = 257, not 0x0101 byte-swapped to 257's little-endian twin.
        let mut bytes = packet(1, 0, &[0u8; 237]);
        assert_eq!(bytes.len(), 257);
        bytes[2] = 0x01;
        bytes[3] = 0x01;
        assert_eq!(Packet::parse(&bytes).unwrap().len(), 257);
    }

    #[test]
    fn a_nineteen_byte_buffer_is_too_short_for_the_header() {
        let bytes = [0u8; 19];
        assert_eq!(
            Packet::parse(&bytes),
            Err(ParseError::HeaderTruncated { got: 19 })
        );
    }

    #[test]
    fn an_empty_buffer_is_too_short() {
        assert_eq!(
            Packet::parse(&[]),
            Err(ParseError::HeaderTruncated { got: 0 })
        );
    }

    #[test]
    fn a_length_field_below_twenty_is_rejected() {
        let mut bytes = packet(1, 0, &[]);
        bytes[2..4].copy_from_slice(&(19u16).to_be_bytes());
        assert_eq!(
            Packet::parse(&bytes),
            Err(ParseError::LengthBelowMinimum { declared: 19 })
        );
    }

    #[test]
    fn a_length_field_above_four_thousand_and_ninety_six_is_rejected() {
        let mut bytes = packet(1, 0, &[]);
        bytes[2..4].copy_from_slice(&(4097u16).to_be_bytes());
        assert_eq!(
            Packet::parse(&bytes),
            Err(ParseError::LengthAboveMaximum { declared: 4097 })
        );
    }

    #[test]
    fn exactly_four_thousand_and_ninety_six_is_accepted() {
        let bytes = packet(1, 0, &[0u8; MAX_PACKET_LEN - HEADER_LEN]);
        assert_eq!(bytes.len(), MAX_PACKET_LEN);
        assert_eq!(Packet::parse(&bytes).unwrap().len(), MAX_PACKET_LEN);
    }

    #[test]
    fn a_truncated_datagram_is_rejected_not_silently_shortened() {
        // The header says 46 bytes, the sender or the network gave us 30.
        // Trusting the length field here is how you read uninitialised
        // memory in C; in Rust it is how you panic in production.
        let full = packet(
            1,
            3,
            &[
                1, 6, b'm', b'a', b'r', b'k', 25, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0,
            ],
        );
        assert_eq!(full.len(), 46);
        let truncated = &full[..30];

        assert_eq!(
            Packet::parse(truncated),
            Err(ParseError::LengthExceedsBuffer {
                declared: 46,
                available: 30,
            })
        );
    }

    #[test]
    fn trailing_padding_past_the_length_field_is_ignored() {
        let mut bytes = packet(1, 9, &[1, 6, b'm', b'a', b'r', b'k']);
        assert_eq!(bytes.len(), 26);
        // A receive buffer that was not cleared between datagrams.
        bytes.extend_from_slice(&[0xff; 64]);

        let p = Packet::parse(&bytes).expect("padding is not an error");
        assert_eq!(p.len(), 26);
        assert_eq!(p.attribute_bytes().len(), 6);
        assert_eq!(p.attributes().count(), 1);
        let name = p.find(AttributeType::UserName).unwrap().unwrap();
        assert_eq!(name.as_str().unwrap(), "mark");
    }

    #[test]
    fn find_returns_none_when_the_list_is_clean_but_lacks_the_attribute() {
        let bytes = packet(1, 1, &[1, 6, b'm', b'a', b'r', b'k']);
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(p.find(AttributeType::NasIpAddress), Ok(None));
    }

    #[test]
    fn find_surfaces_a_malformed_list() {
        let bytes = packet(1, 1, &[1, 0, 0, 0]);
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(
            p.find(AttributeType::NasIpAddress),
            Err(ParseError::AttributeLengthBelowMinimum {
                offset: HEADER_LEN,
                declared: 0,
            })
        );
    }

    #[test]
    fn an_unassigned_code_still_parses() {
        let bytes = packet(200, 1, &[]);
        assert_eq!(Packet::parse(&bytes).unwrap().code(), Code::Unassigned(200));
    }
}
