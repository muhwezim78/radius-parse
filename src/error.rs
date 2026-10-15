//! Parse failures.
//!
//! Every variant carries the offset or the value that caused the rejection, so
//! that a caller logging a malformed packet can say *why* it was malformed
//! without re-reading the buffer.

use core::fmt;

/// Why a buffer could not be read as a RADIUS packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The buffer is smaller than the 20-byte fixed header.
    HeaderTruncated {
        /// Bytes actually available.
        got: usize,
    },

    /// The `Length` field declares fewer than the 20 bytes RFC 2865 requires.
    LengthBelowMinimum {
        /// Value read from the `Length` field.
        declared: u16,
    },

    /// The `Length` field declares more than the 4096-byte maximum.
    LengthAboveMaximum {
        /// Value read from the `Length` field.
        declared: u16,
    },

    /// The `Length` field is in range but points past the end of the buffer.
    ///
    /// This is the interesting case in practice: a short read on a UDP socket,
    /// or a truncating middlebox.
    LengthExceedsBuffer {
        /// Value read from the `Length` field.
        declared: u16,
        /// Bytes actually available.
        available: usize,
    },

    /// Fewer than 2 bytes remain, so no attribute type/length pair can be read.
    AttributeTruncated {
        /// Offset of the stray bytes, from the start of the packet.
        offset: usize,
    },

    /// An attribute declares a length below 2, which cannot even cover its own
    /// type and length octets.
    ///
    /// Accepting this would be a parser bug, not a lenient one: zero would make
    /// the iterator spin forever.
    AttributeLengthBelowMinimum {
        /// Offset of the attribute, from the start of the packet.
        offset: usize,
        /// Value read from the attribute's `Length` octet.
        declared: u8,
    },

    /// An attribute declares a length that runs past the end of the packet.
    AttributeOverrunsPacket {
        /// Offset of the attribute, from the start of the packet.
        offset: usize,
        /// Value read from the attribute's `Length` octet.
        declared: u8,
        /// Bytes left in the packet at that offset.
        remaining: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::HeaderTruncated { got } => {
                write!(f, "packet is {got} bytes, needs at least 20 for the header")
            }
            Self::LengthBelowMinimum { declared } => {
                write!(f, "length field is {declared}, below the minimum of 20")
            }
            Self::LengthAboveMaximum { declared } => {
                write!(f, "length field is {declared}, above the maximum of 4096")
            }
            Self::LengthExceedsBuffer { declared, available } =>
                write!(
                    f,
                    "length field declares {declared} bytes but only {available} are present"
                ),
            Self::AttributeTruncated { offset } => {
                write!(f, "trailing byte at offset {offset} is not a full attribute")
            }
            Self::AttributeLengthBelowMinimum { offset, declared } =>
                write!(
                    f,
                    "attribute at offset {offset} declares length {declared}, below the minimum of 2"
                ),
            Self::AttributeOverrunsPacket { offset, declared, remaining } =>
                write!(
                    f,
                    "attribute at offset {offset} declares length {declared} but only {remaining} bytes remain"
                ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}
