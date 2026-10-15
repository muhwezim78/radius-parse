//! A zero-copy parser for RADIUS packets.
//!
//! RADIUS is the protocol behind almost every ISP's authentication: a router
//! asks a server "may this subscriber on this port have a session", and later
//! tells it how many octets they used. The wire format is
//! [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865) for authentication and
//! [RFC 2866](https://www.rfc-editor.org/rfc/rfc2866) for accounting: a fixed
//! 20-byte header followed by a list of type-length-value attributes.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Code      |  Identifier   |            Length             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! |                         Authenticator                         |
//! |                            (16 bytes)                         |
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Attributes ...
//! +-+-+-+-+-+-+-+-
//! ```
//!
//! # What this crate does and does not do
//!
//! It reads the wire format and nothing else. It does not verify
//! authenticators, obscure or recover passwords, or hold a dictionary of
//! vendor attributes — all of which need a shared secret, a hash, or a
//! configuration file. Keeping them out is why this crate has no
//! dependencies, performs no allocation, and works without `std`.
//!
//! # Design
//!
//! - **Zero-copy.** [`Packet`] and [`Attribute`] borrow the receive buffer.
//!   Nothing is cloned, so parsing a packet costs a few bounds checks.
//! - **No panics on hostile input.** Every length on the wire is attacker
//!   controlled, so every one is checked before it is used as an index. The
//!   test suite is mostly malformed packets for that reason.
//! - **Lazy attributes.** The header is validated on [`Packet::parse`]; the
//!   attribute list is only walked if you ask for it.
//! - **Unknown values are preserved, not rejected.** An unrecognised code or
//!   attribute type is handed back verbatim. Whether to discard the packet is
//!   policy, and policy belongs to the caller.
//!
//! # Example
//!
//! ```
//! use radius_parse::{AttributeType, Code, Packet};
//!
//! fn log_request(datagram: &[u8]) {
//!     let packet = match Packet::parse(datagram) {
//!         Ok(packet) => packet,
//!         Err(error) => {
//!             eprintln!("dropping malformed packet: {error}");
//!             return;
//!         }
//!     };
//!
//!     if packet.code() != Code::AccessRequest {
//!         return;
//!     }
//!
//!     let user = packet
//!         .find(AttributeType::UserName)
//!         .ok()
//!         .flatten()
//!         .and_then(|attribute| attribute.as_str().ok())
//!         .unwrap_or("<unknown>");
//!
//!     let nas = packet
//!         .find(AttributeType::NasIpAddress)
//!         .ok()
//!         .flatten()
//!         .and_then(|attribute| attribute.as_ipv4());
//!
//!     println!("id {} user {user} from {nas:?}", packet.identifier());
//! }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![doc(html_root_url = "https://docs.rs/radius-parse/0.1.0")]

mod attribute;
mod code;
mod error;
mod packet;

pub use attribute::{Attribute, AttributeType, Attributes};
pub use code::Code;
pub use error::ParseError;
pub use packet::{Packet, HEADER_LEN, MAX_PACKET_LEN, MIN_PACKET_LEN};
