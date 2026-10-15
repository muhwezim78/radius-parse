//! The `Code` octet: which kind of RADIUS message this is.

use core::fmt;

/// The first octet of a RADIUS packet.
///
/// Unrecognised values are preserved in [`Code::Unassigned`] rather than
/// rejected. RFC 2865 section 3 says a server receiving a packet with an
/// invalid code must silently discard it, which is the caller's decision to
/// make, not the parser's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// 1 — client asks the server to authenticate a user.
    AccessRequest,
    /// 2 — server accepts.
    AccessAccept,
    /// 3 — server rejects.
    AccessReject,
    /// 4 — client reports session start/stop (RFC 2866).
    AccountingRequest,
    /// 5 — server acknowledges an accounting record (RFC 2866).
    AccountingResponse,
    /// 11 — server asks for more information, e.g. a token code.
    AccessChallenge,
    /// 12 — server liveness probe (RFC 5997).
    StatusServer,
    /// 13 — client liveness probe (RFC 5997).
    StatusClient,
    /// 40 — disconnect an active session (RFC 5176).
    DisconnectRequest,
    /// 41 — disconnect accepted (RFC 5176).
    DisconnectAck,
    /// 42 — disconnect refused (RFC 5176).
    DisconnectNak,
    /// 43 — change an active session's authorisation (RFC 5176).
    CoaRequest,
    /// 44 — change-of-authorisation accepted (RFC 5176).
    CoaAck,
    /// 45 — change-of-authorisation refused (RFC 5176).
    CoaNak,
    /// Any other value, kept verbatim.
    Unassigned(u8),
}

impl Code {
    /// The wire value of this code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::AccessRequest => 1,
            Self::AccessAccept => 2,
            Self::AccessReject => 3,
            Self::AccountingRequest => 4,
            Self::AccountingResponse => 5,
            Self::AccessChallenge => 11,
            Self::StatusServer => 12,
            Self::StatusClient => 13,
            Self::DisconnectRequest => 40,
            Self::DisconnectAck => 41,
            Self::DisconnectNak => 42,
            Self::CoaRequest => 43,
            Self::CoaAck => 44,
            Self::CoaNak => 45,
            Self::Unassigned(raw) => raw,
        }
    }

    /// Whether this code is sent by a client towards a server.
    ///
    /// Change-of-authorisation and disconnect messages travel the other way —
    /// the RADIUS server originates them — so they are not requests in this
    /// sense even though their names end in `Request`.
    #[must_use]
    pub const fn is_client_request(self) -> bool {
        matches!(
            self,
            Self::AccessRequest | Self::AccountingRequest | Self::StatusServer | Self::StatusClient
        )
    }
}

impl From<u8> for Code {
    fn from(raw: u8) -> Self {
        match raw {
            1 => Self::AccessRequest,
            2 => Self::AccessAccept,
            3 => Self::AccessReject,
            4 => Self::AccountingRequest,
            5 => Self::AccountingResponse,
            11 => Self::AccessChallenge,
            12 => Self::StatusServer,
            13 => Self::StatusClient,
            40 => Self::DisconnectRequest,
            41 => Self::DisconnectAck,
            42 => Self::DisconnectNak,
            43 => Self::CoaRequest,
            44 => Self::CoaAck,
            45 => Self::CoaNak,
            other => Self::Unassigned(other),
        }
    }
}

impl From<Code> for u8 {
    fn from(code: Code) -> Self {
        code.as_u8()
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::AccessRequest => "Access-Request",
            Self::AccessAccept => "Access-Accept",
            Self::AccessReject => "Access-Reject",
            Self::AccountingRequest => "Accounting-Request",
            Self::AccountingResponse => "Accounting-Response",
            Self::AccessChallenge => "Access-Challenge",
            Self::StatusServer => "Status-Server",
            Self::StatusClient => "Status-Client",
            Self::DisconnectRequest => "Disconnect-Request",
            Self::DisconnectAck => "Disconnect-ACK",
            Self::DisconnectNak => "Disconnect-NAK",
            Self::CoaRequest => "CoA-Request",
            Self::CoaAck => "CoA-ACK",
            Self::CoaNak => "CoA-NAK",
            Self::Unassigned(raw) => return write!(f, "Unassigned({raw})"),
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::Code;

    #[test]
    fn known_codes_round_trip_through_the_wire_value() {
        for raw in 0u8..=255 {
            let code = Code::from(raw);
            assert_eq!(code.as_u8(), raw, "code {code:?} lost its wire value");
        }
    }

    #[test]
    fn unassigned_keeps_the_raw_octet() {
        assert_eq!(Code::from(200), Code::Unassigned(200));
        assert_eq!(Code::from(200).as_u8(), 200);
    }

    #[test]
    fn coa_request_is_not_a_client_request() {
        // It is named `Request` but the server sends it.
        assert!(!Code::CoaRequest.is_client_request());
        assert!(Code::AccessRequest.is_client_request());
    }
}
