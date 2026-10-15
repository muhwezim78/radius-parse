# radius-parse

A zero-copy, allocation-free, dependency-free parser for RADIUS packets
([RFC 2865](https://www.rfc-editor.org/rfc/rfc2865) authentication,
[RFC 2866](https://www.rfc-editor.org/rfc/rfc2866) accounting).

```rust
use radius_parse::{AttributeType, Code, Packet};

let packet = Packet::parse(datagram)?;

if packet.code() == Code::AccessRequest {
    let user = packet
        .find(AttributeType::UserName)?
        .and_then(|a| a.as_str().ok());

    println!("id {} user {user:?}", packet.identifier());
}
```

## Why

RADIUS is what decides whether a subscriber gets a session. Every ISP runs it,
usually FreeRADIUS behind a BRAS or a hotspot gateway. When you want to build
something next to that — a session monitor, a CoA proxy, a tool that tails
accounting records into a billing system — you need to read the wire format,
and you need to read it from bytes that arrived over the network from a device
you do not control.

That last part is the whole design constraint. Every length field in a RADIUS
packet is attacker-controlled: the 16-bit `Length` in the header, and a 1-byte
`Length` on every attribute. A parser that trusts them indexes out of bounds.
In C that is a buffer overread; in Rust it is a panic, which in a server is
still a denial of service. So:

- **Every length is validated before it is used as an index.** The test suite
  is mostly malformed packets for this reason.
- **No `unsafe`.** Enforced by `#![forbid(unsafe_code)]`.
- **No panic path in `parse`.** The header is peeled off with
  `first_chunk::<20>()` and destructured with an array pattern, so the
  compiler proves the authenticator is 16 bytes. There is no `unwrap`,
  `expect`, or fallible conversion in the parse path.
- **No allocation, no copying.** `Packet` and `Attribute` borrow the receive
  buffer; the lifetime stops either outliving it.
- **No dependencies, and `no_std` with `default-features = false`.**

## What it does not do

It reads the wire format and stops there. It does not:

- verify the Request/Response Authenticator or Message-Authenticator — that
  needs the shared secret and MD5/HMAC-MD5
- obscure or recover User-Password
- carry a dictionary of vendor attributes, or decode VSAs (type 26) past
  handing you the bytes

Those need a secret, a hash, or a config file. Keeping them out is what lets
this crate have no dependencies and build without `std`.

## Design notes

**Lazy attributes.** `Packet::parse` validates the header only. A proxy that
matches a response to a pending request needs the code and identifier and
nothing else, and shouldn't pay to walk the attribute list.

**Attributes iterate as `Result`.** A malformed attribute halfway through a
packet must not look like the end of the list, so `Attributes` yields
`Result<Attribute, ParseError>`. After an error it stops: once you have lost
the attribute boundary, continuing is guesswork.

**Unknown values are preserved, not rejected.** An unrecognised code comes
back as `Code::Unassigned(u8)` and an unrecognised attribute type as
`AttributeType::Other(u8)`. RFC 2865 says a server must silently discard a
packet with an invalid code — but that is policy, and policy belongs to the
caller, not the parser.

**Trailing bytes are ignored.** RFC 2865 §3: "Octets outside the range of the
Length field MUST be treated as padding and ignored on reception." This
matters in practice because `recv_from` hands you a buffer sized for the
largest packet you might get, not for this one.

**`Length` below 2 on an attribute is an error, not a skip.** A declared
length of 0 would leave the iterator's cursor unmoved and spin it forever.
That is the bug this crate is most carefully tested against.

## Tests

```
cargo test                          # 32 tests
cargo clippy --all-targets -- -D warnings
cargo check --no-default-features   # no_std
```

Beyond the field-level unit tests, `tests/wire_vectors.rs` holds:

- two full packets as hex dumps — an Access-Request from a hotspot gateway and
  an Accounting-Request (Stop) with octet counters and a CGNAT
  `Framed-IP-Address` — asserted field by field, including that the attribute
  lengths sum back to the header's `Length`
- every prefix of a real packet, which must be rejected rather than accepted
  as a shorter valid one
- every single-bit flip of a real packet (98 bytes × 8 bits), which must not
  panic
- 20,000 pseudo-random buffers, which must not panic

## Status

Early. The wire format is covered; `Code` and `AttributeType` cover the values
that show up in ISP authentication and accounting, and anything else is
preserved verbatim rather than lost. Next: nested vendor-specific attribute
(type 26) decoding, and a `Builder` for writing packets.

## Licence

MIT. See [LICENSE](LICENSE).
