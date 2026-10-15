//! Tests against whole packets, as hex dumps.
//!
//! The unit tests in the library poke at one field at a time. These start from
//! a full datagram of the shape a BRAS actually sends, because a parser that
//! passes field-level tests and then mis-reads a real packet has passed the
//! wrong tests.

use std::net::Ipv4Addr;

use radius_parse::{AttributeType, Code, Packet, ParseError};

/// Decode a hex dump of the kind `tcpdump -x` prints.
fn hex(dump: &str) -> Vec<u8> {
    let digits: Vec<u8> = dump
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            other => panic!("not a hex digit: {}", other as char),
        })
        .collect();
    assert_eq!(digits.len() % 2, 0, "hex dump has an odd number of digits");
    digits
        .chunks(2)
        .map(|pair| (pair[0] << 4) | pair[1])
        .collect()
}

/// Access-Request for a hotspot subscriber: User-Name, NAS-IP-Address,
/// NAS-Port, NAS-Port-Type, Calling-Station-Id (the client MAC),
/// Called-Station-Id (the SSID) and Acct-Session-Id.
const ACCESS_REQUEST: &str = "
    012a0062 8f25c13b 4ea07719 d2660bf4 519ce83d
    010e 6d61726b40736176616e6e61
    0406 294d0001
    0506 00000005
    3d06 0000000f
    1f13 41342d32422d42302d31312d32322d3333
    1e11 736176616e6e612d686f7473706f74
    2c0a 3831613966306332
";

/// Accounting-Request, Acct-Status-Type = Stop, for the same session.
const ACCOUNTING_STOP: &str = "
    047b0061 1cb74402 9e5ad368 31ff7c10 a62b904d
    2806 00000002
    2c0a 3831613966306332
    010e 6d61726b40736176616e6e61
    0806 64400c09
    2e06 00000e10
    2a06 00100000
    2b06 01400000
    3106 00000001
    2011 736176616e6e612d627261732d3031
";

#[test]
fn reads_an_access_request_end_to_end() {
    let bytes = hex(ACCESS_REQUEST);
    assert_eq!(bytes.len(), 98);

    let packet = Packet::parse(&bytes).expect("this is a well-formed packet");

    assert_eq!(packet.code(), Code::AccessRequest);
    assert!(packet.code().is_client_request());
    assert_eq!(packet.identifier(), 42);
    assert_eq!(packet.len(), 98);
    assert_eq!(packet.authenticator()[0], 0x8f);
    assert_eq!(packet.authenticator()[15], 0x3d);

    let attributes: Vec<_> = packet
        .attributes()
        .map(|a| a.expect("every attribute is well-formed"))
        .collect();
    assert_eq!(attributes.len(), 7);

    // The attribute lengths must add up to the packet length exactly. If the
    // parser were off by one anywhere, this is where it shows.
    let summed: usize = attributes
        .iter()
        .map(radius_parse::Attribute::wire_len)
        .sum();
    assert_eq!(summed + radius_parse::HEADER_LEN, packet.len());

    assert_eq!(
        packet
            .find(AttributeType::UserName)
            .unwrap()
            .unwrap()
            .as_str()
            .unwrap(),
        "mark@savanna"
    );
    assert_eq!(
        packet
            .find(AttributeType::NasIpAddress)
            .unwrap()
            .unwrap()
            .as_ipv4()
            .unwrap(),
        Ipv4Addr::new(41, 77, 0, 1)
    );
    assert_eq!(
        packet
            .find(AttributeType::NasPort)
            .unwrap()
            .unwrap()
            .as_u32()
            .unwrap(),
        5
    );
    assert_eq!(
        packet
            .find(AttributeType::NasPortType)
            .unwrap()
            .unwrap()
            .as_u32()
            .unwrap(),
        15 // Ethernet
    );
    assert_eq!(
        packet
            .find(AttributeType::CallingStationId)
            .unwrap()
            .unwrap()
            .as_str()
            .unwrap(),
        "A4-2B-B0-11-22-33"
    );
    assert_eq!(
        packet
            .find(AttributeType::CalledStationId)
            .unwrap()
            .unwrap()
            .as_str()
            .unwrap(),
        "savanna-hotspot"
    );
    assert_eq!(
        packet
            .find(AttributeType::AcctSessionId)
            .unwrap()
            .unwrap()
            .as_str()
            .unwrap(),
        "81a9f0c2"
    );
}

#[test]
fn reads_an_accounting_stop_end_to_end() {
    let bytes = hex(ACCOUNTING_STOP);
    assert_eq!(bytes.len(), 97);

    let packet = Packet::parse(&bytes).expect("this is a well-formed packet");
    assert_eq!(packet.code(), Code::AccountingRequest);
    assert_eq!(packet.identifier(), 123);
    assert_eq!(packet.attributes().count(), 9);

    let get = |ty| packet.find(ty).unwrap().unwrap();

    assert_eq!(get(AttributeType::AcctStatusType).as_u32().unwrap(), 2); // Stop
    assert_eq!(
        get(AttributeType::AcctSessionId).as_str().unwrap(),
        "81a9f0c2"
    );
    // A CGNAT address, which is what a subscriber behind 100.64/10 gets.
    assert_eq!(
        get(AttributeType::FramedIpAddress).as_ipv4().unwrap(),
        Ipv4Addr::new(100, 64, 12, 9)
    );
    assert_eq!(get(AttributeType::AcctSessionTime).as_u32().unwrap(), 3600);
    assert_eq!(
        get(AttributeType::AcctInputOctets).as_u32().unwrap(),
        1_048_576
    );
    assert_eq!(
        get(AttributeType::AcctOutputOctets).as_u32().unwrap(),
        20_971_520
    );
    assert_eq!(
        get(AttributeType::AcctTerminateCause).as_u32().unwrap(),
        1 // User-Request
    );
    assert_eq!(
        get(AttributeType::NasIdentifier).as_str().unwrap(),
        "savanna-bras-01"
    );
}

#[test]
fn every_prefix_of_a_real_packet_is_either_parsed_or_rejected_cleanly() {
    // Simulates a short read, a fragment, a truncating middlebox. None of
    // these may panic, and none may be accepted as a shorter valid packet.
    let full = hex(ACCESS_REQUEST);

    for cut in 0..full.len() {
        let prefix = &full[..cut];
        match Packet::parse(prefix) {
            Err(ParseError::HeaderTruncated { got }) => assert_eq!(got, cut),
            Err(ParseError::LengthExceedsBuffer {
                declared,
                available,
            }) => {
                assert_eq!(declared, 98);
                assert_eq!(available, cut);
            }
            Err(other) => panic!("unexpected error at cut {cut}: {other}"),
            Ok(_) => panic!("a {cut}-byte prefix must not parse as a 98-byte packet"),
        }
    }

    // And the whole thing still works.
    assert!(Packet::parse(&full).is_ok());
}

#[test]
fn flipping_any_single_byte_never_panics() {
    // Cheap stand-in for a fuzzer: 98 bytes times 8 bit positions. Each
    // result may be Ok or Err, but the parser must not panic and walking the
    // attributes must not panic either.
    let original = hex(ACCESS_REQUEST);

    for index in 0..original.len() {
        for bit in 0..8u32 {
            let mut bytes = original.clone();
            bytes[index] ^= 1 << bit;

            if let Ok(packet) = Packet::parse(&bytes) {
                // Draining the iterator is the part that indexes into the
                // buffer, so it has to run.
                for attribute in packet.attributes().flatten() {
                    let _ = attribute.as_str();
                    let _ = attribute.as_u32();
                    let _ = attribute.as_ipv4();
                    assert!(attribute.wire_len() >= 2);
                }
            }
        }
    }
}

#[test]
fn walks_arbitrary_bytes_without_panicking() {
    // A small xorshift PRNG, so the sweep is deterministic and needs no
    // dev-dependency.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let mut buffer = [0u8; 256];
    for _ in 0..20_000 {
        let len = (next() % 257) as usize;
        for slot in &mut buffer[..len.min(256)] {
            #[allow(clippy::cast_possible_truncation)]
            {
                *slot = next() as u8;
            }
        }
        let input = &buffer[..len.min(256)];

        if let Ok(packet) = Packet::parse(input) {
            assert!(packet.len() >= radius_parse::MIN_PACKET_LEN);
            assert!(packet.len() <= input.len());
            let mut consumed = 0usize;
            for attribute in packet.attributes() {
                match attribute {
                    Ok(attribute) => {
                        consumed += attribute.wire_len();
                        assert!(consumed <= packet.attribute_bytes().len());
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }
}
