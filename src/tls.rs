// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Wire format reproduced from `python-validity/validitysensor/tls.py`
// (MIT, © 2020 uunicorn). No source code is copied — only the byte
// layout and protocol constants. See `THIRD_PARTY.md`.

//! TLS-PSK record / handshake framing for the Validity protocol.
//!
//! The sensor speaks a TLS-1.0-shaped wire format with custom MAC and
//! a non-standard PRF. This module covers the cleartext side of the
//! handshake — building Client Hello and parsing Server Hello et al. —
//! and stops short of any crypto that depends on the per-device
//! pairing record.
//!
//! A complete TLS message lives inside a USB command:
//!
//! ```text
//! 44 00 00 00                       USB command "send TLS data"
//! 16 03 03 <u16 BE len>             TLS record header (handshake, TLSv1.2)
//!   <u8 hs_type> <u24 BE hs_len>      handshake header
//!   <handshake body>                  e.g. Client Hello fields
//! ```

use std::fs::File;
use std::io::Read;

use crate::error::{Error, Result};

/// USB command byte that wraps a TLS record stream.
pub const CMD_TLS_DATA: u8 = 0x44;

/// TLS record content types we care about.
pub const RECORD_HANDSHAKE: u8 = 0x16;
pub const RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const RECORD_APPLICATION_DATA: u8 = 0x17;
pub const RECORD_ALERT: u8 = 0x15;

/// Handshake message types (RFC 5246 §7.4).
pub const HS_CLIENT_HELLO: u8 = 0x01;
pub const HS_SERVER_HELLO: u8 = 0x02;
pub const HS_CERTIFICATE: u8 = 0x0b;
pub const HS_SERVER_KEY_EXCHANGE: u8 = 0x0c;
pub const HS_CERTIFICATE_REQUEST: u8 = 0x0d;
pub const HS_SERVER_HELLO_DONE: u8 = 0x0e;
pub const HS_CERTIFICATE_VERIFY: u8 = 0x0f;
pub const HS_CLIENT_KEY_EXCHANGE: u8 = 0x10;
pub const HS_FINISHED: u8 = 0x14;

/// The single cipher suite the device actually accepts.
pub const SUITE_ECDH_ECDSA_AES256_CBC_SHA: u16 = 0xc005;

/// Random bytes used as the TLS `client_random`. Generated from
/// `/dev/urandom`; a deterministic value can be plugged in for tests.
#[derive(Debug, Clone, Copy)]
pub struct ClientRandom(pub [u8; 32]);

impl ClientRandom {
    pub fn from_urandom() -> Result<Self> {
        let mut buf = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

/// Append a 1/2/3-byte big-endian length prefix in front of `body` and
/// return the combined buffer. Equivalent to python-validity's
/// `with_1byte_size` / `with_2bytes_size` / `with_3bytes_size`.
pub fn with_u8_size(body: &[u8]) -> Vec<u8> {
    debug_assert!(body.len() <= u8::MAX as usize);
    let mut out = Vec::with_capacity(1 + body.len());
    out.push(body.len() as u8);
    out.extend_from_slice(body);
    out
}

pub fn with_u16_size(body: &[u8]) -> Vec<u8> {
    debug_assert!(body.len() <= u16::MAX as usize);
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn with_u24_size(body: &[u8]) -> Vec<u8> {
    debug_assert!(body.len() < (1 << 24));
    let n = body.len() as u32;
    let mut out = Vec::with_capacity(3 + body.len());
    out.push((n >> 16) as u8);
    out.push((n >> 8) as u8);
    out.push(n as u8);
    out.extend_from_slice(body);
    out
}

/// Build a Client Hello body (without the outer handshake header).
///
/// The byte layout matches `python-validity/tls.py:make_client_hello`,
/// including its known oddity: the `extensions` length is encoded as
/// `len(exts) - 2`, not `len(exts)`. We faithfully reproduce that
/// because the device parser was written against it.
pub fn build_client_hello(client_random: &ClientRandom) -> Vec<u8> {
    let mut h = Vec::with_capacity(96);
    h.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 wire version
    h.extend_from_slice(&client_random.0);

    // Session ID — upstream sends a fixed 7-byte zero blob.
    h.extend_from_slice(&with_u8_size(&[0u8; 7]));

    // Cipher suites: only ECDH-ECDSA AES-256-CBC-SHA is honoured by the
    // device; the other two are present for upstream parity.
    let mut suites = Vec::with_capacity(6);
    suites.extend_from_slice(&SUITE_ECDH_ECDSA_AES256_CBC_SHA.to_be_bytes());
    suites.extend_from_slice(&0x003d_u16.to_be_bytes()); // TLS_RSA_WITH_AES_256_CBC_SHA256
    suites.extend_from_slice(&0x008d_u16.to_be_bytes()); // TLS_RSA_WITH_AES_256_CBC_SHA256
    h.extend_from_slice(&with_u16_size(&suites));

    // Compression methods: empty list.
    h.extend_from_slice(&with_u8_size(&[]));

    // Extensions:
    //   - truncated_hmac (id=0x04, body = 0x0017 = SHA-256 truncated MAC)
    //   - ec_point_formats (id=0x0b, body = 0x00 uncompressed)
    let mut exts = Vec::new();
    exts.extend_from_slice(&make_ext(0x0004, &[0x00, 0x17]));
    exts.extend_from_slice(&make_ext(0x000b, &with_u8_size(&[0x00])));

    // Bug-for-bug parity with upstream: length is `len(exts) - 2`.
    let bogus_len = (exts.len() as u16).wrapping_sub(2);
    h.extend_from_slice(&bogus_len.to_be_bytes());
    h.extend_from_slice(&exts);

    h
}

fn make_ext(id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&with_u16_size(body));
    out
}

/// Wrap a handshake body in its 4-byte handshake header (`type || u24 len`).
pub fn make_handshake_message(hs_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(hs_type);
    out.extend_from_slice(&with_u24_size(body));
    out
}

/// Wrap raw record content in a TLS record header (cleartext path).
/// `0x16 0x03 0x03 <u16 BE len> <body>`.
pub fn make_record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(content_type);
    out.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 record version
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Wrap one or more records in the USB `0x44` command framing.
pub fn make_usb_tls_packet(records: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + records.len());
    out.extend_from_slice(&[CMD_TLS_DATA, 0x00, 0x00, 0x00]);
    out.extend_from_slice(records);
    out
}

/// One parsed TLS record. The `body` slice is borrowed from the
/// caller's buffer.
#[derive(Debug)]
pub struct Record<'a> {
    pub content_type: u8,
    pub version_major: u8,
    pub version_minor: u8,
    pub body: &'a [u8],
}

/// Iterate over the TLS records concatenated in `buf`. Errors out on
/// truncation; never panics on malformed input.
pub fn split_records(buf: &[u8]) -> Result<Vec<Record<'_>>> {
    let mut out = Vec::new();
    let mut p = buf;
    while !p.is_empty() {
        if p.len() < 5 {
            return Err(Error::ShortResponse);
        }
        let len = u16::from_be_bytes([p[3], p[4]]) as usize;
        if p.len() < 5 + len {
            return Err(Error::ShortResponse);
        }
        out.push(Record {
            content_type: p[0],
            version_major: p[1],
            version_minor: p[2],
            body: &p[5..5 + len],
        });
        p = &p[5 + len..];
    }
    Ok(out)
}

/// One parsed handshake message (cleartext path). The `body` slice is
/// borrowed from the caller's buffer.
#[derive(Debug)]
pub struct HandshakeMessage<'a> {
    pub hs_type: u8,
    pub body: &'a [u8],
}

/// Walk the handshake messages concatenated inside one record's body.
pub fn split_handshakes(buf: &[u8]) -> Result<Vec<HandshakeMessage<'_>>> {
    let mut out = Vec::new();
    let mut p = buf;
    while !p.is_empty() {
        if p.len() < 4 {
            return Err(Error::ShortResponse);
        }
        let len = ((p[1] as usize) << 16) | ((p[2] as usize) << 8) | (p[3] as usize);
        if p.len() < 4 + len {
            return Err(Error::ShortResponse);
        }
        out.push(HandshakeMessage {
            hs_type: p[0],
            body: &p[4..4 + len],
        });
        p = &p[4 + len..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_prefixes() {
        assert_eq!(with_u8_size(b"abc"), b"\x03abc");
        assert_eq!(with_u16_size(b"abcd"), b"\x00\x04abcd");
        assert_eq!(with_u24_size(b"xy"), b"\x00\x00\x02xy");
    }

    #[test]
    fn client_hello_layout_with_fixed_random() {
        let cr = ClientRandom([0xAA; 32]);
        let ch = build_client_hello(&cr);
        // version
        assert_eq!(&ch[0..2], &[0x03, 0x03]);
        // random
        assert_eq!(&ch[2..34], &[0xAA; 32]);
        // session ID: 1 length byte + 7 zero bytes
        assert_eq!(ch[34], 0x07);
        assert_eq!(&ch[35..42], &[0u8; 7]);
        // cipher suites: u16 length=6, then ECDH-ECDSA-AES256-CBC-SHA first
        assert_eq!(&ch[42..44], &[0x00, 0x06]);
        assert_eq!(&ch[44..46], &[0xc0, 0x05]);
    }

    #[test]
    fn record_roundtrip() {
        let rec = make_record(RECORD_HANDSHAKE, b"hello");
        let parsed = split_records(&rec).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].content_type, RECORD_HANDSHAKE);
        assert_eq!(parsed[0].body, b"hello");
    }

    #[test]
    fn handshake_message_roundtrip() {
        let msg = make_handshake_message(HS_CLIENT_HELLO, b"abc");
        // 1 type byte + 3 length bytes + body
        assert_eq!(
            msg,
            vec![HS_CLIENT_HELLO, 0x00, 0x00, 0x03, b'a', b'b', b'c']
        );
        let parsed = split_handshakes(&msg).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].hs_type, HS_CLIENT_HELLO);
        assert_eq!(parsed[0].body, b"abc");
    }

    /// Real Server Hello reply from the user's P70 to a Client Hello.
    /// Captured 2026-05-05. server_random rotates per handshake but the
    /// message *layout* is invariant — that's what we lock in here.
    const REAL_SERVER_HELLO_REPLY: &[u8] = &[
        // TLS record header — handshake, TLS 1.2, 61-byte body
        0x16, 0x03, 0x03, 0x00, 0x3d,
        // ServerHello message header — type 0x02, 45-byte body
        0x02, 0x00, 0x00, 0x2d, // ServerHello body
        0x03, 0x03, // version 3.3
        // server_random (32 B)
        0x0e, 0xec, 0xf2, 0x3d, 0x11, 0x8d, 0xcf, 0xea, 0xf0, 0x4e, 0x20, 0xee, 0xf7, 0xc3, 0x2f,
        0x0f, 0x41, 0x0a, 0x20, 0xae, 0x44, 0xf1, 0xa5, 0xfa, 0x1e, 0x1f, 0x96, 0x25, 0xb3, 0x6a,
        0xe1, 0xc1,
        // session_id length = 7, then ASCII "TLS" + first 4 of server_random
        0x07, 0x54, 0x4c, 0x53, 0x11, 0x8d, 0xcf, 0xea,
        // cipher suite TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, no compression
        0xc0, 0x05, 0x00, // CertificateRequest — type 0x0d, 4-byte body
        0x0d, 0x00, 0x00, 0x04, 0x01, 0x40, 0x00, 0x00,
        // ServerHelloDone — type 0x0e, empty body
        0x0e, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn split_records_real_server_hello() {
        let records = split_records(REAL_SERVER_HELLO_REPLY).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, RECORD_HANDSHAKE);
        assert_eq!(records[0].version_major, 3);
        assert_eq!(records[0].version_minor, 3);
        assert_eq!(records[0].body.len(), 61);
    }

    #[test]
    fn split_handshakes_real_server_hello() {
        let records = split_records(REAL_SERVER_HELLO_REPLY).unwrap();
        let hs = split_handshakes(records[0].body).unwrap();
        assert_eq!(hs.len(), 3);
        assert_eq!(hs[0].hs_type, HS_SERVER_HELLO);
        assert_eq!(hs[0].body.len(), 45);
        assert_eq!(hs[1].hs_type, HS_CERTIFICATE_REQUEST);
        assert_eq!(hs[1].body, &[0x01, 0x40, 0x00, 0x00]);
        assert_eq!(hs[2].hs_type, HS_SERVER_HELLO_DONE);
        assert!(hs[2].body.is_empty());
    }

    #[test]
    fn server_hello_uses_advertised_suite() {
        let records = split_records(REAL_SERVER_HELLO_REPLY).unwrap();
        let body = split_handshakes(records[0].body).unwrap()[0].body;
        // session_id length is at offset 34, suite at offset 35 + sid_len.
        let sid_len = body[34] as usize;
        let suite_off = 35 + sid_len;
        let suite = u16::from_be_bytes([body[suite_off], body[suite_off + 1]]);
        assert_eq!(suite, SUITE_ECDH_ECDSA_AES256_CBC_SHA);
        assert_eq!(body[suite_off + 2], 0, "compression must be 0");
    }

    #[test]
    fn split_records_rejects_truncation() {
        // claim 100-byte body, only provide 5 bytes after header
        let truncated = &[0x16, 0x03, 0x03, 0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(split_records(truncated).is_err());
    }

    #[test]
    fn client_hello_extensions_quirk_is_preserved() {
        // The `len(exts) - 2` quirk lives at a fixed offset in the body.
        // Compute exts length the same way upstream/our code does and
        // confirm it appears literally in the bytes — protects against a
        // future "fix" that would silently break the device's parser.
        let cr = ClientRandom([0u8; 32]);
        let ch = build_client_hello(&cr);
        // Skip: version(2) + random(32) + sid_len(1) + sid(7) + suites_len(2) +
        // suites(6) + comp_len(1) + comp(0) = 51 bytes.
        let exts_len_offset = 51;
        let claimed_len =
            u16::from_be_bytes([ch[exts_len_offset], ch[exts_len_offset + 1]]) as usize;
        let actual_remaining = ch.len() - exts_len_offset - 2;
        assert_eq!(
            claimed_len + 2,
            actual_remaining,
            "extensions length is intentionally `len(exts) - 2`",
        );
    }

    #[test]
    fn make_record_byte_layout() {
        let r = make_record(RECORD_HANDSHAKE, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(r, vec![0x16, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn make_usb_tls_packet_prepends_44_00_00_00() {
        let inner = vec![0x16, 0x03, 0x03, 0x00, 0x00];
        let pkt = make_usb_tls_packet(&inner);
        assert_eq!(&pkt[..4], &[CMD_TLS_DATA, 0x00, 0x00, 0x00]);
        assert_eq!(&pkt[4..], &inner[..]);
    }
}
