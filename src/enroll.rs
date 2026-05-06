// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Translated from `python-validity/validitysensor/sensor.py`'s enrol
// helpers (MIT, © 2020 uunicorn). See `THIRD_PARTY.md`. **No
// fingerprint template bytes appear in tests** (synthetic placeholder
// payloads only) — see `feedback_no_finger_data_in_tests`.

//! Enrollment-flow building blocks.
//!
//! The on-device enroll flow is a multi-step interactive cycle:
//!
//! 1. `create_enrollment()` — cmd `0x69 01 00 00 00`.
//! 2. Loop until enrol complete:
//!    - `glow_start_scan` then `capture(ENROLL)` (cmd `0x02` w/ ENROLL).
//!    - `enrollment_update_start(key)` — cmd `0x68 <u32 key> <u32 0>`.
//!    - `append_new_image(prev_template)` — cmd `0x6b <prev>` twice
//!      (with an interrupt between), parses TLV chunks out of the
//!      second response.
//! 3. `make_finger_data(subtype, final_template, tid)` — packs the
//!    finger record body for `db.new_finger`.
//! 4. `enrollment_update_end()` — cmd `0x69 00 00 00 00`.
//!
//! Functions in this module deal only with the **framing** layer —
//! the byte layout of requests and the wrapper around the final
//! template. The biometric payloads (`template`, `tid`) are passed
//! through verbatim and never inspected.

use crate::error::{Error, Result};

/// Build the cmd `0x69 <u32 mode>` create-or-end enrollment frame.
/// `mode = 1` → create; `mode = 0` → end.
pub fn build_enrollment_mode(mode: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(0x69);
    out.extend_from_slice(&mode.to_le_bytes());
    out
}

/// Build the cmd `0x68 <u32 key> <u32 0>` enrollment-update-start frame.
pub fn build_enrollment_update_start(key: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(0x68);
    out.extend_from_slice(&key.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}

/// Build the cmd `0x6b <previous_template>` enrollment-update frame.
/// The first call passes an empty `prev`; subsequent calls pass the
/// device's last template output back.
pub fn build_enrollment_update(prev: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + prev.len());
    out.push(0x6b);
    out.extend_from_slice(prev);
    out
}

/// Pack a finished finger record for storage in the template database.
/// Mirrors `sensor.py:make_finger_data`. The wire layout produced is:
///
/// ```text
/// <u16 subtype, u16 3, u16 len(tinfo), u16 0x20>
/// <u16 1, u16 len(template), template_bytes>
/// <u16 2, u16 len(tid), tid_bytes>
/// 32 zero bytes (trailing pad)
/// ```
///
/// `template` and `tid` are biometric payloads — opaque to us.
pub fn make_finger_data(subtype: u16, template: &[u8], tid: &[u8]) -> Vec<u8> {
    fn tlv(out: &mut Vec<u8>, tag: u16, body: &[u8]) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        out.extend_from_slice(body);
    }

    let mut tinfo = Vec::with_capacity(8 + template.len() + tid.len());
    tlv(&mut tinfo, 1, template);
    tlv(&mut tinfo, 2, tid);

    let mut out = Vec::with_capacity(8 + tinfo.len() + 0x20);
    out.extend_from_slice(&subtype.to_le_bytes());
    out.extend_from_slice(&3u16.to_le_bytes());
    out.extend_from_slice(&(tinfo.len() as u16).to_le_bytes());
    out.extend_from_slice(&0x20u16.to_le_bytes());
    out.extend_from_slice(&tinfo);
    out.extend_from_slice(&[0u8; 0x20]);
    out
}

/// One TLV chunk parsed out of an `append_new_image` response.
/// See `sensor.py:append_new_image` lines 766-795 for the upstream
/// pattern. Each chunk's *wire* size is `magic_len (= 0x38) + body_len`,
/// where the first 4 bytes are `<u16 tag, u16 body_len>` and the
/// remaining 52 bytes carry implementation-specific magic.
///
/// **Note** — this parser is intentionally permissive: it handles the
/// observed tags 0/1/3 and ignores anything else. Concrete byte
/// interpretation requires real on-device captures (tomorrow's work).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollChunk {
    pub tag: u16,
    /// The body bytes — slice of the input at offset `magic_len..magic_len+body_len`.
    pub body: Vec<u8>,
    /// The chunk's full wire bytes (`magic_len + body_len` total).
    pub raw: Vec<u8>,
}

/// `append_new_image` magic header length, as documented in
/// `sensor.py:778`. The 4-byte TLV header sits inside this region.
pub const ENROLL_MAGIC_LEN: usize = 0x38;

/// Walk an `append_new_image` reply payload (status word already
/// stripped, leading u16 length already consumed) into a list of TLV
/// chunks.
pub fn parse_append_image(payload: &[u8]) -> Result<Vec<EnrollChunk>> {
    let mut out = Vec::new();
    let mut p = payload;
    while !p.is_empty() {
        if p.len() < 4 {
            return Err(Error::ShortResponse);
        }
        let tag = u16::from_le_bytes([p[0], p[1]]);
        let body_len = u16::from_le_bytes([p[2], p[3]]) as usize;
        let chunk_size = ENROLL_MAGIC_LEN + body_len;
        if p.len() < chunk_size {
            return Err(Error::ShortResponse);
        }
        let body_start = ENROLL_MAGIC_LEN;
        let body = p[body_start..body_start + body_len].to_vec();
        let raw = p[..chunk_size].to_vec();
        out.push(EnrollChunk { tag, body, raw });
        p = &p[chunk_size..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_end_enrollment_frames() {
        assert_eq!(build_enrollment_mode(1), vec![0x69, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(build_enrollment_mode(0), vec![0x69, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn update_start_frame_layout() {
        let f = build_enrollment_update_start(0xdeadbeef);
        assert_eq!(f.len(), 9);
        assert_eq!(f[0], 0x68);
        assert_eq!(&f[1..5], &[0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(&f[5..9], &[0u8; 4]);
    }

    #[test]
    fn update_frame_concats_prev_template() {
        let prev = [0xAAu8; 12];
        let f = build_enrollment_update(&prev);
        assert_eq!(f.len(), 13);
        assert_eq!(f[0], 0x6b);
        assert_eq!(&f[1..], &prev[..]);
    }

    /// `make_finger_data` produces a record with a 16-byte outer
    /// header, two TLV chunks, and a 32-byte zero pad. Synthetic
    /// payloads only — these are NOT real biometric bytes.
    #[test]
    fn make_finger_data_layout() {
        // Use distinct synthetic markers so we can grep the output.
        let template = vec![0x11u8; 5];
        let tid = vec![0x22u8; 3];
        let finger = make_finger_data(/* subtype = right-thumb */ 1, &template, &tid);

        // Outer header (8 bytes)
        assert_eq!(u16::from_le_bytes([finger[0], finger[1]]), 1);
        assert_eq!(u16::from_le_bytes([finger[2], finger[3]]), 3);
        // Inner tinfo length: 4 + 5 + 4 + 3 = 16
        assert_eq!(u16::from_le_bytes([finger[4], finger[5]]), 16);
        assert_eq!(u16::from_le_bytes([finger[6], finger[7]]), 0x20);

        // Inner chunk 1 (template)
        assert_eq!(u16::from_le_bytes([finger[8], finger[9]]), 1);
        assert_eq!(u16::from_le_bytes([finger[10], finger[11]]), 5);
        assert_eq!(&finger[12..17], &template[..]);

        // Inner chunk 2 (tid)
        assert_eq!(u16::from_le_bytes([finger[17], finger[18]]), 2);
        assert_eq!(u16::from_le_bytes([finger[19], finger[20]]), 3);
        assert_eq!(&finger[21..24], &tid[..]);

        // Trailing 32-byte zero pad.
        assert_eq!(&finger[24..56], &[0u8; 32]);
        assert_eq!(finger.len(), 56);
    }

    #[test]
    fn make_finger_data_subtype_propagates() {
        for subtype in [1u16, 7, 10, 0xff, 0xdead] {
            let f = make_finger_data(subtype, b"x", b"y");
            assert_eq!(u16::from_le_bytes([f[0], f[1]]), subtype);
        }
    }

    /// Build a synthetic `append_new_image` reply payload with three
    /// chunks (tags 0, 1, 3) and verify the parser walks them.
    #[test]
    fn parse_append_image_three_chunks() {
        let mk_chunk = |tag: u16, body: &[u8]| -> Vec<u8> {
            let mut chunk = Vec::with_capacity(ENROLL_MAGIC_LEN + body.len());
            chunk.extend_from_slice(&tag.to_le_bytes());
            chunk.extend_from_slice(&(body.len() as u16).to_le_bytes());
            // 52 bytes of magic filler — non-zero so we can spot-check.
            chunk.extend(std::iter::repeat_n(0x55u8, ENROLL_MAGIC_LEN - 4));
            chunk.extend_from_slice(body);
            chunk
        };

        let mut payload = Vec::new();
        payload.extend_from_slice(&mk_chunk(0, &[0xAA; 4]));
        payload.extend_from_slice(&mk_chunk(1, &[0xBB; 8]));
        payload.extend_from_slice(&mk_chunk(3, &[0xCC; 16]));

        let chunks = parse_append_image(&payload).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].tag, 0);
        assert_eq!(chunks[0].body, vec![0xAA; 4]);
        assert_eq!(chunks[1].tag, 1);
        assert_eq!(chunks[1].body, vec![0xBB; 8]);
        assert_eq!(chunks[2].tag, 3);
        assert_eq!(chunks[2].body, vec![0xCC; 16]);
    }

    #[test]
    fn parse_append_image_truncated_errors() {
        // Missing body bytes after the 4-byte header.
        let truncated = [0x00, 0x00, 0x10, 0x00]; // tag=0, body_len=16, but no body
        assert!(parse_append_image(&truncated).is_err());
    }

    #[test]
    fn parse_append_image_empty_input() {
        assert_eq!(parse_append_image(&[]).unwrap().len(), 0);
    }
}
