// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Translated from `python-validity/validitysensor/timeslot.py`'s
// `split_chunks` / `merge_chunks` (MIT, © 2020 uunicorn).
// See `THIRD_PARTY.md`.

//! Tiny TLV codec used by the capture-program format.
//!
//! Every chunk on the wire is `<u16 LE type, u16 LE size, body[size]>`.
//! The capture command (`0x02`) carries a stream of these chunks; the
//! enrol/identify path mutates some chunks before the stream is
//! re-merged and sent. We only handle framing here — interpreting
//! individual chunk types is the next layer up.

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub kind: u16,
    pub body: Vec<u8>,
}

impl Chunk {
    pub fn new(kind: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            body: body.into(),
        }
    }
}

/// Iterate the chunks in `buf`. Errors on truncation; never panics.
pub fn split(buf: &[u8]) -> Result<Vec<Chunk>> {
    let mut out = Vec::new();
    let mut p = buf;
    while !p.is_empty() {
        if p.len() < 4 {
            return Err(Error::ShortResponse);
        }
        let kind = u16::from_le_bytes([p[0], p[1]]);
        let size = u16::from_le_bytes([p[2], p[3]]) as usize;
        if p.len() < 4 + size {
            return Err(Error::ShortResponse);
        }
        out.push(Chunk {
            kind,
            body: p[4..4 + size].to_vec(),
        });
        p = &p[4 + size..];
    }
    Ok(out)
}

/// Concatenate all chunks back into the wire format.
pub fn merge(chunks: &[Chunk]) -> Vec<u8> {
    let total = chunks.iter().map(|c| 4 + c.body.len()).sum();
    let mut out = Vec::with_capacity(total);
    for c in chunks {
        out.extend_from_slice(&c.kind.to_le_bytes());
        out.extend_from_slice(&(c.body.len() as u16).to_le_bytes());
        out.extend_from_slice(&c.body);
    }
    out
}

/// Replace the body of the first chunk whose `kind` matches; appends
/// a new chunk if none matched.
pub fn upsert(chunks: &mut Vec<Chunk>, kind: u16, body: impl Into<Vec<u8>>) -> &mut Chunk {
    if let Some(i) = chunks.iter().position(|c| c.kind == kind) {
        chunks[i].body = body.into();
        &mut chunks[i]
    } else {
        chunks.push(Chunk {
            kind,
            body: body.into(),
        });
        chunks.last_mut().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_three_chunks() {
        let cs = vec![
            Chunk::new(0x0020, vec![0xAA; 8]),
            Chunk::new(0x0032, vec![0xBB; 1]),
            Chunk::new(0x00ff, vec![]),
        ];
        let merged = merge(&cs);
        let back = split(&merged).unwrap();
        assert_eq!(back, cs);
    }

    /// Layout: `<u16 type=0x20> <u16 size=8> <payload>`.
    #[test]
    fn split_decodes_addr_value_chunk() {
        // Real example from upstream `timeslot.py:dump_all`:
        // type 0x20 = "Set Register 32" carries 8 bytes (addr + value).
        let bytes = [
            0x20, 0x00, 0x08, 0x00, 0x10, 0x32, 0x80, 0x00, 0xde, 0xad, 0xbe, 0xef,
        ];
        let cs = split(&bytes).unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].kind, 0x0020);
        assert_eq!(cs[0].body, [0x10, 0x32, 0x80, 0x00, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn split_rejects_truncated_header() {
        assert!(split(&[0x20]).is_err());
        assert!(split(&[0x20, 0x00, 0x01]).is_err());
    }

    #[test]
    fn split_rejects_truncated_body() {
        // size says 4 but only 2 bytes follow.
        assert!(split(&[0x20, 0x00, 0x04, 0x00, 0xAB, 0xCD]).is_err());
    }

    #[test]
    fn upsert_replaces_existing_kind() {
        let mut cs = vec![
            Chunk::new(0x0020, vec![1, 2, 3]),
            Chunk::new(0x0032, vec![9, 9]),
        ];
        upsert(&mut cs, 0x0020, vec![0xff]);
        assert_eq!(cs.len(), 2, "no new chunk should be appended");
        assert_eq!(cs[0].body, vec![0xff]);
    }

    #[test]
    fn upsert_appends_when_absent() {
        let mut cs = vec![Chunk::new(0x0020, vec![1])];
        upsert(&mut cs, 0x0042, vec![7, 7, 7]);
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[1].kind, 0x0042);
        assert_eq!(cs[1].body, vec![7, 7, 7]);
    }

    /// Empty input is a valid empty chunk list — not an error.
    /// (Real captures occasionally pass through zero-length sub-streams.)
    #[test]
    fn split_empty_input_is_empty_list() {
        assert!(split(&[]).unwrap().is_empty());
    }

    #[test]
    fn merge_empty_list_is_empty_buf() {
        assert!(merge(&[]).is_empty());
    }

    /// Zero-length body is legal — the chunk header stands alone with
    /// `size = 0`. Round-trip preserves it.
    #[test]
    fn round_trip_chunk_with_empty_body() {
        let cs = vec![Chunk::new(0x00ff, vec![])];
        let back = split(&merge(&cs)).unwrap();
        assert_eq!(back, cs);
        // Wire form is exactly 4 bytes.
        assert_eq!(merge(&cs).len(), 4);
    }

    /// `upsert` only mutates the first matching chunk; later duplicates
    /// stay untouched. We don't dedup — that's the caller's job.
    #[test]
    fn upsert_only_replaces_first_match() {
        let mut cs = vec![Chunk::new(0x0020, vec![1]), Chunk::new(0x0020, vec![2])];
        upsert(&mut cs, 0x0020, vec![0xff]);
        assert_eq!(cs[0].body, vec![0xff]);
        assert_eq!(cs[1].body, vec![2], "second 0x0020 chunk preserved");
    }
}
