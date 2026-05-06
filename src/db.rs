// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Translated from `python-validity/validitysensor/db.py` and
// `fingerprint_constants.py` (MIT, © 2020 uunicorn). See
// `THIRD_PARTY.md`. No biometric data appears in any test in this
// module — see the `feedback_no_finger_data_in_tests` policy.

//! Database (partition 4) record parsers.
//!
//! Three record kinds are observed:
//!
//! | Type tag | Shape          | What it carries                              |
//! |----------|----------------|----------------------------------------------|
//! | `0x0004` | UserStorage    | A named storage container (e.g. `StgWindsor`) plus an index of its users. |
//! | `0x0001` | User           | An identity (Windows SID), plus a fingers index. |
//! | `0x0008` | Data / template | Per-finger biometric template — **opaque** to us. |
//!
//! Only the **enumeration shape** is documented here. The biometric
//! template bytes themselves are never decoded — see the project's
//! "no finger data in tests" policy.

use crate::error::{Error, Result};

/// Status word the device returns from `0x4a` lookups when no record
/// matches the supplied identity/name.
pub const STATUS_NOT_FOUND: u16 = 0x04b3;

/// One entry in a [`UserStorage::users`] index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserIndexEntry {
    pub dbid: u16,
    pub value_size: u16,
}

/// A storage container that groups users together. Windows uses a
/// single hardcoded storage named `"StgWindsor"`.
#[derive(Debug, Clone)]
pub struct UserStorage {
    pub dbid: u16,
    pub name: Vec<u8>,
    pub users: Vec<UserIndexEntry>,
}

/// One enrolled finger within a [`User`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerEntry {
    pub dbid: u16,
    pub subtype: u16,
    pub storage: u16,
    pub value_size: u16,
}

/// A user record. The `identity` field is the Windows SID (or other
/// identity) bytes — opaque to us; we do not parse them further.
#[derive(Debug, Clone)]
pub struct User {
    pub dbid: u16,
    pub identity: Vec<u8>,
    pub fingers: Vec<FingerEntry>,
}

/// Map a finger-subtype byte to its fprintd / ANSI-381 name. Returns
/// `None` for unknown values.
pub fn subtype_name(s: u16) -> Option<&'static str> {
    match s {
        1 => Some("right-thumb"),
        2 => Some("right-index-finger"),
        3 => Some("right-middle-finger"),
        4 => Some("right-ring-finger"),
        5 => Some("right-little-finger"),
        6 => Some("left-thumb"),
        7 => Some("left-index-finger"),
        8 => Some("left-middle-finger"),
        9 => Some("left-ring-finger"),
        10 => Some("left-little-finger"),
        13 => Some("ANSI_381_POS_RH_FOUR_FINGERS"),
        14 => Some("ANSI_381_POS_LH_FOUR_FINGERS"),
        15 => Some("ANSI_381_POS_TWO_THUMBS"),
        0xf5..=0xfe => Some("WINBIO_FINGER_UNSPECIFIED_POS"),
        _ => None,
    }
}

/// Parse a UserStorage reply from cmd `0x4b` (or a recursive `db.user_storage`
/// query). Returns `Ok(None)` when the device replies with the
/// not-found status `0x04b3`. Layout (after status):
/// `<u16 dbid, u16 user_cnt, u16 name_size, u16 unknown,
///  user_cnt × <u16 dbid, u16 value_size>,
///  name_size bytes name>`.
pub fn parse_user_storage(payload: &[u8]) -> Result<Option<UserStorage>> {
    if payload.len() < 8 {
        return Err(Error::ShortResponse);
    }
    let dbid = u16::from_le_bytes(payload[0..2].try_into().unwrap());
    let user_cnt = u16::from_le_bytes(payload[2..4].try_into().unwrap()) as usize;
    let name_size = u16::from_le_bytes(payload[4..6].try_into().unwrap()) as usize;
    let _unknown = u16::from_le_bytes(payload[6..8].try_into().unwrap());

    let need = 8 + user_cnt * 4 + name_size;
    if payload.len() < need {
        return Err(Error::ShortResponse);
    }

    let mut users = Vec::with_capacity(user_cnt);
    for i in 0..user_cnt {
        let off = 8 + i * 4;
        users.push(UserIndexEntry {
            dbid: u16::from_le_bytes(payload[off..off + 2].try_into().unwrap()),
            value_size: u16::from_le_bytes(payload[off + 2..off + 4].try_into().unwrap()),
        });
    }
    let name_off = 8 + user_cnt * 4;
    let name = payload[name_off..name_off + name_size].to_vec();
    Ok(Some(UserStorage { dbid, name, users }))
}

/// Helper to detect the not-found status before splitting a payload.
pub fn user_storage_or_not_found(reply_with_status: &[u8]) -> Result<Option<UserStorage>> {
    if reply_with_status.len() < 2 {
        return Err(Error::ShortResponse);
    }
    let status = u16::from_le_bytes(reply_with_status[0..2].try_into().unwrap());
    if status == STATUS_NOT_FOUND {
        return Ok(None);
    }
    if status != 0 {
        return Err(Error::FlashRead { status });
    }
    parse_user_storage(&reply_with_status[2..])
}

/// Parse a User reply from cmd `0x4a` (or `db.get_user`). Layout
/// (after status): `<u16 dbid, u16 finger_cnt, u16 unknown, u16 identity_size,
///  finger_cnt × <u16 dbid, u16 subtype, u16 storage, u16 value_size>,
///  identity_size bytes identity>`.
///
/// The identity bytes themselves are returned verbatim — callers can
/// decode further (e.g. SID parsing) as needed.
pub fn parse_user(payload: &[u8]) -> Result<User> {
    if payload.len() < 8 {
        return Err(Error::ShortResponse);
    }
    let dbid = u16::from_le_bytes(payload[0..2].try_into().unwrap());
    let finger_cnt = u16::from_le_bytes(payload[2..4].try_into().unwrap()) as usize;
    let _unknown = u16::from_le_bytes(payload[4..6].try_into().unwrap());
    let identity_size = u16::from_le_bytes(payload[6..8].try_into().unwrap()) as usize;

    let need = 8 + finger_cnt * 8 + identity_size;
    if payload.len() < need {
        return Err(Error::ShortResponse);
    }

    let mut fingers = Vec::with_capacity(finger_cnt);
    for i in 0..finger_cnt {
        let off = 8 + i * 8;
        fingers.push(FingerEntry {
            dbid: u16::from_le_bytes(payload[off..off + 2].try_into().unwrap()),
            subtype: u16::from_le_bytes(payload[off + 2..off + 4].try_into().unwrap()),
            storage: u16::from_le_bytes(payload[off + 4..off + 6].try_into().unwrap()),
            value_size: u16::from_le_bytes(payload[off + 6..off + 8].try_into().unwrap()),
        });
    }
    let id_off = 8 + finger_cnt * 8;
    let identity = payload[id_off..id_off + identity_size].to_vec();
    Ok(User { dbid, identity, fingers })
}

/// `parse_identity` — strip the 8-byte identity-type header and return
/// the inner SID bytes. Layout: `<u32 type=3, u32 length, sid_bytes>`.
/// We only handle `type == 3` (Windows SID); other types are reserved
/// in upstream and not seen on the user's device.
pub fn parse_identity(identity: &[u8]) -> Result<&[u8]> {
    if identity.len() < 8 {
        return Err(Error::ShortResponse);
    }
    let typ = u32::from_le_bytes(identity[0..4].try_into().unwrap());
    if typ != 3 {
        return Err(Error::PairingMalformed { reason: "unknown identity type (expected 3)" });
    }
    let len = u32::from_le_bytes(identity[4..8].try_into().unwrap()) as usize;
    if identity.len() < 8 + len {
        return Err(Error::ShortResponse);
    }
    Ok(&identity[8..8 + len])
}

/// Windows SID identity. Wire layout (in `to_bytes`):
///
/// ```text
/// <u8 revision> <u8 subauth_count>
/// <u16 BE auth_high> <u32 BE auth_low>
/// subauth_count × <u32 LE subauth>
/// ```
///
/// Mirrors `python-validity/sid.py:SidIdentity`. Display format is the
/// canonical `S-<rev>-<auth>-<subauth1>-<subauth2>-...` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidIdentity {
    pub revision: u8,
    pub auth: u64,
    pub subauth: Vec<u32>,
}

impl SidIdentity {
    /// Serialise to wire bytes. Total length is `8 + 4 * subauth.len()`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.subauth.len() * 4);
        out.push(self.revision);
        out.push(self.subauth.len() as u8);
        out.extend_from_slice(&((self.auth >> 32) as u16).to_be_bytes());
        out.extend_from_slice(&((self.auth & 0xffff_ffff) as u32).to_be_bytes());
        for s in &self.subauth {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out
    }

    /// Parse wire bytes (the inverse of [`to_bytes`]). Returns
    /// `Err(Error::ShortResponse)` if the buffer is too small for the
    /// declared `subauth_count`.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 8 {
            return Err(Error::ShortResponse);
        }
        let revision = b[0];
        let subcnt = b[1] as usize;
        let auth_high = u16::from_be_bytes([b[2], b[3]]);
        let auth_low = u32::from_be_bytes(b[4..8].try_into().unwrap());
        let auth = (u64::from(auth_high) << 32) | u64::from(auth_low);
        if b.len() < 8 + subcnt * 4 {
            return Err(Error::ShortResponse);
        }
        let mut subauth = Vec::with_capacity(subcnt);
        for i in 0..subcnt {
            let off = 8 + i * 4;
            subauth.push(u32::from_le_bytes(b[off..off + 4].try_into().unwrap()));
        }
        Ok(Self { revision, auth, subauth })
    }
}

impl std::fmt::Display for SidIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.auth)?;
        for s in &self.subauth {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

/// Wrap a SID for transport in a `db.lookup_user` or `db.new_user`
/// request. Layout: `<u32 type=3, u32 inner_len, sid_bytes>` padded
/// with zeros to a minimum of 76 bytes (`0x4c`) — Windows treats SIDs
/// of different sizes as distinct keys, so the pad is significant.
pub fn identity_to_bytes(sid: &SidIdentity) -> Vec<u8> {
    let inner = sid.to_bytes();
    let mut out = Vec::with_capacity(0x4c.max(8 + inner.len()));
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&(inner.len() as u32).to_le_bytes());
    out.extend_from_slice(&inner);
    while out.len() < 0x4c {
        out.push(0);
    }
    out
}

/// Build the cmd `0x4a` "lookup user" request. Wire layout:
/// `<u8 0x4a, u16 dbid=0, u16 storage_dbid, u16 len(identity_bytes),
/// identity_bytes>`. Mirrors `python-validity/db.py:Db.lookup_user`.
/// `dbid=0` means "look up by identity" (the alternative is
/// `<u8 0x4a, u16 dbid, u16 0, u16 0>` which is `get_user`).
///
/// Returns the `User` record on success, or `STATUS_NOT_FOUND`
/// (0x04b3) when no user with that identity exists.
pub fn build_lookup_user(storage_dbid: u16, identity: &SidIdentity) -> Vec<u8> {
    let id_bytes = identity_to_bytes(identity);
    let mut out = Vec::with_capacity(7 + id_bytes.len());
    out.push(0x4a);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&storage_dbid.to_le_bytes());
    out.extend_from_slice(&(id_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&id_bytes);
    out
}

/// Build the cmd `0x46` "get record children" request. Wire layout:
/// `<u8 0x46, u16 dbid>`. Used to enumerate the records under a
/// parent (e.g. all users under StgWindsor). Mirrors
/// `python-validity/db.py:Db.get_record_children`.
pub fn build_get_record_children(dbid: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    out.push(0x46);
    out.extend_from_slice(&dbid.to_le_bytes());
    out
}

/// Build the cmd `0x47` "new record" request. Wire layout:
/// `<u8 0x47, u16 parent, u16 type, u16 storage, u16 len(data), data>`.
/// Mirrors `python-validity/db.py:Db.new_record`. **Destructive** when
/// sent — included here only as a pure builder for tomorrow's tests.
pub fn build_new_record(parent: u16, kind: u16, storage: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + data.len());
    out.push(0x47);
    out.extend_from_slice(&parent.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&storage.to_le_bytes());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// Build the cmd `0x48` "delete record" request. Wire layout:
/// `<u8 0x48, u16 dbid>`. Mirrors `python-validity/db.py:Db.del_record`.
/// **Destructive** when sent.
pub fn build_del_record(dbid: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    out.push(0x48);
    out.extend_from_slice(&dbid.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic UserStorage with one user and the literal name
    /// `b"StgWindsor\0"` (Windows-driver-fixed string, not biometric).
    #[test]
    fn parse_user_storage_synthetic_one_user() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u16.to_le_bytes()); // dbid = 3
        buf.extend_from_slice(&1u16.to_le_bytes()); // user_cnt = 1
        buf.extend_from_slice(&11u16.to_le_bytes()); // name_size = 11
        buf.extend_from_slice(&0u16.to_le_bytes()); // unknown
        buf.extend_from_slice(&5u16.to_le_bytes()); // user[0].dbid
        buf.extend_from_slice(&0x40u16.to_le_bytes()); // user[0].value_size
        buf.extend_from_slice(b"StgWindsor\0");

        let s = parse_user_storage(&buf).unwrap().unwrap();
        assert_eq!(s.dbid, 3);
        assert_eq!(s.users.len(), 1);
        assert_eq!(s.users[0].dbid, 5);
        assert_eq!(s.users[0].value_size, 0x40);
        assert_eq!(s.name, b"StgWindsor\0");
    }

    /// `0x04b3` status from the device must surface as `Ok(None)`.
    #[test]
    fn user_storage_not_found_status() {
        let bytes = [0xb3, 0x04];
        assert!(user_storage_or_not_found(&bytes).unwrap().is_none());
    }

    /// Non-zero, non-not-found status must error out.
    #[test]
    fn user_storage_unexpected_status_errors() {
        let bytes = [0x42, 0x00];
        assert!(matches!(
            user_storage_or_not_found(&bytes),
            Err(Error::FlashRead { status: 0x0042 }),
        ));
    }

    /// Synthetic User with two fingers (right-thumb, left-index) and
    /// a placeholder identity body. Names are decoded via
    /// `subtype_name`.
    #[test]
    fn parse_user_two_fingers() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u16.to_le_bytes()); // dbid
        buf.extend_from_slice(&2u16.to_le_bytes()); // finger_cnt
        buf.extend_from_slice(&0u16.to_le_bytes()); // unknown
        buf.extend_from_slice(&8u16.to_le_bytes()); // identity_size
        // finger[0] — right-thumb (subtype=1)
        buf.extend_from_slice(&100u16.to_le_bytes()); // dbid
        buf.extend_from_slice(&1u16.to_le_bytes()); // subtype
        buf.extend_from_slice(&3u16.to_le_bytes()); // storage
        buf.extend_from_slice(&256u16.to_le_bytes()); // value_size
        // finger[1] — left-index (subtype=7)
        buf.extend_from_slice(&101u16.to_le_bytes());
        buf.extend_from_slice(&7u16.to_le_bytes());
        buf.extend_from_slice(&3u16.to_le_bytes());
        buf.extend_from_slice(&512u16.to_le_bytes());
        // identity (8 bytes, opaque)
        buf.extend_from_slice(&[0x42; 8]);

        let u = parse_user(&buf).unwrap();
        assert_eq!(u.dbid, 5);
        assert_eq!(u.fingers.len(), 2);
        assert_eq!(u.fingers[0].subtype, 1);
        assert_eq!(subtype_name(u.fingers[0].subtype), Some("right-thumb"));
        assert_eq!(u.fingers[1].subtype, 7);
        assert_eq!(subtype_name(u.fingers[1].subtype), Some("left-index-finger"));
        assert_eq!(u.identity, vec![0x42; 8]);
    }

    #[test]
    fn parse_identity_strips_type_3_header() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_le_bytes()); // type = 3 (SID)
        buf.extend_from_slice(&4u32.to_le_bytes()); // length = 4
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let sid = parse_identity(&buf).unwrap();
        assert_eq!(sid, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn parse_identity_rejects_unknown_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&7u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert!(parse_identity(&buf).is_err());
    }

    /// Spot-check a handful of subtype IDs against fprintd's documented
    /// names. Reverse mapping must be consistent for the IDs upstream
    /// recognises.
    #[test]
    fn subtype_name_known_values() {
        assert_eq!(subtype_name(1), Some("right-thumb"));
        assert_eq!(subtype_name(10), Some("left-little-finger"));
        assert_eq!(subtype_name(0xf7), Some("WINBIO_FINGER_UNSPECIFIED_POS"));
        assert_eq!(subtype_name(0x99), None);
    }

    /// Truncated payloads must error rather than panic.
    #[test]
    fn parse_user_short_payload_errors() {
        assert!(matches!(parse_user(&[0u8; 4]), Err(Error::ShortResponse)));
    }

    #[test]
    fn parse_user_storage_short_payload_errors() {
        assert!(matches!(parse_user_storage(&[0u8; 4]), Err(Error::ShortResponse)));
    }

    /// Round-trip a synthetic Windows SID through `to_bytes`/`from_bytes`
    /// and verify the canonical Display form.
    #[test]
    fn sid_identity_round_trip() {
        let sid = SidIdentity {
            revision: 1,
            auth: 5,
            subauth: vec![21, 1234567890, 987654321, 1122334455, 1001],
        };
        let bytes = sid.to_bytes();
        // 8 bytes header + 5 × 4 = 28 bytes
        assert_eq!(bytes.len(), 28);
        // First 8 bytes: rev=1, count=5, auth_high (BE u16) = 0, auth_low (BE u32) = 5
        assert_eq!(&bytes[..8], &[0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]);
        let back = SidIdentity::from_bytes(&bytes).unwrap();
        assert_eq!(back, sid);
        assert_eq!(format!("{sid}"), "S-1-5-21-1234567890-987654321-1122334455-1001");
    }

    #[test]
    fn sid_identity_high_auth() {
        // Auth values can in theory exceed 32 bits — top 16 bits go in
        // the BE u16 slot.
        let sid = SidIdentity { revision: 1, auth: 0x0001_0000_0000, subauth: vec![] };
        let bytes = sid.to_bytes();
        // auth_high = 0x0001, auth_low = 0
        assert_eq!(&bytes[2..8], &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(SidIdentity::from_bytes(&bytes).unwrap(), sid);
    }

    #[test]
    fn sid_identity_short_input_errors() {
        assert!(matches!(SidIdentity::from_bytes(&[0u8; 7]), Err(Error::ShortResponse)));
        // Header says 3 subauth, only one fits.
        let bytes = [0x01, 0x03, 0, 0, 0, 0, 0, 5, 0xAA, 0xBB, 0xCC, 0xDD];
        assert!(matches!(SidIdentity::from_bytes(&bytes), Err(Error::ShortResponse)));
    }

    /// `identity_to_bytes` wraps a SID with the type-3 header and pads
    /// to at least 0x4c (76) bytes total. Pad bytes are zero.
    #[test]
    fn identity_to_bytes_pads_to_minimum() {
        let sid = SidIdentity { revision: 1, auth: 5, subauth: vec![21, 1, 2, 3] };
        let bytes = identity_to_bytes(&sid);
        assert_eq!(bytes.len(), 0x4c);
        // Type = 3, length = 8 + 16 = 24
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 24);
        // Trailing pad must be zero.
        assert!(bytes[8 + 24..].iter().all(|&b| b == 0));
    }

    /// A SID large enough to push the wrapped buffer past 76 bytes
    /// must NOT be truncated — `identity_to_bytes` returns whatever
    /// length is actually needed.
    #[test]
    fn identity_to_bytes_doesnt_truncate_large_sids() {
        let huge_subauth = vec![1u32; 32]; // 8 + 128 = 136 bytes inner
        let sid = SidIdentity { revision: 1, auth: 5, subauth: huge_subauth };
        let bytes = identity_to_bytes(&sid);
        // Header (8) + inner (136) = 144 bytes. No padding above the cap.
        assert_eq!(bytes.len(), 144);
    }

    /// `build_new_record` produces the canonical `<u8, u16×4, data>`
    /// frame for cmd 0x47.
    #[test]
    fn build_new_record_layout() {
        let data = [0xAAu8, 0xBB, 0xCC];
        let f = build_new_record(0x0003, 0x0008, 0x0003, &data);
        assert_eq!(f[0], 0x47);
        assert_eq!(u16::from_le_bytes([f[1], f[2]]), 3);
        assert_eq!(u16::from_le_bytes([f[3], f[4]]), 8);
        assert_eq!(u16::from_le_bytes([f[5], f[6]]), 3);
        assert_eq!(u16::from_le_bytes([f[7], f[8]]), 3);
        assert_eq!(&f[9..], &data[..]);
    }

    /// `build_del_record` produces the canonical `<u8 0x48, u16 dbid>`
    /// frame.
    #[test]
    fn build_del_record_layout() {
        assert_eq!(build_del_record(0x0042), vec![0x48, 0x42, 0x00]);
        assert_eq!(build_del_record(0xdead), vec![0x48, 0xad, 0xde]);
    }

    /// `build_lookup_user` produces a cmd 0x4a frame with `dbid=0`,
    /// the storage dbid, the identity length, and the SID body
    /// (padded to 0x4c by `identity_to_bytes`).
    #[test]
    fn build_lookup_user_layout() {
        let sid = SidIdentity { revision: 1, auth: 5, subauth: vec![18] };
        let f = build_lookup_user(/* StgWindsor */ 3, &sid);
        assert_eq!(f[0], 0x4a);
        assert_eq!(u16::from_le_bytes([f[1], f[2]]), 0, "dbid=0 means lookup by identity");
        assert_eq!(u16::from_le_bytes([f[3], f[4]]), 3, "storage dbid");
        let id_len = u16::from_le_bytes([f[5], f[6]]) as usize;
        assert_eq!(id_len, 0x4c, "identity is padded to 76 bytes");
        assert_eq!(f.len(), 7 + 0x4c);
    }

    #[test]
    fn build_get_record_children_layout() {
        assert_eq!(build_get_record_children(3), vec![0x46, 0x03, 0x00]);
    }

    /// Canonical SID-string formatting matches the Microsoft format
    /// `S-<rev>-<auth>-<subauth1>-<subauth2>-…`. Lock the wire form so
    /// downstream consumers can `parse()` the output unambiguously.
    #[test]
    fn sid_identity_display_canonical_format() {
        // Well-known "Local System" SID: S-1-5-18.
        let sys = SidIdentity { revision: 1, auth: 5, subauth: vec![18] };
        assert_eq!(sys.to_string(), "S-1-5-18");

        // BUILTIN\Administrators: S-1-5-32-544.
        let admins = SidIdentity { revision: 1, auth: 5, subauth: vec![32, 544] };
        assert_eq!(admins.to_string(), "S-1-5-32-544");

        // No subauth → just the prefix (still legal per the spec).
        let bare = SidIdentity { revision: 1, auth: 5, subauth: vec![] };
        assert_eq!(bare.to_string(), "S-1-5");
    }

    /// `SidIdentity` Display + `to_bytes` agree on byte counts:
    /// 8-byte header + 4 bytes per subauth.
    #[test]
    fn sid_identity_to_bytes_length_invariant() {
        for n in [0usize, 1, 4, 7, 15] {
            let sid = SidIdentity {
                revision: 1,
                auth: 5,
                subauth: (0..n as u32).collect(),
            };
            assert_eq!(sid.to_bytes().len(), 8 + n * 4);
        }
    }

    /// Closing the loop: encode → wrap → strip → decode round trip.
    #[test]
    fn sid_identity_full_pipeline_round_trip() {
        let sid = SidIdentity {
            revision: 1,
            auth: 5,
            subauth: vec![21, 0x1111_2222, 0x3333_4444, 0x5555_6666, 1001],
        };
        let wrapped = identity_to_bytes(&sid);
        let inner = parse_identity(&wrapped).unwrap();
        // The inner slice is exactly the SID bytes (without the pad).
        let back = SidIdentity::from_bytes(inner).unwrap();
        assert_eq!(back, sid);
    }
}
