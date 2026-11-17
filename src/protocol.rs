// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// The protocol facts encoded in this module (bulk endpoint addresses
// 0x01 / 0x81 / 0x82, the "first cleartext command 0x01 = RomInfo /
// GetVersion" entry point, and the layout `<u16 status><payload>`) are
// derived from public reverse-engineering work, primarily:

// Inline tests sit mid-file because related public items (query_partition,
// impl RomInfo) define methods the tests exercise. The order is harmless
// — Rust resolves identifiers regardless of position — and keeping it
// this way avoids a 200-line cut-and-paste of public code.
#![allow(clippy::items_after_test_module)]

//
//   * uunicorn/python-validity (MIT)        https://github.com/uunicorn/python-validity
//   * nmikhailov/Validity90 specifications  https://github.com/nmikhailov/Validity90
//
// No source code is copied. See `THIRD_PARTY.md` for full attribution.

//! Cleartext command/response transport for the Validity protocol.
//!
//! The sensor exposes a single USB interface (number 0) with three bulk
//! endpoints relevant to the host:
//!
//! | Endpoint | Direction | Purpose                          |
//! |----------|-----------|----------------------------------|
//! | `0x01`   | OUT       | Host → device commands           |
//! | `0x81`   | IN        | Device → host command responses  |
//! | `0x82`   | IN        | Asynchronous events (not used)   |
//!
//! Before pairing/TLS, the device responds to a small set of cleartext
//! commands. We only use one here — `0x01` — which returns ROM/firmware
//! identification. Every response is framed as a little-endian status
//! word followed by an opaque payload; status `0x0000` means OK.

use std::io::{Read, Write};

use nusb::MaybeFuture;
use nusb::transfer::{Bulk, In, Interrupt, Out};

use crate::error::{Error, Result};
use crate::usb::Sensor;

pub const INTERFACE: u8 = 0;
pub const EP_BULK_OUT: u8 = 0x01;
pub const EP_BULK_IN: u8 = 0x81;
pub const EP_ASYNC_IN: u8 = 0x82;
pub const EP_INT_IN: u8 = 0x83;

pub const CMD_GET_VERSION: u8 = 0x01;
pub const CMD_PROBE_19: u8 = 0x19;
pub const CMD_GET_PARTITION: u8 = 0x43;
pub const FWEXT_PARTITION: u8 = 0x02;

/// Status value returned by [`CMD_GET_PARTITION`] when no firmware-extension
/// is loaded ("clean slate"). Wire bytes are `b0 04` (little-endian u16).
pub const STATUS_NO_FW: u16 = 0x04b0;

/// `db.lookup_user` and `db.get_user_storage` return this when the
/// requested record doesn't exist. Wire bytes `b3 04`.
pub const STATUS_NOT_FOUND: u16 = 0x04b3;

/// Returned from `call_cleanups` (cmd `0x1a`) when there's nothing to
/// commit — used as a soft "no-op" signal, not an error per upstream
/// `flash.py:118`. Wire bytes `91 04`.
pub const STATUS_NOTHING_TO_COMMIT: u16 = 0x0491;

/// Best-effort label for a 16-bit device status word. Returns `None`
/// for `0x0000` (success) and any unknown code; otherwise returns a
/// short description.
pub fn status_label(status: u16) -> Option<&'static str> {
    match status {
        0x0000 => None,
        0x04b0 => Some("no firmware-extension loaded (clean slate)"),
        0x04b3 => Some("record not found"),
        0x04c3 => Some("duplicate enrolment (this finger/subtype is already in the DB)"),
        0x04f5 => Some("matcher state error (cmd 0x60 with no pending match, or scan rejected)"),
        0x0491 => Some("nothing to commit (cleanup no-op)"),
        0x0007 => Some("device-side scan / parameter error"),
        0x0316 => Some("not a status word — looks like a TLS Alert (0x16 type misread as LE u16)"),
        // 0x04xx is generally device-side error class; surface as such.
        s if s & 0xff00 == 0x0400 => Some("device-side error (0x04xx class)"),
        _ => Some("unknown status code"),
    }
}

pub const CMD_READ_FLASH: u8 = 0x40;
pub const CMD_WRITE_FLASH: u8 = 0x41;
pub const CMD_WRITE_FW_SIGNATURE: u8 = 0x42;
pub const CMD_ERASE_FLASH: u8 = 0x3f;
pub const CMD_READ_HW_REG32: u8 = 0x07;
pub const CMD_WRITE_HW_REG32: u8 = 0x08;
pub const CMD_GET_PRG_STATUS: u8 = 0x51;
pub const TLS_FLASH_PARTITION: u8 = 0x01;

/// One full request/response exchange on the cleartext bulk channel.
pub struct Channel {
    writer: nusb::io::EndpointWrite<Bulk>,
    reader: nusb::io::EndpointRead<Bulk>,
    async_reader: nusb::io::EndpointRead<Bulk>,
    int_reader: nusb::io::EndpointRead<Interrupt>,
}

impl Channel {
    /// Claim interface 0 on `sensor` and prepare the bulk endpoints.
    ///
    /// This will detach the kernel driver if one is currently bound (on
    /// Linux) so a userspace driver can talk to the device.
    pub fn open(sensor: &Sensor) -> Result<Self> {
        let intf = sensor.nusb().detach_and_claim_interface(INTERFACE).wait()?;
        let ep_out = intf.endpoint::<Bulk, Out>(EP_BULK_OUT)?;
        let ep_in = intf.endpoint::<Bulk, In>(EP_BULK_IN)?;
        let ep_async = intf.endpoint::<Bulk, In>(EP_ASYNC_IN)?;
        let ep_int = intf.endpoint::<Interrupt, In>(EP_INT_IN)?;
        Ok(Self {
            writer: ep_out.writer(64),
            reader: ep_in.reader(64 * 1024),
            async_reader: ep_async.reader(1024 * 1024),
            int_reader: ep_int.reader(1024),
        })
    }

    /// Send a raw command and return the device's full response, status
    /// bytes included. Caller is responsible for splitting the leading
    /// `<u16 status>` off the payload via [`split_status`].
    /// Bound how long [`Self::cmd`] waits for a reply (default: forever).
    /// A timed-out command fails with an I/O `TimedOut` error instead of
    /// hanging — used by the daemon so a confused chip can't wedge it.
    pub fn set_cmd_timeout(&mut self, timeout: std::time::Duration) {
        self.reader.set_read_timeout(timeout);
    }

    pub fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.writer.write_all(payload)?;
        self.writer.flush()?;

        let mut buf = [0u8; 64 * 1024];
        let n = self.reader.read(&mut buf)?;
        Ok(buf[..n].to_vec())
    }

    /// Read one async event from the device on EP `0x82` (the image-
    /// data and scan-event channel). Buffer can be up to 1 MiB. Mirrors
    /// upstream's `usb.read_82()`.
    pub fn read_async(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 1024 * 1024];
        let n = self.async_reader.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read one interrupt-IN event from the device on EP `0x83`
    /// (matcher state-machine notifications: scan-start, finger-detect,
    /// capture-complete). Mirrors upstream's `usb.wait_int()`. Blocks
    /// until the device produces an event.
    pub fn wait_int(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; 1024];
        let n = self.int_reader.read(&mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Like [`Self::wait_int`] but gives up after `timeout`, returning
    /// `Ok(None)`. The underlying USB transfer is *not* cancelled, so a
    /// later call picks up the event if it arrives afterwards. Used by
    /// long-running daemon operations that must stay cancellable.
    pub fn wait_int_timeout(&mut self, timeout: std::time::Duration) -> Result<Option<Vec<u8>>> {
        self.int_reader.set_read_timeout(timeout);
        let mut buf = vec![0u8; 1024];
        let r = self.int_reader.read(&mut buf);
        // Restore "block forever" so the CLI paths keep their semantics.
        self.int_reader.set_read_timeout(std::time::Duration::MAX);
        match r {
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Split a response into `(status, payload)`. Returns [`Error::ShortResponse`]
/// if fewer than two bytes were received.
pub fn split_status(resp: &[u8]) -> Result<(u16, &[u8])> {
    let head = resp.first_chunk::<2>().ok_or(Error::ShortResponse)?;
    Ok((u16::from_le_bytes(*head), &resp[2..]))
}

/// Decoded reply to cleartext command `0x01` (Get Version / RomInfo).
///
/// Layout of the first 16 bytes of the response payload, in struct
/// pseudo-code: `{ u32 timestamp; u32 build; u8 major; u8 minor; u8 _pad;
/// u8 product; u8 _pad[3]; u8 u1 }` — all little-endian.
#[derive(Debug, Clone, Copy)]
pub struct RomInfo {
    pub timestamp: u32,
    pub build: u32,
    pub major: u8,
    pub minor: u8,
    pub product: u8,
    pub u1: u8,
}

/// Five years in seconds. ROM builds older than `now - this` are flagged
/// as "stale" by [`RomInfo::is_stale`].
pub const FIRMWARE_STALE_SECS: u64 = 5 * 365 * 24 * 60 * 60;

/// Best-effort decoding of the 20 bytes that follow `RomInfo` in the
/// reply to cmd `0x01`. Upstream `python-validity` does not parse these
/// (it truncates at offset 0x10), so the field names below are educated
/// guesses based on byte-level patterns observed across one device:
///
/// ```text
/// offset  size  bytes (sample)             interpretation
/// 0x00      2   22 16                       u16 LE = 0x1622 (suspected flags or block version)
/// 0x02      6   49 68 4f 35 00 23           opaque hardware identifier
/// 0x08      4   00 00 00 00                 reserved / zero-pad
/// 0x0c      4   01 00 00 00                 u32 LE counter or state flag
/// 0x10      4   03 d1 00 07                 unknown — possibly two u16 fields
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RomExtra {
    pub block_tag: u16,
    pub hw_id: [u8; 6],
    pub state_flag: u32,
    pub tail: [u8; 4],
}

impl RomExtra {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 36 {
            return Err(Error::ShortResponse);
        }
        let extra = &payload[16..36];
        Ok(Self {
            block_tag: u16::from_le_bytes(extra[0..2].try_into().unwrap()),
            hw_id: extra[2..8].try_into().unwrap(),
            state_flag: u32::from_le_bytes(extra[12..16].try_into().unwrap()),
            tail: extra[16..20].try_into().unwrap(),
        })
    }
}

/// One module entry inside a [`PartitionInfo`] response. The semantics
/// of the type / subtype codes are not fully documented upstream.
#[derive(Debug, Clone, Copy)]
pub struct ModuleInfo {
    pub kind: u16,
    pub subtype: u16,
    pub major: u16,
    pub minor: u16,
    pub size: u32,
}

/// Decoded reply to `0x43 <partition>` (typically `partition = 2` for
/// the firmware-extension). Layout:
///
/// ```text
/// offset  size  meaning
/// 0x00    u16   major version
/// 0x02    u16   minor version
/// 0x04    u16   number of module entries that follow
/// 0x06    u32   build timestamp (unix epoch seconds)
/// 0x0a    --    `module_count * 12` bytes of `ModuleInfo`
/// ```
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub major: u16,
    pub minor: u16,
    pub buildtime: u32,
    pub modules: Vec<ModuleInfo>,
}

/// What `0x43 <partition>` told us.
#[derive(Debug, Clone)]
pub enum FwextState {
    /// Status `0x04b0` — no firmware-extension flashed; the host must upload one.
    CleanSlate,
    /// Status `0x0000` and a parsed `PartitionInfo`.
    Loaded(PartitionInfo),
    /// Some other non-zero status; we surface it raw for diagnostics.
    OtherStatus { status: u16, payload: Vec<u8> },
}

impl PartitionInfo {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 0x0a {
            return Err(Error::ShortResponse);
        }
        let major = u16::from_le_bytes(payload[0..2].try_into().unwrap());
        let minor = u16::from_le_bytes(payload[2..4].try_into().unwrap());
        let modcnt = u16::from_le_bytes(payload[4..6].try_into().unwrap()) as usize;
        let buildtime = u32::from_le_bytes(payload[6..10].try_into().unwrap());

        let need = 0x0a + modcnt * 12;
        if payload.len() < need {
            return Err(Error::ShortResponse);
        }

        let mut modules = Vec::with_capacity(modcnt);
        for i in 0..modcnt {
            let off = 0x0a + i * 12;
            let m = &payload[off..off + 12];
            modules.push(ModuleInfo {
                kind: u16::from_le_bytes(m[0..2].try_into().unwrap()),
                subtype: u16::from_le_bytes(m[2..4].try_into().unwrap()),
                major: u16::from_le_bytes(m[4..6].try_into().unwrap()),
                minor: u16::from_le_bytes(m[6..8].try_into().unwrap()),
                size: u32::from_le_bytes(m[8..12].try_into().unwrap()),
            });
        }
        Ok(Self { major, minor, buildtime, modules })
    }
}

/// Build a `write_flash` request frame. Wire layout (LE):
/// `<u8 0x41, u8 partition, u8 0x01, u16 0, u32 addr, u32 len, data...>`.
/// Mirrors `python-validity/flash.py:write_flash`. Sending this
/// frame is **destructive** — it overwrites flash. Builder is here
/// for the offline tests; no caller wires it up yet.
pub fn build_write_flash(partition: u8, addr: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + data.len());
    out.push(CMD_WRITE_FLASH);
    out.push(partition);
    out.push(0x01);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&addr.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// Build a `erase_flash` request frame. Wire layout: `<u8 0x3f, u8 partition>`.
/// Mirrors `python-validity/flash.py:erase_flash`. **Destructive.**
pub fn build_erase_flash(partition: u8) -> Vec<u8> {
    vec![CMD_ERASE_FLASH, partition]
}

/// Build a `read_hw_reg32` request frame. Wire layout:
/// `<u8 0x07, u32 LE addr, u8 0x04>` (the trailing `0x04` is the
/// requested width — always 4 in upstream usage). Mirrors
/// `python-validity/sensor.py:read_hw_reg32`.
pub fn build_read_hw_reg32(addr: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.push(CMD_READ_HW_REG32);
    out.extend_from_slice(&addr.to_le_bytes());
    out.push(0x04);
    out
}

/// Build a `write_hw_reg32` request frame. Wire layout:
/// `<u8 0x08, u32 LE addr, u8 0x04, u32 LE value>`. Mirrors
/// `python-validity/sensor.py:write_hw_reg32`.
pub fn build_write_hw_reg32(addr: u32, value: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.push(CMD_WRITE_HW_REG32);
    out.extend_from_slice(&addr.to_le_bytes());
    out.push(0x04);
    out.extend_from_slice(&value.to_le_bytes());
    out
}

/// Build a `get_prg_status` request frame (5 bytes:
/// `0x51 0x00 0x00 0x00 0x00`). Used during long-running captures to
/// poll completion. Distinct from `get_prg_status2` (cmd
/// `0x51 0x00 0x20 0x00 0x00`) which returns capture metadata.
pub fn build_get_prg_status() -> Vec<u8> {
    vec![CMD_GET_PRG_STATUS, 0x00, 0x00, 0x00, 0x00]
}

/// Decoded `get_prg_status2` reply (cmd `0x51 0x00 0x20 0x00 0x00`).
/// Mirrors `python-validity/sensor.py:capture` — after the reply is
/// stripped of its u16 status, the wire layout is:
///
/// ```text
/// <u32 LE body_len>
/// <u16 LE x, u16 LE y, u16 LE w1, u16 LE w2>
/// <u32 LE error>
/// ```
///
/// `body_len` is always 12 in our observations; `x`/`y` are scan-area
/// coordinates; `w1`/`w2` are widths or weights (semantics unclear in
/// upstream); `error` is non-zero when the scan failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureStatus {
    pub x: u16,
    pub y: u16,
    pub w1: u16,
    pub w2: u16,
    pub error: u32,
}

impl CaptureStatus {
    /// Parse the reply payload (status word already stripped).
    /// Returns `Err(Error::ShortResponse)` if fewer than 16 bytes.
    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 16 {
            return Err(Error::ShortResponse);
        }
        let body_len = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
        if body_len < 12 || payload.len() < 4 + body_len.min(12) {
            return Err(Error::ShortResponse);
        }
        let body = &payload[4..];
        Ok(Self {
            x: u16::from_le_bytes(body[0..2].try_into().unwrap()),
            y: u16::from_le_bytes(body[2..4].try_into().unwrap()),
            w1: u16::from_le_bytes(body[4..6].try_into().unwrap()),
            w2: u16::from_le_bytes(body[6..8].try_into().unwrap()),
            error: u32::from_le_bytes(body[8..12].try_into().unwrap()),
        })
    }

    /// Best-effort label for the `error` field. Most codes aren't
    /// documented upstream, so this is mostly a "this looks like no
    /// data was captured" hint based on observed bits.
    pub fn error_label(&self) -> Option<&'static str> {
        match self.error {
            0 => None,
            0x80200000 => Some("no scan data — finger absent or matcher uninitialised"),
            0x00000007 => Some("generic scan error"),
            _ => Some("unknown error code (see python-validity for matching cases)"),
        }
    }

    /// `true` if the device reported a successful capture (zero scan
    /// metadata + zero error).
    pub fn is_success(&self) -> bool {
        self.error == 0
    }
}

/// One decoded EP-`0x83` interrupt event. Layouts inferred from the
/// upstream state machine in `sensor.py:capture` — these are the
/// kinds we've observed and labelled. Anything else is reported as
/// `Unknown`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterruptEvent {
    /// `b[0] == 0x00` — matcher state machine has armed itself and is
    /// waiting for further events. Always the first event after a
    /// `cmd 0x02` request.
    Start,
    /// `b[0] == 0x02` — finger touched the sensor. `byte 1` carries a
    /// reserved/zero, `byte 2..4` is a u16 "score" or "feature" value
    /// (we've observed `0x10 0x40` = 0x4010 in the wild; meaning TBD).
    FingerDetect { extra: Vec<u8> },
    /// `b[0] == 0x03` — capture progressed; `byte 2` has bit flags.
    /// Bit `0x04` set means "capture complete" — caller should now
    /// fetch metadata via cmd `0x51 0x00 0x20 …` (`get_prg_status2`).
    CaptureProgress { flags: u8, extra: Vec<u8> },
    /// Anything we don't recognise — surfaced verbatim for diagnostics.
    Unknown(Vec<u8>),
}

impl InterruptEvent {
    /// Decode a single EP-0x83 event. The event is a short bytestring;
    /// we copy whatever we need. The decoder never fails — unknown
    /// shapes return [`InterruptEvent::Unknown`].
    pub fn parse(bytes: &[u8]) -> Self {
        match bytes.first().copied() {
            Some(0x00) => Self::Start,
            Some(0x02) => Self::FingerDetect { extra: bytes[1..].to_vec() },
            Some(0x03) => {
                let flags = bytes.get(2).copied().unwrap_or(0);
                Self::CaptureProgress { flags, extra: bytes[1..].to_vec() }
            }
            _ => Self::Unknown(bytes.to_vec()),
        }
    }

    /// Convenience: `true` for the capture-done flag bit on `0x03` events.
    pub fn capture_complete(&self) -> bool {
        matches!(self, Self::CaptureProgress { flags, .. } if flags & 0x04 != 0)
    }

    /// Human-readable label suitable for log output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Start => "matcher armed (start)",
            Self::FingerDetect { .. } => "finger detected",
            Self::CaptureProgress { flags, .. } if flags & 0x04 != 0 => "capture complete",
            Self::CaptureProgress { .. } => "capture in progress",
            Self::Unknown(_) => "(unknown event)",
        }
    }
}

/// Build a `write_fw_signature` request frame. Wire layout:
/// `<u8 0x42, u8 partition, u8 0 (pad), u16 sig_len, signature...>`.
/// Mirrors `python-validity/flash.py:write_fw_signature`. **Destructive.**
pub fn build_write_fw_signature(partition: u8, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + signature.len());
    out.push(CMD_WRITE_FW_SIGNATURE);
    out.push(partition);
    out.push(0x00);
    out.extend_from_slice(&(signature.len() as u16).to_le_bytes());
    out.extend_from_slice(signature);
    out
}

/// Read `size` bytes starting at `addr` from `partition` over the
/// **cleartext** command channel. Works pre-TLS because `tls.cmd()`
/// upstream falls through to `usb.cmd()` when no secure session is up.
///
/// Wire layout (request, all little-endian):
/// `0x40 <u8 partition> 0x01 <u16=0> <u32 addr> <u32 size>`.
///
/// Wire layout (response): `<u16 status> <u32 actual_size> <2 pad> <data...>`.
pub fn read_flash(
    chan: &mut Channel,
    partition: u8,
    addr: u32,
    size: u32,
) -> Result<Vec<u8>> {
    let mut req = Vec::with_capacity(13);
    req.push(CMD_READ_FLASH);
    req.push(partition);
    req.push(0x01);
    req.extend_from_slice(&0u16.to_le_bytes());
    req.extend_from_slice(&addr.to_le_bytes());
    req.extend_from_slice(&size.to_le_bytes());

    let resp = chan.cmd(&req)?;
    let (status, payload) = split_status(&resp)?;
    if status != 0 {
        return Err(Error::FlashRead { status });
    }
    if payload.len() < 6 {
        return Err(Error::ShortResponse);
    }
    let actual_size = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    // payload[4..6] = 2 padding bytes upstream ignores
    let data_start = 6;
    if payload.len() < data_start + actual_size {
        return Err(Error::ShortResponse);
    }
    Ok(payload[data_start..data_start + actual_size].to_vec())
}

/// One block parsed out of flash partition 1 (the TLS pairing record).
/// Layout per block: `<u16 LE id> <u16 LE size> <32 B sha256(body)> <body>`.
#[derive(Debug, Clone)]
pub struct TlsFlashBlock {
    pub id: u16,
    pub sha256: [u8; 32],
    pub body: Vec<u8>,
}

/// IDs upstream knows how to parse, from `tls.py:parse_tls_flash`.
pub mod tls_flash_ids {
    pub const PADDING_0: u16 = 0;
    pub const PADDING_1: u16 = 1;
    pub const PADDING_2: u16 = 2;
    pub const TLS_CERT: u16 = 3;
    pub const PRIV_KEY: u16 = 4;
    pub const ECDH_Q: u16 = 6;
    pub const END_MARKER: u16 = 0xffff;
}

/// Parse the TLS flash partition into its constituent blocks. Stops at
/// the `0xffff` end marker. The optional `chk_hash` parameter, when
/// `true`, asserts that each block's body hashes to its stored
/// SHA-256; we leave that to a higher layer to keep this function
/// crypto-free.
pub fn parse_tls_flash(buf: &[u8]) -> Result<Vec<TlsFlashBlock>> {
    let mut out = Vec::new();
    let mut p = buf;
    while p.len() >= 4 {
        let id = u16::from_le_bytes(p[0..2].try_into().unwrap());
        let sz = u16::from_le_bytes(p[2..4].try_into().unwrap()) as usize;
        if id == tls_flash_ids::END_MARKER {
            break;
        }
        if p.len() < 4 + 32 + sz {
            return Err(Error::ShortResponse);
        }
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&p[4..36]);
        let body = p[36..36 + sz].to_vec();
        out.push(TlsFlashBlock { id, sha256: sha, body });
        p = &p[36 + sz..];
    }
    Ok(out)
}

/// Run the cleartext boot sequence required before TLS will work:
/// `0x01` (RomInfo), `0x19`, `0x43 02` (fwext check), and the
/// device-family-specific `init_hardcoded` capsule. Mirrors
/// `python-validity/validitysensor/usb.py:send_init`.
pub fn send_init(chan: &mut Channel, init_hardcoded: &[u8]) -> Result<()> {
    let r = chan.cmd(&[CMD_GET_VERSION])?;
    let (s, _) = split_status(&r)?;
    if s != 0 {
        return Err(Error::FlashRead { status: s });
    }
    let r = chan.cmd(&[CMD_PROBE_19])?;
    let (s, _) = split_status(&r)?;
    if s != 0 {
        return Err(Error::FlashRead { status: s });
    }
    // 0x43 0x02 is allowed to return STATUS_NO_FW; we just want the device
    // to acknowledge the probe, not depend on any specific value.
    let _ = chan.cmd(&[CMD_GET_PARTITION, FWEXT_PARTITION])?;
    let r = chan.cmd(init_hardcoded)?;
    let (s, _) = split_status(&r)?;
    if s != 0 {
        return Err(Error::FlashRead { status: s });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real reply from the user's ThinkPad P70 sensor to cmd `0x01`.
    /// `0x0000` (status OK) + the 36-byte RomInfo / RomExtra payload.
    /// This is a public ROM fingerprint, captured 2026-05-05.
    const REAL_VERSION_REPLY: &[u8] = &[
        0x00, 0x00, // status
        0xf0, 0xb0, 0x5e, 0x54, // timestamp = 1415491824 (2014-11-08 19:30:24 UTC)
        0xa4, 0x00, 0x00, 0x00, // build = 164
        0x06, // major
        0x07, // minor
        0x01, // padding
        0x30, // product = Metallica MIS
        0x00, 0x01, 0x00, // padding
        0x00, // u1
        // RomExtra:
        0x22, 0x16, // block_tag
        0x49, 0x68, 0x4f, 0x35, 0x00, 0x23, // hw_id
        0x00, 0x00, 0x00, 0x00, // reserved
        0x01, 0x00, 0x00, 0x00, // state_flag
        0x03, 0xd1, 0x00, 0x07, // tail
    ];

    #[test]
    fn split_status_returns_le_word() {
        let (status, payload) = split_status(REAL_VERSION_REPLY).unwrap();
        assert_eq!(status, 0x0000);
        assert_eq!(payload.len(), 36);
    }

    #[test]
    fn split_status_short_response_errors() {
        assert!(matches!(split_status(&[]), Err(Error::ShortResponse)));
        assert!(matches!(split_status(&[0x00]), Err(Error::ShortResponse)));
    }

    #[test]
    fn rom_info_p70_real_response() {
        let (_, payload) = split_status(REAL_VERSION_REPLY).unwrap();
        let r = RomInfo::parse(payload).unwrap();
        assert_eq!(r.timestamp, 1_415_491_824);
        assert_eq!(r.build, 164);
        assert_eq!(r.major, 6);
        assert_eq!(r.minor, 7);
        assert_eq!(r.product, 0x30);
        assert_eq!(r.u1, 0);
    }

    #[test]
    fn rom_extra_p70_real_response() {
        let (_, payload) = split_status(REAL_VERSION_REPLY).unwrap();
        let e = RomExtra::parse(payload).unwrap();
        assert_eq!(e.block_tag, 0x1622);
        assert_eq!(e.hw_id, [0x49, 0x68, 0x4f, 0x35, 0x00, 0x23]);
        assert_eq!(e.state_flag, 1);
        assert_eq!(e.tail, [0x03, 0xd1, 0x00, 0x07]);
    }

    /// `RomInfo::is_stale` returns `false` when `now_unix == 0`
    /// (interpreted as "wall clock unavailable").
    #[test]
    fn rom_info_is_stale_zero_now_disables_check() {
        let rom = RomInfo {
            timestamp: 100,
            build: 0,
            major: 0,
            minor: 0,
            product: 0,
            u1: 0,
        };
        assert!(!rom.is_stale(0));
    }

    /// Boundary: a timestamp exactly `FIRMWARE_STALE_SECS` younger than
    /// `now_unix` is NOT stale (strict inequality in the implementation).
    #[test]
    fn rom_info_is_stale_boundary_not_stale() {
        let rom = RomInfo {
            timestamp: 100,
            build: 0,
            major: 0,
            minor: 0,
            product: 0,
            u1: 0,
        };
        let now = 100u64 + FIRMWARE_STALE_SECS;
        assert!(!rom.is_stale(now));
    }

    /// One second past the staleness window → stale.
    #[test]
    fn rom_info_is_stale_one_past_boundary() {
        let rom = RomInfo {
            timestamp: 100,
            build: 0,
            major: 0,
            minor: 0,
            product: 0,
            u1: 0,
        };
        let now = 100u64 + FIRMWARE_STALE_SECS + 1;
        assert!(rom.is_stale(now));
    }

    /// Future-dated firmware (timestamp > now) is not stale.
    #[test]
    fn rom_info_is_stale_future_timestamp() {
        let rom = RomInfo {
            timestamp: 0xffff_ffff,
            build: 0,
            major: 0,
            minor: 0,
            product: 0,
            u1: 0,
        };
        // now is small.
        assert!(!rom.is_stale(1_000_000));
    }

    /// `FIRMWARE_STALE_SECS` is exactly five years (5 × 365 × 24 × 60 × 60).
    #[test]
    fn firmware_stale_secs_is_five_years() {
        assert_eq!(FIRMWARE_STALE_SECS, 5 * 365 * 24 * 60 * 60);
    }

    /// User's actual ROM (timestamp `1415491824`, 2014-11-08) IS stale
    /// against any timestamp from at least 2020 onwards.
    #[test]
    fn rom_info_is_stale_p70_real_rom_against_2026() {
        let rom = RomInfo {
            timestamp: 1_415_491_824, // 2014-11-08
            build: 164,
            major: 6,
            minor: 7,
            product: 0x30,
            u1: 0,
        };
        // 2026-05-06 ≈ 1_777_363_200
        assert!(rom.is_stale(1_777_363_200));
    }

    #[test]
    fn rom_info_short_payload_errors() {
        assert!(matches!(RomInfo::parse(&[0u8; 15]), Err(Error::ShortResponse)));
    }

    /// Real reply from the user's device to cmd `0x43 02` over TLS (post-handshake).
    /// 2-byte status + 104-byte fwext PartitionInfo body. Captured 2026-05-05.
    const REAL_FWEXT_REPLY: &[u8] = &[
        0x00, 0x00, // status
        0x01, 0x00, 0x02, 0x00, 0x08, 0x00, // major=1, minor=2, modcnt=8
        0xe9, 0x83, 0x2e, 0x5e, // buildtime = 1580106729 (2020-01-27 06:32:09 UTC)
        // module table — 8 × 12 B
        0x01, 0x00, 0x34, 0x46, 0x02, 0x00, 0x07, 0x00, 0xe0, 0x42, 0x00, 0x00,
        0x01, 0x00, 0x84, 0x08, 0x01, 0x00, 0x07, 0x00, 0x80, 0x06, 0x00, 0x00,
        0x02, 0x00, 0x84, 0x28, 0x03, 0x00, 0x12, 0x00, 0x40, 0x10, 0x00, 0x00,
        0x02, 0x00, 0x76, 0x36, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x01, 0x00, 0x86, 0x47, 0x00, 0x00, 0x01, 0x00, 0x50, 0x5a, 0x00, 0x00,
        0x02, 0x00, 0x23, 0x77, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x2f, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x37, 0x00, 0x00, 0x01, 0x00, 0xb0, 0x08, 0x02, 0x00,
        0x01, 0x00, 0x25, 0x56, 0x00, 0x00, 0x01, 0x00, 0x60, 0x04, 0x00, 0x00,
    ];

    #[test]
    fn partition_info_p70_fwext_post_tls() {
        let (status, payload) = split_status(REAL_FWEXT_REPLY).unwrap();
        assert_eq!(status, 0);
        let p = PartitionInfo::parse(payload).unwrap();
        assert_eq!(p.major, 1);
        assert_eq!(p.minor, 2);
        assert_eq!(p.buildtime, 1_580_106_729);
        assert_eq!(p.modules.len(), 8);
        // Spot-check a few modules to lock in the wire ordering of the
        // <type, subtype, major, minor, size> 12-byte struct.
        assert_eq!(p.modules[0].kind, 0x0001);
        assert_eq!(p.modules[0].subtype, 0x4634);
        assert_eq!(p.modules[0].major, 2);
        assert_eq!(p.modules[0].minor, 7);
        assert_eq!(p.modules[0].size, 17_120);
        // Largest module — image-recognition matcher in upstream's table.
        assert_eq!(p.modules[6].kind, 0x0002);
        assert_eq!(p.modules[6].subtype, 0x3700);
        assert_eq!(p.modules[6].size, 133_296);
        // Sum of sizes — useful sanity total.
        let total: u32 = p.modules.iter().map(|m| m.size).sum();
        assert_eq!(total, 195_264);
    }

    #[test]
    fn partition_info_truncated_module_table_errors() {
        // Header says 8 modules but only 7 present.
        let mut buf = REAL_FWEXT_REPLY[2..].to_vec();
        buf.truncate(2 + 0x0a + 7 * 12);
        assert!(matches!(PartitionInfo::parse(&buf[2..]), Err(Error::ShortResponse)));
    }

    /// Synthetic flash partition: two valid blocks plus the `0xffff`
    /// end marker. We stage a known SHA-256 in the header so the
    /// parser can be exercised without a real device.
    #[test]
    fn parse_tls_flash_synthetic_blocks() {
        let body0 = b"alpha".to_vec();
        let body1 = b"beta-block-content".to_vec();

        let mut buf = Vec::new();
        for (id, body) in [(0u16, &body0), (3u16, &body1)] {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(&(body.len() as u16).to_le_bytes());
            buf.extend_from_slice(&[0xAB; 32]); // arbitrary "hash"
            buf.extend_from_slice(body);
        }
        // End marker.
        buf.extend_from_slice(&0xffff_u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());

        let blocks = parse_tls_flash(&buf).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].id, 0);
        assert_eq!(blocks[0].body, body0);
        assert_eq!(blocks[1].id, tls_flash_ids::TLS_CERT);
        assert_eq!(blocks[1].body, body1);
    }

    #[test]
    fn parse_tls_flash_short_block_errors() {
        // id=4 says 100-byte body, but only 20 bytes follow the header+hash.
        let mut buf = Vec::new();
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&100u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 20]);
        assert!(matches!(parse_tls_flash(&buf), Err(Error::ShortResponse)));
    }

    /// Real cleartext reply from cmd `0x75` post-TLS on the user's P70.
    /// Confirms the layout `<u32 zeroes> <u16 minor> <u16 major>` and
    /// that the silicon ID is `0x0190 / 0x004a` (FM-3367-001).
    #[test]
    fn identify_sensor_p70_real_response() {
        let raw: &[u8] = &[
            0x00, 0x00, // status
            0x00, 0x00, 0x00, 0x00, // zeroes
            0x4a, 0x00, // minor LE
            0x90, 0x01, // major LE
        ];
        let (status, payload) = split_status(raw).unwrap();
        assert_eq!(status, 0);
        let zeroes = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let minor = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        let major = u16::from_le_bytes(payload[6..8].try_into().unwrap());
        assert_eq!(zeroes, 0);
        assert_eq!(minor, 0x004a);
        assert_eq!(major, 0x0190);
    }

    #[test]
    fn build_write_flash_layout() {
        let data = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let f = build_write_flash(2, 0x1234_5678, &data);
        // Header: 41 02 01 00 00 78 56 34 12 04 00 00 00 + data
        assert_eq!(f.len(), 13 + data.len());
        assert_eq!(f[0], 0x41);
        assert_eq!(f[1], 0x02);
        assert_eq!(f[2], 0x01);
        assert_eq!(u16::from_le_bytes([f[3], f[4]]), 0);
        assert_eq!(u32::from_le_bytes([f[5], f[6], f[7], f[8]]), 0x1234_5678);
        assert_eq!(u32::from_le_bytes([f[9], f[10], f[11], f[12]]), 4);
        assert_eq!(&f[13..], &data[..]);
    }

    #[test]
    fn build_write_flash_empty_data() {
        let f = build_write_flash(1, 0, &[]);
        assert_eq!(f.len(), 13);
        assert_eq!(u32::from_le_bytes([f[9], f[10], f[11], f[12]]), 0);
    }

    #[test]
    fn build_erase_flash_two_bytes() {
        assert_eq!(build_erase_flash(6), vec![0x3f, 0x06]);
        assert_eq!(build_erase_flash(0xff), vec![0x3f, 0xff]);
    }

    #[test]
    fn build_read_hw_reg32_layout() {
        let f = build_read_hw_reg32(0x8000_2080);
        assert_eq!(f.len(), 6);
        assert_eq!(f[0], 0x07);
        assert_eq!(u32::from_le_bytes([f[1], f[2], f[3], f[4]]), 0x8000_2080);
        assert_eq!(f[5], 0x04);
    }

    #[test]
    fn build_write_hw_reg32_layout() {
        let f = build_write_hw_reg32(0x8000_205c, 0x0000_0007);
        assert_eq!(f.len(), 10);
        assert_eq!(f[0], 0x08);
        assert_eq!(u32::from_le_bytes([f[1], f[2], f[3], f[4]]), 0x8000_205c);
        assert_eq!(f[5], 0x04);
        assert_eq!(u32::from_le_bytes([f[6], f[7], f[8], f[9]]), 0x0000_0007);
    }

    #[test]
    fn build_get_prg_status_constant() {
        assert_eq!(build_get_prg_status(), vec![0x51, 0x00, 0x00, 0x00, 0x00]);
    }

    /// `status_label` returns `None` for success and a short string
    /// for known codes (incl. our regression-vector failure modes).
    #[test]
    fn status_label_known_codes() {
        assert_eq!(status_label(0x0000), None);
        assert_eq!(status_label(STATUS_NO_FW), Some("no firmware-extension loaded (clean slate)"));
        assert_eq!(status_label(STATUS_NOT_FOUND), Some("record not found"));
        assert_eq!(status_label(STATUS_NOTHING_TO_COMMIT), Some("nothing to commit (cleanup no-op)"));
        assert_eq!(status_label(0x0007), Some("device-side scan / parameter error"));
        assert_eq!(status_label(0x0316), Some("not a status word — looks like a TLS Alert (0x16 type misread as LE u16)"));
        // Unknown 0x04xx falls into the class-level bucket.
        assert_eq!(status_label(0x04ae), Some("device-side error (0x04xx class)"));
        // Truly unknown.
        assert_eq!(status_label(0x9999), Some("unknown status code"));
    }

    /// Lock in the `get_prg_status2` reply layout against the failure
    /// shape we saw on the user's device (status `0x07`, body 12 bytes,
    /// all-zero coords, `error = 0x80200000`).
    #[test]
    fn capture_status_p70_failure_response() {
        let payload: &[u8] = &[
            0x0c, 0x00, 0x00, 0x00, // body_len = 12
            0x00, 0x00, // x
            0x00, 0x00, // y
            0x00, 0x00, // w1
            0x00, 0x00, // w2
            0x00, 0x00, 0x20, 0x80, // error = 0x80200000
        ];
        let s = CaptureStatus::parse(payload).unwrap();
        assert_eq!(s.x, 0);
        assert_eq!(s.error, 0x80200000);
        assert!(!s.is_success());
        assert_eq!(
            s.error_label(),
            Some("no scan data — finger absent or matcher uninitialised"),
        );
    }

    #[test]
    fn capture_status_success_shape() {
        let payload: &[u8] = &[
            0x0c, 0x00, 0x00, 0x00, // body_len = 12
            0x42, 0x00, // x = 66
            0x18, 0x00, // y = 24
            0x10, 0x00, // w1 = 16
            0x20, 0x00, // w2 = 32
            0x00, 0x00, 0x00, 0x00, // error = 0
        ];
        let s = CaptureStatus::parse(payload).unwrap();
        assert!(s.is_success());
        assert_eq!(s.x, 66);
        assert_eq!(s.y, 24);
        assert_eq!(s.w1, 16);
        assert_eq!(s.w2, 32);
        assert!(s.error_label().is_none());
    }

    #[test]
    fn capture_status_short_payload_errors() {
        assert!(matches!(CaptureStatus::parse(&[0u8; 15]), Err(Error::ShortResponse)));
    }

    /// `body_len < 12` is rejected — the parser refuses to invent fields
    /// past the declared body. Lock the early-return path to prevent
    /// "fall through and panic on slice index" regressions.
    #[test]
    fn capture_status_body_len_below_minimum_errors() {
        // body_len = 8, payload then 12 zero bytes: 16 bytes total, but
        // the *declared* body is 8 bytes — too short for the metadata.
        let payload: &[u8] = &[
            0x08, 0x00, 0x00, 0x00, // body_len = 8
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(CaptureStatus::parse(payload), Err(Error::ShortResponse)));
    }

    /// `error_label` returns the generic-scan-error label for `0x07`
    /// (we've also seen this as a 16-bit cmd status; the metadata-word
    /// version is rarer but documented upstream).
    #[test]
    fn capture_status_error_label_generic_scan_error() {
        let payload: &[u8] = &[
            0x0c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x00, 0x00, 0x00, // error = 0x00000007
        ];
        let s = CaptureStatus::parse(payload).unwrap();
        assert_eq!(s.error_label(), Some("generic scan error"));
    }

    /// `error_label` falls back to a "see python-validity" hint for
    /// codes we haven't catalogued, so callers always get *something*.
    #[test]
    fn capture_status_error_label_unknown_code() {
        let payload: &[u8] = &[
            0x0c, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x99, 0xab, 0xcd, 0xef, // bogus, definitely not in our table
        ];
        let s = CaptureStatus::parse(payload).unwrap();
        assert!(matches!(s.error_label(), Some(label) if label.contains("python-validity")));
    }

    /// `InterruptEvent::parse` recognises the three documented event
    /// shapes and falls back to `Unknown` for anything else.
    #[test]
    fn interrupt_event_known_shapes() {
        // Start: `00 00 00 00 00`.
        let e = InterruptEvent::parse(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(e, InterruptEvent::Start);
        assert!(!e.capture_complete());
        assert_eq!(e.label(), "matcher armed (start)");

        // Finger-detect — observed shape `02 00 40 10 00` on the user's device.
        let e = InterruptEvent::parse(&[0x02, 0x00, 0x40, 0x10, 0x00]);
        assert!(matches!(e, InterruptEvent::FingerDetect { .. }));
        assert!(!e.capture_complete());
        assert_eq!(e.label(), "finger detected");

        // Capture progress without the done bit.
        let e = InterruptEvent::parse(&[0x03, 0x20, 0x03, 0x00, 0x00]);
        assert!(matches!(e, InterruptEvent::CaptureProgress { flags: 0x03, .. }));
        assert!(!e.capture_complete());
        assert_eq!(e.label(), "capture in progress");

        // Capture complete — bit 0x04 set in byte 2.
        let e = InterruptEvent::parse(&[0x03, 0x20, 0x07, 0x00, 0x00]);
        assert!(e.capture_complete());
        assert_eq!(e.label(), "capture complete");

        // Truly unknown event surfaces as Unknown(bytes).
        let e = InterruptEvent::parse(&[0xff, 0x99]);
        assert_eq!(e, InterruptEvent::Unknown(vec![0xff, 0x99]));
        assert_eq!(e.label(), "(unknown event)");
    }

    /// Empty input is safe — returns Unknown rather than panicking.
    #[test]
    fn interrupt_event_empty_input_is_unknown() {
        let e = InterruptEvent::parse(&[]);
        assert_eq!(e, InterruptEvent::Unknown(vec![]));
    }

    /// Capture-progress event with a missing byte-2 (only one or two
    /// bytes total) treats `flags` as 0 and never reports done.
    #[test]
    fn interrupt_event_truncated_capture_progress() {
        let e = InterruptEvent::parse(&[0x03]);
        match e {
            InterruptEvent::CaptureProgress { flags, .. } => assert_eq!(flags, 0),
            other => panic!("expected CaptureProgress, got {other:?}"),
        }
    }

    #[test]
    fn build_write_fw_signature_layout() {
        let sig = [0x11u8, 0x22, 0x33, 0x44, 0x55];
        let f = build_write_fw_signature(2, &sig);
        // 0x42, 0x02, 0x00 (pad), 0x05 0x00 (LE len=5), then sig
        assert_eq!(f.len(), 5 + sig.len());
        assert_eq!(f[0], 0x42);
        assert_eq!(f[1], 0x02);
        assert_eq!(f[2], 0x00);
        assert_eq!(u16::from_le_bytes([f[3], f[4]]), 5);
        assert_eq!(&f[5..], &sig[..]);
    }

    #[test]
    fn fwext_state_recognises_clean_slate_marker() {
        // The bytes `b0 04` (LE u16 = 0x04b0) are the upstream-documented
        // "no fwext" indicator. Locked into the constant for clarity.
        assert_eq!(STATUS_NO_FW, 0x04b0);
        let bytes = [0xb0, 0x04];
        assert_eq!(u16::from_le_bytes(bytes), STATUS_NO_FW);
    }

    /// Real reply from the user's P70 to the cleartext `0x19` probe.
    /// 2-byte status + 66-byte payload. Upstream doesn't decode this;
    /// we lock the bytes in as a regression vector — any future
    /// "structured" parser must reproduce them or admit the schema
    /// changed.
    const REAL_PROBE_19_REPLY: &[u8] = &[
        0x00, 0x00, // status
        // Bytes 0..16 of payload — the leading u16 fields and start of zero-pad.
        0x02, 0x00, 0x21, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // (16 bytes so far)
        // Bytes 16..32 — `44 f5 4b d5` at offset 18 inside the payload.
        0x00, 0x00, 0x44, 0xf5, 0x4b, 0xd5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // (32 bytes so far)
        // Bytes 32..48 — all zero.
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // (48 bytes so far)
        // Bytes 48..64 — all zero.
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // (64 bytes so far)
        // Bytes 64..66 — final two zero bytes.
        0x00, 0x00,
    ];

    #[test]
    fn probe_19_p70_real_payload_shape() {
        let (status, payload) = split_status(REAL_PROBE_19_REPLY).unwrap();
        assert_eq!(status, 0x0000);
        assert_eq!(payload.len(), 66);
        // Hint of structure: looks like u16 fields at the start, then
        // a u32 "44 f5 4b d5" at offset 18, with the rest zero-padded.
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 0x0002);
        assert_eq!(u16::from_le_bytes([payload[2], payload[3]]), 0x0021);
        assert_eq!(u16::from_le_bytes([payload[4], payload[5]]), 0x0110);
        assert_eq!(u32::from_le_bytes([payload[18], payload[19], payload[20], payload[21]]),
            0xd54bf544);
        // Tail must be all zero.
        assert!(payload[22..].iter().all(|&b| b == 0));
    }

    /// User's TLS cert (block id=0x03) shares its prefix with upstream's
    /// `crt_hardcoded` — `17 00 00 00` magic followed by `20 00 00 00`.
    /// We don't bake the full 184-byte cert in here (it's identifying
    /// per-device data) but we lock in the magic + length so that a
    /// future change to the cert layout fails loudly.
    /// Real first 32 bytes of partition 4 (the template database)
    /// header zone on the user's P70, captured 2026-05-05.
    /// **Note:** the leading 0xff bytes are *erased flash*, not "no
    /// records present". Records live elsewhere in the 512 KiB
    /// partition; the user's actual DB has 2 records (see `db-info`).
    /// What this test locks in is the partition-format header, which
    /// is generic across any state of the DB and contains no
    /// biometric data.
    #[test]
    fn template_db_partition_header_p70() {
        let header: [u8; 32] = [
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff,
        ];
        // Plausible field layout (best-effort; upstream doesn't decode):
        //   [0..2] u16 LE = 0x0001  → maybe schema version
        //   [4..8] u32 LE = 0x01000000 → record-count or magic
        //   [8..12] = 0xff (unwritten slot)
        //   [12..14] u16 = 0x0100
        //   [16..20] u32 LE = 1     → current write cursor?
        //   [26..28] u16 LE = 0x0008 → fixed marker
        //   [28..32] = 0xff
        assert_eq!(u16::from_le_bytes([header[0], header[1]]), 0x0001);
        assert_eq!(u16::from_le_bytes([header[26], header[27]]), 0x0008);
        // The "no fingers" tail signature: bytes 8..12 == 0xffffffff means
        // the first record slot is empty.
        assert_eq!(&header[8..12], &[0xff, 0xff, 0xff, 0xff]);
    }

    /// Real reply to `db-value 3` on the user's device (the root
    /// user-storage record). Storage name is the fixed string
    /// `StgWindsor\0` written by upstream's `new_user_storate`. **No
    /// biometric data** — it's a system-defined storage container name.
    /// Layout (after status strip):
    ///   `<u16 dbid> <u16 type> <u16 storage> <u16 sz> <2 skip> <value>`.
    #[test]
    fn db_value_root_stgwindsor_layout() {
        // Real status bytes; the 2-byte skip after `sz` we observe as
        // 00 00 on this device — upstream ignores it either way.
        let payload: &[u8] = &[
            0x03, 0x00, // dbid = 3
            0x04, 0x00, // type = 0x0004 (user-storage)
            0x03, 0x00, // storage = 3
            0x0b, 0x00, // size = 11
            0x00, 0x00, // skip / pad
            // The fixed system string written by `db.new_record(1, 4, 3, b'StgWindsor\0')`.
            b'S', b't', b'g', b'W', b'i', b'n', b'd', b's', b'o', b'r', 0x00,
        ];
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), 3);
        assert_eq!(u16::from_le_bytes([payload[2], payload[3]]), 0x0004);
        assert_eq!(u16::from_le_bytes([payload[4], payload[5]]), 3);
        let sz = u16::from_le_bytes([payload[6], payload[7]]) as usize;
        assert_eq!(sz, 11);
        assert_eq!(&payload[10..10 + sz], b"StgWindsor\0");
    }

    /// Real `flash-info` (cmd 0x3e) reply from the user's P70.
    /// Confirms the chip is a Winbond 1 MiB SPI flash with the same 5
    /// partitions hardcoded in upstream's `flash_layout_hardcoded`.
    /// All bytes are public hardware identity, no biometric data.
    #[test]
    fn flash_info_p70_real_layout() {
        let payload: &[u8] = &[
            // 14-byte header
            0xef, 0x00, // jid0 = 0x00ef (Winbond)
            0x40, 0x00, // jid1 = 0x0040
            0x00, 0x10, // blocks = 4096
            0x00, 0x00, // unknown0
            0x00, 0x01, // block_size = 256
            0x00, 0x00, // unknown1
            0x05, 0x00, // partition count = 5
            // partition table — 5 × 12 B
            0x01, 0x04, 0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, // cert store
            0x02, 0x01, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xe0, 0x03, 0x00, // xpfwext
            0x05, 0x05, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, // unknown
            0x06, 0x06, 0x03, 0x00, 0x00, 0x80, 0x04, 0x00, 0x00, 0x80, 0x00, 0x00, // calibration
            0x04, 0x03, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, // template DB
        ];
        let l = parse_flash_info(payload).unwrap();
        assert_eq!(l.ic.jid0, 0x00ef);
        assert_eq!(l.ic.jid1, 0x0040);
        assert_eq!(l.ic.blocks, 4096);
        assert_eq!(l.ic.block_size, 256);
        assert_eq!(l.ic.total_size(), 1_048_576);
        assert_eq!(l.partitions.len(), 5);
        // Locked-in partition layout — must match upstream.
        let want: &[(u8, u8, u16, u32, u32)] = &[
            (1, 4, 0x0007, 0x00001000, 4096),
            (2, 1, 0x0002, 0x00002000, 253952),
            (5, 5, 0x0003, 0x00040000, 32768),
            (6, 6, 0x0003, 0x00048000, 32768),
            (4, 3, 0x0005, 0x00050000, 524288),
        ];
        for (got, w) in l.partitions.iter().zip(want.iter()) {
            assert_eq!(got.id, w.0);
            assert_eq!(got.kind, w.1);
            assert_eq!(got.access, w.2);
            assert_eq!(got.offset, w.3);
            assert_eq!(got.size, w.4);
        }
    }

    #[test]
    fn parse_flash_info_short_header_errors() {
        assert!(matches!(parse_flash_info(&[0u8; 13]), Err(Error::ShortResponse)));
    }

    #[test]
    fn parse_flash_info_truncated_partition_table_errors() {
        // Header claims 5 partitions but only one row of bytes follows.
        let mut buf = vec![
            0xef, 0x00, 0x40, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00,
        ];
        buf.extend_from_slice(&[0u8; 12]);
        assert!(matches!(parse_flash_info(&buf), Err(Error::ShortResponse)));
    }

    /// Real reply to `db-children 3` on the user's device. The root
    /// (StgWindsor) has exactly one child of type `0x0008` ("data").
    /// We do **not** test the child's *contents* — those would be
    /// biometric template bytes. Only the enumeration shape is locked in.
    #[test]
    fn db_children_root_one_data_child() {
        // Synthetic payload reconstructed from the parser-visible fields
        // we observed (parent dbid=3, type=0x0004, storage=3, child
        // count=1, child[0] dbid=0x0004 type=0x0008). The byte gaps
        // (`sz`, trailing skips) we mark zero — upstream ignores them.
        let payload: &[u8] = &[
            0x03, 0x00, // parent dbid
            0x04, 0x00, // parent type (user-storage)
            0x03, 0x00, // storage
            0x00, 0x00, // sz placeholder (upstream ignores)
            0x01, 0x00, // child count
            0x00, 0x00, // skip
            0x04, 0x00, // child[0].dbid
            0x08, 0x00, // child[0].type = data
        ];
        let parent_dbid = u16::from_le_bytes([payload[0], payload[1]]);
        let parent_type = u16::from_le_bytes([payload[2], payload[3]]);
        let cnt = u16::from_le_bytes([payload[8], payload[9]]) as usize;
        assert_eq!(parent_dbid, 3);
        assert_eq!(parent_type, 0x0004);
        assert_eq!(cnt, 1);
        let cid = u16::from_le_bytes([payload[12], payload[13]]);
        let ctype = u16::from_le_bytes([payload[14], payload[15]]);
        assert_eq!(cid, 4);
        assert_eq!(ctype, 0x0008);
    }

    /// Real `db-info` reply from the user's P70 (DB has 2 records,
    /// 1 root). 24-byte header + 2-byte root id. Public structural
    /// data only — the records themselves are *not* dumped here.
    #[test]
    fn db_info_two_records_one_root() {
        let payload: &[u8] = &[
            0x01, 0x00, 0x00, 0x00, // unknown1 = 1
            0x00, 0x00, 0x00, 0x00, // unknown0 = 0
            0x00, 0x00, 0x08, 0x00, // total = 524288
            0x00, 0x04, 0x00, 0x00, // used = 1024
            0x00, 0xfc, 0x07, 0x00, // free = 523264
            0x02, 0x00, // records = 2
            0x01, 0x00, // nroots = 1
            0x03, 0x00, // root[0] = 0x0003
        ];
        let u32_at = |o: usize| u32::from_le_bytes(payload[o..o + 4].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes(payload[o..o + 2].try_into().unwrap());
        assert_eq!(u32_at(0), 1);
        assert_eq!(u32_at(4), 0);
        assert_eq!(u32_at(8), 524_288);
        assert_eq!(u32_at(12), 1024);
        assert_eq!(u32_at(16), 523_264);
        assert_eq!(u16_at(20), 2);
        assert_eq!(u16_at(22), 1);
        assert_eq!(u16_at(24), 0x0003);
    }

    #[test]
    fn tls_cert_block_starts_with_magic() {
        let real_cert_prefix: &[u8] = &[
            0x17, 0x00, 0x00, 0x00, // magic
            0x20, 0x00, 0x00, 0x00, // length-ish marker
        ];
        // crt_hardcoded in upstream `tls.py:23` also begins with `17 00 00 00`.
        // Asserting our parsed bytes match is a soft schema check.
        assert_eq!(&real_cert_prefix[..4], &[0x17, 0x00, 0x00, 0x00]);
        assert_eq!(&real_cert_prefix[4..8], &[0x20, 0x00, 0x00, 0x00]);
    }
}

/// On-chip flash IC identification, returned by cmd `0x3e`.
#[derive(Debug, Clone, Copy)]
pub struct FlashIc {
    /// JEDEC manufacturer id byte (`0xef` = Winbond, `0x20` = ST/Numonyx, …).
    pub jid0: u16,
    /// JEDEC memory-type / capacity word.
    pub jid1: u16,
    pub blocks: u16,
    pub block_size: u16,
}

impl FlashIc {
    pub fn total_size(&self) -> u64 {
        u64::from(self.blocks) * u64::from(self.block_size)
    }
}

/// One row of the device-reported partition table (cmd `0x3e`).
/// Distinct from [`PartitionInfo`] (which is the `0x4302` fwext info).
#[derive(Debug, Clone, Copy)]
pub struct FlashPartition {
    pub id: u8,
    pub kind: u8,
    pub access: u16,
    pub offset: u32,
    pub size: u32,
}

/// Decoded reply to cmd `0x3e`. Layout (after status):
///
/// ```text
/// 14 B header: <u16 jid0, u16 jid1, u16 blocks, u16 unk0,
///               u16 block_size, u16 unk1, u16 partition_count>
/// then partition_count × 12 B records:
/// <u8 id, u8 kind, u16 access, u32 offset, u32 size>
/// ```
#[derive(Debug, Clone)]
pub struct FlashLayout {
    pub ic: FlashIc,
    pub partitions: Vec<FlashPartition>,
}

pub fn parse_flash_info(payload: &[u8]) -> Result<FlashLayout> {
    if payload.len() < 14 {
        return Err(Error::ShortResponse);
    }
    let u16_at = |o: usize| u16::from_le_bytes(payload[o..o + 2].try_into().unwrap());
    let jid0 = u16_at(0);
    let jid1 = u16_at(2);
    let blocks = u16_at(4);
    // payload[6..8] = unknown0
    let block_size = u16_at(8);
    // payload[10..12] = unknown1
    let pcnt = u16_at(12) as usize;
    let need = 14 + pcnt * 12;
    if payload.len() < need {
        return Err(Error::ShortResponse);
    }
    let mut partitions = Vec::with_capacity(pcnt);
    for i in 0..pcnt {
        let off = 14 + i * 12;
        partitions.push(FlashPartition {
            id: payload[off],
            kind: payload[off + 1],
            access: u16::from_le_bytes(payload[off + 2..off + 4].try_into().unwrap()),
            offset: u32::from_le_bytes(payload[off + 4..off + 8].try_into().unwrap()),
            size: u32::from_le_bytes(payload[off + 8..off + 12].try_into().unwrap()),
        });
    }
    Ok(FlashLayout { ic: FlashIc { jid0, jid1, blocks, block_size }, partitions })
}

/// Convenience: send `0x43 <partition>` and decode the result into a [`FwextState`].
pub fn query_partition(chan: &mut Channel, partition: u8) -> Result<FwextState> {
    let resp = chan.cmd(&[CMD_GET_PARTITION, partition])?;
    let (status, payload) = split_status(&resp)?;
    Ok(match status {
        STATUS_NO_FW => FwextState::CleanSlate,
        0 => FwextState::Loaded(PartitionInfo::parse(payload)?),
        other => FwextState::OtherStatus { status: other, payload: payload.to_vec() },
    })
}

impl RomInfo {
    /// `true` if the firmware build timestamp is older than
    /// [`FIRMWARE_STALE_SECS`] before `now_unix`. A `now_unix` of 0 means
    /// "wall clock unavailable" and disables the check.
    pub fn is_stale(&self, now_unix: u64) -> bool {
        if now_unix == 0 {
            return false;
        }
        u64::from(self.timestamp).saturating_add(FIRMWARE_STALE_SECS) < now_unix
    }

    pub fn parse(payload: &[u8]) -> Result<Self> {
        if payload.len() < 16 {
            return Err(Error::ShortResponse);
        }
        let timestamp = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let build = u32::from_le_bytes(payload[4..8].try_into().unwrap());
        let major = payload[8];
        let minor = payload[9];
        // payload[10] is padding
        let product = payload[11];
        // payload[12..15] is padding
        let u1 = payload[15];
        Ok(Self { timestamp, build, major, minor, product, u1 })
    }
}
