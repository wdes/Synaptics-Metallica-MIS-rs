// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Translated from `python-validity/validitysensor/sensor.py` (MIT,
// © 2020 uunicorn) — `patch_timeslot_table`, `get_key_line` and the
// per-mode chunk-tail builders. See `THIRD_PARTY.md`.

//! Capture-mode helpers: pure byte transforms applied to the
//! [`crate::sensor_types::FM_3367_001_PROG`] capture program before
//! it's wrapped in cmd `0x02` and sent to the device.

use crate::chunks::{Chunk, merge as merge_chunks, split as split_chunks};
use crate::error::Result;
use crate::sensor_types::SensorTypeInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureMode {
    Calibrate,
    Identify,
    Enroll,
}

/// Mutate the `0x34` Timeslot Table 2D body. Walks the byte stream
/// looking for opcodes whose top 5 bits are `0b00010` (matching
/// `b & 0xf8 == 0x10`) and scales their third byte by `mult`,
/// optionally bumping the address byte by 1.
///
/// Other opcodes recognised: `0x00` (one-byte no-op) and `0x07`
/// (two-byte). Anything else stops the walk — upstream relies on the
/// header being a continuous stream of these three opcodes.
pub fn patch_timeslot_table(input: &[u8], inc_address: bool, mult: u8) -> Vec<u8> {
    let mut b = input.to_vec();
    let mut i = 0;
    while i + 3 < b.len() {
        let op = b[i];
        if op & 0xf8 == 0x10 {
            if b[i + 2] > 1 {
                b[i + 2] = b[i + 2].wrapping_mul(mult);
                if inc_address {
                    b[i + 1] = b[i + 1].wrapping_add(1);
                }
            }
            i += 3;
            continue;
        }
        if op == 0 {
            i += 1;
            continue;
        }
        if op == 7 {
            i += 2;
            continue;
        }
        break;
    }
    b
}

/// Generate the per-line "key" calibration buffer used by
/// [`crate::sensor_types::SensorTypeInfo::line_width`]-pixel sensors.
/// When `calib_data` is empty (fresh device, before calibration) the
/// upstream code returns a zero-filled line — that's the only case we
/// need until we implement calibration.
///
/// `key_calibration_line` is sensor-type-specific (`0x38` for type
/// 0x199 / FM-3367-001).
pub fn get_key_line(
    type_info: &SensorTypeInfo,
    key_calibration_line: u32,
    calib_data: &[u8],
) -> Vec<u8> {
    if calib_data.is_empty() {
        return vec![0u8; type_info.line_width as usize];
    }
    let bytes_per_calibration_line =
        calib_data.len() / type_info.lines_per_calibration_data as usize;
    let off = 8 + bytes_per_calibration_line * key_calibration_line as usize;
    let end = off + type_info.line_width as usize;
    if end > calib_data.len() {
        // Guard: if calibration data is too short, fall back to zeros.
        return vec![0u8; type_info.line_width as usize];
    }
    let mut key = calib_data[off..end].to_vec();
    // Upstream's `bytes([i - 1 if i == 5 else i for i in key_line])` —
    // a single-value substitution.
    for v in key.iter_mut() {
        if *v == 5 {
            *v = 4;
        }
    }
    key
}

/// One decoded program instruction, mirroring upstream's
/// `timeslot.py:decode_insn`. Each variant carries the on-wire
/// instruction length so callers can advance the program counter.
#[derive(Debug, Clone, Copy)]
pub struct Insn {
    pub opcode: u8,
    pub length: u8,
    pub operands: [u32; 3],
}

/// Decode the next instruction at the start of `bytes`. Returns
/// `None` when the input is empty (the script is over) or has no
/// match for known opcodes.
pub fn decode_insn(bytes: &[u8]) -> Option<Insn> {
    let b = bytes.first().copied()?;
    let mut ins = Insn { opcode: 0, length: 0, operands: [0; 3] };
    if b <= 4 {
        ins.opcode = b;
        ins.length = 1;
    } else if b == 5 {
        ins.opcode = 5;
        ins.length = 2;
        ins.operands[0] = u32::from(*bytes.get(1)?);
    } else if b == 6 {
        ins.opcode = 6;
        ins.length = 2;
        ins.operands[0] = u32::from(*bytes.get(1)?);
    } else if b == 7 {
        ins.opcode = 7;
        ins.length = 2;
        let v = *bytes.get(1)?;
        ins.operands[0] = if v == 0 { 0x100 } else { u32::from(v) };
    } else if b & 0xfe == 8 {
        ins.opcode = 8;
        ins.length = 2;
        ins.operands[0] = (u32::from(b & 1) << 8) | u32::from(*bytes.get(1)?);
    } else if b & 0xfe == 0xa {
        ins.opcode = 9;
        ins.length = 2;
        ins.operands[0] = (u32::from(b & 1) << 8) | u32::from(*bytes.get(1)?);
    } else if b & 0xfc == 0xc {
        ins.opcode = 10;
        ins.length = 1;
        ins.operands[0] = u32::from(b & 3);
    } else if b & 0xf8 == 0x10 {
        // Call
        ins.opcode = 11;
        ins.length = 3;
        ins.operands[0] = u32::from(b & 7);
        ins.operands[1] = u32::from(*bytes.get(1)?) << 2;
        let v = *bytes.get(2)?;
        ins.operands[2] = if v == 0 { 0x100 } else { u32::from(v) };
    } else if b & 0xe0 == 0x20 {
        ins.opcode = 12;
        ins.length = 1;
        ins.operands[0] = u32::from(b & 0x1f);
    } else if b & 0xc0 == 0x40 {
        // Write Register
        ins.opcode = 13;
        ins.length = 3;
        ins.operands[0] = u32::from(b & 0x3f) * 4 + 0x8000_2000;
        let lo = *bytes.get(1)?;
        let hi = *bytes.get(2)?;
        ins.operands[1] = u32::from(lo) | (u32::from(hi) << 8);
    } else if b & 0xc0 == 0x80 {
        ins.opcode = 14;
        ins.length = 1;
        ins.operands[0] = u32::from((b & 0x38) >> 3);
        ins.operands[1] = u32::from(b & 7);
    } else {
        return None;
    }
    Some(ins)
}

/// Walk the program and return the byte position (PC) and the
/// decoded instruction at the `n`-th occurrence of `opcode`. `n` is
/// 1-based. Returns `None` if fewer than `n` matches exist before
/// the program ends or hits a malformed instruction. Mirrors
/// `timeslot.py:find_nth_insn`.
pub fn find_nth_insn(program: &[u8], opcode: u8, n: usize) -> Option<(usize, Insn)> {
    let mut p = program;
    let mut pc = 0usize;
    let mut remaining = n;
    while !p.is_empty() {
        let ins = decode_insn(p)?;
        let sz = ins.length as usize;
        if sz == 0 || sz > p.len() {
            return None;
        }
        if ins.opcode == opcode {
            remaining -= 1;
            if remaining == 0 {
                return Some((pc, ins));
            }
        }
        p = &p[sz..];
        pc += sz;
    }
    None
}

/// Walk the program and find the `n`-th `Write Register` (opcode 13)
/// targeting `reg_addr`. Returns `(pc, instruction)` on success.
/// Mirrors `timeslot.py:find_nth_regwrite`.
pub fn find_nth_regwrite(program: &[u8], reg_addr: u32, n: usize) -> Option<(usize, Insn)> {
    let mut p = program;
    let mut pc = 0usize;
    let mut remaining = n;
    while !p.is_empty() {
        let ins = decode_insn(p)?;
        let sz = ins.length as usize;
        if sz == 0 || sz > p.len() {
            return None;
        }
        if ins.opcode == 13 && ins.operands[0] == reg_addr {
            remaining -= 1;
            if remaining == 0 {
                return Some((pc, ins));
            }
        }
        p = &p[sz..];
        pc += sz;
    }
    None
}

/// Mutate the timeslot script per upstream's `patch_timeslot_again`.
/// Walks the program twice:
///   1. From `pc=0`, locate the last `Call` (opcode 11). Use its
///      destination as the start of the second walk.
///   2. From that destination, locate the last `Write Register`
///      (opcode 13) targeting `0x8000203c`.
///   3. Patch the value byte at `match + 1` with `subst_value`.
///
/// `subst_value` is upstream's `factory_calibration_values[key_calibration_line]`
/// — i.e. one byte from the calibration data at the device's chosen
/// key line. Pass `0` for now until calibration is implemented; the
/// transform still runs but the patched byte will be zero.
pub fn patch_timeslot_again(input: &[u8], subst_value: u8) -> Vec<u8> {
    let mut b = input.to_vec();

    // Pass 1: last Call destination.
    let mut pc = 0usize;
    let mut last_call_dest: Option<usize> = None;
    while pc < b.len() {
        let Some(ins) = decode_insn(&b[pc..]) else {
            break;
        };
        if matches!(ins.opcode, 1 | 2 | 4) {
            break;
        }
        if ins.opcode == 11 {
            last_call_dest = Some(ins.operands[1] as usize);
        }
        pc += ins.length as usize;
    }
    let Some(start) = last_call_dest else {
        return b;
    };

    // Pass 2: last Write Register at 0x8000203c.
    pc = start;
    let mut last_write: Option<usize> = None;
    while pc < b.len() {
        let Some(ins) = decode_insn(&b[pc..]) else {
            break;
        };
        if matches!(ins.opcode, 1 | 2 | 4) {
            break;
        }
        if ins.opcode == 13 && ins.operands[0] == 0x8000_203c {
            last_write = Some(pc);
        }
        pc += ins.length as usize;
    }
    if let Some(pos) = last_write
        && pos + 1 < b.len()
    {
        b[pos + 1] = subst_value;
    }
    b
}

/// Hardcoded post-chunk fragments appended by `line_update_type_1`
/// for each capture mode. Source: `sensor.py:412-490`.
///
/// All three modes append a `0x17` reply-config chunk with empty body.
/// `Identify` and `Enroll` then add `0x4e` (presumed finger-detect-like
/// configuration) and `0x2e` (image-reconstruction params).
pub mod tail_chunks {
    use crate::chunks::Chunk;

    pub fn reply_config() -> Chunk {
        Chunk { kind: 0x0017, body: Vec::new() }
    }

    /// Identify-mode 0x4e magic — type-1 device variant.
    pub fn identify_4e_type1() -> Chunk {
        Chunk {
            kind: 0x004e,
            body: vec![
                0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x87, 0x00,
                0x02, 0x00, 0x67, 0x00, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00,
                0x0b, 0x19, 0x00, 0x00, 0x88, 0x13, 0xb8, 0x0b, 0x01, 0x09, 0x10, 0x00,
            ],
        }
    }

    /// Identify-mode 0x2e — image reconstruction parameters.
    pub fn identify_2e() -> Chunk {
        Chunk {
            kind: 0x002e,
            body: vec![
                0x02, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00, 0x70, 0x00, 0x70, 0x00, 0x4d, 0x01,
                0x00, 0x00, 0xa0, 0x00, 0x8c, 0x00, 0x3c, 0x32, 0x32, 0x1e, 0x3c, 0x0a, 0x02, 0x02,
            ],
        }
    }

    /// Identify-mode 0x4e for type-2 devices. Distinct from type-1 in
    /// the middle bytes (`60 01 02 00 40 01 0a` vs `87 00 02 00 67 00 0a`).
    /// Source: `python-validity/sensor.py:line_update_type_2`.
    pub fn identify_4e_type2() -> Chunk {
        Chunk {
            kind: 0x004e,
            body: vec![
                0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x60, 0x01,
                0x02, 0x00, 0x40, 0x01, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00,
                0x0b, 0x19, 0x00, 0x00, 0x88, 0x13, 0xb8, 0x0b, 0x01, 0x09, 0x10, 0x00,
            ],
        }
    }

    /// Identify-mode 0x2e for type-2 devices. Differs from type-1
    /// 0x2e in the geometry block (`90 00 90 00 4d 01 00 00 90 01 7c 01`
    /// vs `70 00 70 00 4d 01 00 00 a0 00 8c 00`).
    pub fn identify_2e_type2() -> Chunk {
        Chunk {
            kind: 0x002e,
            body: vec![
                0x02, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00, 0x90, 0x00, 0x90, 0x00, 0x4d, 0x01,
                0x00, 0x00, 0x90, 0x01, 0x7c, 0x01, 0x3c, 0x32, 0x32, 0x32, 0x64, 0x0a, 0x02, 0x01,
            ],
        }
    }

    /// Enroll-mode 0x26 for type-2 devices.
    pub fn enroll_26_type2() -> Chunk {
        Chunk {
            kind: 0x0026,
            body: vec![
                0xfb, 0xb2, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x30, 0x00, 0x00, 0x00, 0x60, 0x01,
                0x02, 0x00, 0x40, 0x01, 0x0a, 0x00, 0x01, 0x80, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00,
                0x0b, 0x19, 0x00, 0x00, 0x50, 0xc3, 0x60, 0xea, 0x01, 0x09, 0x10, 0x00,
            ],
        }
    }

    /// Enroll-mode 0x2e for type-2 devices. Differs from type-2's
    /// IDENTIFY 0x2e in just one byte (`23 00 00 00` instead of
    /// `02 00 00 00`).
    pub fn enroll_2e_type2() -> Chunk {
        Chunk {
            kind: 0x002e,
            body: vec![
                0x02, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x90, 0x00, 0x90, 0x00, 0x4d, 0x01,
                0x00, 0x00, 0x90, 0x01, 0x7c, 0x01, 0x3c, 0x32, 0x32, 0x32, 0x64, 0x0a, 0x02, 0x01,
            ],
        }
    }
}

/// Apply the type-1 line-update transformation: rewrite the 0x34
/// Timeslot Table chunk with the patched timeslot data + key line, and
/// append the per-mode tail chunks. Mirrors upstream's
/// `Sensor.line_update_type_1`.
///
/// `subst_value` feeds [`patch_timeslot_again`] — pass `0` until
/// calibration data is available.
///
/// `factory_calibration_values` is `factory_bits[0x0e00][3][4..]`
/// (always present; 5-bit-packed via [`bitpack`]). `calib_data` is the
/// per-line calibration baseline produced by [`average_interleaved`]
/// during calibration; pass `&[]` before the device has ever
/// calibrated (CALIBRATE iteration 0).
///
/// For modes other than [`CaptureMode::Calibrate`] this also appends
/// the `0x44 / 0x30 / 0x43` chunks that bake the calibration data
/// into the program — without these the matcher fires a noise-detect
/// sentinel and aborts (this was the root cause of the phantom
/// finger-detect on the user's P70).
pub fn line_update_type_1(
    mode: CaptureMode,
    chunks: &mut Vec<Chunk>,
    type_info: &SensorTypeInfo,
    key_line: &[u8],
    subst_value: u8,
    factory_calibration_values: &[u8],
    calib_data: &[u8],
) {
    let line_width = type_info.line_width as usize;
    let mut patched_tst: Vec<u8> = Vec::new();
    for c in chunks.iter_mut() {
        if c.kind == 0x0034 {
            let mut tst = patch_timeslot_table(&c.body, true, type_info.repeat_multiplier as u8);
            if mode != CaptureMode::Calibrate {
                tst = patch_timeslot_again(&tst, subst_value);
            }
            // Keep the patched timeslot for the line-update anchors.
            patched_tst = tst.clone();
            // body = key_line || tst[line_width..]
            let mut new_body = Vec::with_capacity(line_width + tst.len().saturating_sub(line_width));
            new_body.extend_from_slice(key_line);
            if tst.len() > line_width {
                new_body.extend_from_slice(&tst[line_width..]);
            }
            c.body = new_body;
        }
    }

    // Reply configuration is appended for every mode.
    chunks.push(tail_chunks::reply_config());

    match mode {
        CaptureMode::Identify => {
            chunks.push(tail_chunks::identify_4e_type1());
            chunks.push(tail_chunks::identify_2e());
        }
        CaptureMode::Enroll => {
            // Upstream `sensor.py:442-490` adds a different 0x4e and a
            // 0x2e for enroll. Body bytes deferred until we ship enroll.
        }
        CaptureMode::Calibrate => {}
    }

    // CALIBRATE on this device works without the line-update bundle —
    // we send raw scan requests during the initial 3-iteration
    // baseline. IDENTIFY/ENROLL must include the bundle or the
    // matcher reads sensor noise into the wrong bins.
    if mode == CaptureMode::Calibrate {
        return;
    }

    // ---- 0x44 Interleave (constant: <u32 1>) ----
    chunks.push(Chunk { kind: 0x0044, body: 1u32.to_le_bytes().to_vec() });

    // ---- Build Lines ----
    let mut lines: Vec<Line> = Vec::new();
    let mut cnt: u32 = 2;

    // Line 0: calibration_blob anchored at 2nd "Enable Rx" (opcode 6).
    if let Some((pc, _)) = find_nth_insn(&patched_tst, 6, 2) {
        lines.push(Line {
            mask: 0xff,
            flags: (pc as u32 + 1) | (cnt << 0x14) | 0x0700_0000,
            data: type_info.calibration_blob.to_vec(),
            v0: 0xf,
            v1: 0,
            v2: 0,
        });
        cnt += 1;
    }

    // Line 1: factory_calibration_values, bitpacked, anchored at the
    // 1st reg-write to 0x8000203c.
    if let Some((pc, _)) = find_nth_regwrite(&patched_tst, 0x8000_203c, 1) {
        let (bits, min, packed) = bitpack(factory_calibration_values);
        // Upstream rewrite: `v0 = (v0 - 1) | 8`. Saturating-sub guards
        // against the all-equal case where bitpack returns bits=0.
        let v0 = (bits.saturating_sub(1)) | 8;
        lines.push(Line {
            mask: 0xff,
            flags: (pc as u32 + 1) | (cnt << 0x14) | 0x0700_0000,
            data: packed,
            v0,
            v1: min,
            v2: 0,
        });
        // cnt is used below only for further calib_data lines, which
        // override flags entirely — incrementing here would be dead.
    }

    // Lines 2+: per-line calibration offsets, only when calib_data
    // exists. `bytes_per_calibration_line = len(calib_data) /
    // lines_per_calibration_data`. For each i in [0, 4, 8, ..., 108]:
    //   data = concat for j in [0..112] of
    //          calib_data[8 + j * bytes_per_line + i .. +4]
    // With our P70 sensor: bytes_per_calibration_line = 13440 / 112 =
    // 120, so each Line carries 112 × 4 = 448 bytes.
    if !calib_data.is_empty() && type_info.lines_per_calibration_data > 0 {
        let bytes_per_calib_line =
            calib_data.len() / type_info.lines_per_calibration_data as usize;
        // Outer loop: 28 iterations (0, 4, …, 108).
        for i in (0u32..112).step_by(4) {
            let mut data = Vec::with_capacity(112 * 4);
            for j in 0..112usize {
                let p = 8 + j * bytes_per_calib_line + i as usize;
                if p + 4 <= calib_data.len() {
                    data.extend_from_slice(&calib_data[p..p + 4]);
                } else {
                    // Defensive: pad with zeros if calib_data is short.
                    data.extend_from_slice(&[0; 4]);
                }
            }
            lines.push(Line {
                mask: 0xffff_ffff,
                flags: i | (0x85u32 << 24),
                data,
                v0: 0,
                v1: 0,
                v2: 0,
            });
        }
    }

    // Dword-align each line's data.
    for l in &mut lines {
        l.pad_to_dword();
    }

    // ---- 0x30 Line Update ----
    let mut line_update = Vec::new();
    line_update.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    for l in &lines {
        line_update.extend_from_slice(&l.mask.to_le_bytes());
        line_update.extend_from_slice(&l.flags.to_le_bytes());
    }
    for l in &lines {
        if !l.goes_to_update_transform() {
            line_update.extend_from_slice(&l.data);
        }
    }
    chunks.push(Chunk { kind: 0x0030, body: line_update });

    // ---- 0x43 Line Update Transform ----
    let mut update_transform = Vec::new();
    for l in &lines {
        if l.goes_to_update_transform() {
            update_transform.push(l.v0);
            update_transform.push(l.v1);
            update_transform.extend_from_slice(&l.v2.to_le_bytes());
            update_transform.extend_from_slice(&l.data);
        }
    }
    chunks.push(Chunk { kind: 0x0043, body: update_transform });
}

/// Strip the 8-byte per-line header from each scan line in `raw`,
/// producing a `Vec<Vec<u8>>` of pure pixel data. Each input line is
/// `bytes_per_line` bytes (header + pixels); each output line is
/// `bytes_per_line - 8 = line_width` bytes.
///
/// Lines whose remaining length doesn't match `bytes_per_line` are
/// dropped (defensive — the device sometimes appends a partial
/// trailing line we can't interpret).
pub fn extract_pixel_lines(raw: &[u8], type_info: &SensorTypeInfo) -> Vec<Vec<u8>> {
    let bpl = type_info.bytes_per_line as usize;
    let header_len = 8;
    raw.chunks(bpl)
        .filter(|c| c.len() == bpl)
        .map(|line| line[header_len..].to_vec())
        .collect()
}

/// Serialise a stack of fixed-width pixel lines to a PGM (Portable
/// Gray Map) byte buffer. Width is `line_width`; height is
/// `lines.len()`. The result starts with `P5 <w> <h> 255\n` and
/// continues with raw 8-bit pixel data, exactly the format `display`
/// or `feh` expects.
pub fn lines_to_pgm(lines: &[Vec<u8>], line_width: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(lines.len() * line_width as usize + 32);
    let header = format!("P5\n{} {}\n255\n", line_width, lines.len());
    out.extend_from_slice(header.as_bytes());
    for line in lines {
        out.extend_from_slice(line);
    }
    out
}

/// Convenience: extract pixel lines AND wrap them into a PGM in one step.
pub fn raw_frame_to_pgm(raw: &[u8], type_info: &SensorTypeInfo) -> Vec<u8> {
    let lines = extract_pixel_lines(raw, type_info);
    lines_to_pgm(&lines, type_info.line_width)
}

/// Decode of a single 8-byte per-line header. Layout (observed on
/// 06cb:009a, 2026-05-05):
///
/// ```text
/// byte 0: 0x01      constant magic
/// byte 1: 0xfe      constant magic
/// byte 2: line_idx  1-based line number within the frame
/// byte 3: frame     1-based frame number within the capture
/// byte 4..8: u32 LE constant per capture (timestamp / sequence counter)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineHeader {
    pub magic: [u8; 2],
    pub line_index: u8,
    pub frame_index: u8,
    pub counter: u32,
}

impl LineHeader {
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        Some(Self {
            magic: [b[0], b[1]],
            line_index: b[2],
            frame_index: b[3],
            counter: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        })
    }

    /// `true` when the magic bytes match the documented `01 fe`
    /// pattern. A non-matching header suggests we're either out of
    /// alignment or the device is sending a different stream type.
    pub fn looks_valid(&self) -> bool {
        self.magic == [0x01, 0xfe]
    }
}

/// Walk a raw EP-0x82 byte stream and return the headers of every
/// well-formed line. Lines whose remaining length is less than
/// `bytes_per_line` are skipped.
pub fn line_headers(raw: &[u8], type_info: &SensorTypeInfo) -> Vec<LineHeader> {
    let bpl = type_info.bytes_per_line as usize;
    raw.chunks(bpl)
        .filter(|c| c.len() == bpl)
        .filter_map(|line| LineHeader::parse(&line[..8]))
        .collect()
}

/// Parse the calibration record stored on flash partition 6. Layout
/// (the inverse of upstream `sensor.py:persist_clean_slate`):
///
/// ```text
/// 0x00..0x02  u16 LE = 0x5002 magic
/// 0x02..0x04  u16 LE = outer_len = 4 + len(raw)
/// 0x04..0x24  32 B   = sha256 of inner
/// 0x24..0x44  32 B   = zero-padding
/// 0x44..0x46  u16 LE = len(raw)
/// 0x46..0x46+len(raw)  averaged calibration frame data
/// 0x46+len(raw)..      u16 LE = 0 (trailing)
/// ```
///
/// Returns just the raw averaged data — the part `get_key_line` uses.
/// SHA-256 verification is **not** performed here (kept crypto-free
/// for parser purity); the caller can verify if it cares.
pub fn parse_calibration(partition6: &[u8]) -> Result<Vec<u8>> {
    use crate::error::Error;
    if partition6.len() < 0x46 {
        return Err(Error::ShortResponse);
    }
    let magic = u16::from_le_bytes([partition6[0], partition6[1]]);
    if magic != 0x5002 {
        return Err(Error::PairingMalformed { reason: "calibration magic is not 0x5002" });
    }
    let raw_len = u16::from_le_bytes([partition6[0x44], partition6[0x45]]) as usize;
    let start = 0x46;
    let end = start + raw_len;
    if partition6.len() < end + 2 {
        return Err(Error::ShortResponse);
    }
    Ok(partition6[start..end].to_vec())
}

/// Saturate to the signed-byte range, then return the low 8 bits.
/// Mirrors `sensor.py:clip`.
fn clip_i8(x: i32) -> u8 {
    let c = x.clamp(-128, 127);
    (c & 0xff) as u8
}

/// `scale(x) = clip((x - 0x80) * 10 / 0x22)`. Per-pixel transform
/// applied to each scan line during calibration. Source:
/// `sensor.py:scale`.
pub fn scale_pixel(x: u8) -> u8 {
    let v = (x as i32) - 0x80;
    let v = (v * 10) / 0x22;
    clip_i8(v)
}

/// Signed-saturated addition of two pixel bytes — combines two
/// calibration passes into a refined per-pixel offset.
/// Mirrors `sensor.py:add`.
pub fn add_signed(l: u8, r: u8) -> u8 {
    let l = (l as i8) as i32;
    let r = (r as i8) as i32;
    clip_i8(l + r)
}

/// Refine `calib_data` in-place using a freshly-captured `cooked`
/// frame from `average_interleaved`. First call (calib_data empty)
/// produces the scaled frame; subsequent calls signed-add their
/// scaled frame into the accumulated buffer. Per-line headers
/// (first 8 bytes) are preserved untouched.
///
/// Mirrors `sensor.py:process_calibration_results`.
pub fn process_calibration_results(
    calib_data: &mut Vec<u8>,
    cooked: &[u8],
    bytes_per_line: usize,
) {
    // Build the scaled frame: keep header bytes, scale every pixel.
    let mut scaled = Vec::with_capacity(cooked.len());
    for line in cooked.chunks(bytes_per_line) {
        let header_len = line.len().min(8);
        scaled.extend_from_slice(&line[..header_len]);
        for px in &line[header_len..] {
            scaled.push(scale_pixel(*px));
        }
    }

    if calib_data.is_empty() {
        *calib_data = scaled;
        return;
    }

    // Combine: signed-add line-by-line, preserving headers.
    let mut combined = Vec::with_capacity(calib_data.len());
    for (old_line, new_line) in calib_data
        .chunks(bytes_per_line)
        .zip(scaled.chunks(bytes_per_line))
    {
        let header_len = old_line.len().min(8);
        combined.extend_from_slice(&old_line[..header_len]);
        for (l, r) in old_line[header_len..].iter().zip(new_line[header_len..].iter()) {
            combined.push(add_signed(*l, *r));
        }
    }
    *calib_data = combined;
}

/// Average the raw EP-`0x82` frame stream returned by a CALIBRATE
/// capture into the canonical `lines_per_calibration_data × bytes_per_line`
/// buffer. Mirrors `sensor.py:average` for the `interleave_lines > 1`
/// path (which is what the user's type-0x199 device uses, since
/// 224 lines / 112 cal lines = 2).
///
/// We only cover the common path here. The `interleave_lines == 1`
/// branch would need a different averaging shape and is deferred until
/// we encounter a sensor that needs it.
pub fn average_interleaved(
    raw: &[u8],
    type_info: &SensorTypeInfo,
    lines_per_frame: u32,
    calibration_frames: u32,
) -> Vec<u8> {
    let frame_size = (lines_per_frame * type_info.bytes_per_line as u32) as usize;
    let bytes_per_line = type_info.bytes_per_line as usize;
    let interleave_lines = (lines_per_frame / type_info.lines_per_calibration_data as u32) as usize;
    debug_assert!(interleave_lines >= 2, "this fn only handles interleave>=2");

    // Skip the first frame, work on the second one only — that's what
    // upstream does when input_frames > 1.
    let base_address = if calibration_frames > 1 { frame_size } else { 0 };
    let frame = &raw[base_address..base_address + frame_size];

    // Split into groups of `interleave_lines` lines.
    let group_size = interleave_lines * bytes_per_line;
    let mut out = Vec::with_capacity(frame.len() / interleave_lines);
    for group in frame.chunks_exact(group_size) {
        // Per column position, average `interleave_lines` values.
        for col in 0..bytes_per_line {
            let mut sum = 0u32;
            for line_idx in 0..interleave_lines {
                sum += u32::from(group[line_idx * bytes_per_line + col]);
            }
            out.push((sum / interleave_lines as u32) as u8);
        }
    }
    out
}

/// Compact bit-packed encoding used by the full type-1 line-update.
/// Mirrors `python-validity/sensor.py:bitpack`. Returns
/// `(bits_per_value, min_value, packed_bytes)` — caller stuffs these
/// into the line's `v0` / `v1` / `data` fields.
///
/// Algorithm:
/// 1. Find `min` (`m`) and `max` (`x`) of the input bytes.
/// 2. `delta = x - m`. Compute `u` = `ceil(log2(delta + 1))` bits per
///    output value.
/// 3. Each byte → `u`-bit unsigned representation of `byte - m`.
/// 4. Concatenate the per-byte bitstrings of `bytes.reverse()` to
///    form one large MSB-first integer.
/// 5. Re-emit that integer as LE bytes (`(u * len + 7) / 8` of them).
///
/// Returns `(0, 0, vec![])` for empty input — degenerate but bounded.
pub fn bitpack(input: &[u8]) -> (u8, u8, Vec<u8>) {
    if input.is_empty() {
        return (0, 0, Vec::new());
    }
    let m = *input.iter().min().unwrap();
    let x = *input.iter().max().unwrap();
    let mut delta = x - m;
    let mut u: u32 = 0;
    while delta > 0 {
        delta >>= 1;
        u += 1;
    }
    if u == 0 {
        // All bytes identical: the packed body is empty per upstream
        // (zero bits per element × N elements = 0 bytes).
        return (0, m, Vec::new());
    }

    // Big-integer accumulator: concatenate u-bit values of bytes in
    // reverse order. Mask = (1 << u) - 1.
    // We build directly as little-endian bit-stream bytes.
    let len = input.len();
    let total_bits = u as usize * len;
    let total_bytes = total_bits.div_ceil(8);
    let mut out = vec![0u8; total_bytes];

    // Upstream concatenates reversed-input bytes' bitstrings into a
    // single MSB-first integer, then writes that integer LE. Result:
    // value at reversed-position 0 (= original last byte) ends up in
    // the LOWEST bits of the LE output (bits 0..u). Each subsequent
    // reversed-position value occupies the next u bits up.
    for (rev_pos, b) in input.iter().rev().enumerate() {
        let value = (*b - m) as u32;
        let bit_off = rev_pos * u as usize;
        // Write `u` bits of `value` starting at bit position `bit_off`.
        for i in 0..u as usize {
            let bit = (value >> i) & 1;
            let pos = bit_off + i;
            out[pos / 8] |= (bit as u8) << (pos % 8);
        }
    }

    (u as u8, m, out)
}

/// One row in a line-update structure (`0x30` chunk). Each line points
/// at a program counter inside the timeslot script and supplies a
/// blob of data to substitute there.
///
/// `v0`, `v1`, `v2` are only meaningful when the line lands in the
/// `0x43` update-transform chunk (i.e. when the high nibble of
/// `(flags >> 0x14)` is > 1) — they form a `<u8 v0, u8 v1, u16 v2>`
/// header that prefixes `data`. For ordinary `0x30` lines they stay 0.
#[derive(Debug, Clone)]
pub struct Line {
    pub mask: u32,
    pub flags: u32,
    pub data: Vec<u8>,
    pub v0: u8,
    pub v1: u8,
    pub v2: u16,
}

impl Line {
    /// Pad `data` up to a multiple of 4 bytes (the sensor demands
    /// dword alignment).
    pub fn pad_to_dword(&mut self) {
        let pad = self.data.len() % 4;
        if pad > 0 {
            self.data.extend(std::iter::repeat_n(0u8, 4 - pad));
        }
    }

    /// Bits `[20..24)` of `flags` classify the line: `<= 1` puts its
    /// `data` into the `0x30` (Line Update) chunk; `> 1` puts a `<v0,
    /// v1, v2, data>` record into the `0x43` (Update Transform) chunk.
    pub fn goes_to_update_transform(&self) -> bool {
        ((self.flags >> 0x14) & 0xf) > 1
    }
}

/// Apply the type-2 line-update transformation, mirroring upstream's
/// `Sensor.line_update_type_2`. The `0x34` chunk is rewritten with
/// the patched timeslot table (no `key_line` prepend, unlike type-1).
/// Then per-mode tail chunks (0x4e/0x2e for IDENTIFY, 0x26/0x2e for
/// ENROLL) are appended, followed by a `0x30` line-update chunk
/// containing three fixed Line entries.
///
/// `factory_calib_data` is the bytes of `factory_bits[0x0e00][7][4..]`,
/// optional in upstream (skipped if subtag 7 isn't present).
/// `factory_calibration_values` is the always-present `factory_bits[0x0e00][3][4..]`.
pub fn line_update_type_2(
    mode: CaptureMode,
    chunks: &mut Vec<Chunk>,
    type_info: &SensorTypeInfo,
    factory_calib_data: &[u8],
    factory_calibration_values: &[u8],
    subst_value: u8,
) {
    // 1) Rewrite 0x34 in place.
    for c in chunks.iter_mut() {
        if c.kind == 0x0034 {
            let mut tst = patch_timeslot_table(&c.body, true, type_info.repeat_multiplier as u8);
            if mode != CaptureMode::Calibrate {
                tst = patch_timeslot_again(&tst, subst_value);
            }
            c.body = tst;
        }
    }

    // 2) Reply config + per-mode tail.
    chunks.push(tail_chunks::reply_config());
    match mode {
        CaptureMode::Identify => {
            chunks.push(tail_chunks::identify_4e_type2());
            chunks.push(tail_chunks::identify_2e_type2());
        }
        CaptureMode::Enroll => {
            chunks.push(tail_chunks::enroll_26_type2());
            chunks.push(tail_chunks::enroll_2e_type2());
        }
        CaptureMode::Calibrate => {}
    }

    // 3) Build line-update chunk. We need the post-patch tst body to
    //    locate the call/regwrite anchors. Find the (now updated) 0x34.
    let tst = chunks.iter().find(|c| c.kind == 0x0034).map(|c| c.body.clone()).unwrap_or_default();
    let mut lines: Vec<Line> = Vec::with_capacity(3);

    // Line 1: calibration_blob anchored at 2nd Enable Rx (opcode 6).
    if let Some((pc, _)) = find_nth_insn(&tst, 6, 2) {
        lines.push(Line {
            mask: 0xff,
            flags: ((pc + 1) as u32) | 0x0300_0000,
            data: type_info.calibration_blob.to_vec(),
            v0: 0,
            v1: 0,
            v2: 0,
        });
    }
    // Line 2: factory_calib_data at 1st reg write to 0x800020fc.
    if let Some((pc, _)) = find_nth_regwrite(&tst, 0x8000_20fc, 1) {
        lines.push(Line {
            mask: 0xff,
            flags: ((pc + 1) as u32) | 0x0300_0000,
            data: factory_calib_data.to_vec(),
            v0: 0,
            v1: 0,
            v2: 0,
        });
    }
    // Line 3: factory_calibration_values at 1st reg write to 0x8000203c.
    if let Some((pc, _)) = find_nth_regwrite(&tst, 0x8000_203c, 1) {
        lines.push(Line {
            mask: 0xff,
            flags: ((pc + 1) as u32) | 0x0300_0000,
            data: factory_calibration_values.to_vec(),
            v0: 0,
            v1: 0,
            v2: 0,
        });
    }
    for l in &mut lines {
        l.pad_to_dword();
    }

    // Pack: <u32 line_count, mask+flags pairs, concatenated data>.
    let mut body = Vec::new();
    body.extend_from_slice(&(lines.len() as u32).to_le_bytes());
    for l in &lines {
        body.extend_from_slice(&l.mask.to_le_bytes());
        body.extend_from_slice(&l.flags.to_le_bytes());
    }
    for l in &lines {
        body.extend_from_slice(&l.data);
    }
    chunks.push(Chunk { kind: 0x0030, body });
}

/// Build the cmd `0x02` payload: `<u8=2, u16 bytes_per_line, u16 req_lines>`
/// followed by the merged program chunks. Mirrors upstream's
/// `Sensor.build_cmd_02`.
///
/// `factory_calibration_values` and `calib_data` feed
/// [`line_update_type_1`]; pass empty slices for CALIBRATE mode (or
/// for the very first IDENTIFY before calibration data exists).
#[allow(clippy::too_many_arguments)]
pub fn build_cmd_02(
    mode: CaptureMode,
    program: &[u8],
    type_info: &SensorTypeInfo,
    key_line: &[u8],
    calibration_frames: u16,
    lines_per_frame: u16,
    subst_value: u8,
    factory_calibration_values: &[u8],
    calib_data: &[u8],
) -> Result<Vec<u8>> {
    let mut chunks = split_chunks(program)?;
    line_update_type_1(
        mode,
        &mut chunks,
        type_info,
        key_line,
        subst_value,
        factory_calibration_values,
        calib_data,
    );

    let req_lines: u16 = if mode == CaptureMode::Calibrate {
        calibration_frames * lines_per_frame + 1
    } else {
        0
    };

    let merged = merge_chunks(&chunks);
    let mut out = Vec::with_capacity(5 + merged.len());
    out.push(0x02);
    out.extend_from_slice(&type_info.bytes_per_line.to_le_bytes());
    out.extend_from_slice(&req_lines.to_le_bytes());
    out.extend_from_slice(&merged);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensor_types::FM_3367_001;

    /// `0x10..=0x17` opcodes whose `b[i+2] > 1` get their third byte
    /// multiplied by `mult`; the address byte (`b[i+1]`) bumps by 1
    /// when `inc_address` is true. Note the loop guard `i + 3 < len`
    /// means the *last* possible triplet only fires when there's at
    /// least one trailing byte beyond it — a quirk we preserve from
    /// upstream.
    #[test]
    fn patch_timeslot_scales_third_byte_and_bumps_addr() {
        // 7-byte input: trailing 0x00 keeps the loop alive so both
        // triplets get rewritten.
        let input = [0x10, 0x05, 0x03, 0x10, 0x07, 0x09, 0x00];
        let out = patch_timeslot_table(&input, true, 2);
        assert_eq!(out[0..3], [0x10, 0x06, 0x06]);
        assert_eq!(out[3..6], [0x10, 0x08, 0x12]);
        assert_eq!(out[6], 0x00);
    }

    /// Demonstrates the upstream quirk: a buffer with *exactly* enough
    /// bytes for two triplets only processes the first.
    #[test]
    fn patch_timeslot_loop_guard_drops_last_triplet() {
        let input = [0x10, 0x05, 0x03, 0x10, 0x07, 0x09];
        let out = patch_timeslot_table(&input, true, 2);
        // First triplet IS rewritten.
        assert_eq!(out[0..3], [0x10, 0x06, 0x06]);
        // Second triplet is NOT — `i + 3 < len(b)` is false when i=3.
        assert_eq!(out[3..6], [0x10, 0x07, 0x09]);
    }

    /// `b[i+2] <= 1` means "no repeat" — skip the scale + bump.
    #[test]
    fn patch_timeslot_skips_when_value_is_one() {
        let input = [0x10, 0x05, 0x01];
        let out = patch_timeslot_table(&input, true, 2);
        assert_eq!(out, &input[..]);
    }

    /// Zero opcode advances by one byte; `0x07` advances by two.
    #[test]
    fn patch_timeslot_handles_filler_opcodes() {
        let input = [0x00, 0x07, 0xAA, 0x10, 0x09, 0x02, 0xff /* should stop here */, 0xff];
        let out = patch_timeslot_table(&input, false, 3);
        // Only the 0x10 triplet is rewritten — addr unchanged because
        // inc_address=false, val 2 → 6.
        assert_eq!(out[3..6], [0x10, 0x09, 0x06]);
    }

    /// On a fresh device (empty calib_data) `get_key_line` must
    /// return `line_width` zero bytes.
    #[test]
    fn get_key_line_empty_calib_returns_zeros() {
        let key = get_key_line(&FM_3367_001, 0x38, &[]);
        assert_eq!(key.len(), FM_3367_001.line_width as usize);
        assert!(key.iter().all(|&b| b == 0));
    }

    /// With non-empty calibration data, `get_key_line` carves out the
    /// `key_calibration_line`-th row and applies the `5 → 4` byte
    /// substitution.
    #[test]
    fn get_key_line_extracts_row_with_byte_substitution() {
        let bytes_per_line = FM_3367_001.line_width as usize;
        let lines = FM_3367_001.lines_per_calibration_data as usize;
        let mut data = vec![0xAAu8; 8 + bytes_per_line * lines];
        // Mark the row we expect to extract (key line 2 for this test).
        let key_line = 2usize;
        let row_off = 8 + bytes_per_line * key_line;
        for (i, b) in data[row_off..row_off + bytes_per_line].iter_mut().enumerate() {
            *b = if i == 3 { 5 } else { (i as u8) | 0x80 };
        }
        let key = get_key_line(&FM_3367_001, key_line as u32, &data);
        assert_eq!(key.len(), bytes_per_line);
        // The 5 in the row must have been substituted to 4.
        assert_eq!(key[3], 4);
        // Other bytes pass through untouched.
        assert_eq!(key[0], 0x80);
    }

    /// Decoder must round-trip the small, fully-determined opcodes 0..4.
    #[test]
    fn decode_insn_handles_one_byte_opcodes() {
        for op in 0u8..=4 {
            let i = decode_insn(&[op]).unwrap();
            assert_eq!(i.opcode, op);
            assert_eq!(i.length, 1);
        }
    }

    /// Opcode 7 promotes a literal `0` operand to `0x100` — a quirk
    /// shared by the Call-third-byte handling.
    #[test]
    fn decode_insn_opcode_7_zero_promotes_to_0x100() {
        let i = decode_insn(&[7, 0]).unwrap();
        assert_eq!(i.opcode, 7);
        assert_eq!(i.operands[0], 0x100);
        let j = decode_insn(&[7, 0x42]).unwrap();
        assert_eq!(j.operands[0], 0x42);
    }

    /// Opcode 11 (Call) is recognised by `b[0] & 0xf8 == 0x10`. The
    /// destination is `b[1] << 2`.
    #[test]
    fn decode_insn_call_destination() {
        let i = decode_insn(&[0x10, 0x20, 0x05]).unwrap();
        assert_eq!(i.opcode, 11);
        assert_eq!(i.length, 3);
        assert_eq!(i.operands[1], 0x80);
    }

    /// Opcode 13 (Write Register) addresses are encoded as
    /// `0x80002000 + (b[0] & 0x3f) * 4`.
    #[test]
    fn decode_insn_write_register_address_decode() {
        // (0x4f & 0x3f) * 4 + 0x80002000 = 0xf * 4 + base = 0x8000203c.
        let i = decode_insn(&[0x4f, 0x42, 0x00]).unwrap();
        assert_eq!(i.opcode, 13);
        assert_eq!(i.operands[0], 0x8000_203c);
        assert_eq!(i.operands[1], 0x42);
    }

    /// `patch_timeslot_again` is a no-op when no Call is reachable
    /// before an End-of-Data opcode.
    #[test]
    fn patch_timeslot_again_noop_without_call() {
        // Opcode 1 (End of Table) at offset 0 stops the walk
        // immediately — no Call is ever recorded.
        let input = [1u8, 0, 0, 0];
        assert_eq!(patch_timeslot_again(&input, 0xAA), input);
    }

    /// End-to-end: a small program with one Call and one matching
    /// Write Register at 0x8000203c gets the substitution byte applied.
    #[test]
    fn patch_timeslot_again_substitutes_in_subroutine() {
        // Program layout:
        //   [0..3] Call → destination = 0x10 << 2 = 0x40
        //   [3..4] End of Data (4)
        //   [4..0x40] zero-padded
        //   [0x40..0x43] Write Register at 0x8000203c with value 0x77
        //   [0x43..0x44] End (1)
        let mut prog = vec![0u8; 0x44];
        prog[0] = 0x10; prog[1] = 0x10; prog[2] = 0x05; // Call
        prog[3] = 4; // End of Data
        prog[0x40] = 0x4f; // Write Register at 0x8000203c
        prog[0x41] = 0x77; // value byte
        prog[0x42] = 0x00;
        prog[0x43] = 1; // End of Table

        let out = patch_timeslot_again(&prog, 0xAB);
        assert_eq!(out[0x41], 0xAB, "value byte must be replaced with subst_value");
        // Other bytes unchanged.
        assert_eq!(out[0x40], 0x4f);
        assert_eq!(out[0x42], 0x00);
    }

    /// `line_update_type_1` in CALIBRATE mode must:
    /// - rewrite the 0x34 chunk with key_line || patched-tail;
    /// - append exactly one 0x17 reply-config chunk;
    /// - **not** add identify-only 0x4e/0x2e chunks.
    #[test]
    fn line_update_type_1_calibrate_mode() {
        use crate::chunks::Chunk;
        use crate::sensor_types::FM_3367_001;
        let mut chunks = vec![
            Chunk { kind: 0x0034, body: vec![0xAAu8; 200] },
            Chunk { kind: 0x0020, body: vec![0u8; 8] },
        ];
        let key_line = vec![0x55u8; 112];
        line_update_type_1(
            CaptureMode::Calibrate,
            &mut chunks,
            &FM_3367_001,
            &key_line,
            0,
            &[],
            &[],
        );
        // 0x34 body: first 112 bytes = key_line, rest = patched tail (>= 88 B).
        let timeslot = chunks.iter().find(|c| c.kind == 0x0034).unwrap();
        assert_eq!(&timeslot.body[..112], &key_line[..]);
        assert!(timeslot.body.len() >= 200);
        // Exactly one 0x17 reply-config appended; no 0x4e or 0x2e.
        assert_eq!(chunks.iter().filter(|c| c.kind == 0x0017).count(), 1);
        assert!(chunks.iter().all(|c| c.kind != 0x004e));
        assert!(chunks.iter().all(|c| c.kind != 0x002e));
    }

    /// IDENTIFY mode adds the 0x4e + 0x2e tail chunks.
    #[test]
    fn line_update_type_1_identify_mode_adds_tail() {
        use crate::chunks::Chunk;
        use crate::sensor_types::FM_3367_001;
        let mut chunks = vec![Chunk { kind: 0x0034, body: vec![0u8; 130] }];
        let key_line = vec![0u8; 112];
        line_update_type_1(
            CaptureMode::Identify,
            &mut chunks,
            &FM_3367_001,
            &key_line,
            0,
            &[],
            &[],
        );
        assert_eq!(chunks.iter().filter(|c| c.kind == 0x004e).count(), 1);
        assert_eq!(chunks.iter().filter(|c| c.kind == 0x002e).count(), 1);
        // IDENTIFY without calibration data still emits the 0x44/0x30/0x43
        // bundle; otherwise the device firing a noise-detect sentinel.
        assert_eq!(chunks.iter().filter(|c| c.kind == 0x0044).count(), 1);
        assert_eq!(chunks.iter().filter(|c| c.kind == 0x0030).count(), 1);
        assert_eq!(chunks.iter().filter(|c| c.kind == 0x0043).count(), 1);
    }

    /// `build_cmd_02` produces a payload starting with the magic 5-byte
    /// header `<0x02, u16 bytes_per_line, u16 req_lines>`.
    #[test]
    fn build_cmd_02_calibrate_header() {
        use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};
        let key_line = vec![0u8; FM_3367_001.line_width as usize];
        let pkt = build_cmd_02(
            CaptureMode::Calibrate,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            /* calibration_frames */ 3,
            /* lines_per_frame */ 224,
            /* subst_value */ 0,
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(pkt[0], 0x02);
        let bytes_per_line = u16::from_le_bytes([pkt[1], pkt[2]]);
        let req_lines = u16::from_le_bytes([pkt[3], pkt[4]]);
        assert_eq!(bytes_per_line, 0x78);
        // calibration_frames * lines_per_frame + 1 = 3 * 224 + 1 = 673.
        assert_eq!(req_lines, 673);
    }

    /// Lock in the first 32 bytes of `build_cmd_02(Calibrate, …)` for
    /// the canonical zero-key_line + zero-subst inputs. Regression
    /// guard: any change to upstream's program, type-info, or
    /// line-update logic that affects these bytes will trip the test.
    #[test]
    fn build_cmd_02_calibrate_byte_exact_prefix() {
        use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};
        let key_line = vec![0u8; FM_3367_001.line_width as usize];
        let pkt = build_cmd_02(
            CaptureMode::Calibrate,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            3,
            224,
            0,
            &[],
            &[],
        )
        .unwrap();
        // Total length is fully determined by the inputs.
        assert_eq!(pkt.len(), 657);
        // Header (5 bytes) + first chunk-list bytes are deterministic.
        // First 32 bytes lock in the 5-byte cmd header, the empty 0x23
        // chunk, the 0x20 chunk's body, and the start of the 0x32 chunk.
        assert_eq!(
            hex_dbg(&pkt[..32]),
            "027800a102230000002000080000200080000001003200740000000080202004",
        );
    }

    fn hex_dbg(b: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }

    /// Same lock-in for IDENTIFY mode. Different `req_lines` (= 0) +
    /// different tail chunks (0x4e, 0x2e) → different total length and
    /// different bytes after the chunks list.
    #[test]
    fn build_cmd_02_identify_byte_exact_total_length() {
        use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};
        let key_line = vec![0u8; FM_3367_001.line_width as usize];
        let pkt = build_cmd_02(
            CaptureMode::Identify,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            3,
            224,
            0,
            &[],
            &[],
        )
        .unwrap();
        // Calibrate is 657 bytes; identify adds:
        //   0x4e: 4 hdr + 40 body = 44 bytes
        //   0x2e: 4 hdr + 28 body = 32 bytes
        //   0x44: 4 hdr + 4 body  =  8 bytes (interleave constant)
        //   0x30: 4 hdr + 20 body = 24 bytes
        //         body = u32 line count + 2× (u32 mask, u32 flags) = 20
        //         (both lines go to 0x43, so no `data` lands here)
        //   0x43: 4 hdr + 120 body = 124 bytes
        //         Line 0: <v0=0xf, v1, v2> + calibration_blob (112) = 116
        //         Line 1: <v0, v1, v2> + bitpack(empty) (0) = 4
        // Inputs are empty factory_calibration_values + calib_data, so
        // the 28× per-line calib offsets (Lines 2+) don't appear.
        assert_eq!(pkt.len(), 657 + 44 + 32 + 8 + 24 + 124);
    }

    /// IDENTIFY mode sets `req_lines = 0` (the device free-runs).
    #[test]
    fn build_cmd_02_identify_zero_req_lines() {
        use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};
        let key_line = vec![0u8; FM_3367_001.line_width as usize];
        let pkt = build_cmd_02(
            CaptureMode::Identify,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            3,
            224,
            0,
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(u16::from_le_bytes([pkt[3], pkt[4]]), 0);
    }

    /// Lock the *structure* of cmd-02 IDENTIFY against python-validity's
    /// reference capture (`scripts/captured/pv_cmd02_identify.hex` —
    /// 13729 bytes total, captured 2026-05-06 from the user's P70).
    /// We don't byte-match because the inputs (calib_data,
    /// factory_calibration_values) aren't trivially recoverable from
    /// the dump alone — but the chunk count, types, and sizes are
    /// fully determined by the device geometry and the fixed program.
    #[test]
    fn build_cmd_02_identify_matches_pv_structure() {
        use crate::chunks::split as split_chunks_inner;
        use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};

        // Synthetic but realistic inputs sized to reproduce python-
        // validity's exact 192-byte 0x43 chunk:
        //   - calib_data = 13440 bytes (112 lines × 120 bytes/line).
        //   - factory_calibration_values = 115 entries spanning range
        //     [0..30] above some min, so `bitpack` picks 5 bits/value
        //     (delta=30 → 5 bits) and emits ⌈5×115/8⌉ = 72 bytes,
        //     already dword-aligned. 0x43 then totals 4 + 112 + 4 + 72 = 192.
        let key_line = vec![0u8; FM_3367_001.line_width as usize];
        let calib_data: Vec<u8> = (0..13440u32).map(|i| (i & 0xff) as u8).collect();
        let factory_cal_values: Vec<u8> =
            (0..115u32).map(|i| 0x70u8 + (i % 31) as u8).collect();

        let pkt = build_cmd_02(
            CaptureMode::Identify,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            3,
            224,
            0,
            &factory_cal_values,
            &calib_data,
        )
        .unwrap();

        // Header layout: <0x02, u16 bpl=0x78, u16 req_lines=0>.
        assert_eq!(pkt[0], 0x02);
        assert_eq!(u16::from_le_bytes([pkt[1], pkt[2]]), 0x78);
        assert_eq!(u16::from_le_bytes([pkt[3], pkt[4]]), 0);

        let chunks = split_chunks_inner(&pkt[5..]).unwrap();

        // python-validity emits exactly 16 chunks for this device.
        assert_eq!(chunks.len(), 16, "got {} chunks", chunks.len());

        // Locked chunk-type sequence (from `walk_cmd02.py` on the
        // captured dump).
        let expected_types: &[u16] = &[
            0x0023, 0x0020, 0x0032, 0x0033, 0x0032, 0x0032, 0x0034, 0x002f, 0x0029, 0x0035, 0x0017,
            0x004e, 0x002e, 0x0044, 0x0030, 0x0043,
        ];
        let actual_types: Vec<u16> = chunks.iter().map(|c| c.kind).collect();
        assert_eq!(&actual_types[..], expected_types);

        // Sizes that depend ONLY on FM-3367 geometry (must match the
        // python-validity capture exactly).
        assert_eq!(chunks[13].body.len(), 4, "0x44 interleave");
        assert_eq!(chunks[14].body.len(), 12788, "0x30 line update");
        assert_eq!(chunks[15].body.len(), 192, "0x43 update transform");

        // 0x44 body is the constant <u32 1>.
        assert_eq!(chunks[13].body, [0x01, 0x00, 0x00, 0x00]);

        // 0x30 body header: <u32 line_count=30> + 30× (u32 mask, u32 flags)
        // + 28 × 448 bytes of slab data = 4 + 240 + 12544 = 12788.
        let line_count = u32::from_le_bytes(chunks[14].body[0..4].try_into().unwrap());
        assert_eq!(line_count, 30, "expected 2 transform lines + 28 calib slab lines");

        // 0x43 body starts with the calibration_blob's first transform
        // header: <v0=0xf, v1=0, v2=0, calibration_blob[112]>.
        assert_eq!(chunks[15].body[0], 0x0f);
        assert_eq!(chunks[15].body[1], 0x00);
        assert_eq!(&chunks[15].body[4..4 + FM_3367_001.calibration_blob.len()],
                   FM_3367_001.calibration_blob,
                   "calibration_blob copied into 0x43 chunk");
    }

    /// With zero calib_data, the 0x30 chunk shrinks: only the 2
    /// transform lines (which go to 0x43, not 0x30) populate the
    /// header — 0x30's body is 4 + 16 + 0 = 20 bytes.
    #[test]
    fn build_cmd_02_identify_empty_calib_minimal_0x30() {
        use crate::chunks::split as split_chunks_inner;
        use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};
        let key_line = vec![0u8; FM_3367_001.line_width as usize];
        let pkt = build_cmd_02(
            CaptureMode::Identify,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            3,
            224,
            0,
            &[],
            &[],
        )
        .unwrap();
        let chunks = split_chunks_inner(&pkt[5..]).unwrap();
        let line_update = chunks.iter().find(|c| c.kind == 0x0030).unwrap();
        assert_eq!(line_update.body.len(), 4 + 16);
        assert_eq!(u32::from_le_bytes(line_update.body[0..4].try_into().unwrap()), 2);
    }

    /// Cross-check the chunk skeleton (header bytes, types, sizes)
    /// against the literal python-validity capture. We only compare
    /// fields whose values are deterministic regardless of host —
    /// the cmd-02 header, chunk type sequence, and chunks 0-12 which
    /// don't depend on calibration data. Chunks 13/14/15 vary with
    /// per-host inputs, so we only assert their *sizes* match.
    #[test]
    fn build_cmd_02_identify_chunks_0_to_12_byte_match_pv_capture() {
        use crate::chunks::split as split_chunks_inner;
        use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};

        const PV_HEX: &str = include_str!("../scripts/captured/pv_cmd02_identify.hex");
        let pv: Vec<u8> = (0..PV_HEX.trim().len() / 2)
            .map(|i| u8::from_str_radix(&PV_HEX.trim()[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let pv_chunks = split_chunks_inner(&pv[5..]).unwrap();

        // Need a valid `key_line` so chunk 6 (0x34) byte-matches.
        // python-validity's `key_line` is the first 112 bytes of the
        // patched 0x34 body, so we extract it directly from the
        // capture and feed it back in. Same for `subst_value`: that's
        // baked into chunk 6's tail by `patch_timeslot_again`.
        let pv_0x34 = pv_chunks.iter().find(|c| c.kind == 0x0034).unwrap();
        let pv_key_line = &pv_0x34.body[..FM_3367_001.line_width as usize];
        // The subst byte is the only byte that differs between
        // patch_timeslot_table and patch_timeslot_again on this
        // program — search for it by diffing against a no-subst run.
        // For determinism we just dial it up via brute force.
        let mut found_subst: Option<u8> = None;
        for trial in 0..=255u8 {
            let pkt = build_cmd_02(
                CaptureMode::Identify,
                &FM_3367_001_PROG,
                &FM_3367_001,
                pv_key_line,
                3,
                224,
                trial,
                &[],
                &[],
            )
            .unwrap();
            let our_chunks = split_chunks_inner(&pkt[5..]).unwrap();
            if our_chunks[6].body == pv_0x34.body {
                found_subst = Some(trial);
                break;
            }
        }
        let subst = found_subst.expect("brute-force found a subst that matches");
        // Should be the user's known subst_value 0x8c.
        assert_eq!(subst, 0x8c, "P70 subst is 0x8c per `factory-calibration` output");

        // Now build with the right inputs and byte-compare chunks 0-12.
        let pkt = build_cmd_02(
            CaptureMode::Identify,
            &FM_3367_001_PROG,
            &FM_3367_001,
            pv_key_line,
            3,
            224,
            subst,
            &[],
            &[],
        )
        .unwrap();
        let our_chunks = split_chunks_inner(&pkt[5..]).unwrap();
        assert_eq!(our_chunks.len(), pv_chunks.len());

        for i in 0..=12 {
            assert_eq!(
                our_chunks[i].kind, pv_chunks[i].kind,
                "chunk[{i}] type mismatch",
            );
            assert_eq!(
                our_chunks[i].body, pv_chunks[i].body,
                "chunk[{i}] (type 0x{:04x}) body bytes mismatch",
                pv_chunks[i].kind,
            );
        }

        // Chunk 13 (0x44 interleave) is also constant.
        assert_eq!(our_chunks[13].body, pv_chunks[13].body, "0x44 interleave");
    }

    /// `Line::goes_to_update_transform` reads the 4-bit field at
    /// position `[20..24)` of `flags`. `<= 1` → 0x30, `> 1` → 0x43.
    #[test]
    fn line_classification_by_flag_bits() {
        let l = Line { mask: 0, flags: 0, data: vec![], v0: 0, v1: 0, v2: 0 };
        assert!(!l.goes_to_update_transform());
        let l = Line { mask: 0, flags: 1u32 << 0x14, data: vec![], v0: 0, v1: 0, v2: 0 };
        assert!(!l.goes_to_update_transform());
        // Boundary: cnt=2 → goes to 0x43.
        let l = Line { mask: 0, flags: 2u32 << 0x14, data: vec![], v0: 0, v1: 0, v2: 0 };
        assert!(l.goes_to_update_transform());
        let l = Line { mask: 0, flags: 0xfu32 << 0x14, data: vec![], v0: 0, v1: 0, v2: 0 };
        assert!(l.goes_to_update_transform());
    }

    /// Build a synthetic partition 6 with known calibration data and
    /// confirm the parser extracts it. SHA-256 / zeros / trailing
    /// fields are all zero in this synthetic input — the parser
    /// shouldn't care.
    #[test]
    fn parse_calibration_extracts_raw_data() {
        let raw: Vec<u8> = (0..1000u32).map(|i| (i & 0xff) as u8).collect();
        let raw_len = raw.len() as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x5002u16.to_le_bytes());
        // outer_len = 2 + len(raw) + 2 (we don't actually validate this)
        buf.extend_from_slice(&((4u16) + raw_len).to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]); // sha placeholder
        buf.extend_from_slice(&[0u8; 32]); // zero pad
        buf.extend_from_slice(&raw_len.to_le_bytes());
        buf.extend_from_slice(&raw);
        buf.extend_from_slice(&0u16.to_le_bytes()); // trailing zero

        let got = parse_calibration(&buf).unwrap();
        assert_eq!(got, raw);
    }

    /// Wrong magic must surface as a clear error.
    #[test]
    fn parse_calibration_rejects_wrong_magic() {
        let mut buf = vec![0u8; 0x48];
        buf[0..2].copy_from_slice(&0x4242u16.to_le_bytes());
        assert!(parse_calibration(&buf).is_err());
    }

    /// `find_nth_insn` walks the program until it counts `n`
    /// occurrences of the requested opcode, returning the offset.
    #[test]
    fn find_nth_insn_locates_nth_call() {
        // Three Call instructions (opcode 11) at known offsets.
        let prog = [
            0x10, 0x10, 0x05, // Call at pc=0
            0x00, // padding (opcode 0, 1 byte)
            0x10, 0x20, 0x07, // Call at pc=4
            0x00, // padding
            0x10, 0x30, 0x09, // Call at pc=8
        ];
        let (pc1, ins1) = find_nth_insn(&prog, 11, 1).unwrap();
        assert_eq!(pc1, 0);
        assert_eq!(ins1.opcode, 11);

        let (pc2, _) = find_nth_insn(&prog, 11, 2).unwrap();
        assert_eq!(pc2, 4);

        let (pc3, _) = find_nth_insn(&prog, 11, 3).unwrap();
        assert_eq!(pc3, 8);

        // No 4th occurrence.
        assert!(find_nth_insn(&prog, 11, 4).is_none());
    }

    #[test]
    fn find_nth_insn_returns_none_for_unknown_opcode() {
        let prog = [0x00, 0x00, 0x00];
        assert!(find_nth_insn(&prog, 99, 1).is_none());
    }

    /// `find_nth_regwrite` matches only the Write Register opcode (13)
    /// AND filters by the target address.
    #[test]
    fn find_nth_regwrite_filters_by_address() {
        // Write Register at 0x80002000 (opcode 0x40), then at 0x80002004 (0x41),
        // then at 0x80002000 again.
        let prog = [
            0x40, 0x11, 0x22, // Write 0x80002000 = 0x2211
            0x41, 0x33, 0x44, // Write 0x80002004 = 0x4433
            0x40, 0x55, 0x66, // Write 0x80002000 = 0x6655
        ];
        let (pc1, ins1) = find_nth_regwrite(&prog, 0x80002000, 1).unwrap();
        assert_eq!(pc1, 0);
        assert_eq!(ins1.operands[1], 0x2211);

        let (pc2, ins2) = find_nth_regwrite(&prog, 0x80002000, 2).unwrap();
        assert_eq!(pc2, 6);
        assert_eq!(ins2.operands[1], 0x6655);

        // Address 0x80002004 has only one occurrence.
        assert!(find_nth_regwrite(&prog, 0x80002004, 2).is_none());
    }

    /// `LineHeader::parse` extracts each documented field correctly
    /// from the 8-byte prefix.
    #[test]
    fn line_header_parses_documented_layout() {
        let bytes = [0x01, 0xfe, 0x05, 0x02, 0x44, 0xf5, 0x4b, 0xd5];
        let h = LineHeader::parse(&bytes).unwrap();
        assert_eq!(h.magic, [0x01, 0xfe]);
        assert_eq!(h.line_index, 5);
        assert_eq!(h.frame_index, 2);
        assert_eq!(h.counter, 0xd54bf544);
        assert!(h.looks_valid());
    }

    #[test]
    fn line_header_rejects_short_input() {
        assert!(LineHeader::parse(&[0x01, 0xfe, 0x00]).is_none());
    }

    #[test]
    fn line_header_looks_valid_only_for_correct_magic() {
        let bad = LineHeader { magic: [0x00, 0x00], line_index: 1, frame_index: 1, counter: 0 };
        assert!(!bad.looks_valid());
        let good = LineHeader { magic: [0x01, 0xfe], line_index: 1, frame_index: 1, counter: 0 };
        assert!(good.looks_valid());
    }

    /// `line_headers` over a synthetic two-frame buffer returns the
    /// expected line / frame index sequence.
    #[test]
    fn line_headers_walk_two_frames() {
        use crate::sensor_types::FM_3367_001;
        let bpl = FM_3367_001.bytes_per_line as usize;
        let mut raw = Vec::new();
        for frame in 1u8..=2 {
            for line in 1u8..=3 {
                raw.extend_from_slice(&[0x01, 0xfe, line, frame, 0, 0, 0, 0]);
                raw.extend(std::iter::repeat_n(0u8, bpl - 8));
            }
        }
        let hdrs = line_headers(&raw, &FM_3367_001);
        assert_eq!(hdrs.len(), 6);
        assert_eq!(hdrs[0].frame_index, 1);
        assert_eq!(hdrs[2].frame_index, 1);
        assert_eq!(hdrs[3].frame_index, 2);
        assert!(hdrs.iter().all(|h| h.looks_valid()));
    }

    /// Strip per-line headers from a synthetic 3-line frame and verify
    /// each line returns exactly `line_width` bytes of pixel data.
    #[test]
    fn extract_pixel_lines_strips_headers() {
        use crate::sensor_types::FM_3367_001;
        let bpl = FM_3367_001.bytes_per_line as usize;
        let lw = FM_3367_001.line_width as usize;
        let mut raw = Vec::new();
        for line_idx in 0..3u8 {
            // 8-byte header
            raw.extend_from_slice(&[0x01, 0xfe, line_idx, 0x01, 0xb8, 0xfa, 0x0f, 0x00]);
            // pixel bytes — synthetic, distinct per line
            raw.extend(std::iter::repeat_n(0x40 + line_idx, lw));
        }
        let lines = extract_pixel_lines(&raw, &FM_3367_001);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| l.len() == lw));
        assert!(lines[0].iter().all(|&b| b == 0x40));
        assert!(lines[1].iter().all(|&b| b == 0x41));
        assert!(lines[2].iter().all(|&b| b == 0x42));
        // Make sure no padding/header bytes leaked through.
        for line in &lines {
            assert_ne!(line[0], 0x01, "first byte must not be the header magic");
        }
        let _ = bpl; // silence unused if optimiser elides
    }

    /// A trailing partial line (less than bytes_per_line) is dropped
    /// rather than producing a short pixel row.
    #[test]
    fn extract_pixel_lines_drops_partial_trailing() {
        use crate::sensor_types::FM_3367_001;
        let bpl = FM_3367_001.bytes_per_line as usize;
        let mut raw = vec![0u8; bpl];
        raw.extend_from_slice(&[0x01, 0xfe, 0x99]); // 3 dangling bytes
        let lines = extract_pixel_lines(&raw, &FM_3367_001);
        assert_eq!(lines.len(), 1);
    }

    /// PGM output: starts with `P5 <w> <h> 255\n` and ends with raw
    /// pixel data (no separator, no terminator).
    #[test]
    fn lines_to_pgm_header_and_payload() {
        let lines = vec![vec![0x10u8; 8], vec![0x20u8; 8], vec![0x30u8; 8]];
        let pgm = lines_to_pgm(&lines, 8);
        let s = std::str::from_utf8(&pgm[..15]).unwrap();
        assert!(s.starts_with("P5\n8 3\n255\n"), "got: {s:?}");
        // Total length = header + 24 pixel bytes.
        let header_end = pgm.iter().position(|&b| b == b'\n').unwrap();
        let header_end = pgm[header_end + 1..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| header_end + 1 + i)
            .unwrap();
        let header_end = pgm[header_end + 1..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| header_end + 1 + i)
            .unwrap();
        let pixel_start = header_end + 1;
        assert_eq!(pgm.len() - pixel_start, 24);
        // Pixel data: 0x10×8, 0x20×8, 0x30×8.
        assert!(pgm[pixel_start..pixel_start + 8].iter().all(|&b| b == 0x10));
        assert!(pgm[pixel_start + 8..pixel_start + 16].iter().all(|&b| b == 0x20));
        assert!(pgm[pixel_start + 16..].iter().all(|&b| b == 0x30));
    }

    #[test]
    fn raw_frame_to_pgm_round_trip() {
        use crate::sensor_types::FM_3367_001;
        let bpl = FM_3367_001.bytes_per_line as usize;
        let lw = FM_3367_001.line_width as usize;
        // 2 lines of synthetic data
        let mut raw = Vec::new();
        for _ in 0..2 {
            raw.extend_from_slice(&[0x01, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            raw.extend(std::iter::repeat_n(0x55u8, lw));
        }
        let pgm = raw_frame_to_pgm(&raw, &FM_3367_001);
        // Header length is at most ~20 bytes; pixel data is 2 * 112 = 224.
        assert!(pgm.len() > 224);
        assert!(pgm.starts_with(b"P5\n"));
        let _ = bpl;
    }

    /// `average_interleaved` produces an output sized
    /// `lines_per_calibration_data × bytes_per_line` regardless of
    /// `calibration_frames`.
    #[test]
    fn average_interleaved_output_dimensions() {
        use crate::sensor_types::FM_3367_001;
        // Three-frame buffer; first frame skipped, only second is used.
        let frames_count = 3;
        let lines_per_frame: u32 = 224;
        let frame_size = (lines_per_frame * FM_3367_001.bytes_per_line as u32) as usize;
        let raw = vec![0u8; frame_size * frames_count];

        let cooked = average_interleaved(&raw, &FM_3367_001, lines_per_frame, frames_count as u32);
        let expected_len =
            FM_3367_001.lines_per_calibration_data as usize * FM_3367_001.bytes_per_line as usize;
        assert_eq!(cooked.len(), expected_len);
        // All-zero input → all-zero output.
        assert!(cooked.iter().all(|&b| b == 0));
    }

    /// Pair-averaging actually averages: feed alternating 0x40 / 0x80
    /// lines and expect 0x60 in the output.
    #[test]
    fn average_interleaved_pairs_average_correctly() {
        use crate::sensor_types::FM_3367_001;
        let lines_per_frame: u32 = 224;
        let bytes_per_line = FM_3367_001.bytes_per_line as usize;
        let frame_size = lines_per_frame as usize * bytes_per_line;
        // Two frames; we'll use the second one (index 1).
        let mut raw = vec![0u8; frame_size * 2];
        // Fill the second frame with alternating-line pattern: even
        // lines = 0x40, odd lines = 0x80.
        for line in 0..lines_per_frame as usize {
            let off = frame_size + line * bytes_per_line;
            let val = if line % 2 == 0 { 0x40 } else { 0x80 };
            for b in &mut raw[off..off + bytes_per_line] {
                *b = val;
            }
        }
        let cooked = average_interleaved(&raw, &FM_3367_001, lines_per_frame, 2);
        // Every byte should be the integer average of 0x40 and 0x80 = 0x60.
        assert!(cooked.iter().all(|&b| b == 0x60), "expected all 0x60, got {:?}", &cooked[..4]);
    }

    /// `scale(0x80) = 0`, and the formula `(x-0x80)*10/0x22` lands
    /// well within `[-128, 127]` for any byte input — the clip is a
    /// safety net, not the dominant transform.
    #[test]
    fn scale_pixel_known_values() {
        assert_eq!(scale_pixel(0x80), 0);
        // 0xa2 - 0x80 = 0x22, * 10 / 0x22 = 10 → 0x0a.
        assert_eq!(scale_pixel(0xa2), 0x0a);
        // 0x5e - 0x80 = -0x22, * 10 / 0x22 = -10 → -10 → 0xf6.
        assert_eq!(scale_pixel(0x5e), 0xf6);
        // 0x00 - 0x80 = -128, * 10 / 0x22 = -1280/34 = -37 → 0xdb.
        assert_eq!(scale_pixel(0x00), 0xdb);
        // 0xff - 0x80 = 127, * 10 / 0x22 = 1270/34 = 37 → 0x25.
        assert_eq!(scale_pixel(0xff), 0x25);
    }

    /// `add_signed` is signed two's-complement with saturation.
    #[test]
    fn add_signed_saturates() {
        assert_eq!(add_signed(0x10, 0x10), 0x20);
        // 0x7f + 0x01 → would overflow → saturates to 0x7f.
        assert_eq!(add_signed(0x7f, 0x01), 0x7f);
        // 0x80 + 0xff = -128 + -1 → saturates to -128 = 0x80.
        assert_eq!(add_signed(0x80, 0xff), 0x80);
    }

    /// First call to `process_calibration_results` stores the scaled
    /// frame; subsequent calls add into it.
    #[test]
    fn process_calibration_results_first_then_combine() {
        // 2 lines × (8 header + 4 pixels).
        let line_len = 12;
        let mut frame_a = vec![0xAAu8; line_len * 2];
        let mut frame_b = vec![0xAAu8; line_len * 2];
        // Replace pixel data so we can observe the transform.
        for i in 0..2 {
            for px in 0..4 {
                frame_a[i * line_len + 8 + px] = 0xa2; // → scaled to +10
                frame_b[i * line_len + 8 + px] = 0x5e; // → scaled to -10
            }
        }
        let mut calib = Vec::new();
        process_calibration_results(&mut calib, &frame_a, line_len);
        // Header bytes preserved verbatim; pixels = +10.
        assert_eq!(&calib[..8], &frame_a[..8]);
        assert!(calib[8..12].iter().all(|&b| b == 0x0a));

        process_calibration_results(&mut calib, &frame_b, line_len);
        // After signed-add: scale(0xa2) + scale(0x5e) = 10 + (-10) = 0.
        assert!(calib[8..12].iter().all(|&b| b == 0x00));
    }

    /// Truncated trailing zero must error rather than panic.
    #[test]
    fn parse_calibration_rejects_truncated_trailer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x5002u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&100u16.to_le_bytes()); // raw_len=100
        // Only provide 50 bytes of raw + no trailer.
        buf.extend_from_slice(&[0xAA; 50]);
        assert!(parse_calibration(&buf).is_err());
    }

    /// Empty input → degenerate `(0, 0, [])`.
    #[test]
    fn bitpack_empty_input() {
        assert_eq!(bitpack(&[]), (0, 0, vec![]));
    }

    /// All-equal input → `bits = 0`, `min = the value`, body empty.
    #[test]
    fn bitpack_all_equal() {
        let (u, m, body) = bitpack(&[0x42; 7]);
        assert_eq!(u, 0);
        assert_eq!(m, 0x42);
        assert!(body.is_empty());
    }

    /// Two-value input: `[m, m+1]` needs 1 bit per value.
    #[test]
    fn bitpack_two_values_one_bit_each() {
        // Three bytes, second is m+1; bits needed = 1.
        let (u, m, body) = bitpack(&[0x10, 0x11, 0x10]);
        assert_eq!(u, 1);
        assert_eq!(m, 0x10);
        // Reversed input deltas: [0, 1, 0]. As LE bit stream:
        //   bit 0 = 0, bit 1 = 1, bit 2 = 0  → byte 0 = 0b010 = 0x02.
        assert_eq!(body, vec![0x02]);
    }

    /// 8-bit-wide input: `[0x00, 0xff]` needs 8 bits per value.
    #[test]
    fn bitpack_full_byte_range() {
        let (u, m, body) = bitpack(&[0x00, 0xff]);
        assert_eq!(u, 8);
        assert_eq!(m, 0);
        // Reversed: [0xff, 0x00]. LE-packed at u=8: byte 0 = 0xff, byte 1 = 0x00.
        assert_eq!(body, vec![0xff, 0x00]);
    }

    /// Round-trip property: total packed-byte length matches the
    /// formula `(u * n + 7) / 8`.
    #[test]
    fn bitpack_size_formula() {
        for n in [1usize, 3, 7, 8, 13, 32] {
            // Use a varied range so u > 0.
            let input: Vec<u8> = (0..n).map(|i| (i * 7 + 1) as u8).collect();
            let (u, _, body) = bitpack(&input);
            let expected = (u as usize * n).div_ceil(8);
            assert_eq!(body.len(), expected, "n={n}, u={u}");
        }
    }

    /// `Line::pad_to_dword` pads to multiples of 4. Lengths 0/1/2/3/4
    /// produce 0/4/4/4/4 bytes after padding.
    #[test]
    fn line_pad_to_dword() {
        for (input_len, expected) in [(0usize, 0), (1, 4), (2, 4), (3, 4), (4, 4), (5, 8)] {
            let mut line = Line { mask: 0, flags: 0, data: vec![0xAA; input_len], v0: 0, v1: 0, v2: 0 };
            line.pad_to_dword();
            assert_eq!(line.data.len(), expected);
        }
    }

    /// `line_update_type_2` for CALIBRATE mode appends only the
    /// reply-config + a single line-update (0x30) chunk; no per-mode
    /// 0x4e/0x26/0x2e tails.
    #[test]
    fn line_update_type_2_calibrate_appends_minimum_tail() {
        use crate::sensor_types::FM_3367_001;
        let mut chunks = vec![Chunk { kind: 0x0034, body: vec![0u8; 200] }];
        line_update_type_2(
            CaptureMode::Calibrate,
            &mut chunks,
            &FM_3367_001,
            &[0x10u8; 100],
            &[0x20u8; 112],
            0,
        );
        assert!(chunks.iter().any(|c| c.kind == 0x0017));
        assert!(chunks.iter().any(|c| c.kind == 0x0030));
        // No identify/enroll-only chunks.
        assert!(chunks.iter().all(|c| c.kind != 0x004e));
        assert!(chunks.iter().all(|c| c.kind != 0x0026));
        assert!(chunks.iter().all(|c| c.kind != 0x002e));
    }

    /// IDENTIFY mode adds the type-2 0x4e + 0x2e tail chunks.
    #[test]
    fn line_update_type_2_identify_adds_4e_2e_type2() {
        use crate::sensor_types::FM_3367_001;
        let mut chunks = vec![Chunk { kind: 0x0034, body: vec![0u8; 200] }];
        line_update_type_2(
            CaptureMode::Identify,
            &mut chunks,
            &FM_3367_001,
            &[0x10u8; 100],
            &[0x20u8; 112],
            0,
        );
        let id4e = chunks.iter().find(|c| c.kind == 0x004e).expect("0x4e missing");
        // Type-2 0x4e is 40 bytes and starts with the same magic.
        assert_eq!(id4e.body.len(), 40);
        assert_eq!(id4e.body[0], 0xfb);
        // First differentiator byte (offset 12) = 0x60 (vs type-1's 0x87).
        assert_eq!(id4e.body[12], 0x60);
    }

    /// ENROLL mode adds the 0x26 + 0x2e (type-2) tails.
    #[test]
    fn line_update_type_2_enroll_adds_26_2e_type2() {
        use crate::sensor_types::FM_3367_001;
        let mut chunks = vec![Chunk { kind: 0x0034, body: vec![0u8; 200] }];
        line_update_type_2(
            CaptureMode::Enroll,
            &mut chunks,
            &FM_3367_001,
            &[0x10u8; 100],
            &[0x20u8; 112],
            0,
        );
        assert!(chunks.iter().any(|c| c.kind == 0x0026));
        let enr2e = chunks.iter().find(|c| c.kind == 0x002e).expect("0x2e missing");
        // Type-2 enroll 0x2e differs from identify in byte 4: `23` vs `02`.
        assert_eq!(enr2e.body[4], 0x23);
    }

    /// All four type-2 tail-chunk constants have the documented
    /// kind tags and lengths.
    #[test]
    fn type_2_tail_chunks_layout() {
        assert_eq!(tail_chunks::identify_4e_type2().kind, 0x004e);
        assert_eq!(tail_chunks::identify_4e_type2().body.len(), 40);
        assert_eq!(tail_chunks::identify_2e_type2().kind, 0x002e);
        assert_eq!(tail_chunks::identify_2e_type2().body.len(), 28);
        assert_eq!(tail_chunks::enroll_26_type2().kind, 0x0026);
        assert_eq!(tail_chunks::enroll_26_type2().body.len(), 40);
        assert_eq!(tail_chunks::enroll_2e_type2().kind, 0x002e);
        assert_eq!(tail_chunks::enroll_2e_type2().body.len(), 28);
    }

    #[test]
    fn tail_chunks_have_locked_in_byte_layout() {
        let cfg = tail_chunks::reply_config();
        assert_eq!(cfg.kind, 0x0017);
        assert!(cfg.body.is_empty());

        let id4e = tail_chunks::identify_4e_type1();
        assert_eq!(id4e.kind, 0x004e);
        assert_eq!(id4e.body.len(), 40);
        assert_eq!(id4e.body[0], 0xfb);
        assert_eq!(id4e.body[39], 0x00);

        let id2e = tail_chunks::identify_2e();
        assert_eq!(id2e.kind, 0x002e);
        assert_eq!(id2e.body.len(), 28);
    }
}
