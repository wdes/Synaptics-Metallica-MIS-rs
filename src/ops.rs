// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! High-level, reusable sensor operations.
//!
//! The CLI in `src/main.rs` drives each flow inline with lots of
//! operator-facing output. This module packages the same wire sequences
//! (session setup, user DB lookups, identify, enroll, delete) as plain
//! library calls with progress callbacks and cooperative cancellation,
//! so long-running services such as the fprintd-compatible D-Bus daemon
//! can embed them.
//!
//! Every function here mirrors a CLI path that was verified on real
//! hardware; byte sequences are unchanged.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::blobs::{DB_WRITE_ENABLE_9A, GLOW_END_SCAN, GLOW_START_SCAN, INIT_HARDCODED_9A};
use crate::capture::{
    CaptureMode, average_interleaved, build_cmd_02, get_key_line, process_calibration_results,
};
use crate::db::{
    FingerEntry, SidIdentity, User, build_del_record, build_lookup_user, build_new_record,
    identity_to_bytes, parse_user, parse_user_storage,
};
use crate::enroll::{
    ENROLL_MAGIC_LEN, build_enrollment_mode, build_enrollment_update,
    build_enrollment_update_start, make_finger_data,
};
use crate::protocol::{CaptureStatus, STATUS_NOT_FOUND};
use crate::sensor_types::{FM_3367_001, FM_3367_001_PROG};
use crate::{
    Channel, Error, Result, TLS_FLASH_PARTITION, cache, crypto, dmi, handshake, pairing,
    parse_tls_flash, read_flash, send_init, split_status, tls_flash_ids, usb,
};

const KEY_CAL_LINE: u32 = 0x38;
const LINES_PER_FRAME: u16 = 224;
const CALIBRATION_FRAMES: u16 = 3;
const CALIBRATION_ITERATIONS: usize = 3;
/// How often blocking waits wake up to check the cancel flag.
const POLL: Duration = Duration::from_millis(200);
/// Upper bound for waits that should complete quickly (no finger needed).
const QUICK_WAIT: Duration = Duration::from_secs(10);
/// After finger-down, how long the chip may take to finish a capture.
/// python-validity on a P52 saw 0.1 s (identify) to ~3.5 s (enroll,
/// finger held); if the finger is lifted too early it never finishes.
const CAPTURE_STALL: Duration = Duration::from_secs(8);
/// Longest we wait for the reply to any single command.
const CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// Returns `true` when the caller wants the current operation aborted.
pub type CancelFn<'a> = &'a dyn Fn() -> bool;

/// Map a local Unix uid to the SID identity stored on the sensor.
/// Identical to python-validity's `dbus-service` scheme, so fingers
/// enrolled there are found here too.
pub fn sid_for_uid(uid: u32) -> SidIdentity {
    SidIdentity {
        revision: 1,
        auth: 5,
        subauth: vec![21, 111_111_111, 1_111_111_111, 1_111_111_111, uid],
    }
}

/// Result of one identify attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifyOutcome {
    /// The matcher found a template. `user_dbid` is the user record.
    Match { user_dbid: u32, subtype: u16 },
    /// Good scan, but it matches nothing in the device DB.
    NoMatch,
    /// Scan was too poor to match; ask for another press.
    RetryScan,
    /// The cancel callback fired.
    Cancelled,
}

/// Progress notifications during [`Sensor::enroll`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollEvent {
    /// A press was accepted. `good` counts accepted presses so far.
    StagePassed { good: u32 },
    /// The press was rejected (too quick / off-centre); press again.
    RetryScan,
}

/// Final result of [`Sensor::enroll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollOutcome {
    Completed { finger_dbid: u16 },
    Cancelled,
    Failed(&'static str),
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn dev_err(reason: &'static str) -> Error {
    Error::PairingMalformed { reason }
}

/// Load the pairing record from the on-disk cache, or read + decrypt it
/// from flash and refresh the cache. Same logic as the CLI.
pub fn load_or_decrypt_pairing(chan: &mut Channel) -> Result<cache::PairingCache> {
    let host = dmi::HostId::read();
    let cache_path = Path::new(cache::DEFAULT_PATH);

    if let Ok(c) = cache::PairingCache::load(cache_path)
        && c.check_host(&host.product_name, &host.product_serial).is_ok()
    {
        return Ok(c);
    }

    let buf = read_flash(chan, TLS_FLASH_PARTITION, 0, 0x1000)?;
    let blocks = parse_tls_flash(&buf)?;
    let keys = crypto::GwkKeys::derive(&host.product_name, &host.product_serial);
    let find = |id| blocks.iter().find(|b| b.id == id);
    let priv_blob = find(tls_flash_ids::PRIV_KEY).ok_or(dev_err("no priv-key block"))?;
    let cert_blob = find(tls_flash_ids::TLS_CERT).ok_or(dev_err("no TLS cert block"))?;
    let ecdh_blob = find(tls_flash_ids::ECDH_Q).ok_or(dev_err("no ECDH q block"))?;

    let cached = cache::PairingCache {
        product_name: host.product_name,
        product_serial: host.product_serial,
        tls_cert: cert_blob.body.clone(),
        priv_key: pairing::decrypt_priv(&priv_blob.body, &keys)?,
        ecdh_q: pairing::parse_ecdh(&ecdh_blob.body)?,
    };
    if let Err(e) = cached.save(cache_path) {
        log::warn!("could not write pairing cache to {}: {e}", cache_path.display());
    }
    Ok(cached)
}

/// An open, TLS-established session with the sensor.
///
/// Dropping it releases the USB interface. If an operation was
/// cancelled mid-capture the device may be left mid-program; the next
/// [`Sensor::open`] USB-resets the chip, so callers should simply drop
/// the session after a cancellation.
pub struct Sensor {
    chan: Channel,
    session: handshake::Session,
    usb: usb::Sensor,
    /// Set when an operation was abandoned mid-capture: the chip is still
    /// running a scan program, so on drop we USB-reset it (which also
    /// turns the LED off) instead of talking to it.
    dirty: bool,
}

impl Drop for Sensor {
    fn drop(&mut self) {
        if self.dirty {
            use nusb::MaybeFuture;
            log::info!("resetting sensor after an interrupted scan");
            if let Err(e) = self.usb.nusb().reset().wait() {
                log::warn!("USB reset after cancel failed: {e}");
            }
        }
    }
}

/// How a single capture attempt ended.
enum Capture {
    Complete,
    /// Finger detected but the chip never finished (finger lifted early).
    Stalled,
    Cancelled,
}

/// Inputs every capture program needs, fetched once per session.
pub struct CaptureParams {
    calib_data: Vec<u8>,
    factory_cal_values: Vec<u8>,
    subst_value: u8,
}

impl Sensor {
    /// Open the first supported sensor, USB-reset it, and complete the
    /// TLS-PSK handshake.
    pub fn open() -> Result<Self> {
        use nusb::MaybeFuture;
        let sensor = usb::Sensor::open_first()?;
        sensor.nusb().reset().wait()?;
        let mut chan = Channel::open(&sensor)?;
        chan.set_cmd_timeout(CMD_TIMEOUT);
        let p = load_or_decrypt_pairing(&mut chan)?;
        send_init(&mut chan, &INIT_HARDCODED_9A)?;
        let est = handshake::run(&mut chan, &p.tls_cert, &p.priv_key, &p.ecdh_q)?;
        log::info!("sensor session open (TLS handshake OK)");
        Ok(Self { chan, session: handshake::Session::new(est), usb: sensor, dirty: false })
    }

    /// Is a supported sensor on the bus right now? (No I/O to it.)
    pub fn present() -> bool {
        usb::enumerate().map(|v| !v.is_empty()).unwrap_or(false)
    }

    fn cmd(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        self.session.cmd(&mut self.chan, payload)
    }

    /// Send a command, require status 0, return the payload.
    fn cmd_ok(&mut self, payload: &[u8], what: &'static str) -> Result<Vec<u8>> {
        let resp = self.cmd(payload)?;
        let (s, p) = split_status(&resp)?;
        if s != 0 {
            log::warn!("{what}: device status {s:#06x}");
            return Err(dev_err(what));
        }
        Ok(p.to_vec())
    }

    /// `db_write_enable` → command → `call_cleanups`, as upstream does
    /// for every flash-modifying operation.
    fn write_enable_then(&mut self, cmd_payload: &[u8]) -> Result<Vec<u8>> {
        self.cmd_ok(&DB_WRITE_ENABLE_9A, "db_write_enable rejected")?;
        let result = self.cmd(cmd_payload);
        if let Ok(rsp) = self.cmd(&[0x1a]) {
            let (s, _) = split_status(&rsp).unwrap_or((0xffff, &[]));
            if s != 0 && s != 0x0491 {
                log::warn!("call_cleanups returned status {s:#06x}");
            }
        }
        result
    }

    /// Wait for an interrupt event matching `pred`, polling `cancel`.
    /// Returns `Ok(None)` if cancelled.
    fn wait_evt(
        &mut self,
        cancel: CancelFn<'_>,
        pred: impl Fn(&[u8]) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        loop {
            if cancel() {
                return Ok(None);
            }
            if let Some(e) = self.chan.wait_int_timeout(POLL)? {
                log::info!("  sensor event {}", hex(&e));
                if pred(&e) {
                    return Ok(Some(e));
                }
            }
        }
    }

    /// Wait for any interrupt event, bounded by [`QUICK_WAIT`]. For
    /// steps that need no finger and must not be abandoned half-way.
    fn wait_quick(&mut self) -> Result<Vec<u8>> {
        let deadline = Instant::now() + QUICK_WAIT;
        loop {
            if let Some(e) = self.chan.wait_int_timeout(POLL)? {
                log::info!("  sensor event {}", hex(&e));
                return Ok(e);
            }
            if Instant::now() > deadline {
                return Err(dev_err("timed out waiting for device event"));
            }
        }
    }

    // ───────────────────────── user database ─────────────────────────

    /// dbid of the `StgWindsor` user storage.
    pub fn storage_dbid(&mut self) -> Result<u16> {
        let p = self.cmd_ok(&[0x4b, 0x03, 0, 0, 0, 0, 0, 0, 0], "get_user_storage failed")?;
        Ok(parse_user_storage(&p)?.ok_or(dev_err("StgWindsor missing"))?.dbid)
    }

    /// Find the user record for `identity`, if one exists.
    pub fn lookup_user(&mut self, storage: u16, identity: &SidIdentity) -> Result<Option<u16>> {
        let resp = self.cmd(&build_lookup_user(storage, identity))?;
        let (s, p) = split_status(&resp)?;
        match s {
            STATUS_NOT_FOUND => Ok(None),
            0 if p.len() >= 2 => Ok(Some(u16::from_le_bytes([p[0], p[1]]))),
            _ => Err(dev_err("lookup_user failed")),
        }
    }

    /// Read a user record (its fingers list).
    pub fn get_user(&mut self, dbid: u16) -> Result<User> {
        let mut req = vec![0x4a];
        req.extend_from_slice(&dbid.to_le_bytes());
        req.extend_from_slice(&[0, 0, 0, 0]);
        let p = self.cmd_ok(&req, "get_user failed")?;
        parse_user(&p)
    }

    /// Fingers enrolled for `identity` (empty if the user is unknown).
    pub fn fingers_for(&mut self, identity: &SidIdentity) -> Result<Vec<FingerEntry>> {
        let stg = self.storage_dbid()?;
        match self.lookup_user(stg, identity)? {
            Some(dbid) => Ok(self.get_user(dbid)?.fingers),
            None => Ok(Vec::new()),
        }
    }

    /// Delete a user or finger record. Deleting a user cascades.
    pub fn delete_record(&mut self, dbid: u16) -> Result<()> {
        let resp = self.write_enable_then(&build_del_record(dbid))?;
        let (s, _) = split_status(&resp)?;
        if s != 0 {
            log::warn!("del_record({dbid}) status {s:#06x}");
            return Err(dev_err("delete record failed"));
        }
        Ok(())
    }

    // ───────────────────────── capture setup ─────────────────────────

    /// Three refining calibration passes, python-validity style: every
    /// pass carries the factory values and the calib_data so far.
    fn calibrate(&mut self, factory_cal_values: &[u8]) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        for _ in 0..CALIBRATION_ITERATIONS {
            let key_line = get_key_line(&FM_3367_001, KEY_CAL_LINE, &buf);
            let pkt = build_cmd_02(
                CaptureMode::Calibrate,
                &FM_3367_001_PROG,
                &FM_3367_001,
                &key_line,
                CALIBRATION_FRAMES,
                LINES_PER_FRAME,
                0,
                factory_cal_values,
                &buf,
            )?;
            self.cmd_ok(&pkt, "calibrate rejected")?;
            let raw = self.chan.read_async()?;
            let cooked = average_interleaved(
                &raw,
                &FM_3367_001,
                LINES_PER_FRAME as u32,
                CALIBRATION_FRAMES as u32,
            );
            process_calibration_results(&mut buf, &cooked, FM_3367_001.bytes_per_line as usize);
        }
        Ok(buf)
    }

    fn factory_calibration_values(&mut self) -> Result<Vec<u8>> {
        let mut req = vec![0x6f];
        req.extend_from_slice(&0x0e00u16.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        let payload = self.cmd_ok(&req, "factory_bits(0x0e00) failed")?;
        if payload.len() < 8 {
            return Err(dev_err("factory_bits(0x0e00) short"));
        }
        let entries = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
        let mut p = &payload[8..];
        let mut subtag3: Option<&[u8]> = None;
        for _ in 0..entries {
            if p.len() < 12 {
                break;
            }
            let len = u16::from_le_bytes([p[4], p[5]]) as usize;
            let subtag = u16::from_le_bytes([p[8], p[9]]);
            if p.len() < 12 + len {
                break;
            }
            if subtag == 3 {
                subtag3 = Some(&p[12..12 + len]);
            }
            p = &p[12 + len..];
        }
        let v = subtag3.ok_or(dev_err("no subtag=3 in factory_bits"))?;
        if v.len() < 4 {
            return Err(dev_err("factory_calibration_values too short"));
        }
        Ok(v[4..].to_vec())
    }

    /// Load the saved calibration baseline (running and saving a fresh
    /// one if none exists yet) and fetch the factory values.
    /// Calibrate in *this* session (finger off the sensor), then fetch
    /// the factory values. Like python-validity, which calibrates in the
    /// same session it scans in: on a ThinkPad P52, IDENTIFY with a
    /// baseline measured in an earlier session gave clean scans that the
    /// matcher rejected every time; calibrating first made them match.
    /// Costs well under a second. The result is also written to the
    /// usual calib_data path for the CLI's `--use-saved-calib`.
    pub fn capture_params(&mut self) -> Result<CaptureParams> {
        let factory_cal_values = self.factory_calibration_values()?;
        let started = Instant::now();
        let calib_data = self.calibrate(&factory_cal_values)?;
        log::info!("calibrated in-session ({} B, {:?})", calib_data.len(), started.elapsed());
        if let Err(e) = cache::save_calib_data(Path::new(cache::CALIB_DATA_PATH), &calib_data) {
            log::debug!("could not save calibration copy: {e}");
        }
        let subst_value = *factory_cal_values
            .get(KEY_CAL_LINE as usize)
            .ok_or(dev_err("factory_calibration_values too short"))?;
        Ok(CaptureParams { calib_data, factory_cal_values, subst_value })
    }

    fn capture_program(&self, mode: CaptureMode, cp: &CaptureParams) -> Result<Vec<u8>> {
        let key_line = get_key_line(&FM_3367_001, KEY_CAL_LINE, &cp.calib_data);
        build_cmd_02(
            mode,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            CALIBRATION_FRAMES,
            LINES_PER_FRAME,
            cp.subst_value,
            &cp.factory_cal_values,
            &cp.calib_data,
        )
    }

    /// Start a capture and wait for finger-down then capture-complete.
    /// `on_finger` fires when the finger is detected. Returns `false`
    /// if cancelled.
    fn capture(
        &mut self,
        mode: CaptureMode,
        cp: &CaptureParams,
        cancel: CancelFn<'_>,
    ) -> Result<Capture> {
        let pkt = self.capture_program(mode, cp)?;
        self.cmd_ok(&pkt, "capture rejected")?;
        log::info!("{mode:?} scan armed; waiting for finger");
        // start event, then finger-down (b[0]==2), then capture complete.
        if self.wait_evt(cancel, |_| true)?.is_none()
            || self.wait_evt(cancel, |e| e.first() == Some(&0x02))?.is_none()
        {
            self.dirty = true;
            return Ok(Capture::Cancelled);
        }
        log::info!("finger detected; reading (keep the finger still)");
        let deadline = Instant::now() + CAPTURE_STALL;
        let stalled = std::cell::Cell::new(false);
        let give_up = || {
            if cancel() {
                return true;
            }
            if Instant::now() > deadline {
                stalled.set(true);
                return true;
            }
            false
        };
        if self
            .wait_evt(&give_up, |e| e.first() == Some(&0x03) && e.len() >= 3 && (e[2] & 0x04) != 0)?
            .is_none()
        {
            if stalled.get() && !cancel() {
                // Finger probably lifted before the chip finished. Stop
                // the capture program the way python-validity's
                // `capture()` always does (`finally: tls.app('04')`) and
                // let the caller ask for another press.
                log::info!("capture did not complete within {CAPTURE_STALL:?}; stopping it");
                let _ = self.cmd(&[0x04]);
                return Ok(Capture::Stalled);
            }
            self.dirty = true;
            return Ok(Capture::Cancelled);
        }
        Ok(Capture::Complete)
    }

    /// `get_prg_status2` — `true` when the last scan was good.
    fn scan_ok(&mut self) -> Result<bool> {
        let resp = self.cmd(&[0x51, 0x00, 0x20, 0x00, 0x00])?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            log::info!("scan status {status:#06x} → retry");
            return Ok(false);
        }
        let err = CaptureStatus::parse(payload)?.error;
        log::info!("scan quality: {}", if err == 0 { "good".to_string() } else { format!("rejected ({err:#010x})") });
        Ok(err == 0)
    }

    // ───────────────────────── identify ─────────────────────────

    /// One identify attempt: wait for a press, run the on-chip matcher
    /// against every enrolled template. Mirrors `match-finger`.
    pub fn identify_once(
        &mut self,
        cp: &CaptureParams,
        cancel: CancelFn<'_>,
    ) -> Result<IdentifyOutcome> {
        self.cmd(&GLOW_START_SCAN)?;
        match self.capture(CaptureMode::Identify, cp, cancel)? {
            Capture::Complete => {}
            Capture::Stalled => {
                let _ = self.cmd(&GLOW_END_SCAN);
                return Ok(IdentifyOutcome::RetryScan);
            }
            Capture::Cancelled => return Ok(IdentifyOutcome::Cancelled),
        }
        if !self.scan_ok()? {
            let _ = self.cmd(&GLOW_END_SCAN);
            return Ok(IdentifyOutcome::RetryScan);
        }
        let _ = self.cmd(&GLOW_END_SCAN);

        let mut m = vec![0x5e, 0x02, 0xff];
        for v in [0u16, 0, 1, 0, 0] {
            m.extend_from_slice(&v.to_le_bytes());
        }
        let resp = self.cmd(&m)?;
        let (s, _) = split_status(&resp)?;
        if s != 0 {
            let _ = self.cmd(&[0x62, 0, 0, 0, 0]);
            return Err(dev_err("match cmd rejected"));
        }
        let verdict = self.wait_quick()?;
        log::info!("matcher verdict {}", hex(&verdict));
        if verdict.first() != Some(&0x03) {
            let _ = self.cmd(&[0x62, 0, 0, 0, 0]);
            // Anything but 0x03 is "finger not recognized", exactly as in
            // python-validity's match_finger(). (0x05..04b3 = no records at
            // all; 0x04..0001 = good scan that matched no stored print.)
            // Treating 0x04 as retry made pam_fprintd loop on "scan again".
            return Ok(IdentifyOutcome::NoMatch);
        }

        let resp = self.cmd(&[0x60, 0x00, 0x00, 0x00, 0x00])?;
        let _ = self.cmd(&[0x62, 0, 0, 0, 0]);
        let (s, payload) = split_status(&resp)?;
        if s != 0 || payload.len() < 2 {
            return Err(dev_err("fetch match result failed"));
        }
        let body_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let mut p = &payload[2..2 + body_len.min(payload.len() - 2)];
        let (mut user, mut subtype) = (None, None);
        while p.len() >= 4 {
            let tag = u16::from_le_bytes([p[0], p[1]]);
            let l = u16::from_le_bytes([p[2], p[3]]) as usize;
            if 4 + l > p.len() {
                break;
            }
            let val = &p[4..4 + l];
            match tag {
                1 if l == 4 => user = Some(u32::from_le_bytes(val.try_into().unwrap())),
                3 if l == 2 => subtype = Some(u16::from_le_bytes(val.try_into().unwrap())),
                _ => {}
            }
            p = &p[4 + l..];
        }
        match (user, subtype) {
            (Some(user_dbid), Some(subtype)) => {
                log::info!("matcher: hit user dbid {user_dbid}, finger {subtype}");
                Ok(IdentifyOutcome::Match { user_dbid, subtype })
            }
            _ => Err(dev_err("malformed match payload")),
        }
    }

    // ───────────────────────── enroll ─────────────────────────

    /// Enroll finger `subtype` for `identity`. Mirrors the CLI `enroll`
    /// flow (with `--use-saved-calib`), reporting each press through
    /// `on_event`. Cancellation is honoured only while waiting for a
    /// finger; once the template is complete the DB write runs to the end.
    pub fn enroll(
        &mut self,
        cp: &CaptureParams,
        identity: &SidIdentity,
        subtype: u16,
        cancel: CancelFn<'_>,
        on_event: &mut dyn FnMut(EnrollEvent),
    ) -> Result<EnrollOutcome> {
        const MAX_ATTEMPTS: u32 = 25;
        const MAX_GOOD_PRESSES: u32 = 12;

        let stg = self.storage_dbid()?;
        let _ = self.cmd(&build_enrollment_mode(0));
        self.cmd_ok(&build_enrollment_mode(1), "create_enrollment failed")?;
        log::info!("enrollment session created");

        let mut prev_template: Vec<u8> = Vec::new();
        let mut key: u32 = 0;
        let mut good: u32 = 0;
        let mut attempts: u32 = 0;
        let final_tid: Vec<u8>;
        let abort = |s: &mut Self| {
            let _ = s.cmd(&GLOW_END_SCAN);
            let _ = s.cmd(&build_enrollment_mode(0));
        };

        loop {
            attempts += 1;
            if attempts > MAX_ATTEMPTS || good > MAX_GOOD_PRESSES {
                abort(self);
                return Ok(EnrollOutcome::Failed("device never completed the template"));
            }
            self.cmd(&GLOW_START_SCAN)?;
            match self.capture(CaptureMode::Enroll, cp, cancel)? {
                Capture::Complete => {}
                Capture::Stalled => {
                    on_event(EnrollEvent::RetryScan);
                    let _ = self.cmd(&build_enrollment_mode(0));
                    continue;
                }
                Capture::Cancelled => return Ok(EnrollOutcome::Cancelled),
            }
            if !self.scan_ok()? {
                on_event(EnrollEvent::RetryScan);
                let _ = self.cmd(&build_enrollment_mode(0));
                continue;
            }

            let resp = self.cmd(&build_enrollment_update_start(key))?;
            let (s, p) = split_status(&resp)?;
            if s != 0 || p.len() < 4 {
                on_event(EnrollEvent::RetryScan);
                let _ = self.cmd(&build_enrollment_mode(0));
                continue;
            }
            key = u32::from_le_bytes(p[..4].try_into().unwrap());
            self.wait_quick()?;

            let _ = self.write_enable_then(&build_enrollment_update(&prev_template))?;
            self.wait_quick()?;
            let resp = self.write_enable_then(&build_enrollment_update(&prev_template))?;
            let (s, p) = split_status(&resp)?;
            let body = if s == 0 && p.len() >= 2 {
                let n = u16::from_le_bytes([p[0], p[1]]) as usize;
                (2 + n <= p.len()).then(|| p[2..2 + n].to_vec())
            } else {
                None
            };
            let Some(body) = body else {
                on_event(EnrollEvent::RetryScan);
                let _ = self.cmd(&build_enrollment_mode(0));
                continue;
            };

            let mut walker = &body[..];
            let mut tid: Option<Vec<u8>> = None;
            while walker.len() >= 4 {
                let tag = u16::from_le_bytes([walker[0], walker[1]]);
                let l = u16::from_le_bytes([walker[2], walker[3]]) as usize;
                let chunk = ENROLL_MAGIC_LEN + l;
                if walker.len() < chunk {
                    break;
                }
                match tag {
                    0 => prev_template = walker[..chunk].to_vec(),
                    3 => tid = Some(walker[ENROLL_MAGIC_LEN..chunk].to_vec()),
                    _ => {}
                }
                walker = &walker[chunk..];
            }
            good += 1;
            log::info!("enroll press {good} accepted{}", if tid.is_some() { " — template complete" } else { "" });
            let _ = self.cmd(&build_enrollment_mode(0));
            if let Some(t) = tid {
                final_tid = t;
                break;
            }
            on_event(EnrollEvent::StagePassed { good });
        }
        let _ = self.cmd(&build_enrollment_mode(0));

        // Create (or reuse) the user record, then write the finger.
        let user_dbid = match self.lookup_user(stg, identity)? {
            Some(d) => d,
            None => {
                let cmd = build_new_record(stg, 5, stg, &identity_to_bytes(identity));
                let resp = self.write_enable_then(&cmd)?;
                let (s, p) = split_status(&resp)?;
                if s != 0 || p.len() < 2 {
                    let _ = self.cmd(&GLOW_END_SCAN);
                    return Ok(EnrollOutcome::Failed("could not create user record"));
                }
                u16::from_le_bytes([p[0], p[1]])
            }
        };
        let finger_data = make_finger_data(subtype, &prev_template, &final_tid);
        let resp = self.write_enable_then(&build_new_record(user_dbid, 0xb, stg, &finger_data))?;
        let (s, p) = split_status(&resp)?;
        if s != 0 || p.len() < 2 {
            let _ = self.cmd(&GLOW_END_SCAN);
            return Ok(EnrollOutcome::Failed("could not write finger record"));
        }
        let finger_dbid = u16::from_le_bytes([p[0], p[1]]);
        log::info!("finger record written (dbid {finger_dbid}) for user dbid {user_dbid}");
        let _ = self.wait_quick();
        let _ = self.cmd(&GLOW_END_SCAN);
        Ok(EnrollOutcome::Completed { finger_dbid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_matches_python_validity_scheme() {
        assert_eq!(
            sid_for_uid(1000).to_string(),
            "S-1-5-21-111111111-1111111111-1111111111-1000"
        );
    }
}
