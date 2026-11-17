// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Device backends for the daemon: the real sensor, and a simulated
//! one (`--mock`) used to test the D-Bus layer without hardware.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use think_touch::ops::{self, EnrollEvent, EnrollOutcome, IdentifyOutcome, Sensor};

pub type Cancel<'a> = &'a dyn Fn() -> bool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult {
    Match,
    NoMatch,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollProgress {
    StagePassed,
    RetryScan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollResult {
    Completed,
    Cancelled,
    Failed(String),
}

pub trait Backend: Send + Sync + 'static {
    /// Is the sensor attached?
    fn present(&self) -> bool;
    /// Enrolled finger subtypes (1..=10) for `uid`.
    fn list(&self, uid: u32) -> Result<Vec<u16>, String>;
    /// Delete every finger for `uid`.
    fn delete_all(&self, uid: u32) -> Result<(), String>;
    /// Delete one finger for `uid`.
    fn delete_one(&self, uid: u32, subtype: u16) -> Result<(), String>;
    /// Wait for a press and check it belongs to `uid` (and to finger
    /// `want`, if given). `on_retry` fires for each rejected scan.
    fn verify(
        &self,
        uid: u32,
        want: Option<u16>,
        cancel: Cancel<'_>,
        on_retry: &mut dyn FnMut(),
    ) -> Result<VerifyResult, String>;
    fn enroll(
        &self,
        uid: u32,
        subtype: u16,
        cancel: Cancel<'_>,
        on_progress: &mut dyn FnMut(EnrollProgress),
    ) -> Result<EnrollResult, String>;
}

/// Sleep for `d`, waking early if cancelled. Returns `true` if cancelled.
fn nap(d: Duration, cancel: Cancel<'_>) -> bool {
    let step = Duration::from_millis(100);
    let mut left = d;
    while !left.is_zero() {
        if cancel() {
            return true;
        }
        let s = left.min(step);
        std::thread::sleep(s);
        left -= s;
    }
    cancel()
}

// ───────────────────────── real hardware ─────────────────────────

pub struct Hardware {
    /// Serialises every USB session — the chip handles one at a time.
    dev: Mutex<()>,
    /// uid → enrolled subtypes. Avoids a full TLS session for every
    /// `ListEnrolledFingers` (KDE and pam_fprintd call it a lot).
    cache: Mutex<HashMap<u32, Vec<u16>>>,
}

/// Rejected scans tolerated in one verify before giving up with no-match.
const MAX_VERIFY_RETRIES: u32 = 8;

impl Hardware {
    pub fn new() -> Self {
        Self { dev: Mutex::new(()), cache: Mutex::new(HashMap::new()) }
    }

    fn with_sensor<R>(
        &self,
        f: impl FnOnce(&mut Sensor) -> think_touch::Result<R>,
    ) -> Result<R, String> {
        let _guard = self.dev.lock().unwrap_or_else(|e| e.into_inner());
        let mut s = Sensor::open().map_err(|e| format!("open sensor: {e}"))?;
        f(&mut s).map_err(|e| e.to_string())
    }

    fn forget(&self, uid: u32) {
        self.cache.lock().unwrap().remove(&uid);
    }
}

impl Backend for Hardware {
    fn present(&self) -> bool {
        Sensor::present()
    }

    fn list(&self, uid: u32) -> Result<Vec<u16>, String> {
        if let Some(v) = self.cache.lock().unwrap().get(&uid) {
            return Ok(v.clone());
        }
        let id = ops::sid_for_uid(uid);
        let mut v: Vec<u16> =
            self.with_sensor(|s| s.fingers_for(&id))?.iter().map(|f| f.subtype).collect();
        v.sort_unstable();
        v.dedup();
        self.cache.lock().unwrap().insert(uid, v.clone());
        Ok(v)
    }

    fn delete_all(&self, uid: u32) -> Result<(), String> {
        let id = ops::sid_for_uid(uid);
        self.forget(uid);
        self.with_sensor(|s| {
            let stg = s.storage_dbid()?;
            if let Some(dbid) = s.lookup_user(stg, &id)? {
                s.delete_record(dbid)?;
            }
            Ok(())
        })
    }

    fn delete_one(&self, uid: u32, subtype: u16) -> Result<(), String> {
        let id = ops::sid_for_uid(uid);
        self.forget(uid);
        self.with_sensor(|s| {
            for f in s.fingers_for(&id)?.iter().filter(|f| f.subtype == subtype) {
                s.delete_record(f.dbid)?;
            }
            Ok(())
        })
    }

    fn verify(
        &self,
        uid: u32,
        want: Option<u16>,
        cancel: Cancel<'_>,
        on_retry: &mut dyn FnMut(),
    ) -> Result<VerifyResult, String> {
        let id = ops::sid_for_uid(uid);
        self.with_sensor(|s| {
            let stg = s.storage_dbid()?;
            let Some(my_dbid) = s.lookup_user(stg, &id)? else {
                return Ok(VerifyResult::NoMatch);
            };
            let cp = s.capture_params()?;
            let mut retries = 0;
            loop {
                match s.identify_once(&cp, cancel)? {
                    IdentifyOutcome::Cancelled => return Ok(VerifyResult::Cancelled),
                    IdentifyOutcome::NoMatch => return Ok(VerifyResult::NoMatch),
                    IdentifyOutcome::Match { user_dbid, subtype } => {
                        let ok = user_dbid == u32::from(my_dbid)
                            && want.is_none_or(|w| w == subtype);
                        log::info!(
                            "matched user dbid {user_dbid} finger {subtype}; \
                             expected dbid {my_dbid} → {}",
                            if ok { "accept" } else { "reject" }
                        );
                        return Ok(if ok { VerifyResult::Match } else { VerifyResult::NoMatch });
                    }
                    IdentifyOutcome::RetryScan => {
                        retries += 1;
                        if retries > MAX_VERIFY_RETRIES {
                            return Ok(VerifyResult::NoMatch);
                        }
                        on_retry();
                        // Give the user a moment to lift the finger: the
                        // matcher rejects a continuously-held press.
                        if nap(Duration::from_millis(800), cancel) {
                            return Ok(VerifyResult::Cancelled);
                        }
                    }
                }
            }
        })
    }

    fn enroll(
        &self,
        uid: u32,
        subtype: u16,
        cancel: Cancel<'_>,
        on_progress: &mut dyn FnMut(EnrollProgress),
    ) -> Result<EnrollResult, String> {
        let id = ops::sid_for_uid(uid);
        self.forget(uid);
        let out = self.with_sensor(|s| {
            let cp = s.capture_params()?;
            s.enroll(&cp, &id, subtype, cancel, &mut |e| match e {
                EnrollEvent::StagePassed { .. } => on_progress(EnrollProgress::StagePassed),
                EnrollEvent::RetryScan => on_progress(EnrollProgress::RetryScan),
            })
        })?;
        self.forget(uid);
        Ok(match out {
            EnrollOutcome::Completed { .. } => EnrollResult::Completed,
            EnrollOutcome::Cancelled => EnrollResult::Cancelled,
            EnrollOutcome::Failed(why) => EnrollResult::Failed(why.to_string()),
        })
    }
}

// ───────────────────────── simulated device ─────────────────────────

/// In-memory stand-in for the sensor. Behaviour knobs (env vars):
/// `MOCK_VERIFY=match|nomatch` (default match), `MOCK_PRESS_MS` delay
/// per simulated press (default 300).
pub struct Mock {
    db: Mutex<HashMap<u32, Vec<u16>>>,
}

impl Mock {
    pub fn new() -> Self {
        Self { db: Mutex::new(HashMap::new()) }
    }
    fn press() -> Duration {
        let ms = std::env::var("MOCK_PRESS_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(300);
        Duration::from_millis(ms)
    }
}

impl Backend for Mock {
    fn present(&self) -> bool {
        true
    }
    fn list(&self, uid: u32) -> Result<Vec<u16>, String> {
        Ok(self.db.lock().unwrap().get(&uid).cloned().unwrap_or_default())
    }
    fn delete_all(&self, uid: u32) -> Result<(), String> {
        self.db.lock().unwrap().remove(&uid);
        Ok(())
    }
    fn delete_one(&self, uid: u32, subtype: u16) -> Result<(), String> {
        if let Some(v) = self.db.lock().unwrap().get_mut(&uid) {
            v.retain(|&s| s != subtype);
        }
        Ok(())
    }
    fn verify(
        &self,
        uid: u32,
        want: Option<u16>,
        cancel: Cancel<'_>,
        on_retry: &mut dyn FnMut(),
    ) -> Result<VerifyResult, String> {
        if nap(Self::press(), cancel) {
            return Ok(VerifyResult::Cancelled);
        }
        on_retry(); // exercise the retry path once
        if nap(Self::press(), cancel) {
            return Ok(VerifyResult::Cancelled);
        }
        let enrolled = self.list(uid)?;
        let hit = std::env::var("MOCK_VERIFY").as_deref() != Ok("nomatch")
            && want.map_or(!enrolled.is_empty(), |w| enrolled.contains(&w));
        Ok(if hit { VerifyResult::Match } else { VerifyResult::NoMatch })
    }
    fn enroll(
        &self,
        uid: u32,
        subtype: u16,
        cancel: Cancel<'_>,
        on_progress: &mut dyn FnMut(EnrollProgress),
    ) -> Result<EnrollResult, String> {
        for i in 0..crate::ENROLL_STAGES {
            if nap(Self::press(), cancel) {
                return Ok(EnrollResult::Cancelled);
            }
            if i == 2 {
                on_progress(EnrollProgress::RetryScan);
            }
            if i + 1 < crate::ENROLL_STAGES {
                on_progress(EnrollProgress::StagePassed);
            }
        }
        self.db.lock().unwrap().entry(uid).or_default().push(subtype);
        Ok(EnrollResult::Completed)
    }
}
