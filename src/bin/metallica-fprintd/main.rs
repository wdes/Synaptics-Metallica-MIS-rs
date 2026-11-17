// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `metallica-fprintd` — a drop-in replacement for the fprintd D-Bus
//! service (`net.reactivated.Fprint`) backed by this crate's driver.
//!
//! Desktop settings panels (KDE, GNOME), `pam_fprintd` (SDDM, sudo, the
//! KDE lock screen) and `fprintd-*` command-line tools all talk to
//! fprintd over this D-Bus API, so implementing it lets them use the
//! Metallica MIS sensor without libfprint.
//!
//! Users are mapped to on-sensor records by uid, using the same SID
//! scheme as python-validity (`S-1-5-21-111111111-1111111111-1111111111-<uid>`).
//!
//! Flags:
//!   --mock        simulated sensor (for testing without hardware)
//!   --session     use the session bus instead of the system bus
//!   --no-polkit   skip polkit checks (testing only)

mod backend;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use backend::{Backend, EnrollProgress, EnrollResult, VerifyResult};
use futures_util::StreamExt;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, Value};
use zbus::{Connection, fdo, interface};

/// Enrollment stages advertised to clients. The chip decides when a
/// template is complete (usually after ~8 good presses); this only
/// drives progress bars.
pub const ENROLL_STAGES: u32 = 8;
const MANAGER_PATH: &str = "/net/reactivated/Fprint/Manager";
const DEV_PATH: &str = "/net/reactivated/Fprint/Device/0";
const BUS_NAME: &str = "net.reactivated.Fprint";

const ACT_VERIFY: &str = "net.reactivated.fprint.device.verify";
const ACT_ENROLL: &str = "net.reactivated.fprint.device.enroll";
const ACT_SETUSER: &str = "net.reactivated.fprint.device.setusername";

// ───────────────────────── errors ─────────────────────────

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "net.reactivated.Fprint.Error")]
enum FpError {
    #[zbus(error)]
    ZBus(zbus::Error),
    ClaimDevice(String),
    AlreadyInUse(String),
    Internal(String),
    PermissionDenied(String),
    NoEnrolledPrints(String),
    FingerAlreadyEnrolled(String),
    NoActionInProgress(String),
    InvalidFingername(String),
    NoSuchDevice(String),
    PrintsNotDeleted(String),
}

impl From<fdo::Error> for FpError {
    fn from(e: fdo::Error) -> Self {
        FpError::Internal(e.to_string())
    }
}


// ───────────────────────── helpers ─────────────────────────

fn finger_subtype(name: &str) -> Option<u16> {
    (1..=10).find(|&s| think_touch::db::subtype_name(s) == Some(name))
}

fn finger_name(subtype: u16) -> Option<&'static str> {
    if (1..=10).contains(&subtype) { think_touch::db::subtype_name(subtype) } else { None }
}

struct Caller {
    sender: String,
    uid: u32,
}

async fn caller(conn: &Connection, hdr: &Header<'_>) -> Result<Caller, FpError> {
    let sender = hdr
        .sender()
        .ok_or_else(|| FpError::Internal("message has no sender".into()))?
        .to_string();
    let bus = BusName::try_from(sender.as_str()).map_err(|e| FpError::Internal(e.to_string()))?;
    let uid = fdo::DBusProxy::new(conn).await?.get_connection_unix_user(bus).await?;
    Ok(Caller { sender, uid })
}

/// Resolve the username argument fprintd methods take ("" = caller).
fn resolve_user(name: &str, caller_uid: u32) -> Result<(String, u32), FpError> {
    use nix::unistd::{Uid, User};
    let user = if name.is_empty() {
        User::from_uid(Uid::from_raw(caller_uid))
    } else {
        User::from_name(name)
    };
    match user {
        Ok(Some(u)) => Ok((u.name, u.uid.as_raw())),
        _ => Err(FpError::Internal(format!("unknown user {name:?}"))),
    }
}

async fn polkit_check(conn: &Connection, sender: &str, action: &str) -> zbus::Result<bool> {
    let mut subject: HashMap<&str, Value<'_>> = HashMap::new();
    subject.insert("name", Value::from(sender));
    let details: HashMap<&str, &str> = HashMap::new();
    let reply = conn
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            // flags = 1: AllowUserInteraction (password prompt if needed)
            &(("system-bus-name", subject), action, details, 1u32, ""),
        )
        .await?;
    let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) =
        reply.body().deserialize()?;
    Ok(authorized)
}

// ───────────────────────── state ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Verify,
    Enroll,
}

struct Claim {
    sender: String,
    username: String,
    uid: u32,
}

#[derive(Default)]
struct State {
    claim: Option<Claim>,
    /// Current action, kept until the client calls *Stop even after the
    /// worker has finished (fprintd semantics).
    action: Option<Kind>,
    cancel: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

type Shared = Arc<Mutex<State>>;

fn lock(s: &Shared) -> std::sync::MutexGuard<'_, State> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

/// Cancel the running action (if any) and give its worker a moment to
/// exit. Never blocks the caller for long: D-Bus clients (KDE settings)
/// call *Stop/Release synchronously and freeze while they wait. A worker
/// that is still winding down keeps the device lock, so the next
/// operation simply queues behind it.
async fn stop_action(state: &Shared) {
    let worker = {
        let mut st = lock(state);
        st.cancel.store(true, Ordering::SeqCst);
        st.action = None;
        st.worker.take()
    };
    if let Some(w) = worker {
        let finished = blocking::unblock(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !w.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            w.is_finished()
        })
        .await;
        if !finished {
            log::warn!("worker still shutting down; continuing without waiting");
        }
    }
}

// ───────────────────────── Manager ─────────────────────────

struct Manager {
    backend: Arc<dyn Backend>,
}

#[interface(name = "net.reactivated.Fprint.Manager")]
impl Manager {
    async fn get_devices(&self) -> Vec<OwnedObjectPath> {
        let b = self.backend.clone();
        if blocking::unblock(move || b.present()).await {
            vec![OwnedObjectPath::try_from(DEV_PATH).unwrap()]
        } else {
            Vec::new()
        }
    }

    async fn get_default_device(&self) -> Result<OwnedObjectPath, FpError> {
        let b = self.backend.clone();
        if blocking::unblock(move || b.present()).await {
            Ok(OwnedObjectPath::try_from(DEV_PATH).unwrap())
        } else {
            Err(FpError::NoSuchDevice("No devices available".into()))
        }
    }
}

// ───────────────────────── Device ─────────────────────────

struct Device {
    backend: Arc<dyn Backend>,
    state: Shared,
    polkit: bool,
}

impl Device {
    async fn authorize(&self, conn: &Connection, c: &Caller, action: &str) -> Result<(), FpError> {
        if c.uid == 0 || !self.polkit {
            return Ok(());
        }
        log::info!("polkit: asking whether uid {} may {action} (a password prompt may appear)", c.uid);
        let r = polkit_check(conn, &c.sender, action).await;
        log::info!("polkit: {action} → {r:?}");
        match r {
            Ok(true) => Ok(()),
            Ok(false) => Err(FpError::PermissionDenied(format!("Not Authorized: {action}"))),
            Err(e) => Err(FpError::PermissionDenied(format!("polkit check failed: {e}"))),
        }
    }

    /// The (username, uid) the caller has claimed the device for.
    fn claimed_by(&self, sender: &str) -> Result<(String, u32), FpError> {
        let st = lock(&self.state);
        match &st.claim {
            None => Err(FpError::ClaimDevice("Device was not claimed before use".into())),
            Some(c) if c.sender != sender => {
                Err(FpError::AlreadyInUse("Device already in use by another user".into()))
            }
            Some(c) => Ok((c.username.clone(), c.uid)),
        }
    }

    /// Begin an action: requires no other action in flight.
    fn begin(&self, kind: Kind) -> Result<Arc<AtomicBool>, FpError> {
        let mut st = lock(&self.state);
        if let Some(a) = st.action {
            let running = st.worker.as_ref().is_some_and(|w| !w.is_finished());
            if running || a != kind {
                return Err(FpError::AlreadyInUse("An action is already in progress".into()));
            }
            // Previous action of the same kind finished but wasn't
            // stopped; be lenient and reuse the slot.
        }
        let cancel = Arc::new(AtomicBool::new(false));
        st.cancel = cancel.clone();
        st.action = Some(kind);
        Ok(cancel)
    }

    async fn list_names(&self, uid: u32) -> Result<Vec<String>, FpError> {
        let b = self.backend.clone();
        let subtypes = blocking::unblock(move || b.list(uid)).await.map_err(FpError::Internal)?;
        Ok(subtypes.into_iter().filter_map(finger_name).map(String::from).collect())
    }
}

#[interface(name = "net.reactivated.Fprint.Device")]
impl Device {
    async fn list_enrolled_fingers(
        &self,
        username: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<Vec<String>, FpError> {
        let c = caller(conn, &hdr).await?;
        let (_, uid) = resolve_user(username, c.uid)?;
        log::info!("ListEnrolledFingers({username:?}) from {} (uid {})", c.sender, c.uid);
        if uid != c.uid {
            self.authorize(conn, &c, ACT_SETUSER).await?;
        }
        self.authorize(conn, &c, ACT_VERIFY).await?;
        let names = self.list_names(uid).await?;
        log::info!("  → {names:?}");
        if names.is_empty() {
            return Err(FpError::NoEnrolledPrints("Failed to discover prints".into()));
        }
        Ok(names)
    }

    /// Deprecated fprintd API: delete all prints of `username` without a claim.
    async fn delete_enrolled_fingers(
        &self,
        username: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        let (_, uid) = resolve_user(username, c.uid)?;
        if uid != c.uid {
            self.authorize(conn, &c, ACT_SETUSER).await?;
        }
        self.authorize(conn, &c, ACT_ENROLL).await?;
        let b = self.backend.clone();
        blocking::unblock(move || b.delete_all(uid)).await.map_err(FpError::PrintsNotDeleted)
    }

    async fn delete_enrolled_fingers2(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        let (_, uid) = self.claimed_by(&c.sender)?;
        self.authorize(conn, &c, ACT_ENROLL).await?;
        let b = self.backend.clone();
        blocking::unblock(move || b.delete_all(uid)).await.map_err(FpError::PrintsNotDeleted)
    }

    async fn delete_enrolled_finger(
        &self,
        finger_name: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        let (_, uid) = self.claimed_by(&c.sender)?;
        let subtype = finger_subtype(finger_name)
            .ok_or_else(|| FpError::InvalidFingername(format!("Invalid finger name {finger_name}")))?;
        self.authorize(conn, &c, ACT_ENROLL).await?;
        let b = self.backend.clone();
        blocking::unblock(move || b.delete_one(uid, subtype))
            .await
            .map_err(FpError::PrintsNotDeleted)
    }

    async fn claim(
        &self,
        username: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        let (name, uid) = resolve_user(username, c.uid)?;
        if uid != c.uid {
            self.authorize(conn, &c, ACT_SETUSER).await?;
        }
        self.authorize(conn, &c, ACT_VERIFY).await?;
        let mut st = lock(&self.state);
        if st.claim.is_some() {
            return Err(FpError::AlreadyInUse("Device was already claimed".into()));
        }
        log::info!("claimed by {} for user {name} (uid {uid})", c.sender);
        st.claim = Some(Claim { sender: c.sender, username: name, uid });
        Ok(())
    }

    async fn release(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        self.claimed_by(&c.sender)?;
        stop_action(&self.state).await;
        lock(&self.state).claim = None;
        log::info!("released by {}", c.sender);
        Ok(())
    }

    async fn verify_start(
        &self,
        finger_name: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        let (username, uid) = self.claimed_by(&c.sender)?;
        self.authorize(conn, &c, ACT_VERIFY).await?;

        let enrolled = self.list_names(uid).await?;
        if enrolled.is_empty() {
            return Err(FpError::NoEnrolledPrints(format!("No fingerprints enrolled for {username}")));
        }
        let (want, selected) = match finger_name {
            "" | "any" => (None, "any".to_string()),
            f => {
                let s = finger_subtype(f)
                    .ok_or_else(|| FpError::InvalidFingername(format!("Invalid finger name {f}")))?;
                if !enrolled.iter().any(|e| e == f) {
                    return Err(FpError::NoEnrolledPrints(format!("{f} is not enrolled")));
                }
                (Some(s), f.to_string())
            }
        };

        let cancel = self.begin(Kind::Verify)?;
        let backend = self.backend.clone();
        let conn = conn.clone();
        log::info!("verify start for {username} (finger {selected})");
        let worker = std::thread::spawn(move || {
            let Ok(em) = SignalEmitter::new(&conn, DEV_PATH) else { return };
            let emit = |r: &str, done: bool| {
                log::info!("VerifyStatus {r} done={done}");
                let _ = zbus::block_on(Device::verify_status(&em, r, done));
            };
            let _ = zbus::block_on(Device::verify_finger_selected(&em, &selected));
            let is_cancelled = || cancel.load(Ordering::SeqCst);
            let res = backend.verify(uid, want, &is_cancelled, &mut || {
                emit("verify-retry-scan", false)
            });
            match res {
                Ok(VerifyResult::Match) => emit("verify-match", true),
                Ok(VerifyResult::NoMatch) => emit("verify-no-match", true),
                Ok(VerifyResult::Cancelled) => log::info!("verify cancelled"),
                Err(e) => {
                    log::error!("verify failed: {e}");
                    let r = if backend.present() { "verify-unknown-error" } else { "verify-disconnected" };
                    emit(r, true);
                }
            }
        });
        lock(&self.state).worker = Some(worker);
        Ok(())
    }

    async fn verify_stop(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        self.claimed_by(&c.sender)?;
        if lock(&self.state).action != Some(Kind::Verify) {
            return Err(FpError::NoActionInProgress("No verification in progress".into()));
        }
        stop_action(&self.state).await;
        Ok(())
    }

    async fn enroll_start(
        &self,
        finger_name: &str,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        log::info!("EnrollStart({finger_name:?}) from {}", c.sender);
        let (username, uid) = self.claimed_by(&c.sender)?;
        let subtype = finger_subtype(finger_name)
            .ok_or_else(|| FpError::InvalidFingername(format!("Invalid finger name {finger_name}")))?;
        self.authorize(conn, &c, ACT_ENROLL).await?;
        if self.list_names(uid).await?.iter().any(|e| e == finger_name) {
            return Err(FpError::FingerAlreadyEnrolled(format!("{finger_name} is already enrolled")));
        }

        let cancel = self.begin(Kind::Enroll)?;
        let backend = self.backend.clone();
        let conn = conn.clone();
        log::info!("enroll start for {username} (finger {finger_name})");
        let worker = std::thread::spawn(move || {
            let Ok(em) = SignalEmitter::new(&conn, DEV_PATH) else { return };
            let emit = |r: &str, done: bool| {
                log::info!("EnrollStatus {r} done={done}");
                let _ = zbus::block_on(Device::enroll_status(&em, r, done));
            };
            let is_cancelled = || cancel.load(Ordering::SeqCst);
            let res = backend.enroll(uid, subtype, &is_cancelled, &mut |p| match p {
                EnrollProgress::StagePassed => emit("enroll-stage-passed", false),
                EnrollProgress::RetryScan => emit("enroll-retry-scan", false),
            });
            match res {
                Ok(EnrollResult::Completed) => emit("enroll-completed", true),
                Ok(EnrollResult::Cancelled) => log::info!("enroll cancelled"),
                Ok(EnrollResult::Failed(why)) => {
                    log::error!("enroll failed: {why}");
                    emit("enroll-failed", true);
                }
                Err(e) => {
                    log::error!("enroll error: {e}");
                    let r = if backend.present() { "enroll-unknown-error" } else { "enroll-disconnected" };
                    emit(r, true);
                }
            }
        });
        lock(&self.state).worker = Some(worker);
        Ok(())
    }

    async fn enroll_stop(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> Result<(), FpError> {
        let c = caller(conn, &hdr).await?;
        log::info!("EnrollStop from {}", c.sender);
        self.claimed_by(&c.sender)?;
        if lock(&self.state).action != Some(Kind::Enroll) {
            return Err(FpError::NoActionInProgress("No enrollment in progress".into()));
        }
        stop_action(&self.state).await;
        Ok(())
    }

    #[zbus(signal)]
    async fn verify_finger_selected(em: &SignalEmitter<'_>, finger_name: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn verify_status(em: &SignalEmitter<'_>, result: &str, done: bool) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn enroll_status(em: &SignalEmitter<'_>, result: &str, done: bool) -> zbus::Result<()>;

    #[zbus(property, name = "name")]
    fn name(&self) -> String {
        "Synaptics Metallica MIS (06cb:009a)".into()
    }

    #[zbus(property, name = "num-enroll-stages")]
    fn num_enroll_stages(&self) -> i32 {
        ENROLL_STAGES as i32
    }

    #[zbus(property, name = "scan-type")]
    fn scan_type(&self) -> String {
        "press".into()
    }

    #[zbus(property, name = "finger-present")]
    fn finger_present(&self) -> bool {
        false
    }

    #[zbus(property, name = "finger-needed")]
    fn finger_needed(&self) -> bool {
        lock(&self.state).worker.as_ref().is_some_and(|w| !w.is_finished())
    }
}

// ───────────────────────── main ─────────────────────────

/// Release the device if its claimer disconnects without calling
/// Release (crashed client, killed sudo, …).
async fn watch_clients(conn: Connection, state: Shared) -> zbus::Result<()> {
    let proxy = fdo::DBusProxy::new(&conn).await?;
    let mut changes = proxy.receive_name_owner_changed().await?;
    while let Some(sig) = changes.next().await {
        let Ok(args) = sig.args() else { continue };
        if args.new_owner().is_some() {
            continue;
        }
        let gone = args.name().to_string();
        let was_claimer = lock(&state).claim.as_ref().is_some_and(|c| c.sender == gone);
        if was_claimer {
            log::info!("claimer {gone} vanished; releasing device");
            stop_action(&state).await;
            lock(&state).claim = None;
        }
    }
    Ok(())
}

async fn run(mock: bool, session: bool, polkit: bool) -> zbus::Result<()> {
    let backend: Arc<dyn Backend> =
        if mock { Arc::new(backend::Mock::new()) } else { Arc::new(backend::Hardware::new()) };
    let state: Shared = Arc::default();

    let builder =
        if session { zbus::connection::Builder::session()? } else { zbus::connection::Builder::system()? };
    let conn = builder
        .name(BUS_NAME)?
        .serve_at(MANAGER_PATH, Manager { backend: backend.clone() })?
        .serve_at(DEV_PATH, Device { backend, state: state.clone(), polkit })?
        .build()
        .await?;
    log::info!(
        "metallica-fprintd ready on the {} bus{}{}",
        if session { "session" } else { "system" },
        if mock { " (mock sensor)" } else { "" },
        if polkit { "" } else { " (polkit disabled)" },
    );
    watch_clients(conn.clone(), state).await?;
    std::future::pending::<()>().await;
    Ok(())
}

fn main() -> std::process::ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    for a in &args {
        if !matches!(a.as_str(), "--mock" | "--session" | "--no-polkit") {
            eprintln!("usage: metallica-fprintd [--mock] [--session] [--no-polkit]");
            return std::process::ExitCode::from(2);
        }
    }
    let has = |f: &str| args.iter().any(|a| a == f);
    match zbus::block_on(run(has("--mock"), has("--session"), !has("--no-polkit"))) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            log::error!("fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
