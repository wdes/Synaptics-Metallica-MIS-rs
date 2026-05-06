// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use jiff::Timestamp;
use std::path::Path;

use think_touch::{
    CMD_GET_VERSION, CMD_PROBE_19, Channel, Error, FWEXT_PARTITION, FwextState, Result, RomExtra,
    RomInfo, TLS_FLASH_PARTITION, blobs, cache, crypto, dmi, handshake, pairing, parse_tls_flash,
    query_partition, read_flash, send_init, split_status, tls, tls_flash_ids, usb,
};

#[derive(Parser)]
#[command(version, about = "Userspace driver for Synaptics/Validity Metallica-MIS fingerprint sensors")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List supported fingerprint sensors currently on the USB bus.
    List,
    /// Open the first supported sensor and print its descriptors.
    Identify,
    /// Send the cleartext `Get Version` (cmd 0x01) and print the reply.
    Version,
    /// Run the cleartext boot probes (cmd 0x01, 0x19, 0x43 02) and report
    /// whether a firmware-extension is loaded.
    BootInfo,
    /// Print the pre-TLS GWK keys derived from this host's DMI identity.
    /// Useful for cross-checking the crypto layer against python-validity.
    Gwk,
    /// Send a Client Hello and dump whatever TLS records the device replies
    /// with. Stops before any cryptographic step that needs pairing data.
    TlsHello,
    /// Read the TLS pairing record (flash partition 1, 4 KiB) over the
    /// cleartext command channel and decode its blocks.
    FlashRead,
    /// Read flash partition 1 and decrypt the per-host pairing record
    /// (priv key + ECDH q). Verifies that the device is paired with this
    /// exact host — non-zero HMAC mismatch means re-pair is required.
    Pairing,
    /// Run a full TLS-PSK handshake end-to-end and print the negotiated
    /// session keys (redacted). Proves the entire crypto stack works.
    TlsHandshake,
    /// Identify the specific sensor variant (cmd 0x75 over TLS).
    IdentifySensor,
    /// Send an arbitrary hex payload through the TLS session and dump the
    /// decrypted reply. Useful for protocol exploration.
    Send {
        /// Hex string (e.g. "01" or "75 ff").
        hex: String,
    },
    /// USB-reset the sensor. Use this to recover when a previous run was
    /// killed before its `reboot` ran and the device is now stuck in TLS
    /// state (any cleartext probe returns bytes starting with `15 03 …`).
    Reset,
    /// Query the fwext partition (`0x43 02`) over TLS and decode the
    /// `PartitionInfo` reply (firmware-extension version + module table).
    FwextInfo,
    /// Delete the cached pairing record at `/var/lib/think-touch/session`.
    /// Use after re-pairing or to force a flash re-read on the next run.
    Forget,
    /// Run the 3-pass calibration loop, then persist the resulting
    /// calib_data buffer to `/var/lib/think-touch/calib_data` (mode 0600).
    /// Subsequent `try-identify` runs can `--use-saved-calib` to skip
    /// the iteration loop entirely.
    SaveCalib,
    /// Query the fingerprint template database (cmd 0x45 over TLS).
    /// Prints occupancy stats and the list of root IDs.
    DbInfo,
    /// Get the children of a database record by id (cmd 0x46 over TLS).
    /// Useful to walk the DB tree from a root reported by `db-info`.
    DbChildren {
        /// Record id (e.g. `3` for the user's root).
        dbid: u16,
    },
    /// Get the value of a database record (cmd 0x49 over TLS). Prints
    /// the type, storage and raw bytes.
    DbValue {
        /// Record id.
        dbid: u16,
    },
    /// Look up a user-storage record by name (cmd 0x4b over TLS).
    /// Default name is `StgWindsor` (the Windows-driver default).
    DbUserStorage {
        /// Storage name (default: `StgWindsor`).
        #[arg(long, default_value = "StgWindsor")]
        name: String,
    },
    /// Get a User record by id (cmd 0x4a over TLS). Prints the
    /// enrolled fingers' subtypes and their fprintd / ANSI-381 names.
    DbUser {
        /// User record id.
        dbid: u16,
    },
    /// Query the chip's flash IC + partition table (cmd 0x3e over TLS).
    /// Returns JEDEC ids, total size, and the live partition layout —
    /// useful to confirm our hardcoded layout matches the device.
    FlashInfo,
    /// Fetch a factory-bits TLV table (cmd 0x6f over TLS). The most
    /// useful tag is `0x0e00`, which contains the
    /// `factory_calibration_values` array used during IDENTIFY/ENROLL.
    FactoryBits {
        /// 16-bit tag selector (default `0x0e00`).
        #[arg(long, default_value_t = 0x0e00)]
        tag: u16,
    },
    /// Extract the per-host `factory_calibration_values[key_calibration_line]`
    /// byte that IDENTIFY/ENROLL captures use as `subst_value` in
    /// `patch_timeslot_again`. Pulls factory_bits(0x0e00) → subtag=3,
    /// skips its 4-byte prefix, indexes by `key_calibration_line`
    /// (0x38 for type 0x199 / FM-3367-001).
    FactoryCalibration,
    /// Send a single CALIBRATE cmd 0x02 with `key_line = zeros`, drain
    /// EP 0x82, and dump the captured raw byte count + first 256 hex
    /// bytes. Read-only: the device captures frames but doesn't persist
    /// them. First call exercising our `build_cmd_02` framing on hardware.
    TryCalibrate {
        /// Optional PGM output path for the second frame's pixel data
        /// (the one `average_interleaved` would consume).
        #[arg(long)]
        save_pgm: Option<String>,
    },
    /// Trigger an LED blink (`0x39` glow-start). Then turn it back off.
    /// No capture — just exercises the LED control path.
    Blink,
    /// Watch the EP `0x83` interrupt-IN endpoint and print every event
    /// that arrives. Useful for diagnosing why the matcher state machine
    /// isn't behaving — runs until you Ctrl-C.
    IntWatch,
    /// Decode a hex string of EP-`0x83` event bytes and print the
    /// inferred event kind + flags. Offline-only diagnostic.
    IntDecode {
        /// Hex string (e.g. `0320070000` for capture-complete).
        hex: String,
    },
    /// Send a raw command and dump the EP `0x83` interrupts that follow.
    /// Useful for figuring out which commands generate which events.
    /// Example: `int-probe "39 20 bf 02 …"` to send glow-start and see
    /// what comes back.
    IntProbe {
        /// Hex string of the command bytes to send through the TLS session
        /// before draining EP `0x83`.
        hex: String,
        /// How many interrupts to wait for before exiting (default 4).
        #[arg(long, default_value_t = 4)]
        count: usize,
    },
    /// Convert a hex string of raw EP-0x82 bytes (e.g. captured by an
    /// earlier `try-calibrate` that wrote them somewhere) into a PGM
    /// image file. Offline-only — does not touch the device.
    FrameToPgm {
        /// Hex string of the raw EP-0x82 byte stream.
        hex: String,
        /// Output PGM file path.
        out: String,
    },
    /// Dump the byte-exact output of `build_cmd_02` for a given mode,
    /// using `key_line = zeros` and `subst_value = 0`. Offline-only;
    /// useful for diff-checking against `python-validity`'s own
    /// `build_cmd_02` if you suspect framing drift.
    #[command(name = "dump-cmd-02")]
    DumpCmd02 {
        /// Capture mode: `calibrate` | `identify` | `enroll`.
        #[arg(value_parser = ["calibrate", "identify", "enroll"])]
        mode: String,
        /// Optional path; if set, the bytes are also written there.
        #[arg(long)]
        out: Option<String>,
    },
    /// One-shot read-only diagnostic. Runs every safe query in sequence
    /// (list, identify, version, boot-info, identify-sensor, fwext-info,
    /// factory-calibration, db-info) and prints a one-page summary. Use
    /// this to capture a complete state report when something feels off.
    Diagnose,
    /// Run the matcher (cmd 0x5e) and ask for a match against any
    /// enrolled finger in any user storage. Must be called immediately
    /// after a successful IDENTIFY capture (i.e. once `try-identify`
    /// reports `error=0x00000000` from `get_prg_status2`). Currently
    /// stubbed — wire format is documented in
    /// `python-validity/sensor.py:865-895` but not yet wired.
    MatchFinger,
    /// First real fingerprint scan: glow-start, IDENTIFY capture using
    /// the device's own calibration data + factory_calibration_values
    /// from its flash, drain EP 0x82, glow-end. Press the finger
    /// during the capture window. Reports raw byte count of the
    /// scan; matching is left to a future slice.
    TryIdentify {
        /// Use the existing partition-6 calibration data (Windows-paired)
        /// instead of running 3 fresh CALIBRATE iterations.
        #[arg(long, conflicts_with = "use_saved_calib")]
        use_stored_calib: bool,
        /// Use the calibration data previously saved via `save-calib`
        /// (file at `/var/lib/think-touch/calib_data`). Skips the
        /// iteration loop on each run.
        #[arg(long)]
        use_saved_calib: bool,
    },
    /// **Destructive** — write a fingerprint enrollment to the device.
    /// Drives the full upstream enroll loop: create_enrollment →
    /// (capture(ENROLL) → enrollment_update_start → append_new_image)+
    /// until the device emits a final template, then writes a User
    /// record (if the SID is new) and a Finger record under it.
    ///
    /// `--subtype` is the ANSI-381 finger position (1=right-thumb,
    /// 2=right-index, …, 7=left-index, …). `--sid-string` is the
    /// canonical SID used as the user's identity (default: a stub
    /// `S-1-5-21-1-1-1-1000` — replace per host policy).
    ///
    /// Asks for confirmation before writing flash unless `--yes` is set.
    Enroll {
        /// Finger position (1..=10 per ANSI-381). Default: 1 (right-thumb).
        #[arg(long, default_value_t = 1)]
        subtype: u16,
        /// Canonical SID string `S-<rev>-<auth>-<subauth1>-…`. Default
        /// is a placeholder for host-isolated single-user setups.
        #[arg(long, default_value = "S-1-5-21-1-1-1-1000")]
        sid_string: String,
        /// Skip the confirmation prompt before writing flash.
        #[arg(long)]
        yes: bool,
    },
    /// Read a flash partition over the TLS session. Defaults to addr 0
    /// and size 0x1000 (4 KiB) — bigger reads must opt in via `--size`.
    ///
    /// Valid partition IDs for the Metallica MIS family (from
    /// `init_flash.py:flash_layout_hardcoded`):
    ///   1 = cert store / TLS pairing record (4 KiB)
    ///   2 = xpfwext / firmware-extension (248 KiB)
    ///   4 = template database — enrolled fingerprints (512 KiB)
    ///   5 = unknown (32 KiB)
    ///   6 = calibration data (32 KiB)
    /// Other IDs return device status `0x04xx` ("partition not found").
    TlsReadFlash {
        /// Partition index.
        partition: u8,
        /// Optional starting offset inside the partition (default: 0).
        #[arg(long, default_value_t = 0)]
        addr: u32,
        /// Optional byte count to read (default: 4096).
        #[arg(long, default_value_t = 0x1000)]
        size: u32,
    },
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let result = match Cli::parse().cmd {
        Cmd::List => list(),
        Cmd::Identify => identify(),
        Cmd::Version => version(),
        Cmd::BootInfo => boot_info(),
        Cmd::Gwk => gwk(),
        Cmd::TlsHello => tls_hello(),
        Cmd::FlashRead => flash_read(),
        Cmd::Pairing => pairing(),
        Cmd::TlsHandshake => tls_handshake(),
        Cmd::IdentifySensor => identify_sensor(),
        Cmd::Send { hex } => send(&hex),
        Cmd::Reset => reset(),
        Cmd::FwextInfo => fwext_info(),
        Cmd::Forget => forget(),
        Cmd::SaveCalib => save_calib(),
        Cmd::TlsReadFlash { partition, addr, size } => tls_read_flash(partition, addr, size),
        Cmd::DbInfo => db_info(),
        Cmd::DbChildren { dbid } => db_children(dbid),
        Cmd::DbValue { dbid } => db_value(dbid),
        Cmd::DbUserStorage { name } => db_user_storage(&name),
        Cmd::DbUser { dbid } => db_user(dbid),
        Cmd::FlashInfo => flash_info(),
        Cmd::FactoryBits { tag } => factory_bits(tag),
        Cmd::FactoryCalibration => factory_calibration(),
        Cmd::TryCalibrate { save_pgm } => try_calibrate(save_pgm.as_deref()),
        Cmd::Blink => blink(),
        Cmd::IntWatch => int_watch(),
        Cmd::IntDecode { hex } => int_decode(&hex),
        Cmd::IntProbe { hex, count } => int_probe(&hex, count),
        Cmd::MatchFinger => match_finger(),
        Cmd::Diagnose => diagnose(),
        Cmd::FrameToPgm { hex, out } => frame_to_pgm(&hex, &out),
        Cmd::DumpCmd02 { mode, out } => dump_cmd_02(&mode, out.as_deref()),
        Cmd::TryIdentify { use_stored_calib, use_saved_calib } => {
            try_identify(use_stored_calib, use_saved_calib)
        }
        Cmd::Enroll { subtype, sid_string, yes } => enroll_cmd(subtype, &sid_string, yes),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report(&e);
            ExitCode::FAILURE
        }
    }
}

/// Pretty-print a top-level error and tack on a hint when we recognise it.
fn report(err: &Error) {
    eprintln!("error: {err}");
    if let Some(hint) = hint_for(err) {
        eprintln!();
        eprintln!("{hint}");
    }
}

fn hint_for(err: &Error) -> Option<&'static str> {
    let Error::Usb(usb_err) = err else {
        return None;
    };
    let is_permission = matches!(usb_err.kind(), nusb::ErrorKind::PermissionDenied)
        || usb_err.os_error() == Some(13);
    if !is_permission {
        return None;
    }
    Some(concat!(
        "hint: the kernel refused to open the sensor for this user.\n",
        "      think-touch ships a udev rule that grants access to the\n",
        "      active console session. Install it once with:\n",
        "\n",
        "        sudo install -m 644 packaging/udev/70-think-touch.rules \\\n",
        "          /etc/udev/rules.d/\n",
        "        sudo udevadm control --reload\n",
        "        sudo udevadm trigger --action=add \\\n",
        "          --attr-match=idVendor=06cb --attr-match=idProduct=009a\n",
        "\n",
        "      No replug needed. After that, `think-touch` runs without sudo.",
    ))
}

fn list() -> Result<()> {
    let sensors = usb::enumerate()?;
    if sensors.is_empty() {
        println!("no supported fingerprint sensor found");
        return Ok(());
    }
    for (info, _) in sensors {
        println!("{info}");
    }
    Ok(())
}

fn identify() -> Result<()> {
    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);
    if let Some(s) = &sensor.info.serial {
        println!("  serial:       {s}");
    }
    if let Some(m) = &sensor.info.manufacturer {
        println!("  manufacturer: {m}");
    }
    Ok(())
}

fn version() -> Result<()> {
    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);

    let mut chan = Channel::open(&sensor)?;
    let resp = chan.cmd(&[CMD_GET_VERSION])?;
    let (status, payload) = split_status(&resp)?;

    println!("> 01");
    println!("< status={} payload_len={}", fmt_status(status), payload.len());
    println!("  raw: {}", hex(&resp));

    let rom = RomInfo::parse(payload)?;
    println!("RomInfo:");
    println!("  firmware build : {}.{}.{}", rom.major, rom.minor, rom.build);
    println!(
        "  build timestamp: {} ({})",
        rom.timestamp,
        format_unix(rom.timestamp),
    );
    println!("  product code   : 0x{:02x}", rom.product);
    println!("  u1             : 0x{:02x}", rom.u1);

    if payload.len() >= 36 {
        let extra = RomExtra::parse(payload)?;
        println!("RomExtra (best-effort, undocumented upstream):");
        println!("  block_tag  : 0x{:04x}", extra.block_tag);
        println!("  hw_id      : {}", hex(&extra.hw_id));
        println!("  state_flag : 0x{:08x} ({})", extra.state_flag, extra.state_flag);
        println!("  tail       : {}", hex(&extra.tail));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if rom.is_stale(now) {
        let years = now.saturating_sub(u64::from(rom.timestamp)) / (365 * 24 * 60 * 60);
        eprintln!();
        eprintln!(
            "warning: sensor ROM is {years} years old (build {}, dated {}).",
            rom.build,
            format_unix(rom.timestamp),
        );
        eprintln!(
            "         The on-chip ROM is generally not user-updatable, but a newer"
        );
        eprintln!(
            "         firmware-extension blob (`xpfwext`) is loaded by the host on"
        );
        eprintln!(
            "         every boot. For this device family Lenovo ships:"
        );
        eprintln!();
        eprintln!("           file  : 6_07f_lenovo_mis_qm.xpfwext");
        eprintln!("           inside: https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe");
        eprintln!();
        eprintln!(
            "         Upstream `python-validity` automates the download / extraction"
        );
        eprintln!(
            "         (see its `validity-sensors-firmware` script). think-touch does"
        );
        eprintln!("         not yet upload fwext.");
        eprintln!();
        eprintln!(
            "         Note: python-validity treats ROM builds < 6.5 as legacy; {}.{}",
            rom.major, rom.minor
        );
        eprintln!("         on this device is above that bar but old in calendar terms.");
    }
    Ok(())
}

/// Format a 16-bit device status word as `0xXXXX (label)`. The label
/// comes from [`think_touch::protocol::status_label`]; success
/// (`0x0000`) renders as `OK`.
fn fmt_status(s: u16) -> String {
    use think_touch::protocol::status_label;
    match status_label(s) {
        None => format!("{s:#06x} (OK)"),
        Some(label) => format!("{s:#06x} ({label})"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn flash_read() -> Result<()> {
    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);

    let mut chan = Channel::open(&sensor)?;
    let buf = read_flash(&mut chan, TLS_FLASH_PARTITION, 0, 0x1000)?;
    println!("read {} bytes from flash partition {}", buf.len(), TLS_FLASH_PARTITION);

    let blocks = parse_tls_flash(&buf)?;
    println!("\n{} block(s):", blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        let label = match b.id {
            tls_flash_ids::TLS_CERT => "TLS cert",
            tls_flash_ids::PRIV_KEY => "private key",
            tls_flash_ids::ECDH_Q => "ECDH server q",
            tls_flash_ids::PADDING_0 | tls_flash_ids::PADDING_1 | tls_flash_ids::PADDING_2 => {
                "padding"
            }
            _ => "unknown",
        };
        let hash_ok = crypto::sha256(&b.body) == b.sha256;
        let mark = if hash_ok { "ok" } else { "BAD" };
        println!(
            "  [{i}] id=0x{:04x} ({label}), {} bytes, sha256={mark} (prefix={}…)",
            b.id,
            b.body.len(),
            hex(&b.sha256[..8]),
        );
    }
    if blocks.is_empty() {
        println!("(empty — partition 1 is unwritten or all 0xff)");
    }
    Ok(())
}

/// Run a closure with a freshly-established TLS session. We *don't*
/// auto-reboot on exit — upstream's `05 02 00` reboot capsule drops
/// the device off the USB bus, which makes back-to-back invocations
/// fail. Instead, [`establish_session`] always issues a USB-level
/// reset before opening the interface, which clears any leftover TLS
/// state on the chip without dropping it from the bus.
fn with_session<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut Channel, &handshake::Session) -> Result<R>,
{
    let (mut chan, session) = establish_session()?;
    f(&mut chan, &session)
}

/// Open the sensor, run the boot prelude, and complete a TLS-PSK
/// handshake. Returns the active channel and session ready for app-data.
fn establish_session() -> Result<(Channel, handshake::Session)> {
    use nusb::MaybeFuture;

    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);

    // Idempotent cleanup: a USB-level reset on the chip clears any TLS
    // session state left behind by a previous (possibly killed) run.
    // On a freshly-plugged device this is a no-op.
    sensor.nusb().reset().wait()?;

    let mut chan = Channel::open(&sensor)?;
    let pairing_data = load_or_decrypt_pairing(&mut chan)?;

    send_init(&mut chan, &blobs::INIT_HARDCODED_9A)?;
    let est = handshake::run(
        &mut chan,
        &pairing_data.tls_cert,
        &pairing_data.priv_key,
        &pairing_data.ecdh_q,
    )?;
    Ok((chan, handshake::Session::new(est)))
}

/// Try the on-disk cache first; fall back to reading flash + AES-CBC
/// decrypt and write the cache for next time.
fn load_or_decrypt_pairing(chan: &mut Channel) -> Result<cache::PairingCache> {
    let host = dmi::HostId::read();
    let cache_path = Path::new(cache::DEFAULT_PATH);

    if let Ok(c) = cache::PairingCache::load(cache_path) {
        match c.check_host(&host.product_name, &host.product_serial) {
            Ok(()) => {
                log::debug!("pairing cache hit: {}", cache_path.display());
                return Ok(c);
            }
            Err(why) => {
                log::warn!("ignoring stale pairing cache ({why}); refreshing");
            }
        }
    }

    let buf = read_flash(chan, TLS_FLASH_PARTITION, 0, 0x1000)?;
    let blocks = parse_tls_flash(&buf)?;
    let keys = crypto::GwkKeys::derive(&host.product_name, &host.product_serial);

    let priv_blob = blocks
        .iter()
        .find(|b| b.id == tls_flash_ids::PRIV_KEY)
        .ok_or(Error::PairingMalformed { reason: "no priv-key block" })?;
    let cert_blob = blocks
        .iter()
        .find(|b| b.id == tls_flash_ids::TLS_CERT)
        .ok_or(Error::PairingMalformed { reason: "no TLS cert block" })?;
    let ecdh_blob = blocks
        .iter()
        .find(|b| b.id == tls_flash_ids::ECDH_Q)
        .ok_or(Error::PairingMalformed { reason: "no ECDH q block" })?;

    let priv_key = pairing::decrypt_priv(&priv_blob.body, &keys)?;
    let q = pairing::parse_ecdh(&ecdh_blob.body)?;

    let cached = cache::PairingCache {
        product_name: host.product_name,
        product_serial: host.product_serial,
        tls_cert: cert_blob.body.clone(),
        priv_key,
        ecdh_q: q,
    };
    if let Err(e) = cached.save(cache_path) {
        log::warn!("could not write pairing cache to {}: {e}", cache_path.display());
    } else {
        log::info!("wrote pairing cache to {}", cache_path.display());
    }
    Ok(cached)
}

fn tls_handshake() -> Result<()> {
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        println!();
        println!("smoke test: cmd 0x01 (Get Version) via app-data…");
        let resp = session.cmd(chan, &[CMD_GET_VERSION])?;
        let (status, payload) = split_status(&resp)?;
        println!("  app-data status: {status:#06x} payload_len={}", payload.len());
        if status == 0 && let Ok(rom) = think_touch::RomInfo::parse(payload) {
            println!(
                "  RomInfo via TLS : fw {}.{}.{} (cleartext-path baseline: 164)",
                rom.major, rom.minor, rom.build,
            );
        }
        Ok(())
    })
}

fn identify_sensor() -> Result<()> {
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let resp = session.cmd(chan, &[0x75])?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("identify_sensor: device returned status {}", fmt_status(status));
            return Ok(());
        }
        if payload.len() < 8 {
            eprintln!("identify_sensor: short payload ({} B): {}", payload.len(), hex(payload));
            return Ok(());
        }
        let zeroes = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let minor = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        let major = u16::from_le_bytes(payload[6..8].try_into().unwrap());
        println!();
        println!("Sensor identification (cmd 0x75):");
        println!("  reserved (must be 0): 0x{zeroes:08x}");
        println!("  major               : 0x{major:04x}");
        println!("  minor               : 0x{minor:04x}");
        if zeroes != 0 {
            eprintln!("  WARNING: non-zero reserved word — upstream would treat this as malformed");
        }
        if payload.len() > 8 {
            println!("  trailing bytes      : {}", hex(&payload[8..]));
        }
        Ok(())
    })
}

fn send(hex_str: &str) -> Result<()> {
    let bytes = parse_hex(hex_str).map_err(|e| Error::PairingMalformed { reason: e })?;
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        println!("> sending {} bytes: {}", bytes.len(), hex(&bytes));
        let resp = session.cmd(chan, &bytes)?;
        let (status, payload) = split_status(&resp)?;
        println!("< status={}, payload_len={}", fmt_status(status), payload.len());
        println!("  raw reply (status+payload): {}", hex(&resp));
        if !payload.is_empty() {
            println!("  payload only             : {}", hex(payload));
        }
        Ok(())
    })
}

fn fwext_info() -> Result<()> {
    use think_touch::{CMD_GET_PARTITION, FWEXT_PARTITION, PartitionInfo};
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let resp = session.cmd(chan, &[CMD_GET_PARTITION, FWEXT_PARTITION])?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("fwext-info: device returned status {}", fmt_status(status));
            return Ok(());
        }
        let p = PartitionInfo::parse(payload)?;
        println!();
        println!("Firmware-extension info (cmd 0x43 02 over TLS):");
        println!("  version    : {}.{}", p.major, p.minor);
        println!("  buildtime  : {} ({})", p.buildtime, format_unix(p.buildtime));
        println!("  modules    : {}", p.modules.len());
        for (i, m) in p.modules.iter().enumerate() {
            println!(
                "    [{i:02}] type=0x{:04x} sub=0x{:04x} v{}.{} size={}",
                m.kind, m.subtype, m.major, m.minor, m.size,
            );
        }
        Ok(())
    })
}

fn db_children(dbid: u16) -> Result<()> {
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let mut req = Vec::with_capacity(3);
        req.push(0x46);
        req.extend_from_slice(&dbid.to_le_bytes());
        let resp = session.cmd(chan, &req)?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("db-children: device returned status {}", fmt_status(status));
            return Ok(());
        }
        // Layout (per upstream `db.py:get_record_children`):
        //   <skip 2> u16 dbid u16 type u16 storage u16 sz u16 cnt <skip 2>
        //   then `cnt` × (u16 dbid, u16 type)
        // The leading 2-byte skip is part of the response *after* status —
        // upstream's unpack uses `<xxHHHHHxx>` on `rsp[:14]` *before*
        // stripping status, so on our (already-stripped) payload the
        // skip is `<HHHHHxx>` against the first 12 bytes. Wait —
        // upstream does `rsp = rsp[2:]` after assert_status? Let me
        // re-check: no, it doesn't strip; it uses `<xx...>` to skip.
        // We *did* strip via split_status, so we offset by -2 here.
        if payload.len() < 12 {
            eprintln!("db-children: short payload ({} B): {}", payload.len(), hex(payload));
            return Ok(());
        }
        let parent_dbid = u16::from_le_bytes(payload[0..2].try_into().unwrap());
        let parent_type = u16::from_le_bytes(payload[2..4].try_into().unwrap());
        let parent_storage = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        let _sz = u16::from_le_bytes(payload[6..8].try_into().unwrap());
        let cnt = u16::from_le_bytes(payload[8..10].try_into().unwrap()) as usize;
        // bytes 10..12 are the trailing skip in upstream's format.
        println!();
        println!("Record 0x{dbid:04x} children:");
        println!(
            "  parent dbid={parent_dbid} (0x{parent_dbid:04x}), type=0x{parent_type:04x}, \
             storage=0x{parent_storage:04x}",
        );
        println!("  child count: {cnt}");
        let need = 12 + cnt * 4;
        if payload.len() < need {
            eprintln!("  (truncated — got {} B, expected {})", payload.len(), need);
            return Ok(());
        }
        for i in 0..cnt {
            let off = 12 + i * 4;
            let cid = u16::from_le_bytes(payload[off..off + 2].try_into().unwrap());
            let ctype = u16::from_le_bytes(payload[off + 2..off + 4].try_into().unwrap());
            let kind = match ctype {
                1 => "user",
                2 => "fingerprint",
                4 => "user-storage",
                5 => "fingerprint-template",
                8 => "data",
                _ => "(unknown)",
            };
            println!("  [{i}] dbid=0x{cid:04x} type=0x{ctype:04x} ({kind})");
        }
        Ok(())
    })
}

fn db_user_storage(name: &str) -> Result<()> {
    use think_touch::db;
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        // Wire format: <u8 0x4b, u16 dbid=0, u16 name_len, name_bytes...>.
        // Upstream appends a null terminator to non-empty names.
        let mut name_bytes: Vec<u8> = name.as_bytes().to_vec();
        if !name_bytes.is_empty() {
            name_bytes.push(0);
        }
        let mut req = Vec::with_capacity(5 + name_bytes.len());
        req.push(0x4b);
        req.extend_from_slice(&0u16.to_le_bytes()); // dbid hint = 0
        req.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        req.extend_from_slice(&name_bytes);

        let resp = session.cmd(chan, &req)?;
        match db::user_storage_or_not_found(&resp) {
            Ok(None) => {
                println!("\n(no user-storage with name {name:?} on this device)");
            }
            Ok(Some(s)) => {
                println!();
                println!("UserStorage:");
                println!("  dbid : {} (0x{:04x})", s.dbid, s.dbid);
                println!(
                    "  name : {:?} ({} bytes)",
                    String::from_utf8_lossy(&s.name).trim_end_matches('\0'),
                    s.name.len()
                );
                println!("  users: {}", s.users.len());
                for (i, u) in s.users.iter().enumerate() {
                    println!(
                        "    [{i}] dbid=0x{:04x} value_size={}",
                        u.dbid, u.value_size
                    );
                }
            }
            Err(e) => println!("error: {e}"),
        }
        Ok(())
    })
}

fn db_user(dbid: u16) -> Result<()> {
    use think_touch::db;
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        // Wire format: <u8 0x4a, u16 dbid, u16 0, u16 0> = 7 bytes.
        let mut req = Vec::with_capacity(7);
        req.push(0x4a);
        req.extend_from_slice(&dbid.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes());
        let resp = session.cmd(chan, &req)?;
        let (status, payload) = split_status(&resp)?;
        if status == db::STATUS_NOT_FOUND {
            println!("\n(no user with dbid 0x{dbid:04x})");
            return Ok(());
        }
        if status != 0 {
            eprintln!("db-user: device returned status {}", fmt_status(status));
            return Ok(());
        }
        let u = db::parse_user(payload)?;
        println!();
        println!("User 0x{:04x}:", u.dbid);
        println!("  identity bytes: {} B", u.identity.len());
        println!("  fingers       : {}", u.fingers.len());
        for (i, f) in u.fingers.iter().enumerate() {
            let name = db::subtype_name(f.subtype).unwrap_or("(unknown)");
            println!(
                "    [{i}] dbid=0x{:04x} subtype=0x{:04x} ({name}), storage=0x{:04x}, value_size={}",
                f.dbid, f.subtype, f.storage, f.value_size,
            );
        }
        println!();
        println!("Note: identity bytes are the Windows SID — opaque here.");
        println!("`db.parse_identity` strips the 8-byte type/length header to get the raw SID.");
        Ok(())
    })
}

fn db_value(dbid: u16) -> Result<()> {
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let mut req = Vec::with_capacity(3);
        req.push(0x49);
        req.extend_from_slice(&dbid.to_le_bytes());
        let resp = session.cmd(chan, &req)?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("db-value: device returned status {}", fmt_status(status));
            return Ok(());
        }
        // Layout (per upstream `db.py:get_record_value`):
        //   <skip 2> u16 dbid u16 type u16 storage u16 sz <value...>
        // After our split_status strip, that's:
        //   u16 dbid u16 type u16 storage u16 sz <value> (10 B header)
        if payload.len() < 10 {
            eprintln!("db-value: short payload ({} B): {}", payload.len(), hex(payload));
            return Ok(());
        }
        let id = u16::from_le_bytes(payload[0..2].try_into().unwrap());
        let typ = u16::from_le_bytes(payload[2..4].try_into().unwrap());
        let storage = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        let sz = u16::from_le_bytes(payload[6..8].try_into().unwrap()) as usize;
        let end = 10usize.saturating_add(sz).min(payload.len());
        let value = &payload[10..end];
        println!();
        println!("Record 0x{dbid:04x} value:");
        println!("  dbid={id} (0x{id:04x}), type=0x{typ:04x}, storage=0x{storage:04x}");
        println!("  size : {sz} bytes");
        let preview = value.len().min(128);
        println!("  bytes: {}{}", hex(&value[..preview]),
            if value.len() > preview { " …" } else { "" });
        // Best-effort UTF-8 view if it looks ASCII-ish.
        if value.iter().all(|&b| matches!(b, 0x20..=0x7e | 0)) {
            let s = String::from_utf8_lossy(value).replace('\0', "·");
            println!("  ascii: {s:?}");
        }
        Ok(())
    })
}

fn factory_calibration() -> Result<()> {
    const KEY_CAL_LINE: usize = 0x38; // for type 0x199 / FM-3367-001
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let mut req = Vec::with_capacity(9);
        req.push(0x6f);
        req.extend_from_slice(&0x0e00u16.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        let resp = session.cmd(chan, &req)?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("factory-calibration: device returned status {}", fmt_status(status));
            return Ok(());
        }
        if payload.len() < 8 {
            eprintln!("factory-calibration: short payload");
            return Ok(());
        }
        let _wtf = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let entries = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;

        let mut p = &payload[8..];
        let mut subtag3: Option<&[u8]> = None;
        for i in 0..entries {
            if p.len() < 12 {
                eprintln!("entry {i}: header truncated");
                return Ok(());
            }
            // <u32 ptr, u16 len, u16 tag, u16 subtag, u16 flags>
            let len = u16::from_le_bytes([p[4], p[5]]) as usize;
            let _tag = u16::from_le_bytes([p[6], p[7]]);
            let subtag = u16::from_le_bytes([p[8], p[9]]);
            if p.len() < 12 + len {
                eprintln!("entry {i}: body truncated");
                return Ok(());
            }
            let value = &p[12..12 + len];
            if subtag == 3 {
                subtag3 = Some(value);
                println!(
                    "factory_bits entry {i}: subtag=3, len={len} → factory_calibration_values"
                );
            }
            p = &p[12 + len..];
        }

        let Some(value) = subtag3 else {
            eprintln!("subtag=3 not found in factory_bits(0x0e00)");
            return Ok(());
        };
        if value.len() < 4 + KEY_CAL_LINE + 1 {
            eprintln!(
                "factory_calibration_values too short: len={}, need >= {}",
                value.len(),
                4 + KEY_CAL_LINE + 1,
            );
            return Ok(());
        }
        let table = &value[4..];
        let subst = table[KEY_CAL_LINE];
        println!();
        println!("factory_calibration_values:");
        println!("  total entries           : {}", table.len());
        println!("  key_calibration_line    : 0x{KEY_CAL_LINE:02x} ({KEY_CAL_LINE})");
        println!("  subst_value (table[0x38]): 0x{subst:02x} ({subst})");
        println!();
        println!("This is the `subst_value` to feed `patch_timeslot_again` for");
        println!("IDENTIFY / ENROLL captures on this host.");
        Ok(())
    })
}

/// Fetch the full `factory_calibration_values` array (subtag=3 of the
/// `factory_bits(0x0e00)` reply), with the 4-byte vendor header
/// stripped. Used both for `subst_value` extraction and for baking
/// into the cmd-02 IDENTIFY program via [`build_cmd_02`].
fn fetch_factory_calibration_values(
    chan: &mut Channel,
    session: &handshake::Session,
) -> Result<Vec<u8>> {
    let mut req = Vec::with_capacity(9);
    req.push(0x6f);
    req.extend_from_slice(&0x0e00u16.to_le_bytes());
    req.extend_from_slice(&0u16.to_le_bytes());
    req.extend_from_slice(&0u32.to_le_bytes());
    let resp = session.cmd(chan, &req)?;
    let (status, payload) = split_status(&resp)?;
    if status != 0 || payload.len() < 8 {
        return Err(Error::PairingMalformed { reason: "factory_bits(0x0e00) failed" });
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
    let value = subtag3.ok_or(Error::PairingMalformed { reason: "no subtag=3 in factory_bits" })?;
    if value.len() < 4 {
        return Err(Error::PairingMalformed { reason: "factory_calibration_values too short" });
    }
    Ok(value[4..].to_vec())
}

/// Fetch `factory_calibration_values[key_calibration_line]` over TLS.
/// Helper used by `try-identify`; returns the single byte the device
/// expects as `subst_value` in `patch_timeslot_again`.
fn fetch_factory_subst(
    chan: &mut Channel,
    session: &handshake::Session,
    key_calibration_line: usize,
) -> Result<u8> {
    let values = fetch_factory_calibration_values(chan, session)?;
    if key_calibration_line >= values.len() {
        return Err(Error::PairingMalformed { reason: "factory_calibration_values too short" });
    }
    Ok(values[key_calibration_line])
}

fn dump_cmd_02(mode: &str, out_path: Option<&str>) -> Result<()> {
    use std::fs;
    use think_touch::capture::{CaptureMode, build_cmd_02};
    use think_touch::sensor_types::{FM_3367_001, FM_3367_001_PROG};

    let cap_mode = match mode {
        "calibrate" => CaptureMode::Calibrate,
        "identify" => CaptureMode::Identify,
        "enroll" => CaptureMode::Enroll,
        _ => return Err(Error::PairingMalformed { reason: "unknown mode" }),
    };

    let key_line = vec![0u8; FM_3367_001.line_width as usize];
    let pkt = build_cmd_02(
        cap_mode,
        &FM_3367_001_PROG,
        &FM_3367_001,
        &key_line,
        /* calibration_frames */ 3,
        /* lines_per_frame */ 224,
        /* subst_value */ 0,
        /* factory_calibration_values */ &[],
        /* calib_data */ &[],
    )?;

    println!("cmd 0x02 ({mode}, key_line=zeros, subst=0): {} bytes", pkt.len());
    println!();
    println!("header (5 bytes): {}", hex(&pkt[..5.min(pkt.len())]));
    if pkt.len() >= 5 {
        let bytes_per_line = u16::from_le_bytes([pkt[1], pkt[2]]);
        let req_lines = u16::from_le_bytes([pkt[3], pkt[4]]);
        println!("  cmd byte         : 0x{:02x}", pkt[0]);
        println!("  bytes_per_line   : {bytes_per_line}");
        println!("  req_lines        : {req_lines}");
    }
    println!();
    println!("full hex:");
    for off in (0..pkt.len()).step_by(32) {
        let end = (off + 32).min(pkt.len());
        println!("  0x{:04x}: {}", off, hex(&pkt[off..end]));
    }

    if let Some(path) = out_path {
        fs::write(path, &pkt)?;
        println!("\nwrote {} bytes to {path}", pkt.len());
    }
    Ok(())
}

fn frame_to_pgm(hex_str: &str, out_path: &str) -> Result<()> {
    use std::collections::BTreeSet;
    use std::fs;
    use think_touch::capture::{line_headers, raw_frame_to_pgm};
    use think_touch::sensor_types::FM_3367_001;
    let bytes = parse_hex(hex_str).map_err(|e| Error::PairingMalformed { reason: e })?;

    // Header-only summary first (no pixel data exposed).
    let hdrs = line_headers(&bytes, &FM_3367_001);
    let mut frames = BTreeSet::new();
    let mut bad = 0;
    for h in &hdrs {
        frames.insert(h.frame_index);
        if !h.looks_valid() {
            bad += 1;
        }
    }
    println!(
        "{} lines parsed; frame indices observed: {:?}; malformed-magic count: {bad}",
        hdrs.len(),
        frames.iter().collect::<Vec<_>>(),
    );
    if let Some(first) = hdrs.first() {
        println!("first line header: {:?}", first);
    }
    if let Some(last) = hdrs.last() {
        println!("last  line header: {:?}", last);
    }

    let pgm = raw_frame_to_pgm(&bytes, &FM_3367_001);
    fs::write(out_path, &pgm)?;
    println!(
        "wrote {} PGM bytes ({} pixel lines × {} px) to {out_path}",
        pgm.len(),
        hdrs.len(),
        FM_3367_001.line_width,
    );
    Ok(())
}

fn diagnose() -> Result<()> {
    use think_touch::PartitionInfo;
    println!("=== think-touch diagnose ===\n");

    // Cleartext probes first — these don't require the full TLS dance.
    println!("[1/8] USB enumeration");
    list()?;

    println!("\n[2/8] Sensor descriptors (USB only)");
    let _ = identify();

    println!("\n[3/8] Cleartext RomInfo (cmd 0x01)");
    let _ = version();

    println!("\n[4/8] DMI host identity + GWK keys");
    let _ = gwk();

    println!("\n[5/8] Pairing record decryption");
    let _ = pairing();

    // The rest go through TLS, all in a single session.
    println!("\n[6/8] TLS handshake + session checks");
    with_session(|chan, session| {
        let resp = session.cmd(chan, &[CMD_GET_VERSION])?;
        let (s, p) = split_status(&resp)?;
        println!("  cmd 0x01 over TLS: status={} payload_len={}", fmt_status(s), p.len());

        let resp = session.cmd(chan, &[0x75])?;
        let (s, p) = split_status(&resp)?;
        if s == 0 && p.len() >= 8 {
            let minor = u16::from_le_bytes([p[4], p[5]]);
            let major = u16::from_le_bytes([p[6], p[7]]);
            println!("  identify_sensor: major=0x{major:04x} minor=0x{minor:04x}");
        }

        let resp = session.cmd(chan, &[CMD_PROBE_19])?;
        let (s, p) = split_status(&resp)?;
        println!("  cmd 0x19: status={} payload_len={}", fmt_status(s), p.len());

        let resp = session.cmd(chan, &[0x43, FWEXT_PARTITION])?;
        let (s, p) = split_status(&resp)?;
        if s == 0 && let Ok(part) = PartitionInfo::parse(p) {
            println!(
                "  fwext: {}.{} build {} ({}), {} modules",
                part.major,
                part.minor,
                part.buildtime,
                format_unix(part.buildtime),
                part.modules.len(),
            );
        }

        let resp = session.cmd(chan, &[0x45])?;
        let (s, p) = split_status(&resp)?;
        if s == 0 && p.len() >= 0x18 {
            let total = u32::from_le_bytes(p[8..12].try_into().unwrap());
            let used = u32::from_le_bytes(p[12..16].try_into().unwrap());
            let records = u16::from_le_bytes(p[20..22].try_into().unwrap());
            let nroots = u16::from_le_bytes(p[22..24].try_into().unwrap());
            println!(
                "  db: {records} records, {nroots} roots, {used}/{total} bytes used",
            );
        }

        let subst = fetch_factory_subst(chan, session, 0x38)?;
        println!("  factory_calibration_values[0x38]: 0x{subst:02x}");
        Ok(())
    })?;

    println!("\n[7/8] Pairing cache state");
    let cache_path = Path::new(cache::DEFAULT_PATH);
    if cache_path.exists() {
        println!("  ✓ {}", cache_path.display());
    } else {
        println!("  (no cache; first TLS run will write one)");
    }

    println!("\n[8/8] Calibration save state");
    let calib_path = Path::new(cache::CALIB_DATA_PATH);
    if calib_path.exists() {
        let len = std::fs::metadata(calib_path).map(|m| m.len()).unwrap_or(0);
        println!("  ✓ {} ({} bytes)", calib_path.display(), len);
    } else {
        println!("  (no saved calib_data; run `save-calib` to persist)");
    }
    Ok(())
}

/// Parse a canonical Microsoft SID string (`S-<rev>-<auth>-<sub1>-<sub2>-…`)
/// into a [`SidIdentity`]. Returns a structured error on bad input.
fn parse_sid_string(s: &str) -> Result<think_touch::db::SidIdentity> {
    use think_touch::db::SidIdentity;
    let stripped = s.strip_prefix("S-")
        .ok_or(Error::PairingMalformed { reason: "SID must start with 'S-'" })?;
    let parts: Vec<&str> = stripped.split('-').collect();
    if parts.len() < 2 {
        return Err(Error::PairingMalformed { reason: "SID must have at least revision and auth" });
    }
    let revision: u8 = parts[0]
        .parse()
        .map_err(|_| Error::PairingMalformed { reason: "SID revision parse failed" })?;
    let auth: u64 = parts[1]
        .parse()
        .map_err(|_| Error::PairingMalformed { reason: "SID auth parse failed" })?;
    let mut subauth = Vec::with_capacity(parts.len() - 2);
    for sub in &parts[2..] {
        let v: u32 = sub
            .parse()
            .map_err(|_| Error::PairingMalformed { reason: "SID subauth parse failed" })?;
        subauth.push(v);
    }
    Ok(SidIdentity { revision, auth, subauth })
}

/// `write_enable` followed by a single TLS command, with `call_cleanups`
/// in a "finally" position. Mirrors upstream's `db_write_enable` +
/// command + `call_cleanups()` triplet used by every flash-modifying
/// op (cmd 0x47 new-record, cmd 0x48 del-record, etc).
fn write_enable_then(
    chan: &mut Channel,
    session: &handshake::Session,
    cmd_payload: &[u8],
) -> Result<Vec<u8>> {
    use think_touch::blobs::DB_WRITE_ENABLE_9A;
    // Step 1: send the write-enable capsule. Status must be OK.
    let resp = session.cmd(chan, &DB_WRITE_ENABLE_9A)?;
    let (s, _) = split_status(&resp)?;
    if s != 0 {
        return Err(Error::PairingMalformed { reason: "db_write_enable rejected" });
    }
    // Step 2: send the actual command. Capture the result; we still
    // need to call_cleanups even on error.
    let result = session.cmd(chan, cmd_payload);
    // Step 3: cleanup (cmd 0x1a). Status 0x0491 = "nothing to commit"
    // is treated as OK per upstream `flash.py:115-120`.
    let cleanup = session.cmd(chan, &[0x1a]);
    if let Ok(rsp) = cleanup {
        let (s, _) = split_status(&rsp).unwrap_or((0xffff, &[]));
        if s != 0 && s != 0x0491 {
            eprintln!("  warn: call_cleanups returned status 0x{s:04x}");
        }
    }
    result
}

#[allow(clippy::too_many_lines)]
fn enroll_cmd(subtype: u16, sid_string: &str, yes: bool) -> Result<()> {
    use think_touch::blobs::{GLOW_END_SCAN, GLOW_START_SCAN};
    use think_touch::capture::{
        CaptureMode, average_interleaved, build_cmd_02, get_key_line,
        process_calibration_results,
    };
    use think_touch::db::{
        build_get_record_children, build_lookup_user, build_new_record, identity_to_bytes,
        parse_user_storage, subtype_name,
    };
    use think_touch::enroll::{
        ENROLL_MAGIC_LEN, build_enrollment_mode, build_enrollment_update,
        build_enrollment_update_start, make_finger_data,
    };
    use think_touch::sensor_types::{FM_3367_001, FM_3367_001_PROG};

    const KEY_CAL_LINE: u32 = 0x38;
    const CALIBRATION_ITERATIONS: usize = 3;
    const LINES_PER_FRAME: u16 = 224;
    const CALIBRATION_FRAMES: u16 = 3;

    let identity = parse_sid_string(sid_string)?;
    let subtype_label = subtype_name(subtype).unwrap_or("(unknown)");

    if !yes {
        eprintln!(
            "About to enroll a fingerprint:\n  finger:   {subtype} ({subtype_label})\n  identity: {identity}"
        );
        eprintln!(
            "\nThis writes to flash partitions 4 (templates) and modifies the user DB.\n\
             It is destructive. Re-run with --yes to proceed."
        );
        return Ok(());
    }

    println!("identity: {identity}");
    println!("finger:   {subtype} ({subtype_label})");

    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");

        // 0. Resolve StgWindsor's dbid (always 3 on this device, but
        //    fetch it for correctness).
        let resp = session.cmd(chan, &[0x4b, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;
        let (s, p) = split_status(&resp)?;
        if s != 0 {
            eprintln!("get_user_storage failed: {}", fmt_status(s));
            return Ok(());
        }
        let stg = parse_user_storage(p)?
            .ok_or(Error::PairingMalformed { reason: "StgWindsor missing" })?;
        let stg_dbid = stg.dbid;
        println!("StgWindsor dbid: {stg_dbid}");

        // 1. Pre-flight calibration (re-run; matches `try-identify`).
        let factory_cal_values = fetch_factory_calibration_values(chan, session)?;
        let subst_value = factory_cal_values.get(KEY_CAL_LINE as usize).copied()
            .ok_or(Error::PairingMalformed { reason: "factory_calibration_values too short" })?;
        println!("subst_value: 0x{subst_value:02x}");

        let mut calib_data: Vec<u8> = Vec::new();
        for iter in 1..=CALIBRATION_ITERATIONS {
            let key_line = get_key_line(&FM_3367_001, KEY_CAL_LINE, &calib_data);
            let pkt = build_cmd_02(
                CaptureMode::Calibrate,
                &FM_3367_001_PROG,
                &FM_3367_001,
                &key_line,
                CALIBRATION_FRAMES,
                LINES_PER_FRAME,
                0,
                &[],
                &[],
            )?;
            let resp = session.cmd(chan, &pkt)?;
            let (status, _) = split_status(&resp)?;
            if status != 0 {
                eprintln!("calibrate iter {iter}: status {}", fmt_status(status));
                return Ok(());
            }
            let raw = chan.read_async()?;
            let cooked = average_interleaved(&raw, &FM_3367_001, LINES_PER_FRAME as u32, CALIBRATION_FRAMES as u32);
            process_calibration_results(&mut calib_data, &cooked, FM_3367_001.bytes_per_line as usize);
            println!("  calibrate iter {iter}/{CALIBRATION_ITERATIONS} ok");
        }
        let key_line = get_key_line(&FM_3367_001, KEY_CAL_LINE, &calib_data);

        // 2. create_enrollment (cmd 0x69 01).
        let resp = session.cmd(chan, &build_enrollment_mode(1))?;
        let (s, _) = split_status(&resp)?;
        if s != 0 {
            eprintln!("create_enrollment failed: {}", fmt_status(s));
            return Ok(());
        }
        println!("create_enrollment OK");

        // 3. Enrol loop. Press the finger 8-12 times typically (the
        //    device decides when it has enough data — termination is
        //    signalled by `tid` being non-empty in `append_new_image`).
        let mut prev_template: Vec<u8> = Vec::new();
        let mut key: u32 = 0;
        let final_tid: Vec<u8>;
        let mut step = 0;
        loop {
            step += 1;
            if step > 20 {
                eprintln!("aborting: too many enroll iterations without finalising");
                let _ = session.cmd(chan, &build_enrollment_mode(0));
                return Ok(());
            }
            println!("\n[enroll step {step}] glow on, sending capture(ENROLL)…");
            let _ = session.cmd(chan, &GLOW_START_SCAN)?;

            // 3a. capture(ENROLL).
            let pkt = build_cmd_02(
                CaptureMode::Enroll,
                &FM_3367_001_PROG,
                &FM_3367_001,
                &key_line,
                CALIBRATION_FRAMES,
                LINES_PER_FRAME,
                subst_value,
                &factory_cal_values,
                &calib_data,
            )?;
            let resp = session.cmd(chan, &pkt)?;
            let (status, payload) = split_status(&resp)?;
            println!(
                "  cmd-02 reply: status={} payload={} B",
                fmt_status(status),
                payload.len()
            );
            if status != 0 {
                eprintln!("  capture(ENROLL) status: {}", fmt_status(status));
                let _ = session.cmd(chan, &GLOW_END_SCAN);
                let _ = session.cmd(chan, &build_enrollment_mode(0));
                return Ok(());
            }
            // start (expect b[0]==0)
            let evt = chan.wait_int()?;
            println!("  start event: {}", hex(&evt));
            if evt.first() != Some(&0x00) {
                eprintln!("  warn: expected b[0]=0x00 start, got {}", hex(&evt));
            }
            // Wait for the finger event (b[0]==2). Print every event we
            // see — useful for debugging this hang.
            println!("  → press your finger NOW (waiting for b[0]=0x02)…");
            loop {
                let evt = chan.wait_int()?;
                println!("  int: {}", hex(&evt));
                if evt.first() == Some(&0x02) {
                    break;
                }
            }
            // Wait for capture-complete (b[0]==3 with bit 0x04 set).
            println!("  waiting for capture-complete (b[0]=0x03, bit 0x04)…");
            loop {
                let evt = chan.wait_int()?;
                println!("  int: {}", hex(&evt));
                if evt.first() == Some(&0x03) && evt.len() >= 3 && (evt[2] & 0x04) != 0 {
                    break;
                }
            }
            // get_prg_status2 — must be error == 0 for the matcher to be happy.
            let resp = session.cmd(chan, &[0x51, 0x00, 0x20, 0x00, 0x00])?;
            let (status, payload) = split_status(&resp)?;
            if status != 0 {
                eprintln!("  prg_status: {}", fmt_status(status));
                continue;
            }
            let cs = think_touch::protocol::CaptureStatus::parse(payload)?;
            println!("  scan: x={} y={} w1={} w2={} error=0x{:08x}", cs.x, cs.y, cs.w1, cs.w2, cs.error);

            // 3b. enrollment_update_start (cmd 0x68 + wait_int).
            let resp = session.cmd(chan, &build_enrollment_update_start(key))?;
            let (s, p) = split_status(&resp)?;
            if s != 0 || p.len() < 4 {
                eprintln!("  enrollment_update_start: {}", fmt_status(s));
                let _ = session.cmd(chan, &GLOW_END_SCAN);
                let _ = session.cmd(chan, &build_enrollment_mode(0));
                return Ok(());
            }
            key = u32::from_le_bytes(p[..4].try_into().unwrap());
            let _ = chan.wait_int()?;

            // 3c. append_new_image: cmd 0x6b prev (twice with wait_int between).
            let _ = write_enable_then(chan, session, &build_enrollment_update(&prev_template))?;
            let _ = chan.wait_int()?;
            let resp = write_enable_then(chan, session, &build_enrollment_update(&prev_template))?;
            let (s, p) = split_status(&resp)?;
            if s != 0 {
                eprintln!("  append_new_image: {}", fmt_status(s));
                let _ = session.cmd(chan, &GLOW_END_SCAN);
                let _ = session.cmd(chan, &build_enrollment_mode(0));
                return Ok(());
            }
            // The reply payload starts with a u16 declared length, then a
            // stream of TLV chunks (tag/len/magic/body) each ENROLL_MAGIC_LEN+body_len.
            if p.len() < 2 {
                eprintln!("  append_new_image: short reply");
                continue;
            }
            let body_len = u16::from_le_bytes([p[0], p[1]]) as usize;
            if 2 + body_len > p.len() {
                eprintln!("  append_new_image: declared body_len {body_len} exceeds reply");
                continue;
            }
            let body = &p[2..2 + body_len];

            // Walk chunks per upstream: tag 0 → next-iteration prev (full
            // chunk including 0x38 magic header); tag 3 → final tid.
            let mut walker = body;
            let mut new_prev: Option<Vec<u8>> = None;
            let mut tid: Option<Vec<u8>> = None;
            while !walker.is_empty() {
                if walker.len() < 4 { break; }
                let tag = u16::from_le_bytes([walker[0], walker[1]]);
                let l = u16::from_le_bytes([walker[2], walker[3]]) as usize;
                let chunk_size = ENROLL_MAGIC_LEN + l;
                if walker.len() < chunk_size { break; }
                if tag == 0 {
                    new_prev = Some(walker[..chunk_size].to_vec());
                } else if tag == 3 {
                    tid = Some(walker[ENROLL_MAGIC_LEN..ENROLL_MAGIC_LEN + l].to_vec());
                }
                walker = &walker[chunk_size..];
            }
            if let Some(np) = new_prev {
                prev_template = np;
                println!("  prev_template now {} B", prev_template.len());
            }
            if let Some(t) = tid {
                final_tid = t;
                println!("  final tid received ({} B) → enroll complete.", final_tid.len());
                let _ = session.cmd(chan, &build_enrollment_mode(0));
                break;
            }
            // 3d. End this iteration's enrollment_update (cmd 0x69 0).
            let _ = session.cmd(chan, &build_enrollment_mode(0));
        }

        // 4. Idempotent end (upstream calls it twice).
        let _ = session.cmd(chan, &build_enrollment_mode(0));

        // 5. do_create_finger.
        println!("\n> creating user record (if needed)…");
        let resp = session.cmd(chan, &build_lookup_user(stg_dbid, &identity))?;
        let (s, p) = split_status(&resp)?;
        let user_dbid = if s == think_touch::protocol::STATUS_NOT_FOUND {
            // Make a new user.
            let id_bytes = identity_to_bytes(&identity);
            let cmd = build_new_record(stg_dbid, /* type=User */ 5, stg_dbid, &id_bytes);
            let resp = write_enable_then(chan, session, &cmd)?;
            let (s, p) = split_status(&resp)?;
            if s != 0 || p.len() < 2 {
                eprintln!("new_user failed: {}", fmt_status(s));
                let _ = session.cmd(chan, &GLOW_END_SCAN);
                return Ok(());
            }
            let new_dbid = u16::from_le_bytes([p[0], p[1]]);
            println!("  created new user record dbid={new_dbid}");
            new_dbid
        } else if s == 0 && p.len() >= 2 {
            let dbid = u16::from_le_bytes([p[0], p[1]]);
            println!("  existing user dbid={dbid}");
            dbid
        } else {
            eprintln!("lookup_user failed: {}", fmt_status(s));
            let _ = session.cmd(chan, &GLOW_END_SCAN);
            return Ok(());
        };

        println!("> writing finger record…");
        let finger_data = make_finger_data(subtype, &prev_template, &final_tid);
        // Record type 0xb = "fingerprint" — the device rewrites this
        // to 0x6 internally per upstream comment in db.py:233-235.
        let cmd = build_new_record(user_dbid, 0xb, stg_dbid, &finger_data);
        let resp = write_enable_then(chan, session, &cmd)?;
        let (s, p) = split_status(&resp)?;
        if s != 0 || p.len() < 2 {
            eprintln!("new_finger failed: {}", fmt_status(s));
            let _ = session.cmd(chan, &GLOW_END_SCAN);
            return Ok(());
        }
        let finger_dbid = u16::from_le_bytes([p[0], p[1]]);
        println!("  finger record created dbid={finger_dbid}");
        let _ = chan.wait_int()?;

        // 6. Glow off + verify.
        let _ = session.cmd(chan, &GLOW_END_SCAN)?;
        // Suppress unused-warn on the children helper — exercise it as
        // a final readback so the user sees the new entry.
        let resp = session.cmd(chan, &build_get_record_children(stg_dbid))?;
        let (s, _) = split_status(&resp)?;
        println!(
            "\nenrollment complete — StgWindsor children read-back: {}",
            fmt_status(s)
        );
        Ok(())
    })
}

fn match_finger() -> Result<()> {
    // Wire format (per upstream `sensor.py:match_finger`):
    //   <u8 0x5e, u8 2, u8 0xff, u16 stg_id=0, u16 usr_id=0, u16 1, u16 0, u16 0>
    // = 12 bytes total. After cmd, wait for interrupt b[0]=3, then
    //   send `60 00 00 00 00` to read results.
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let mut req = Vec::with_capacity(12);
        req.push(0x5e);
        req.push(0x02);
        req.push(0xff);
        req.extend_from_slice(&0u16.to_le_bytes()); // stg_id
        req.extend_from_slice(&0u16.to_le_bytes()); // usr_id
        req.extend_from_slice(&1u16.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes());
        let resp = session.cmd(chan, &req)?;
        let (status, payload) = split_status(&resp)?;
        println!("> match_finger cmd: status={} payload_len={}", fmt_status(status), payload.len());
        if status != 0 {
            eprintln!("device rejected match_finger (no enrolled finger / no current capture)");
            return Ok(());
        }
        println!("> waiting for matcher result interrupt (b[0]=3)…");
        let evt = chan.wait_int()?;
        println!("  got: {}", hex(&evt));
        if evt.first() != Some(&0x03) {
            eprintln!("expected b[0]=3 from matcher, got {}", hex(&evt));
            return Ok(());
        }

        // Fetch the match result via cmd 0x60.
        let resp = session.cmd(chan, &[0x60, 0x00, 0x00, 0x00, 0x00])?;
        let (status, payload) = split_status(&resp)?;
        println!("\n> match-result fetch: status={} payload_len={}", fmt_status(status), payload.len());
        if status != 0 || payload.len() < 2 {
            return Ok(());
        }
        let len = u16::from_le_bytes(payload[0..2].try_into().unwrap()) as usize;
        let body = &payload[2..];
        println!("  declared body len: {len}, actual: {}", body.len());
        println!("  raw: {}", hex(body));
        // Per-record body decoding deferred — see upstream
        // `sensor.py:match_finger` lines 880-895.
        Ok(())
    })
}

fn int_decode(hex_str: &str) -> Result<()> {
    use think_touch::protocol::InterruptEvent;
    let bytes = parse_hex(hex_str).map_err(|e| Error::PairingMalformed { reason: e })?;
    let evt = InterruptEvent::parse(&bytes);
    println!("input  : {} bytes ({})", bytes.len(), hex(&bytes));
    println!("decoded: {evt:?}");
    println!("label  : {}", evt.label());
    if evt.capture_complete() {
        println!("→ capture done; fetch metadata via `send 5100200000`.");
    }
    Ok(())
}

fn int_watch() -> Result<()> {
    use think_touch::protocol::InterruptEvent;
    with_session(|chan, _session| {
        println!("HANDSHAKE OK ✓");
        println!("watching EP 0x83 — Ctrl-C to stop");
        let mut count = 0u32;
        loop {
            let bytes = chan.wait_int()?;
            count += 1;
            let parsed = InterruptEvent::parse(&bytes);
            println!(
                "[{count:>4}] {} bytes: {} → {}",
                bytes.len(),
                hex(&bytes),
                parsed.label(),
            );
        }
    })
}

fn int_probe(hex_str: &str, count: usize) -> Result<()> {
    let bytes = parse_hex(hex_str).map_err(|e| Error::PairingMalformed { reason: e })?;
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        println!("> sending {} bytes: {}", bytes.len(), hex(&bytes));
        let resp = session.cmd(chan, &bytes)?;
        let (status, payload) = split_status(&resp)?;
        println!("< cmd reply: status={} payload_len={}", fmt_status(status), payload.len());
        println!("\nwaiting for {count} interrupt event(s) on EP 0x83…");
        for i in 1..=count {
            let evt = chan.wait_int()?;
            println!("  [{i}/{count}] {} B: {}", evt.len(), hex(&evt));
        }
        Ok(())
    })
}

fn blink() -> Result<()> {
    use std::thread::sleep;
    use std::time::Duration;
    use think_touch::blobs::{GLOW_END_SCAN, GLOW_START_SCAN};
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        println!("> glow start");
        let _ = session.cmd(chan, &GLOW_START_SCAN)?;
        sleep(Duration::from_millis(1500));
        println!("> glow end");
        let _ = session.cmd(chan, &GLOW_END_SCAN)?;
        println!("done — LED should have blinked.");
        Ok(())
    })
}

fn try_identify(use_stored_calib: bool, use_saved_calib: bool) -> Result<()> {
    use std::path::Path;
    use think_touch::blobs::{GLOW_END_SCAN, GLOW_START_SCAN};
    use think_touch::capture::{
        CaptureMode, average_interleaved, build_cmd_02, get_key_line, parse_calibration,
        process_calibration_results,
    };
    use think_touch::sensor_types::{FM_3367_001, FM_3367_001_PROG};
    const KEY_CAL_LINE: u32 = 0x38;
    const CALIBRATION_ITERATIONS: usize = 3;
    const LINES_PER_FRAME: u16 = 224;
    const CALIBRATION_FRAMES: u16 = 3;
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");

        // 1. Factory calibration values (constant for this host).
        let factory_cal_values = fetch_factory_calibration_values(chan, session)?;
        let subst_value = if (KEY_CAL_LINE as usize) < factory_cal_values.len() {
            factory_cal_values[KEY_CAL_LINE as usize]
        } else {
            return Err(Error::PairingMalformed {
                reason: "factory_calibration_values too short",
            });
        };
        println!(
            "  factory_calibration_values: {} B, subst_value (idx 0x{:02x}): 0x{:02x}",
            factory_cal_values.len(),
            KEY_CAL_LINE,
            subst_value
        );

        // 2. Build calib_data — pick the source.
        let calib_data: Vec<u8> = if use_saved_calib {
            let path = Path::new(cache::CALIB_DATA_PATH);
            let saved = cache::load_calib_data(path)?;
            println!(
                "\n[saved-calib] loaded {} B from {}",
                saved.len(),
                path.display(),
            );
            saved
        } else if use_stored_calib {
            let p6 = session.read_flash_all(chan, 6, 0, 0x8000)?;
            let stored = parse_calibration(&p6)?;
            println!(
                "\n[stored-calib] using partition 6 calibration: {} B",
                stored.len()
            );
            stored
        } else {
            let mut buf: Vec<u8> = Vec::new();
            for iter in 1..=CALIBRATION_ITERATIONS {
                let key_line = get_key_line(&FM_3367_001, KEY_CAL_LINE, &buf);
                let pkt = build_cmd_02(
                    CaptureMode::Calibrate,
                    &FM_3367_001_PROG,
                    &FM_3367_001,
                    &key_line,
                    CALIBRATION_FRAMES,
                    LINES_PER_FRAME,
                    0,
                    /* factory_calibration_values */ &[],
                    /* calib_data */ &[],
                )?;
                println!(
                    "\n[calibration iter {iter}/{CALIBRATION_ITERATIONS}] cmd 0x02 ({} B) …",
                    pkt.len()
                );
                let resp = session.cmd(chan, &pkt)?;
                let (status, _) = split_status(&resp)?;
                if status != 0 {
                    eprintln!("  device rejected calibrate (status {status:#06x})");
                    return Ok(());
                }
                let raw = chan.read_async()?;
                let cooked = average_interleaved(
                    &raw,
                    &FM_3367_001,
                    LINES_PER_FRAME as u32,
                    CALIBRATION_FRAMES as u32,
                );
                process_calibration_results(
                    &mut buf,
                    &cooked,
                    FM_3367_001.bytes_per_line as usize,
                );
                println!("  raw {} B → calib_data {} B", raw.len(), buf.len());
            }
            buf
        };

        // 3. Build key_line from the chosen calibration buffer.
        let key_line = get_key_line(&FM_3367_001, KEY_CAL_LINE, &calib_data);
        let source = if use_saved_calib {
            "saved file"
        } else if use_stored_calib {
            "partition 6 (Windows-paired)"
        } else {
            "this run's iterations"
        };
        println!("\n  key_line: {} B (source: {source})", key_line.len());

        // 4. Glow on (the matcher's "looking for finger" indicator).
        println!("\n> glow start");
        let _ = session.cmd(chan, &GLOW_START_SCAN)?;

        // 3. Build cmd 0x02 in IDENTIFY mode and send.
        let pkt = build_cmd_02(
            CaptureMode::Identify,
            &FM_3367_001_PROG,
            &FM_3367_001,
            &key_line,
            /* calibration_frames */ 3,
            /* lines_per_frame */ 224,
            subst_value,
            &factory_cal_values,
            &calib_data,
        )?;
        println!("> sending cmd 0x02 (IDENTIFY), {} bytes", pkt.len());
        let resp = session.cmd(chan, &pkt)?;
        let (status, payload) = split_status(&resp)?;
        println!("< cmd reply: status={} payload_len={}", fmt_status(status), payload.len());
        if status != 0 {
            let _ = session.cmd(chan, &GLOW_END_SCAN);
            eprintln!("device rejected IDENTIFY (status {})", fmt_status(status));
            return Ok(());
        }

        // 4. Interrupt-event dance — upstream's `Sensor.capture()`.
        //    Without consuming these events on EP 0x83, the device
        //    never advances its matcher state machine and EP 0x82
        //    reads block forever.
        println!();
        println!("> waiting for matcher start event on EP 0x83…");
        let evt = chan.wait_int()?;
        println!("  got {} B: {} (expected b[0]=0x00)", evt.len(), hex(&evt));
        if evt.first() != Some(&0x00) {
            eprintln!("  unexpected start interrupt — bailing out");
            let _ = session.cmd(chan, &GLOW_END_SCAN);
            return Ok(());
        }

        println!();
        println!("┌────────────────────────────────────────────────┐");
        println!("│  PRESS YOUR FINGER FIRMLY ON THE SENSOR NOW.   │");
        println!("│  Hold for ~2 seconds; release after that.      │");
        println!("│  Ctrl-C aborts (will require `reset`).         │");
        println!("└────────────────────────────────────────────────┘");
        println!();
        println!("> waiting for finger-detect event (b[0]=0x02)…");
        loop {
            let e = chan.wait_int()?;
            println!("  int event: {}", hex(&e));
            if e.first() == Some(&0x02) {
                break;
            }
        }
        println!("  → finger detected.");

        println!();
        println!("> waiting for capture-complete event (b[0]=0x03 with bit 0x04 set)…");
        loop {
            let e = chan.wait_int()?;
            println!("  int event: {}", hex(&e));
            if e.first() == Some(&0x03) && e.len() >= 3 && (e[2] & 0x04) != 0 {
                break;
            }
            if e.first() != Some(&0x03) {
                eprintln!("  unexpected interrupt — bailing out");
                let _ = session.cmd(chan, &GLOW_END_SCAN);
                return Ok(());
            }
        }
        println!("  → capture complete.");

        // 5. Capture metadata via `get_prg_status2` (cmd 0x51 0x00 0x20 0x00 0x00).
        let resp = session.cmd(chan, &[0x51, 0x00, 0x20, 0x00, 0x00])?;
        let (status, payload) = split_status(&resp)?;
        println!("\n> get_prg_status2: status={} payload_len={}", fmt_status(status), payload.len());

        // Decode the metadata via the typed parser — even on non-zero
        // status, the body still carries x/y/w1/w2/error fields that
        // explain *why* the scan failed.
        match think_touch::protocol::CaptureStatus::parse(payload) {
            Ok(s) => {
                println!("  x={} y={} w1={} w2={} error=0x{:08x}", s.x, s.y, s.w1, s.w2, s.error);
                if let Some(label) = s.error_label() {
                    println!("  → {label}");
                }
            }
            Err(_) => println!("  raw: {}", hex(payload)),
        }

        // IDENTIFY mode does NOT push image data on EP 0x82 — the
        // device runs the matcher internally on the captured frame
        // and only exposes metadata (x/y/w1/w2/error) plus the matcher
        // verdict. Reading EP 0x82 here would block forever. (Verified
        // against python-validity's `Sensor.capture()` which also
        // doesn't read EP 0x82 in this mode — only `Sensor.calibrate()`
        // does.)

        // 6. Run the matcher (python-validity `match_finger()`):
        //    a. Send cmd 0x5e <2, 0xff, stg_id=0, usr_id=0, 1, 0, 0>
        //       — match against any storage and any user (13-byte body).
        //    b. Wait for an interrupt on EP 0x83.
        //       - b[0] == 3 → match found, fetch with cmd 0x60.
        //       - b[0] != 3 → "Finger not recognized"; the bytes carry
        //         the device's verdict (e.g. b[0]=5 with body 0xb3 0x04
        //         = STATUS_NOT_FOUND, expected when StgWindsor.users==0).
        //    c. If matched, fetch result with cmd 0x60.
        //    d. Always run cmd 0x62 cleanup at the end.
        println!();
        println!("> match-finger (cmd 0x5e, all-storages all-users)…");
        let mut match_cmd = Vec::with_capacity(13);
        match_cmd.push(0x5e);
        match_cmd.push(0x02);
        match_cmd.push(0xff);
        match_cmd.extend_from_slice(&0u16.to_le_bytes()); // stg_id
        match_cmd.extend_from_slice(&0u16.to_le_bytes()); // usr_id
        match_cmd.extend_from_slice(&1u16.to_le_bytes());
        match_cmd.extend_from_slice(&0u16.to_le_bytes());
        match_cmd.extend_from_slice(&0u16.to_le_bytes());
        let resp = session.cmd(chan, &match_cmd)?;
        let (mf_status, _) = split_status(&resp)?;
        println!("  match cmd accepted: status={}", fmt_status(mf_status));
        if mf_status != 0 {
            let _ = session.cmd(chan, &[0x62, 0, 0, 0, 0]); // cleanup
            let _ = session.cmd(chan, &GLOW_END_SCAN);
            return Ok(());
        }

        println!("> waiting for matcher verdict on EP 0x83…");
        let verdict = chan.wait_int()?;
        println!("  int event: {}", hex(&verdict));
        if verdict.first() == Some(&0x05) {
            // python-validity raises "Finger not recognized: <hex>" here.
            // Wire shape: <u8 0x05, u8 0x00, u16 LE status, u8 trailer>.
            // The status is typically 0x04b3 (record not found) when
            // no enrolment exists. The trailer byte is opaque.
            if verdict.len() >= 4 {
                let body_status = u16::from_le_bytes([verdict[2], verdict[3]]);
                println!("  → no DB match (verdict status: {})", fmt_status(body_status));
            } else {
                println!("  → no DB match (short verdict)");
            }
        } else if verdict.first() == Some(&0x03) {
            use think_touch::db::subtype_name;
            // Match candidate found — fetch with cmd 0x60. The response
            // is `<u16 body_len, <u16 tag, u16 len, body>+>`. Documented
            // tags: 1 = user_id (u32), 3 = subtype (u16), 4 = template
            // hash (32 bytes). Mirrors python-validity match_finger().
            let resp = session.cmd(chan, &[0x60, 0x00, 0x00, 0x00, 0x00])?;
            let (m_status, m_payload) = split_status(&resp)?;
            println!(
                "  match-result: status={} payload={} B",
                fmt_status(m_status),
                m_payload.len()
            );
            if m_status == 0 && m_payload.len() >= 2 {
                let body_len = u16::from_le_bytes([m_payload[0], m_payload[1]]) as usize;
                let body = &m_payload[2..2 + body_len.min(m_payload.len() - 2)];
                let mut p = body;
                let mut user_id: Option<u32> = None;
                let mut subtype: Option<u16> = None;
                let mut tmpl_hash: Option<&[u8]> = None;
                while p.len() >= 4 {
                    let tag = u16::from_le_bytes([p[0], p[1]]);
                    let l = u16::from_le_bytes([p[2], p[3]]) as usize;
                    if 4 + l > p.len() { break; }
                    let val = &p[4..4 + l];
                    match tag {
                        1 if l == 4 => user_id = Some(u32::from_le_bytes(val.try_into().unwrap())),
                        3 if l == 2 => subtype = Some(u16::from_le_bytes(val.try_into().unwrap())),
                        4 if l == 32 => tmpl_hash = Some(val),
                        _ => {}
                    }
                    p = &p[4 + l..];
                }
                println!();
                println!("┌── MATCH ──────────────────────────────────────────┐");
                if let Some(uid) = user_id {
                    println!("│  user dbid : {uid}");
                }
                if let Some(s) = subtype {
                    let label = subtype_name(s).unwrap_or("(unknown)");
                    println!("│  finger    : {s} ({label})");
                }
                if let Some(h) = tmpl_hash {
                    println!("│  hash[..8] : {}…", hex(&h[..8]));
                }
                println!("└────────────────────────────────────────────────────┘");
            }
        } else if verdict.first() == Some(&0x04) {
            // Observed once on the user's P70 with capture error
            // 0x00080000 — the matcher refused to compare a low-quality
            // scan against the DB. python-validity's `match_finger()`
            // also treats this as "Finger not recognized". Distinct
            // from b[0]=0x05 (no match in DB) — here, the matcher
            // didn't even try.
            println!("  → matcher rejected scan (likely low quality; retry)");
        } else {
            println!("  → unexpected verdict byte 0x{:02x}", verdict[0]);
        }

        // 7. Capture-stop cleanup (per upstream `match_finger()` finally clause).
        let _ = session.cmd(chan, &[0x62, 0, 0, 0, 0])?;

        // 8. Glow off.
        println!("\n> glow end");
        let _ = session.cmd(chan, &GLOW_END_SCAN)?;
        Ok(())
    })
}

fn factory_bits(tag: u16) -> Result<()> {
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        // Wire layout: <u8 0x6f, u16 tag, u16 0, u32 0> — 9 bytes.
        let mut req = Vec::with_capacity(9);
        req.push(0x6f);
        req.extend_from_slice(&tag.to_le_bytes());
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());

        let resp = session.cmd(chan, &req)?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("factory-bits: device returned status {}", fmt_status(status));
            return Ok(());
        }
        // Per upstream `sensor.py:get_factory_bits`:
        //   <u32 wtf, u32 entries, then `entries` records>
        // Each record: <u32 ptr, u16 len, u16 tag, u16 subtag, u16 flags, body[len]>.
        if payload.len() < 8 {
            eprintln!("factory-bits: short payload ({} B): {}", payload.len(), hex(payload));
            return Ok(());
        }
        let wtf = u32::from_le_bytes(payload[0..4].try_into().unwrap());
        let entries = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
        println!();
        println!("Factory bits (cmd 0x6f tag=0x{tag:04x}):");
        println!("  wtf      : 0x{wtf:08x}");
        println!("  entries  : {entries}");

        let mut p = &payload[8..];
        for i in 0..entries {
            if p.len() < 12 {
                eprintln!("  [{i}] header truncated ({} B remaining)", p.len());
                break;
            }
            let ptr = u32::from_le_bytes(p[0..4].try_into().unwrap());
            let len = u16::from_le_bytes(p[4..6].try_into().unwrap()) as usize;
            let etag = u16::from_le_bytes(p[6..8].try_into().unwrap());
            let subtag = u16::from_le_bytes(p[8..10].try_into().unwrap());
            let flags = u16::from_le_bytes(p[10..12].try_into().unwrap());
            if p.len() < 12 + len {
                eprintln!(
                    "  [{i}] body truncated: declared {len}, only {} remaining",
                    p.len() - 12
                );
                break;
            }
            let body = &p[12..12 + len];
            // Show a short hex preview — never dump suspected biometric
            // payloads in full. Subtag 0x0003 is the calibration_values
            // table which is hardware-public; subtag 0x0007 is similar.
            let preview = body.len().min(48);
            println!(
                "  [{i:02}] ptr=0x{ptr:08x} len={len} tag=0x{etag:04x} subtag=0x{subtag:04x} \
                 flags=0x{flags:04x}",
            );
            println!(
                "       body[..{preview}]: {}{}",
                hex(&body[..preview]),
                if body.len() > preview { " …" } else { "" }
            );
            p = &p[12 + len..];
        }
        if !p.is_empty() {
            eprintln!("  ({} bytes of trailing garbage)", p.len());
        }
        Ok(())
    })
}

fn try_calibrate(save_pgm_path: Option<&str>) -> Result<()> {
    use std::fs;
    use think_touch::capture::{
        CaptureMode, average_interleaved, build_cmd_02, parse_calibration, raw_frame_to_pgm,
    };
    use think_touch::sensor_types::{FM_3367_001, FM_3367_001_PROG};

    fn one_pass(
        chan: &mut Channel,
        session: &handshake::Session,
        label: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
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
        )?;
        let resp = session.cmd(chan, &pkt)?;
        let (status, _) = split_status(&resp)?;
        if status != 0 {
            return Err(Error::FlashRead { status });
        }
        let frame = chan.read_async()?;
        let cooked = average_interleaved(&frame, &FM_3367_001, 224, 3);
        println!("  [{label}] EP-0x82 raw: {} B, cooked: {} B", frame.len(), cooked.len());
        if cooked.len() >= 8 {
            println!("       cooked line-0 header: {}", hex(&cooked[..8]));
        }
        Ok((cooked, frame))
    }

    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");

        // Run the same calibrate twice with the same key_line. Same
        // physical sensor + same key_line → cooked outputs should be
        // very close (only sensor-noise variation).
        println!("\nrun 1:");
        let (cooked_a, raw_a) = one_pass(chan, session, "1")?;
        println!("\nrun 2:");
        let (cooked_b, _raw_b) = one_pass(chan, session, "2")?;

        // Self-consistency: how stable is our pipeline?
        let same = cooked_a.iter().zip(cooked_b.iter()).filter(|(a, b)| a == b).count();
        println!(
            "\nrun1 vs run2 byte agreement: {}/{} ({:.1}%) — high % means the pipeline is\n\
             stable (same key_line → same data, modulo sensor noise).",
            same,
            cooked_a.len(),
            (same as f64) * 100.0 / cooked_a.len() as f64,
        );

        // Optional PGM dump of the *second* frame from run-1 (same one
        // that `average_interleaved` consumes), so the user can
        // visually inspect what the sensor saw.
        if let Some(path) = save_pgm_path {
            let frame_size = 224 * FM_3367_001.bytes_per_line as usize;
            if raw_a.len() >= 2 * frame_size {
                let frame2 = &raw_a[frame_size..2 * frame_size];
                let pgm = raw_frame_to_pgm(frame2, &FM_3367_001);
                fs::write(path, &pgm)?;
                println!("\nwrote {} bytes to {path}", pgm.len());
            } else {
                eprintln!(
                    "\n--save-pgm: capture had only {} bytes, expected ≥ {}",
                    raw_a.len(),
                    2 * frame_size,
                );
            }
        }

        // Cross-check against partition 6 — but with `key_line=zeros`
        // we expect the per-line *headers* to match (~896 / 13440 ≈
        // 6.7%) and the pixel data to legitimately differ from the
        // Windows-paired calibration that's currently stored.
        println!("\ncross-check against partition 6 (Windows-written calibration):");
        let p6 = session.read_flash_all(chan, 6, 0, 0x8000)?;
        match parse_calibration(&p6) {
            Ok(stored) => {
                let same =
                    stored.iter().zip(cooked_a.iter()).filter(|(a, b)| a == b).count();
                println!(
                    "  agreement: {}/{} ({:.1}%) — {} headers + {} pixels.",
                    same,
                    stored.len(),
                    (same as f64) * 100.0 / stored.len() as f64,
                    896_usize.min(same),
                    same.saturating_sub(896),
                );
                println!("       stored line-0 header: {}", hex(&stored[..8]));
            }
            Err(e) => println!("  parse_calibration failed: {e}"),
        }
        Ok(())
    })
}

fn flash_info() -> Result<()> {
    use think_touch::parse_flash_info;
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let resp = session.cmd(chan, &[0x3e])?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("flash-info: device returned status {status:#06x}");
            return Ok(());
        }
        let layout = parse_flash_info(payload)?;
        let total = layout.ic.total_size();
        let mfg = match layout.ic.jid0 & 0xff {
            0xef => "Winbond",
            0x20 => "ST/Numonyx",
            0xc2 => "Macronix",
            _ => "(unknown)",
        };
        println!();
        println!("Flash IC:");
        println!(
            "  JEDEC id   : 0x{:04x} 0x{:04x}  ({mfg})",
            layout.ic.jid0, layout.ic.jid1,
        );
        println!("  blocks     : {}", layout.ic.blocks);
        println!("  block size : {} bytes", layout.ic.block_size);
        println!("  total size : {total} bytes ({:.0} KiB)", total as f64 / 1024.0);
        println!();
        println!("Partitions ({}):", layout.partitions.len());
        for (i, p) in layout.partitions.iter().enumerate() {
            let label = match p.id {
                1 => "cert store",
                2 => "xpfwext",
                4 => "template DB",
                5 => "(unknown)",
                6 => "calibration",
                _ => "?",
            };
            println!(
                "  [{i}] id={} type={} access=0x{:04x} offset=0x{:08x} size={:6}  ({label})",
                p.id, p.kind, p.access, p.offset, p.size,
            );
        }
        Ok(())
    })
}

fn db_info() -> Result<()> {
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let resp = session.cmd(chan, &[0x45])?;
        let (status, payload) = split_status(&resp)?;
        if status != 0 {
            eprintln!("db-info: device returned status {status:#06x}");
            return Ok(());
        }
        // Layout: <u32 unknown1, u32 unknown0, u32 total, u32 used,
        //         u32 free, u16 records, u16 nroots> then nroots × u16 roots.
        if payload.len() < 0x18 {
            eprintln!("db-info: short payload ({} B): {}", payload.len(), hex(payload));
            return Ok(());
        }
        let u32_at = |o: usize| u32::from_le_bytes(payload[o..o + 4].try_into().unwrap());
        let u16_at = |o: usize| u16::from_le_bytes(payload[o..o + 2].try_into().unwrap());
        let unknown1 = u32_at(0x00);
        let unknown0 = u32_at(0x04);
        let total = u32_at(0x08);
        let used = u32_at(0x0c);
        let free = u32_at(0x10);
        let records = u16_at(0x14);
        let nroots = u16_at(0x16) as usize;
        println!();
        println!("Database (partition 4) — cmd 0x45:");
        println!("  unknown1 : {unknown1} (upstream observes always 1)");
        println!("  unknown0 : {unknown0} (upstream observes always 0)");
        println!(
            "  total    : {total} bytes ({:.1} KiB)",
            total as f64 / 1024.0,
        );
        println!(
            "  used     : {used} bytes ({:.1}%)",
            (used as f64 * 100.0) / total.max(1) as f64,
        );
        println!("  free     : {free} bytes");
        println!("  records  : {records}");
        println!("  roots    : {nroots}");
        if payload.len() >= 0x18 + nroots * 2 {
            for i in 0..nroots {
                let r = u16::from_le_bytes(
                    payload[0x18 + i * 2..0x18 + i * 2 + 2].try_into().unwrap(),
                );
                println!("    [{i}] 0x{r:04x}");
            }
        }
        if records == 0 {
            println!();
            println!("  → no fingers enrolled. `enroll` is the next step (not yet implemented).");
        }
        Ok(())
    })
}

fn tls_read_flash(partition: u8, addr: u32, size: u32) -> Result<()> {
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        // Use the chunked path so requests > 4 KiB don't overflow the
        // device's single-reply buffer.
        let data = session.read_flash_all(chan, partition, addr, size)?;
        println!(
            "partition {partition} @ 0x{addr:x}, requested {size} bytes, got {}",
            data.len(),
        );
        const ROW: usize = 32;
        let preview = data.len().min(256);
        for off in (0..preview).step_by(ROW) {
            let end = (off + ROW).min(preview);
            println!("  0x{:04x}: {}", off, hex(&data[off..end]));
        }
        if data.len() > preview {
            println!("  … ({} more bytes — paste into a hex tool to inspect)", data.len() - preview);
        }
        Ok(())
    })
}

fn save_calib() -> Result<()> {
    use std::path::Path;
    use think_touch::capture::{
        CaptureMode, average_interleaved, build_cmd_02, get_key_line,
        process_calibration_results,
    };
    use think_touch::sensor_types::{FM_3367_001, FM_3367_001_PROG};
    const KEY_CAL_LINE: u32 = 0x38;
    with_session(|chan, session| {
        println!("HANDSHAKE OK ✓");
        let mut buf: Vec<u8> = Vec::new();
        for iter in 1..=3 {
            let key_line = get_key_line(&FM_3367_001, KEY_CAL_LINE, &buf);
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
            )?;
            println!("[iter {iter}/3] cmd 0x02 {} bytes", pkt.len());
            let resp = session.cmd(chan, &pkt)?;
            let (status, _) = split_status(&resp)?;
            if status != 0 {
                eprintln!("device rejected calibrate (status {status:#06x})");
                return Ok(());
            }
            let raw = chan.read_async()?;
            let cooked =
                average_interleaved(&raw, &FM_3367_001, 224, 3);
            process_calibration_results(&mut buf, &cooked, FM_3367_001.bytes_per_line as usize);
        }

        let path = Path::new(cache::CALIB_DATA_PATH);
        cache::save_calib_data(path, &buf)?;
        println!("\nsaved {} bytes to {}", buf.len(), path.display());
        Ok(())
    })
}

fn forget() -> Result<()> {
    let path = Path::new(cache::DEFAULT_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => {
            println!("removed pairing cache at {}", path.display());
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no pairing cache to remove ({})", path.display());
            Ok(())
        }
        Err(e) => Err(Error::Io(e)),
    }
}

fn reset() -> Result<()> {
    use nusb::MaybeFuture;

    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);
    sensor.nusb().reset().wait()?;
    println!("USB reset issued — device should be back to a clean state.");
    Ok(())
}

fn parse_hex(s: &str) -> std::result::Result<Vec<u8>, &'static str> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("hex string must have an even number of nibbles");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex digit")?;
        out.push(byte);
    }
    Ok(out)
}

fn pairing() -> Result<()> {
    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);

    let mut chan = Channel::open(&sensor)?;
    let buf = read_flash(&mut chan, TLS_FLASH_PARTITION, 0, 0x1000)?;
    let blocks = parse_tls_flash(&buf)?;

    // Verify each block's stored SHA-256 first.
    for b in &blocks {
        if crypto::sha256(&b.body) != b.sha256 {
            return Err(Error::FlashBlockHash { id: b.id });
        }
    }

    let host = dmi::HostId::read();
    let keys = crypto::GwkKeys::derive(&host.product_name, &host.product_serial);
    println!(
        "DMI: product_name={:?} product_serial={:?}",
        host.product_name, host.product_serial,
    );

    let priv_blob = blocks
        .iter()
        .find(|b| b.id == tls_flash_ids::PRIV_KEY)
        .ok_or(Error::PairingMalformed { reason: "no priv-key block (id=0x04) on flash" })?;
    let cert_blob = blocks
        .iter()
        .find(|b| b.id == tls_flash_ids::TLS_CERT)
        .ok_or(Error::PairingMalformed { reason: "no TLS cert block (id=0x03) on flash" })?;
    let ecdh_blob = blocks
        .iter()
        .find(|b| b.id == tls_flash_ids::ECDH_Q)
        .ok_or(Error::PairingMalformed { reason: "no ECDH q block (id=0x06) on flash" })?;

    let priv_key = pairing::decrypt_priv(&priv_blob.body, &keys)?;
    let q = pairing::parse_ecdh(&ecdh_blob.body)?;

    println!();
    println!("Pairing OK — HMAC verifies with this host's GWK validation key.");
    println!();
    println!("Client TLS cert:  {} bytes (prefix {}…)", cert_blob.body.len(), hex(&cert_blob.body[..8]));
    println!();
    println!("Client priv key (P-256, big-endian):");
    println!("  x: {}", hex(&priv_key.x));
    println!("  y: {}", hex(&priv_key.y));
    println!("  d: {}…(scalar redacted)…", hex(&priv_key.d[..4]));
    println!();
    println!("Server ECDH q (P-256, big-endian):");
    println!("  qx: {}", hex(&q.x));
    println!("  qy: {}", hex(&q.y));
    Ok(())
}

fn tls_hello() -> Result<()> {
    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);

    let mut chan = Channel::open(&sensor)?;

    let cr = tls::ClientRandom::from_urandom()?;
    let ch_body = tls::build_client_hello(&cr);
    let hs = tls::make_handshake_message(tls::HS_CLIENT_HELLO, &ch_body);
    let record = tls::make_record(tls::RECORD_HANDSHAKE, &hs);
    let pkt = tls::make_usb_tls_packet(&record);

    println!("client_random: {}", hex(&cr.0));
    println!("\n> sending {} bytes ({} TLS record bytes)", pkt.len(), record.len());

    // Note: USB cmd 0x44 replies with a raw TLS-record stream, *without* the
    // `<u16 status>` prefix that the cleartext command channel uses.
    let resp = chan.cmd(&pkt)?;
    println!("< {} bytes total", resp.len());
    if resp.is_empty() {
        println!("(empty payload — device rejected the Client Hello)");
        return Ok(());
    }
    println!("  raw: {}", hex(&resp));

    println!();
    let records = tls::split_records(&resp)?;
    for (i, r) in records.iter().enumerate() {
        println!(
            "[record {i}] type=0x{:02x} v{}.{} len={}",
            r.content_type,
            r.version_major,
            r.version_minor,
            r.body.len(),
        );
        if r.content_type == tls::RECORD_HANDSHAKE {
            for (j, m) in tls::split_handshakes(r.body)?.iter().enumerate() {
                let kind = match m.hs_type {
                    tls::HS_SERVER_HELLO => "ServerHello",
                    tls::HS_CERTIFICATE => "Certificate",
                    tls::HS_SERVER_KEY_EXCHANGE => "ServerKeyExchange",
                    tls::HS_CERTIFICATE_REQUEST => "CertificateRequest",
                    tls::HS_SERVER_HELLO_DONE => "ServerHelloDone",
                    _ => "(unknown)",
                };
                println!(
                    "  [{j}] hs_type=0x{:02x} {} len={}",
                    m.hs_type,
                    kind,
                    m.body.len(),
                );
                if m.hs_type == tls::HS_SERVER_HELLO {
                    print_server_hello(m.body);
                }
            }
        } else if r.content_type == tls::RECORD_ALERT {
            println!("  alert payload: {}", hex(r.body));
        }
    }
    Ok(())
}

/// Decode a ServerHello body and print its key fields. Layout matches
/// `python-validity/tls.py:handle_server_hello`.
fn print_server_hello(body: &[u8]) {
    if body.len() < 35 {
        println!("      (truncated ServerHello body, {} bytes)", body.len());
        return;
    }
    let version = format!("{}.{}", body[0], body[1]);
    let server_random = &body[2..34];
    let sid_len = body[34] as usize;
    let after_sid = 35 + sid_len;
    if body.len() < after_sid + 3 {
        println!("      (truncated session_id, {} bytes)", body.len());
        return;
    }
    let session_id = &body[35..after_sid];
    let suite = u16::from_be_bytes([body[after_sid], body[after_sid + 1]]);
    let compression = body[after_sid + 2];
    println!("      version       : {version} (raw {:02x} {:02x})", body[0], body[1]);
    println!("      server_random : {}", hex(server_random));
    println!("      session_id    : {} ({} bytes)", hex(session_id), sid_len);
    println!(
        "      cipher_suite  : 0x{suite:04x}{}",
        if suite == tls::SUITE_ECDH_ECDSA_AES256_CBC_SHA {
            " (TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA — expected)"
        } else {
            " (UNEXPECTED)"
        },
    );
    println!("      compression   : 0x{compression:02x}");
}

fn gwk() -> Result<()> {
    let host = dmi::HostId::read();
    println!("DMI identity:");
    println!("  product_name  : {:?}", host.product_name);
    println!("  product_serial: {:?}", host.product_serial);

    let keys = crypto::GwkKeys::derive(&host.product_name, &host.product_serial);
    println!();
    println!("Pre-TLS GWK keys (derived locally, no USB I/O):");
    println!("  psk_encryption_key: {}", hex(&keys.psk_encryption_key));
    println!("  psk_validation_key: {}", hex(&keys.psk_validation_key));
    println!();
    println!("Cross-check (stdlib-only Python — no python-validity install needed):");
    println!("  python3 scripts/cross_check_gwk.py");
    Ok(())
}

fn boot_info() -> Result<()> {
    let sensor = usb::Sensor::open_first()?;
    println!("opened: {}", sensor.info);

    let mut chan = Channel::open(&sensor)?;

    // 1) Get Version
    let resp = chan.cmd(&[CMD_GET_VERSION])?;
    let (status, payload) = split_status(&resp)?;
    println!("\n[01] Get Version → status={} ({} B payload)", fmt_status(status), payload.len());
    if status == 0 {
        let rom = RomInfo::parse(payload)?;
        println!(
            "     rom = fw {}.{}.{} built {}",
            rom.major,
            rom.minor,
            rom.build,
            format_unix(rom.timestamp),
        );
    }

    // 2) Probe 0x19. Upstream sends this in `send_init()` and only checks
    //    that status == 0; the payload semantics are undocumented. We dump
    //    the raw bytes so the user can compare against other devices.
    let resp = chan.cmd(&[CMD_PROBE_19])?;
    let (status, payload) = split_status(&resp)?;
    println!("\n[19] Probe         → status={} ({} B payload)", fmt_status(status), payload.len());
    if !payload.is_empty() {
        println!("     raw payload: {}", hex(payload));
    }

    // 3) Get fwext partition header.
    println!("\n[43 02] Partition fwext:");
    match query_partition(&mut chan, FWEXT_PARTITION)? {
        FwextState::CleanSlate => {
            println!("     CLEAN SLATE — no firmware-extension is loaded.");
            println!("     The host must upload an `xpfwext` blob before TLS pairing.");
        }
        FwextState::Loaded(p) => {
            println!("     fwext loaded: version {}.{}", p.major, p.minor);
            println!("     buildtime   : {} ({})", p.buildtime, format_unix(p.buildtime));
            println!("     modules     : {}", p.modules.len());
            for (i, m) in p.modules.iter().enumerate() {
                println!(
                    "       [{i:02}] type=0x{:04x} sub=0x{:04x} v{}.{} size={}",
                    m.kind, m.subtype, m.major, m.minor, m.size,
                );
            }
        }
        FwextState::OtherStatus { status, payload } => {
            println!("     unexpected status {status:#06x} — raw payload: {}", hex(&payload));
        }
    }

    Ok(())
}

/// Format a unix-epoch second value as `YYYY-MM-DD HH:MM:SS UTC`.
/// Falls back to the raw integer if the value is out of range for jiff.
fn format_unix(secs: u32) -> String {
    Timestamp::from_second(i64::from(secs))
        .map(|ts| ts.strftime("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|_| format!("unix {secs}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `parse_sid_string` accepts the canonical Microsoft form
    /// `S-<rev>-<auth>-<sub>-…` and rejects malformed strings.
    #[test]
    fn parse_sid_string_canonical_examples() {
        let s = parse_sid_string("S-1-5-18").unwrap();
        assert_eq!(s.revision, 1);
        assert_eq!(s.auth, 5);
        assert_eq!(s.subauth, vec![18]);

        let s = parse_sid_string("S-1-5-32-544").unwrap();
        assert_eq!(s.subauth, vec![32, 544]);

        let s = parse_sid_string("S-1-5-21-1-1-1-1000").unwrap();
        assert_eq!(s.subauth, vec![21, 1, 1, 1, 1000]);
    }

    #[test]
    fn parse_sid_string_rejects_malformed() {
        assert!(parse_sid_string("1-5-18").is_err(), "missing S- prefix");
        assert!(parse_sid_string("S-1").is_err(), "missing auth");
        assert!(parse_sid_string("S-x-5").is_err(), "non-numeric revision");
        assert!(parse_sid_string("S-1-y").is_err(), "non-numeric auth");
        assert!(parse_sid_string("S-1-5-z").is_err(), "non-numeric subauth");
    }
}
