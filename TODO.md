# Roadmap

Current state (2026-05-08):

- ✅ pair (read-only) / calibrate / identify / enroll / match all
  working end-to-end on real hardware (ThinkPad P70).
- ✅ `setcap cap_dac_read_search+ep` packaging + udev rules for
  unprivileged use; `packaging/install.sh` automates it.
- ✅ PAM integration via `pam_exec` + sample drop-ins for sudo / su /
  sddm; see `packaging/pam/`.
- ✅ Project renamed from `think-touch` to `Synaptics-Metallica-MIS-rs`
  (CLI command: `synaptics-metallica-mis`, library import:
  `think_touch` retained for source compat).
- ⚠ **Cannot pair an un-paired device** — see "Caveats" in README.
  Critical limitation, documented but not addressed.

211 unit tests passing, lint clean, 34 subcommands.

## What still needs work

### 1. Native PAM module

The `pam_exec` wrapper at `packaging/pam/synaptics-mis-pam.sh` is
solid for daily use, but a native PAM module compiled from
`src/pam.rs` (using `pam-binding` crate) would:

- Be a single `.so` to install (no shell wrapper to keep in sync)
- Run in the PAM process directly (one less fork+exec per auth)
- Expose more of the matcher's structured info to PAM (e.g.
  per-finger ACLs)

Lower priority since `pam_exec` already gives us sudo / su / sddm.

### 2. fprintd / libfprint D-Bus shim

GNOME Settings, KDE Plasma's Authentication panel, and a few other
desktop UIs talk to fprintd over D-Bus rather than going through PAM.
A standalone Rust binary implementing the
`net.reactivated.Fprint.Device` D-Bus interface (via the `zbus` crate)
would let those UIs see our sensor.

Roughly: fork on system bus, expose `EnrollStart` / `VerifyStart` /
`ListEnrolledFingers` / etc., delegate to our library. Medium-sized
project; no destructive risk.

### 3. Other Validity sensors (138a:0090, 0097, 009d)

Recognised in `usb.rs` but not driven. The protocol shape is the
same; the per-device blobs (init_hardcoded, db_write_enable, glow
patterns, partition_signature) differ. python-validity has all four
sets in its `blobs_*.py` modules — port verbatim.

### 4. xpfwext upload (clean-slate devices)

For devices that ship un-paired (no Lenovo Windows pre-pair), the
host has to upload the firmware-extension blob before the matcher
will run. The `6_07f_lenovo_mis_qm.xpfwext` blob is publicly
extractable from Lenovo's Windows installer; the upload sequence is
in `python-validity/upload_fwext.py`. Currently we only *verify* the
blob is present, we don't *ship* it.

### 5. Pair from scratch — ⚠ destructive, deferred

To pair an un-paired device, we'd need to erase + re-write flash
partition 1. This is risky on already-paired hardware: a botched
run leaves a half-formatted flash that neither think-touch nor
python-validity can recover from. The README's "Caveats and
limitations" section explains the user-facing impact; the code-side
work needed (in priority order):

1. Port `reset_blob` from `python-validity/blobs_9a.py` (~250 B vendor
   capsule that puts the device into clean-slate mode).
2. Port `partition_signature` (256-byte signed flash layout descriptor,
   per device-family).
3. Implement `partition_flash`: cmds `0x40` + `0x42` wrapped in the
   existing `db_write_enable` machinery.
4. Implement `make_tls_flash`: build the cert + encrypted-priv + ECDH-q
   records given a fresh ECDH keypair, write to partition 1.
5. Implement `encrypt_priv`: invert `pairing::decrypt_priv` (same AES
   + HMAC, encrypt direction).

NOT scheduled until we have a sacrificial test device — implementing
on the user's daily laptop risks bricking the sensor.

## What's confirmed working

- Pairing record decryption (HMAC verifies, AES-CBC unwraps)
- TLS-PSK handshake (Synaptics quirks preserved bug-for-bug)
- Cleartext + post-TLS protocol commands (34 subcommands)
- Calibration (3-iteration loop, partition 6 layout match)
- Save/load calib data to disk
- IDENTIFY cmd-02 (16 chunks, 13729 bytes, byte-exact vs upstream)
- ENROLL cmd-02 (same shape with 0x26+0x2e tail, byte-exact vs upstream)
- Capture pipeline (start → finger-detect → progress → complete)
- `get_prg_status2` metadata parser
- match-finger (cmd 0x5e + cmd 0x60 + TLV decode + structured stdout)
  + retries with smart "lift+repress" hint
- delete-record (cmd 0x48 wrapped in db_write_enable + call_cleanups)
- enroll loop with retry on low-quality scans
- LED control (after the 256→125-byte glow blob fix)
- setcap-based unprivileged invocation (one-shot installer ships)
- PAM integration via `pam_exec` for sudo / su / sddm
- 211 unit tests, lint clean

## Reference data

- python-validity captures: `scripts/captured/pv_cmd02_*.hex`
- Memory snapshot:
  `~/.claude/projects/-mnt-Dev--wdes-synaptics-metallica-mis/memory/`
  (same directory across the rename — Claude Code keys on the original
  path)
- Cross-check scripts: `scripts/python_validity_*.py`,
  `scripts/cross_check_gwk.py`, `scripts/walk_cmd02.py`
