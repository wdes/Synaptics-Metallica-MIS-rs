# Synaptics-Metallica-MIS-rs

> CLI command: `synaptics-metallica-mis` — library crate: `think_touch` — package: `synaptics-metallica-mis-rs`

A pure-Rust userspace driver for the Synaptics / Validity **Metallica MIS**
fingerprint sensor (USB id `06cb:009a`) found on Lenovo laptops including
the ThinkPad P70 and ThinkPad T480s.

> **Status: working end-to-end.** Pairing, three-pass calibration,
> capture, enrollment, database writes, and fingerprint matching all run
> on real hardware. Enrollment and matching have been validated on a
> ThinkPad T480s with the FM-3367-001 sensor (`06cb:009a`, sensor type
> `0x0199`).
>
> 213 unit tests, lint-clean under `-D warnings`, MPL-2.0.

```
┌──────────────────── Synaptics-Metallica-MIS-rs ─────────────────────┐
│   pair → calibrate → capture → match  ──→  user dbid + finger name  │
└─────────────────────────────────────────────────────────────────────┘
```

## Why another driver?

The only working free-software stack today is
[`python-validity`](https://github.com/uunicorn/python-validity), which
talks to the same family of sensors and plugs into `libfprint` /
`fprintd`. It works, but the implementation is hard to embed in
non-`fprintd` workflows, and the runtime story (system-wide Python +
`libgmp` + a GLib service) is fragile to ship.

`synaptics-metallica-mis` aims to be:

* **Pure Rust**, so a single static binary can drive the sensor.
* **Library-first**, so the driver can be embedded in custom auth flows
  (kernel locks, `pam_exec`, GUI prompts, …) without `fprintd`.
* **Small and auditable**, MPL-2.0 licensed, byte-exact against
  python-validity for every wire packet we send.

## Hardware target

| VID    | PID    | Codename       | Notes                                       |
|--------|--------|----------------|---------------------------------------------|
| `06cb` | `009a` | Metallica MIS  | Validated on ThinkPad P70 and T480s — primary target |
| `138a` | `0090` | Prometheus     | Recognised, not yet driven                  |
| `138a` | `0097` | Prometheus 97  | Recognised, not yet driven                  |
| `138a` | `009d` | Prometheus 9d  | Recognised, not yet driven                  |

## Quick start

```sh
# Build (release-mode binary lives at target/release/synaptics-metallica-mis)
cargo build --release

# Look for the sensor on the USB bus
sudo ./target/release/synaptics-metallica-mis list

# Run the full read-only health-check (no flash writes)
sudo ./target/release/synaptics-metallica-mis diagnose

# Generate and save the three-pass calibration baseline
sudo ./target/release/synaptics-metallica-mis save-calib

# Match an enrolled finger
sudo ./target/release/synaptics-metallica-mis match-finger --retries 5
# Press an enrolled finger when prompted. A successful result looks like:
#
#   MATCH dbid=9 subtype=2 right-index-finger

# Enroll a finger; subtype 4 is the right ring finger
sudo ./target/release/synaptics-metallica-mis enroll \
    --subtype 4 \
    --sid-string S-1-5-21-0-0-0-1000 \
    --yes
```

The SID identifies the user record stored on the sensor. Use a stable
SID for the same Linux account across subsequent enrollments. The value
above is an example.

## How it all fits together

The driver is a stack of independently-testable layers:

```
┌─────────────────────────────────────────────────────────────────┐
│  CLI          (src/main.rs)                                     │
│   list • identify • diagnose • try-identify • enroll • …        │
├─────────────────────────────────────────────────────────────────┤
│  Capture pipeline       (src/capture.rs)                        │
│   build_cmd_02 / line_update_type_1 / patch_timeslot_*          │
│   bitpack / find_nth_insn / Line / parse_calibration            │
├─────────────────────────────────────────────────────────────────┤
│  TLS-PSK session        (src/handshake.rs, src/tls.rs)          │
│   ClientHello → KEX → Finished    bidirectional record I/O      │
│   Custom Synaptics framing + validity-padded AES-256-CBC        │
├─────────────────────────────────────────────────────────────────┤
│  Pairing record         (src/pairing.rs)                        │
│   parse_ecdh / decrypt_priv / GWK keys (HMAC-SHA256 PRF)        │
├─────────────────────────────────────────────────────────────────┤
│  Cleartext protocol     (src/protocol.rs)                       │
│   Channel { bulk OUT/IN + interrupt IN }                        │
│   RomInfo / PartitionInfo / FlashLayout / CaptureStatus parsers │
├─────────────────────────────────────────────────────────────────┤
│  USB transport          (src/usb.rs)                            │
│   nusb 0.2 — endpoint 0x01 OUT / 0x81 IN / 0x82 IN / 0x83 INT   │
└─────────────────────────────────────────────────────────────────┘
```

Each layer has its own regression tests (totalling 213) so a change at
the byte level shows up immediately.

## Talking to the sensor

The Metallica MIS exposes four USB endpoints once you've claimed the
right interface:

```
host                         device (06cb:009a)

EP 0x01  ──── bulk OUT ────►   command requests
                               (cleartext until pairing,
                                TLS-PSK records after handshake)

EP 0x81  ◄─── bulk IN  ────    command replies
                               (status word + payload)

EP 0x82  ◄─── bulk IN  ────    image data
                               (raw scan frames during CALIBRATE only)

EP 0x83  ◄─── intr  IN ────    asynchronous events
                               (matcher state changes, finger detect)
```

A typical IDENTIFY round-trip looks like this:

```
    host                                       device
    │                                              │
    │── cmd 0x02 IDENTIFY (13 741 B) ─────────────►│
    │                                              │
    │◄────────────────────  EP 0x83: 0000000000  ──│  matcher armed
    │                                              │
    │       (user presses finger here)             │
    │                                              │
    │◄────────────────────  EP 0x83: 0200401000  ──│  finger detected
    │                                              │
    │◄────────────────────  EP 0x83: 0340010000  ──│  capture-progress
    │◄────────────────────  EP 0x83: 0342040040  ──│  capture complete
    │                                              │
    │── cmd 0x51 0x00 0x20 0x00 0x00 ─────────────►│  get_prg_status2
    │◄──────  status=OK  x=112 y=112 error=0  ─────│
    │                                              │
    │── cmd 0x5e (match-against-any) ─────────────►│
    │◄────────────────────────  status=OK  ────────│
    │                                              │
    │◄────────────────────  EP 0x83: 03000100db  ──│  match found
    │                                              │
    │── cmd 0x60 (fetch result) ──────────────────►│
    │◄──────  payload = TLV(user_id, subtype, ─────│
    │                          template_hash)      │
    │                                              │
```

## Pairing

On first contact the device is **un-paired** — host can read flash but
not run the matcher. python-validity's `init_flash` formats the flash
and pairs the device. On Lenovos like the P70 the device is already
paired by the Windows Synaptics driver; we just *read* the existing
pairing record.

```
┌─ host DMI ─┐                  ┌─── flash partition 1 ────────────┐
│ name       │  HMAC-SHA256 PRF │ 0x03  TLS client cert            │
│ serial     │ ───────────────► │ 0x04  encrypted client priv key  │
└────────────┘    GWK keys      │       (AES-256-CBC + HMAC tag)   │
                                │ 0x06  device ECDH public point Q │
                                └──────────────────────────────────┘

         GWK = (psk_encryption_key, psk_validation_key)
         AES-CBC decrypt + HMAC verify  → client (x, y, d)
```

If the HMAC tag doesn't validate, the device was paired against a
*different host* (e.g. `dd`-cloned Windows installs); the only fix is
to re-pair, which wipes existing enrolments. We refuse to do this
without explicit user consent.

## TLS-PSK, the Synaptics edition

The session protocol is shaped like TLS 1.0 but with three vendor
quirks:

1. The cipher suite is `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA` (`0xc005`)
   driven by the host's pairing ECDH keypair, not a server certificate.
2. Padding is `l` bytes of value `l - 1` (one less than PKCS#7), with
   `l ∈ [1, 16]` always — even on exact-block boundaries.
3. The Client Hello carries a `len(extensions) - 2` byte-count quirk
   we have to preserve bug-for-bug or the device rejects us.

```
       ClientHello       ───►   sent first; carries ECDH point + nonce
       ServerHello       ◄───   server nonce + selected cipher
       Certificate       ◄───   echo of our pairing cert
       ClientKeyExchange ───►   our ECDH point
       CertificateVerify ───►   ECDSA-sign(transcript)
       ChangeCipherSpec  ───►
       Finished          ───►   first encrypted record
       ChangeCipherSpec  ◄───
       Finished          ◄───
```

All this lives in `src/handshake.rs`. After Finished, every command is a
TLS application-data record and the entire `protocol::Channel` API
becomes session-encrypted.

## Calibration and the cmd-02 program

The hardest part of bringing this sensor up wasn't TLS — it was the
13 741-byte program we have to ship with every IDENTIFY/ENROLL.

The capture command (`cmd 0x02`) carries a stream of TLV chunks that
the device interprets as a tiny sensor program: which scan-line
schedule to run, where to put pixels, which transforms to apply.

Calibration is iterative. The first pass sends an 897-byte program.
Passes two and three feed the accumulated 13 440-byte calibration
result back into the device and therefore send 13 665-byte packets.
IDENTIFY and ENROLL then embed that calibration data in a 13 741-byte
`cmd 0x02` packet. Without the feedback passes and embedded per-line
offsets, the matcher reads sensor noise and rejects otherwise valid
fingerprints.

```
            ┌────── cmd 0x02 IDENTIFY (16 chunks, 13 729 B) ──────┐
            │ [ 0] 0x0023  setup record                           │
            │ [ 1] 0x0020  Set Register 32                        │
            │ [ 2] 0x0032  Set Registers 16                       │
            │ [ 3] 0x0033  Set Register 32 (alt)                  │
            │ [ 4] 0x0032  …                                      │
            │ [ 5] 0x0032  …                                      │
            │ [ 6] 0x0034  Timeslot Table 2D (patched per host)   │
            │ [ 7] 0x002f  …                                      │
            │ [ 8] 0x0029  …                                      │
            │ [ 9] 0x0035  …                                      │
            │ [10] 0x0017  Reply Configuration                    │
            │ [11] 0x004e  IDENTIFY-mode marker                   │
            │ [12] 0x002e  Image Reconstruction                   │
            │ [13] 0x0044  Interleave  (← line_update_type_1      │
            │ [14] 0x0030  Line Update     emits these three      │
            │ [15] 0x0043  Update Transform   chunks)             │
            └─────────────────────────────────────────────────────┘
```

ENROLL is the same 16 chunks, except chunk 11 becomes `0x0026` and
chunk 12 has a single byte different at index 4 (`0x23` instead of
`0x02`). Both shapes are byte-verified against python-validity's
on-wire output (`scripts/captured/pv_cmd02_*.hex`).

## Where data lives

### On disk (your laptop)

```
/var/lib/synaptics-metallica-mis/
├── session                  pairing cache (mode 0600)
│                            key=value, host DMI + decrypted client keys
│                            speeds up subsequent runs by skipping
│                            flash partition 1 read+decrypt
│
└── calib_data               last-saved calibration baseline (mode 0600)
                             13 440 bytes; 112 lines × 120 bytes/line
                             produced by `save-calib`; reused by
                             `match-finger` and enrollment
```

Both files live under `/var/lib` because they're host-state, not
ephemeral; they survive reboots and only change when the host or the
sensor is re-paired/re-calibrated.

### On the device (USB flash)

The Metallica MIS has a small NOR flash split into 5 partitions:

```
┌──────┬──────────┬───────────────────────────────────────────────┐
│ id   │ size     │ purpose                                       │
├──────┼──────────┼───────────────────────────────────────────────┤
│  1   │   4 KiB  │ TLS pairing record (cert + privkey + ECDH q)  │
│  2   │ 248 KiB  │ xpfwext — firmware-extension blob (v1.2)      │
│  4   │ 512 KiB  │ Template database — enrolled fingerprints     │
│  5   │  32 KiB  │ Unknown / reserved                            │
│  6   │  32 KiB  │ Calibration data (Windows-paired baseline)    │
└──────┴──────────┴───────────────────────────────────────────────┘
```

On supported Lenovo systems previously initialised by the Synaptics
OEM driver or `python-validity`, partitions 1, 2, and 6 are already
populated. We *read* them during a normal
`synaptics-metallica-mis` session; enrollment writes fingerprint
records to partition 4.

### On host hardware

The pairing record is tied to the host identity exposed through:

```
/sys/class/dmi/id/product_name
/sys/class/dmi/id/product_serial
```

These values feed the GWK key derivation. Without the matching host
identity, the driver cannot decrypt the pairing record. The installer
grants `CAP_DAC_READ_SEARCH` so the installed binary can read the
protected DMI serial without running the whole process as root.

## ThinkPad T480s validation

The ThinkPad T480s implementation was validated on the FM-3367-001
sensor (`06cb:009a`, sensor type `0x0199`). The tested workflow covers:

* three-pass calibration with packet sizes 897 / 13 665 / 13 665 bytes;
* saving and reloading the 13 440-byte calibration baseline;
* enrolling a new fingerprint;
* matching existing and newly enrolled fingerprints;
* matching after a USB reset;
* retrying low-quality captures without leaving the sensor stuck.

This resolves the enrollment stall reported in
[issue #1](https://github.com/wdes/Synaptics-Metallica-MIS-rs/issues/1).

## Command reference

### Read-only diagnostics (safe to run anytime)

```sh
synaptics-metallica-mis list                # enumerate supported sensors on the bus
synaptics-metallica-mis identify            # open the first supported sensor and print descriptors
synaptics-metallica-mis version             # cleartext RomInfo (cmd 0x01)
synaptics-metallica-mis boot-info           # cleartext probes 01 / 19 / 43 02
synaptics-metallica-mis flash-read          # dump TLS pairing record (partition 1)
synaptics-metallica-mis pairing             # decrypt + verify the per-host TLS keys
synaptics-metallica-mis gwk                 # derive pre-TLS GWK keys offline (no I/O)
synaptics-metallica-mis tls-hello           # exchange a Client Hello, parse Server Hello
synaptics-metallica-mis tls-handshake       # full TLS-PSK handshake + RomInfo round trip
synaptics-metallica-mis identify-sensor     # cmd 0x75 → silicon revision (FM-3367-001 etc.)
synaptics-metallica-mis fwext-info          # structured fwext partition info
synaptics-metallica-mis flash-info          # cmd 0x3e: chip JEDEC id + partition table
synaptics-metallica-mis tls-read-flash <P>  # post-TLS read of partition P (1, 2, 4, 5, 6)
synaptics-metallica-mis db-info             # cmd 0x45: DB occupancy
synaptics-metallica-mis db-children <id>    # cmd 0x46: walk DB tree
synaptics-metallica-mis db-value <id>       # cmd 0x49: dump record bytes (avoid type-8 = templates)
synaptics-metallica-mis db-user-storage     # decode StgWindsor + its user list
synaptics-metallica-mis db-user <dbid>      # decode a single User record
synaptics-metallica-mis factory-bits        # cmd 0x6f: factory TLV table
synaptics-metallica-mis factory-calibration # subst_value byte for IDENTIFY/ENROLL
synaptics-metallica-mis send <hex>          # arbitrary post-TLS command (protocol exploration)
synaptics-metallica-mis int-watch           # passive EP 0x83 reader (Ctrl-C to stop)
synaptics-metallica-mis int-probe <hex>     # send <hex> + dump resulting interrupts
synaptics-metallica-mis int-decode <hex>    # offline decoder for an EP 0x83 event
synaptics-metallica-mis diagnose            # one-shot: every read-only query in sequence
synaptics-metallica-mis reset               # USB-reset the sensor (recovers stuck state)
synaptics-metallica-mis forget              # delete cached pairing record (forces re-decrypt)
```

### Capture, identify, enroll

```sh
synaptics-metallica-mis save-calib                                     # 3-pass calibration → /var/lib/synaptics-metallica-mis/calib_data
synaptics-metallica-mis try-calibrate [--save-pgm out.pgm]             # one CALIBRATE pass; optionally PGM-render
synaptics-metallica-mis try-identify [--use-saved-calib | --use-stored-calib]
                                                           # full identify + match flow with verbose trace
synaptics-metallica-mis match-finger [--retries N]                     # identify+match; stdout: "MATCH dbid=N subtype=M …"
                                                           # exit 0 = match, non-zero = no-match / low-quality / error
synaptics-metallica-mis enroll --subtype 1 [--sid-string S-...] --yes  # write a fingerprint (destructive, auto-retries on quality errors)
synaptics-metallica-mis delete-record <dbid> --yes                     # remove a user or finger record (cmd 0x48, cascades for users)
synaptics-metallica-mis blink                                          # exercise the LED control path
```

### Offline decoders (no USB needed)

```sh
synaptics-metallica-mis dump-cmd-02 <mode>             # build cmd-02 packet from canonical inputs and hex-dump it
synaptics-metallica-mis frame-to-pgm <hex> <out.pgm>   # convert an EP 0x82 frame dump to grayscale PGM
synaptics-metallica-mis int-decode <hex>               # explain an EP 0x83 interrupt event
```

## Installing

### One-shot installer (recommended)

The fastest path — handles binary install, capabilities, udev rule,
state directory, and (optionally) PAM wiring in a single command:

```sh
cargo build --release
sudo ./packaging/install.sh                   # base install only
sudo ./packaging/install.sh --sudo            # base install + sudo wiring
sudo ./packaging/install.sh --all             # sudo + su + sddm
sudo ./packaging/install.sh --help            # full flag list
```

Re-running is safe — every step is idempotent (binary is overwritten
in place, udev rule is replaced, state dir uses `mkdir -p`, PAM
edits are skipped when the marker comment is already present).

#### What the installer does

1. **Binary** → copied to `/usr/local/bin/synaptics-metallica-mis`
   (mode `0755`).

2. **Capabilities** → runs
   `setcap cap_dac_read_search+ep <binary>`. This grants permission
   to read any file regardless of DAC permissions, so the binary
   can open `/sys/class/dmi/id/product_serial` (mode `0400 root:root`
   on most distros) without being root. The DMI serial feeds the
   GWK-key derivation; without it the TLS-PSK handshake fails.

3. **Udev rule** → installs
   `/etc/udev/rules.d/70-synaptics-metallica-mis.rules` and reloads
   udev. The rule tags the USB device with `uaccess` so whoever owns
   the active local console session inherits read/write access. No
   group required by default; if you'd rather use a group, edit the
   rule to `GROUP="plugdev", MODE="0660"`.

4. **State directory** → creates `/var/lib/synaptics-metallica-mis/`
   with group ownership (default `plugdev`, override with `SMM_GROUP`)
   and mode `0770`. Houses the pairing cache (`session`) and saved
   calibration data (`calib_data`), both mode `0600` (or `0660` if
   the cache was first written by a non-root group member).

5. **PAM wiring** *(optional, behind `--sudo` / `--su` / `--sddm` /
   `--all`)* → copies `packaging/pam/synaptics-mis-pam.sh` to
   `/usr/local/lib/synaptics-mis-pam.sh`, then patches each requested
   `/etc/pam.d/<service>` to add an `auth sufficient pam_exec.so …`
   line at the top. Before patching, the original is backed up to
   `<service>.bak-smm`. The marker comment `# synaptics-metallica-mis`
   above the inserted line makes future re-runs idempotent.

   ⚠ After enabling PAM wiring, **always test in a NEW terminal** —
   keep your current shell open as a recovery escape. To revert a
   service, restore its `.bak-smm`:

   ```sh
   sudo mv /etc/pam.d/sudo.bak-smm /etc/pam.d/sudo
   ```

#### Configuration env vars

| var | default | purpose |
|---|---|---|
| `PREFIX` | `/usr/local` | where the binary lives |
| `BIN_SRC` | `target/release/synaptics-metallica-mis` | source path |
| `UDEV_DIR` | `/etc/udev/rules.d` | udev rules location |
| `STATE_DIR` | `/var/lib/synaptics-metallica-mis` | pairing cache + calib data |
| `SMM_GROUP` | `plugdev` | unix group that owns `STATE_DIR` |
| `PAM_LIB` | `/usr/local/lib/synaptics-mis-pam.sh` | PAM wrapper script |

E.g. installing to `/opt`, with a `wheel` group:

```sh
sudo PREFIX=/opt SMM_GROUP=wheel ./packaging/install.sh --sudo
```

### Manual install

The same moves the installer assembles, run by hand:

```sh
# 1. Binary + capabilities
sudo install -m 0755 target/release/synaptics-metallica-mis /usr/local/bin/
sudo setcap cap_dac_read_search+ep /usr/local/bin/synaptics-metallica-mis

# 2. Udev rule
sudo install -m 0644 packaging/udev/70-synaptics-metallica-mis.rules \
                     /etc/udev/rules.d/
sudo udevadm control --reload
sudo udevadm trigger --action=add \
                     --attr-match=idVendor=06cb --attr-match=idProduct=009a

# 3. State directory
sudo mkdir -p /var/lib/synaptics-metallica-mis
sudo chgrp plugdev /var/lib/synaptics-metallica-mis
sudo chmod 0770    /var/lib/synaptics-metallica-mis

# 4. (optional) PAM wrapper for sudo / su / sddm
sudo install -m 0755 packaging/pam/synaptics-mis-pam.sh /usr/local/lib/
# Then add ONE line at the top of /etc/pam.d/sudo (etc.):
#   auth   sufficient   pam_exec.so   /usr/local/lib/synaptics-mis-pam.sh
```

### Verify the install

```sh
# As your unprivileged user (no sudo prefix):
groups | grep -q plugdev && echo "in plugdev: ok"
synaptics-metallica-mis list             # should show your sensor
synaptics-metallica-mis save-calib       # 1 sec, populates state dir
synaptics-metallica-mis match-finger     # press an enrolled finger
```

If `list` still asks for root, re-plug the sensor (or reboot) so
udev re-applies the new rule.

### Uninstall

```sh
# Reverse PAM wiring (if you ran --sudo / --su / --sddm)
for svc in sudo su sddm; do
    [ -f /etc/pam.d/$svc.bak-smm ] \
        && sudo mv /etc/pam.d/$svc.bak-smm /etc/pam.d/$svc
done

# Remove binary, udev rule, PAM wrapper
sudo rm -f /usr/local/bin/synaptics-metallica-mis
sudo rm -f /etc/udev/rules.d/70-synaptics-metallica-mis.rules
sudo rm -f /usr/local/lib/synaptics-mis-pam.sh
sudo udevadm control --reload

# Optionally also remove cached state — DESTRUCTIVE: wipes saved
# pairing cache + calibration; you'll need to re-run save-calib
sudo rm -rf /var/lib/synaptics-metallica-mis
```

## Testing

```sh
cargo test                                              # 213 unit tests
cargo clippy --all-targets --all-features -- -D warnings  # lint
```

Several tests are byte-exact regression vectors against python-validity
captures stored under `scripts/captured/`. If the device protocol
changes (or our code drifts), they fail loudly.

The `scripts/` directory also has helpers for cross-checking against
python-validity:

```sh
python3 scripts/cross_check_gwk.py             # GWK keys against python-validity
python3 scripts/python_validity_identify.py    # one identify cycle via python-validity
python3 scripts/walk_cmd02.py < out.hex        # parse a saved cmd-02 dump
```

## PAM / login integration

`sudo` / `su` / `sddm` authentication via fingerprint is shipped
through `pam_exec` — no native PAM module needed. The
[Installing](#installing) section above covers the install side via
the `--sudo` / `--su` / `--sddm` / `--all` flags on
`packaging/install.sh`. For the design rationale, what the wrapper
script does, and which login managers are known to work, see
[`packaging/pam/README.md`](./packaging/pam/README.md).

After PAM wiring, `sudo` prompts for a fingerprint first; on a clean
match no password is needed. On miss / timeout PAM falls through to
your existing password auth — no security regression vs the default.

Native fprintd / libfprint integration (so GNOME / KDE Settings see
the sensor through their normal D-Bus pipes) is on the roadmap; see
[`TODO.md`](./TODO.md).

## Caveats and limitations

### ⚠ Cannot pair an un-paired device (yet)

This driver only works on devices that are **already paired** by either
the Lenovo Windows Synaptics OEM driver or by `python-validity`'s
`init_flash` flow. We *read* the existing pairing record from flash
partition 1; we do not yet write a fresh one.

Concretely, that means:

- ✅ **ThinkPad shipped with Windows, then Linux installed** — the
  Windows Synaptics driver pairs the device on first boot, after
  which synaptics-metallica-mis can use it indefinitely.
- ✅ **Device previously paired by python-validity** — we read the
  same record format and decrypt with the same GWK-key derivation.
- ❌ **Brand-new device, never connected to Windows or python-validity** —
  flash partition 1 is empty, our handshake fails with
  `pairing record is malformed: priv key prefix is not 0x02`.
- ❌ **Device that's been factory-reset** — same as above.

Implementing pair-from-scratch is on the roadmap but is a **destructive,
non-trivial** operation that requires:

1. The vendor `reset_blob` capsule (~250 bytes) — not yet ported from
   `python-validity/blobs_9a.py`.
2. A 256-byte `partition_signature` blob hardcoded per device family.
3. A new flash-format flow (cmds `0x40`/`0x42` wrapped in
   `db_write_enable`) that erases partitions 1, 2, 4, 5, 6.
4. A `make_tls_flash` builder that assembles the cert + encrypted
   priv key + ECDH-q records and writes them back to partition 1.
5. The encrypt direction of `crypto::aes256_cbc_decrypt` (we currently
   only have decrypt for reading the existing record).

Until that lands, **if your sensor is unpaired, the only path to
pairing it is** [`python-validity`](https://github.com/uunicorn/python-validity)
— install it, run `python -m validitysensor.init_flash`, then come
back to synaptics-metallica-mis which will then read the same pairing record.

A botched pair-from-scratch run on this hardware leaves a half-formatted
flash that neither synaptics-metallica-mis nor python-validity can recover from
without serial-port-level vendor tooling. That's why we're not
shipping it casually.

## Prior art and protocol references

* [`uunicorn/python-validity`](https://github.com/uunicorn/python-validity)
  — reference implementation, supports the full pairing + enroll +
  identify cycle. Used as our protocol oracle.
* [`nmikhailov/Validity90`](https://github.com/nmikhailov/Validity90) —
  original reverse-engineering effort and protocol notes for the family.
* [Reversing a Fingerprint Reader Protocol — Neodyme](https://neodyme.io/en/blog/fingerprint_reversing/)
  — write-up of the TLS-PSK-over-USB scheme used by these sensors.
* [r/archlinux thread on `06cb:009a`](https://www.reddit.com/r/archlinux/comments/1t2hzvo/06cb009a_synaptics_metallica_mis_anyone_got_it/)
  — community discussion of the device on Linux.

## Attribution

Protocol knowledge (USB endpoint addresses, cleartext command bytes,
response framing, vendor blob bytes) is derived from the public
reverse-engineering work listed in
[`THIRD_PARTY.md`](./THIRD_PARTY.md). No source code is copied; only
protocol facts and verbatim binary blobs (vendor capsules the device
demands as opaque inputs) are reproduced. All Rust code is clean-room.

## License

Mozilla Public License 2.0. See [`LICENSE`](./LICENSE).
