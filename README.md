# Synaptics-Metallica-MIS-rs

> CLI command: `think-touch` — library crate: `think_touch` — package: `synaptics-metallica-mis-rs`

A pure-Rust userspace driver for the Synaptics / Validity **Metallica MIS**
fingerprint sensor (USB id `06cb:009a`) found on the ThinkPad P70 and a
handful of other Lenovo laptops from that era.

> **Status: working end-to-end.** Pairing, calibration, capture, and
> matching against an enrolled finger all run on real hardware.
> Enrollment write path is wired (verified byte-for-byte against
> python-validity) but the resilient retry loop is still being tuned.
>
> 209 unit tests, lint-clean under `-D warnings`, MPL-2.0.

```
┌──────────────────────────── think-touch ────────────────────────────┐
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

`think-touch` aims to be:

* **Pure Rust**, so a single static binary can drive the sensor.
* **Library-first**, so the driver can be embedded in custom auth flows
  (kernel locks, `pam_exec`, GUI prompts, …) without `fprintd`.
* **Small and auditable**, MPL-2.0 licensed, byte-exact against
  python-validity for every wire packet we send.

## Hardware target

| VID    | PID    | Codename       | Notes                                       |
|--------|--------|----------------|---------------------------------------------|
| `06cb` | `009a` | Metallica MIS  | ThinkPad P70 / T480 / X1 C6 — primary target |
| `138a` | `0090` | Prometheus     | Recognised, not yet driven                  |
| `138a` | `0097` | Prometheus 97  | Recognised, not yet driven                  |
| `138a` | `009d` | Prometheus 9d  | Recognised, not yet driven                  |

## Quick start

```sh
# Build (release-mode binary lives at target/release/think-touch)
cargo build --release

# Look for the sensor on the USB bus
sudo ./target/release/think-touch list

# Run the full read-only health-check (no flash writes)
sudo ./target/release/think-touch diagnose

# Capture + match an enrolled finger
sudo ./target/release/think-touch save-calib            # 3-pass calibration, ~1 sec
sudo ./target/release/think-touch try-identify --use-saved-calib
# Press your enrolled finger when prompted. You should see:
#
#   ┌── MATCH ───────────────────────────────────────────┐
#   │  user dbid : 5                                     │
#   │  finger    : 1 (right-thumb)                       │
#   │  hash[..8] : 322987beb350cefa…                     │
#   └────────────────────────────────────────────────────┘
```

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

Each layer has its own regression tests (totalling 209) so a change at
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
    │── cmd 0x02 IDENTIFY (13 729 B) ─────────────►│
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
13 729-byte program we have to ship with every IDENTIFY/ENROLL.

The capture command (`cmd 0x02`) carries a stream of TLV chunks that
the device interprets as a tiny sensor program: which scan-line
schedule to run, where to put pixels, which transforms to apply. For
calibration we send a small program (657 bytes) and read back raw
pixels on EP 0x82. For identify/enroll we have to bake the calibration
data *into* the program as per-line offsets — without those, the
matcher reads sensor noise and fires a phantom-touch sentinel.

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
/var/lib/think-touch/
├── session                  pairing cache (mode 0600)
│                            key=value, host DMI + decrypted client keys
│                            speeds up subsequent runs by skipping
│                            flash partition 1 read+decrypt
│
└── calib_data               last-saved calibration baseline (mode 0600)
                             13 440 bytes; 112 lines × 120 bytes/line
                             produced by `save-calib`; reused by
                             `try-identify --use-saved-calib`
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

On Lenovo P70s shipped with Windows, partitions 1, 2, and 6 are
already populated by the Synaptics OEM driver. We *read* all of them
during a normal think-touch session; we only *write* to partition 4
during enrollment.

### On host hardware

```
/sys/class/dmi/id/product_name      "20QRCTO1WW"  on the user's P70
/sys/class/dmi/id/product_serial    "PF1YZ4SV"

  → fed into the GWK key derivation. Without these the host can't
    decrypt the pairing record.
```

Currently we read these directly which requires `sudo`. A future
`setcap CAP_DAC_READ_SEARCH` step will let an unprivileged user run
the binary.

## Command reference

### Read-only diagnostics (safe to run anytime)

```sh
think-touch list                # enumerate supported sensors on the bus
think-touch identify            # open the first supported sensor and print descriptors
think-touch version             # cleartext RomInfo (cmd 0x01)
think-touch boot-info           # cleartext probes 01 / 19 / 43 02
think-touch flash-read          # dump TLS pairing record (partition 1)
think-touch pairing             # decrypt + verify the per-host TLS keys
think-touch gwk                 # derive pre-TLS GWK keys offline (no I/O)
think-touch tls-hello           # exchange a Client Hello, parse Server Hello
think-touch tls-handshake       # full TLS-PSK handshake + RomInfo round trip
think-touch identify-sensor     # cmd 0x75 → silicon revision (FM-3367-001 etc.)
think-touch fwext-info          # structured fwext partition info
think-touch flash-info          # cmd 0x3e: chip JEDEC id + partition table
think-touch tls-read-flash <P>  # post-TLS read of partition P (1, 2, 4, 5, 6)
think-touch db-info             # cmd 0x45: DB occupancy
think-touch db-children <id>    # cmd 0x46: walk DB tree
think-touch db-value <id>       # cmd 0x49: dump record bytes (avoid type-8 = templates)
think-touch db-user-storage     # decode StgWindsor + its user list
think-touch db-user <dbid>      # decode a single User record
think-touch factory-bits        # cmd 0x6f: factory TLV table
think-touch factory-calibration # subst_value byte for IDENTIFY/ENROLL
think-touch send <hex>          # arbitrary post-TLS command (protocol exploration)
think-touch int-watch           # passive EP 0x83 reader (Ctrl-C to stop)
think-touch int-probe <hex>     # send <hex> + dump resulting interrupts
think-touch int-decode <hex>    # offline decoder for an EP 0x83 event
think-touch diagnose            # one-shot: every read-only query in sequence
think-touch reset               # USB-reset the sensor (recovers stuck state)
think-touch forget              # delete cached pairing record (forces re-decrypt)
```

### Capture, identify, enroll

```sh
think-touch save-calib                                     # 3-pass calibration → /var/lib/think-touch/calib_data
think-touch try-calibrate [--save-pgm out.pgm]             # one CALIBRATE pass; optionally PGM-render
think-touch try-identify [--use-saved-calib | --use-stored-calib]
                                                           # full identify + match flow with verbose trace
think-touch match-finger                                   # one-shot identify+match; stdout: "MATCH dbid=N subtype=M …"
                                                           # exit 0 = match, non-zero = no-match / low-quality / error
think-touch enroll --subtype 1 [--sid-string S-...] --yes  # write a fingerprint (destructive, auto-retries on quality errors)
think-touch delete-record <dbid> --yes                     # remove a user or finger record (cmd 0x48, cascades for users)
think-touch blink                                          # exercise the LED control path
```

### Offline decoders (no USB needed)

```sh
think-touch dump-cmd-02 <mode>             # build cmd-02 packet from canonical inputs and hex-dump it
think-touch frame-to-pgm <hex> <out.pgm>   # convert an EP 0x82 frame dump to grayscale PGM
think-touch int-decode <hex>               # explain an EP 0x83 interrupt event
```

## Permissions — running without `sudo`

There's a one-shot installer in `packaging/`:

```sh
cargo build --release
sudo ./packaging/install.sh
```

That:

1. Copies the binary to `/usr/local/bin/think-touch`.
2. Runs `setcap cap_dac_read_search+ep` on it so it can read
   `/sys/class/dmi/id/product_serial` (mode `0400 root:root` on most
   distros) without being root itself. The DMI serial is what the
   GWK key derivation needs to decrypt the device's pairing record.
3. Installs the udev rule so the local-console user can claim the
   USB device (`uaccess` tag).
4. Creates `/var/lib/think-touch/` with group ownership (default
   `plugdev`, override with `THINK_TOUCH_GROUP=…`) so the pairing
   cache and saved calibration data survive across reboots without
   needing root each time.

After install, plain-user invocation works:

```sh
think-touch list
think-touch diagnose
think-touch match-finger
```

If you'd rather configure things by hand, the moving parts are:

- `setcap cap_dac_read_search+ep <bin>` for DMI access.
- `packaging/udev/70-think-touch.rules` → `/etc/udev/rules.d/`.
- `/var/lib/think-touch/` accessible to whichever group runs the
  binary (default install picks `plugdev`).

Without setcap, the binary still works under `sudo` — the install
step is opt-in for unprivileged use.

## Testing

```sh
cargo test                                 # 209 unit tests
cargo clippy --all-targets -- -D warnings  # lint
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

## Caveats and limitations

### ⚠ Cannot pair an un-paired device (yet)

This driver only works on devices that are **already paired** by either
the Lenovo Windows Synaptics OEM driver or by `python-validity`'s
`init_flash` flow. We *read* the existing pairing record from flash
partition 1; we do not yet write a fresh one.

Concretely, that means:

- ✅ **ThinkPad shipped with Windows, then Linux installed** — the
  Windows Synaptics driver pairs the device on first boot, after
  which think-touch can use it indefinitely.
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
back to think-touch which will then read the same pairing record.

A botched pair-from-scratch run on this hardware leaves a half-formatted
flash that neither think-touch nor python-validity can recover from
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
