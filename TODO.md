# Roadmap

Current state (2026-05-07): pair → calibrate → identify → match
working end-to-end on the user's ThinkPad P70. python-validity-written
enrollment matches via our cmd-02 + cmd 0x5e + cmd 0x60 path.
Resilient enroll loop, `delete-record`, and one-shot `match-finger`
landed in commit `5512811`.

## What still needs work

### 1. Setcap for unprivileged use

The binary requires `sudo` only for `/sys/class/dmi/id/product_serial`
(needed to derive the GWK keys). A `setcap cap_dac_read_search+ep`
on the binary would let an unprivileged user run it without `sudo`.
Needs investigation: which DMI files are root-only on which distros,
and whether `nusb` claims the interface cleanly under capabilities.

### 2. Other Validity sensors (138a:0090, 0097, 009d)

Recognised in `usb.rs` but not driven. The protocol shape is the
same; the per-device blobs (init_hardcoded, db_write_enable, glow
patterns) differ. python-validity has all four sets in its
`blobs_*.py` modules — we just need to port them.

### 3. fprintd integration

The driver is library-shaped enough to be wrapped, but no
`libfprint` adapter exists yet. A first cut would be a thin shim
that exposes our `match_finger` over D-Bus matching the libfprint
device interface.

### 4. xpfwext upload (clean-slate devices)

For devices that ship un-paired (no Lenovo Windows pre-pair), we'd
need to upload the firmware-extension blob ourselves. The
`6_07f_lenovo_mis_qm.xpfwext` blob is publicly extractable from
Lenovo's Windows installer; the upload sequence is in
`python-validity/upload_fwext.py`. Currently we only verify the
blob is present, we don't ship it.

### 5. Pair from scratch

Today we *read* an existing pairing record (Windows-paired). To
work on a clean device, we'd need to format flash partition 1 and
write our own cert + keys (`init_flash.py:partition_flash`).
Destructive — wipes any existing enrollments.

## What's confirmed working

- Pairing record decryption (HMAC verifies, AES-CBC unwraps)
- TLS-PSK handshake (Synaptics quirks preserved bug-for-bug)
- Cleartext + post-TLS protocol commands (34 subcommands)
- Calibration (3-iteration loop, partition 6 layout match)
- Save/load calib data to disk
- IDENTIFY cmd-02 (16 chunks, 13729 bytes, byte-exact vs upstream)
- ENROLL cmd-02 (same shape with 0x26+0x2e tail, byte-exact vs upstream)
- Capture pipeline (start → finger-detect → progress → complete)
- get_prg_status2 metadata parser
- match-finger (cmd 0x5e + cmd 0x60 + TLV decode + structured stdout)
- delete-record (cmd 0x48 wrapped in db_write_enable + call_cleanups)
- enroll loop with retry on low-quality scans
- LED control (after the 256→125 byte glow blob fix)
- 209 unit tests, lint clean

## Reference data

- python-validity captures: `scripts/captured/pv_cmd02_*.hex`
- Memory snapshot: `~/.claude/projects/-mnt-Dev--wdes-think-touch/memory/`
- Cross-check scripts: `scripts/python_validity_*.py`,
  `scripts/cross_check_gwk.py`, `scripts/walk_cmd02.py`
