# Roadmap

Current state (2026-05-07): pair → calibrate → identify → match
working end-to-end on the user's ThinkPad P70. python-validity-written
enrollment matches via our cmd-02 + cmd 0x5e + cmd 0x60 path.

## What still needs work

### 1. Resilient enroll loop

Our `think-touch enroll --subtype N --yes` builds the right cmd-02
ENROLL bytes (byte-verified against python-validity's capture), but
the outer loop bails on the first non-fatal error. python-validity
catches `Scanning problem: 80000` and similar quality-failure errors
and retries the iteration. We should:

- Not abort on `error=0x00080000` from `get_prg_status2` (treat as
  "this iteration produced a low-quality scan; try again").
- Not abort on missed `b[2] & 0x04` after a few hundred ms (allow
  press timeout, retry).
- Cap total iterations at ~12 (matches upstream).
- Print clearer prompts ("press → hold → release → repeat" cycle).

### 2. Delete-user / delete-finger subcommand

`db.del_record` (cmd 0x48) is wired in `db.rs` but not exposed.
Useful to clean up test enrollments — currently you have to keep
re-running `python-validity` enroll if you want to start fresh.

### 3. Match-finger as a top-level command

Currently `match-finger` is a stub. Reuse the `try-identify` pipeline
but skip the calibration step (assume calib_data is loaded) and
return only the `(user_dbid, subtype)` pair. Useful as a
`pam_exec`-friendly mode.

### 4. Setcap for unprivileged use

The binary requires `sudo` only for `/sys/class/dmi/id/product_serial`
(needed to derive the GWK keys). A `setcap cap_dac_read_search+ep`
on the binary would let an unprivileged user run it without `sudo`.
Needs investigation: which DMI files are root-only on which distros.

### 5. Other Validity sensors (138a:0090, 0097, 009d)

Recognised in `usb.rs` but not driven. The protocol shape is the
same; the per-device blobs (init_hardcoded, db_write_enable, glow
patterns) differ. python-validity has all four sets in its
`blobs_*.py` modules — we just need to port them.

## What's confirmed working

- Pairing record decryption (HMAC verifies, AES-CBC unwraps)
- TLS-PSK handshake (Synaptics quirks preserved bug-for-bug)
- Cleartext + post-TLS protocol commands (32 subcommands)
- Calibration (3-iteration loop, partition 6 layout match)
- Save/load calib data to disk
- IDENTIFY cmd-02 (16 chunks, 13729 bytes, byte-exact vs upstream)
- ENROLL cmd-02 (same shape with 0x26+0x2e tail, byte-exact vs upstream)
- Capture pipeline (start → finger-detect → progress → complete)
- get_prg_status2 metadata parser
- match-finger (cmd 0x5e + cmd 0x60 + TLV decode)
- LED control (after the 256→125 byte glow blob fix)
- 209 unit tests, lint clean

## Reference data

- python-validity captures: `scripts/captured/pv_cmd02_*.hex`
- Memory snapshot: `~/.claude/projects/-mnt-Dev--wdes-think-touch/memory/`
- Cross-check scripts: `scripts/python_validity_*.py`,
  `scripts/cross_check_gwk.py`, `scripts/walk_cmd02.py`
