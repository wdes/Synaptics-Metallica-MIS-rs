# Pending hardware tests for tomorrow

These need the device + you. Work through them in order; each is read-only / non-destructive.

## 1. Try the saved-calibration path

The fastest path to a clean state is a one-time save, then reuse:

```sh
sudo ./target/debug/think-touch save-calib                          # writes /var/lib/think-touch/calib_data
sudo ./target/debug/think-touch try-identify --use-saved-calib      # uses the saved file (fast, deterministic)
sudo ./target/debug/think-touch reset
```

If `save-calib` runs successfully, every subsequent `try-identify --use-saved-calib` skips the iteration loop and is much faster. The cooked output should also be identical between runs (deterministic).

## 2. Try the partition-6-stored calibration path

```sh
sudo ./target/debug/think-touch try-identify --use-stored-calib
sudo ./target/debug/think-touch reset
```

This uses the calibration data Windows wrote to flash partition 6. If the matcher state machine is keyed against Windows' calibration, this should eliminate the phantom-finger detection.

## 3. Watch raw EP-0x83 traffic

If `try-identify` keeps misbehaving, watch what the device actually sends:

```sh
sudo ./target/debug/think-touch int-watch       # passive — Ctrl-C to stop
sudo ./target/debug/think-touch reset
```

Or send a specific command and watch the resulting interrupts:

```sh
sudo ./target/debug/think-touch int-probe "39 20 bf 02 00 ff ff 00 00 01 99 00 20 00 00 00 00 99 99"   # truncated glow
sudo ./target/debug/think-touch reset
```

## 4. If nothing works, retry the basic flow on a fresh USB session

```sh
# unplug-replug the laptop's fingerprint sensor, or:
sudo ./target/debug/think-touch reset
sudo ./target/debug/think-touch try-calibrate    # known-good baseline (returns 80760 bytes)
```

## Inspect what's currently enrolled (read-only, safe)

```sh
sudo ./target/debug/think-touch db-user-storage             # decodes the StgWindsor storage record + its users index
sudo ./target/debug/think-touch db-user <dbid>              # for each user dbid the previous step lists, structured finger info
```

These print the enrolled fingers' subtypes (e.g. "right-thumb", "left-index-finger") *without* dumping any fingerprint template bytes. **Do NOT use `db-value` on type-8 records — those are template data.**

## See what the sensor actually captures

```sh
sudo ./target/debug/think-touch try-calibrate --save-pgm /tmp/calib_blank.pgm
xdg-open /tmp/calib_blank.pgm     # or: feh /tmp/calib_blank.pgm
```

`try-calibrate` is finger-free (returns sensor noise / blank) — the PGM
should look like a uniform grey 112×224 image. If you ever want to see
a real-finger frame, capture the EP-0x82 hex output of `try-identify`
into a file and convert via:

```sh
./target/debug/think-touch frame-to-pgm <hex-string> /tmp/frame.pgm
```

(That's a fingerprint image — your data; only convert if you want to
look at it yourself.)

## What's known to work

- 108 unit tests, lint clean ✅
- TLS-PSK handshake + app-data round trip ✅
- All cleartext + post-TLS commands listed in `--help` ✅
- `try-calibrate` end-to-end (cmd 0x02 framing validated; output structurally matches partition 6) ✅
- `factory-calibration` extracts `subst_value = 0x8c` for this host ✅
- Interrupt-event dance (EP 0x83 reader, start/finger/capture-complete) ✅

## Open question for tomorrow

`try-identify` consistently produces a *phantom* finger-detect interrupt + `error=0x80200000` from `get_prg_status2`, with `x=y=w1=w2=0` (zero capture metadata). The LED never glows. Suspect:
- Mismatched calibration (try `--use-stored-calib` and `--use-saved-calib` first).
- Sensor program for ROM 6.7.164 doesn't exist upstream — only `(major=6,minor=0,build=0)` matches our device, and the fuzzy-match might be inadequate. Worth comparing against running `python-validity` itself if you can install it briefly (`pip install python-validity`) to see whether upstream also fails on this specific ROM/host combo.

## Recurring agent

A 30-min in-session cron is set up (`c185e824`) that wakes Claude every 30 min while this session is alive, to keep chipping at offline tasks. Sandbox refused a persistent (across-session) recurring routine, so when the session ends the cron stops too.
