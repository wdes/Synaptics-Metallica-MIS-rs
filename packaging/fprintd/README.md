# metallica-fprintd — fprintd-compatible D-Bus service

`metallica-fprintd` speaks fprintd's D-Bus API (`net.reactivated.Fprint`)
and drives the sensor through this crate. Anything that already supports
fprintd then works with the Metallica MIS without libfprint:

| Client | Uses it for |
|---|---|
| KDE System Settings → Users → Fingerprint | enrol / delete fingers |
| KDE lock screen (`kde-fingerprint` PAM service) | unlock |
| `pam_fprintd` (via `pam-config`) | sudo, su, SDDM login |
| `fprintd-enroll`, `fprintd-verify`, `fprintd-list`, `fprintd-delete` | command line |

It replaces only the daemon. The distro's `fprintd` and `fprintd-pam`
packages stay installed, and their D-Bus policy, polkit actions and
`pam_fprintd.so` are reused. A systemd unit at
`/etc/systemd/system/fprintd.service` overrides the stock one, so D-Bus
activation starts this daemon.

## Install (openSUSE Tumbleweed)

```sh
cargo build --release                               # as your user
sudo ./packaging/fprintd/install-tumbleweed.sh
```

Then enrol a finger, either from **System Settings → Users → your user →
Configure Fingerprint Authentication** or in a terminal:

```sh
fprintd-enroll -f right-index-finger
fprintd-verify
```

Watch what the daemon is doing in a second terminal while you test:

```sh
journalctl -u fprintd -f
```

## PAM

- **Lock screen:** openSUSE's `kde-fingerprint` PAM file already calls
  `pam_fprintd`, so lock-screen unlock should work once a finger is enrolled.
- **sudo / su / SDDM login:**
  ```sh
  sudo pam-config --add --fprintd      # undo: sudo pam-config --delete --fprintd
  ```
  This adds `pam_fprintd` to `common-auth`, which every login service uses.
  On SDDM you then press Enter on an empty password field and touch the sensor.
  Keep a root shell open while you try it the first time.

If you used `packaging/install.sh --sudo/--su/--sddm` earlier, undo that
first (restore the `.bak-smm` files). Otherwise you'll be asked for your
finger twice.

## How users map to the sensor

Fingerprints live in the sensor's own flash, keyed by a Windows-style SID.
Each Linux user gets `S-1-5-21-111111111-1111111111-1111111111-<uid>`, the
same scheme python-validity uses, so its enrolments carry over. Fingers
enrolled under **Windows** belong to your Windows SID, so they don't
appear here. Re-enrol them once from KDE.

Verification runs the chip's matcher against every template, then
accepts the match only if it belongs to the claimed user.

## Uninstall

```sh
sudo ./packaging/fprintd/install-tumbleweed.sh --uninstall
```

This restores the stock fprintd. Enrolled fingers remain on the sensor.

## Testing without hardware

```sh
metallica-fprintd --mock --session --no-polkit   # simulated sensor on the session bus
```

`MOCK_VERIFY=nomatch` and `MOCK_PRESS_MS=<ms>` tweak the simulation.

## Known limitations

- Each unlock or enrolment starts with a sub-second calibration, taken in
  the same session as the scan. Without it, scans on a P52 came out clean
  but never matched. Calibration needs the sensor untouched, so wait for
  the prompt before touching it.

- The chip decides when an enrolment is complete (usually around 8 good
  presses). KDE's progress bar assumes 8 stages, so it may finish slightly
  early or late.
- One operation at a time. While a verify is waiting for a finger, for
  example on the lock screen, other clients wait for it to finish.
- Root callers skip polkit, matching fprintd. Everyone else is checked
  against the `net.reactivated.fprint.device.*` polkit actions shipped by
  the fprintd package.
