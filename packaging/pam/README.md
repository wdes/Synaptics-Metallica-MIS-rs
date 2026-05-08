# Linux fingerprint integration via `pam_exec`

The `synaptics-metallica-mis match-finger` subcommand follows the
`pam_exec(8)` exit-code contract:

| exit code | meaning |
|---|---|
| 0 | match found — `MATCH dbid=N subtype=M label` printed on stdout |
| ≠ 0 | no match / low quality / device error |

That's all `pam_exec` needs. You can wire fingerprint authentication
into login managers (sddm, gdm, lightdm), `sudo`, screen lockers, etc.,
without writing a native PAM module.

This directory ships:

```
pam/
├── README.md                  ← this file
├── synaptics-mis-pam.sh       ← wrapper script with sane defaults
├── pam.d/
│   ├── sddm-fingerprint       ← drop-in for /etc/pam.d/sddm
│   ├── sudo-fingerprint       ← drop-in for /etc/pam.d/sudo
│   └── su-fingerprint         ← drop-in for /etc/pam.d/su
└── systemd/
    └── synaptics-mis-permissions.service  ← optional one-shot to
                                            re-apply setcap on upgrades
```

## Quick: enable fingerprint for `sudo`

```sh
# 1. Install the wrapper somewhere root-readable.
sudo install -m 0755 synaptics-mis-pam.sh /usr/local/lib/synaptics-mis-pam.sh

# 2. Add ONE line at the top of /etc/pam.d/sudo (BEFORE the existing
#    auth lines, with `sufficient` so a successful match skips the
#    rest):
#
#    auth   sufficient   pam_exec.so   /usr/local/lib/synaptics-mis-pam.sh
#
# A copy of that one-line patch is in pam.d/sudo-fingerprint:
sudo install -m 0644 pam.d/sudo-fingerprint /etc/pam.d/sudo-fingerprint
# Then edit /etc/pam.d/sudo to include sudo-fingerprint above the rest.
```

After that, `sudo <anything>` will:

1. First prompt you to press your enrolled finger (~5s timeout).
2. On match → run the command (no password).
3. On miss / timeout → fall through to your existing password auth.

## Why `pam_exec` instead of a real PAM module

Two reasons:

- **Simplicity.** A native Rust PAM module needs `cdylib` linkage,
  `pam-binding`, lifecycle care for `pam_handle_t*`, and packaging as a
  `.so`. `pam_exec` is built into PAM itself; just point it at our binary.
- **Auditability.** The binary's behaviour is identical whether invoked
  by PAM or from a shell — the same exit codes, the same stdout. Easier
  to debug and to lock down.

A real PAM module is a future enhancement; the existing
`pam_exec`-based wiring is enough for daily use today.

## Caveats

- **No fingerprint enrollment via login UIs.** GNOME Settings ›
  Users › Authentication asks `fprintd`'s D-Bus interface, which we
  don't implement. To enrol fingers run `synaptics-metallica-mis enroll
  --subtype N --yes` from a terminal.
- **No screen-lock unlock** if your distro's screen locker only
  speaks `fprintd`. swaylock with `pam_exec` works; KDE's older
  versions might not.
- **Each PAM-driven match runs a fresh capture cycle**, ~1 second per
  press. Acceptable for `sudo`, possibly slow for repeated screen
  unlocks.

If you want full GNOME / KDE Settings integration, that needs the
fprintd D-Bus shim — see TODO.md.
