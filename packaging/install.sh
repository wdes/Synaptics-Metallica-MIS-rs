#!/bin/sh
# install.sh — system-wide install of synaptics-metallica-mis with no-sudo runtime.
#
# What this does (always):
#   1. Copies target/release/synaptics-metallica-mis → /usr/local/bin/synaptics-metallica-mis
#   2. Grants it CAP_DAC_READ_SEARCH so it can read
#      /sys/class/dmi/id/product_serial without root.
#   3. Installs the udev rule so unprivileged users can claim the USB
#      device once they're at the local console.
#   4. Creates /var/lib/synaptics-metallica-mis/ owned by the `plugdev` group
#      (configurable via SMM_GROUP env var) so the cache file
#      survives across reboots and is reachable by group members.
#
# Optional PAM integration flags (each is idempotent and backs up the
# /etc/pam.d/* file before editing it):
#   --sudo    enable fingerprint for `sudo`
#   --su      enable fingerprint for `su`
#   --sddm    enable fingerprint for sddm login
#   --all     all of the above
#
# Run with sudo. Idempotent — safe to re-run.
set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN_SRC="${BIN_SRC:-target/release/synaptics-metallica-mis}"
BIN_DST="${PREFIX}/bin/synaptics-metallica-mis"
UDEV_DIR="${UDEV_DIR:-/etc/udev/rules.d}"
UDEV_FILE="70-synaptics-metallica-mis.rules"
STATE_DIR="${STATE_DIR:-/var/lib/synaptics-metallica-mis}"
GROUP="${SMM_GROUP:-plugdev}"
PAM_LIB="${PAM_LIB:-/usr/local/lib/synaptics-mis-pam.sh}"
# `quiet` suppresses pam_exec's "exit code N" message on failure
# (sudo otherwise prints "<wrapper> échec : code de sortie 1" before
# falling through to the password prompt). The wrapper still logs to
# syslog at NOTICE for audit.
PAM_LINE='auth   sufficient   pam_exec.so   quiet   '"$PAM_LIB"
PAM_MARKER='# synaptics-metallica-mis'

ENABLE_SUDO=0
ENABLE_SU=0
ENABLE_SDDM=0

while [ $# -gt 0 ]; do
    case "$1" in
        --sudo) ENABLE_SUDO=1 ;;
        --su)   ENABLE_SU=1   ;;
        --sddm) ENABLE_SDDM=1 ;;
        --all)  ENABLE_SUDO=1; ENABLE_SU=1; ENABLE_SDDM=1 ;;
        -h|--help)
            sed -n '2,21p' "$0" | sed 's/^# *//'
            exit 0 ;;
        *)
            echo "$0: unknown flag '$1'. Try --help." >&2
            exit 1 ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "$0: must run as root (try: sudo $0)" >&2
    exit 1
fi

if [ ! -x "$BIN_SRC" ]; then
    echo "$0: $BIN_SRC not found — run \`cargo build --release\` first." >&2
    exit 1
fi

# ──────────────── 1. binary + udev + state dir ────────────────

echo "→ installing binary to $BIN_DST"
install -m 0755 "$BIN_SRC" "$BIN_DST"

echo "→ granting CAP_DAC_READ_SEARCH (needed for /sys/class/dmi/id/product_serial)"
if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_dac_read_search+ep' "$BIN_DST"
else
    echo "  warn: setcap not found; install libcap2-bin (Debian/Ubuntu)"
    echo "        or libcap (Arch) and re-run."
fi

echo "→ installing udev rule to $UDEV_DIR/$UDEV_FILE"
install -m 0644 "packaging/udev/$UDEV_FILE" "$UDEV_DIR/$UDEV_FILE"
udevadm control --reload
udevadm trigger --action=add --attr-match=idVendor=06cb --attr-match=idProduct=009a 2>/dev/null || true
udevadm trigger --action=add --attr-match=idVendor=138a 2>/dev/null || true

echo "→ ensuring state dir $STATE_DIR exists, group=$GROUP"
mkdir -p "$STATE_DIR"
if getent group "$GROUP" >/dev/null 2>&1; then
    chgrp "$GROUP" "$STATE_DIR"
    chmod 0770 "$STATE_DIR"
else
    echo "  note: group '$GROUP' doesn't exist on this system."
    echo "        Leaving $STATE_DIR root-owned. To switch to a group,"
    echo "        re-run with SMM_GROUP=<groupname>."
    chmod 0700 "$STATE_DIR"
fi

# ──────────────── 2. optional PAM wiring ────────────────

# Returns 0 if the marker is already present in the named pam.d file.
pam_already_wired() {
    grep -qF "$PAM_MARKER" "$1" 2>/dev/null
}

# Insert our auth stanza at the top of /etc/pam.d/<service>, after any
# leading `#%PAM-1.0` shebang. Backs up the original to <file>.bak-smm
# (only on first install — re-runs leave the existing backup alone).
wire_pam_service() {
    service="$1"
    target="/etc/pam.d/$service"

    if [ ! -f "$target" ]; then
        echo "  skip: $target does not exist on this system"
        return 0
    fi
    if pam_already_wired "$target"; then
        echo "  $target: already wired (idempotent skip)"
        return 0
    fi

    backup="${target}.bak-smm"
    if [ ! -f "$backup" ]; then
        cp -p "$target" "$backup"
        echo "  → backed up $target to $backup"
    fi

    # Build the new file: marker + auth line, then the original (with
    # any leading `#%PAM-1.0` line preserved at the top by appending
    # *after* it).
    tmp=$(mktemp)
    if head -n1 "$target" | grep -q '^#%PAM'; then
        head -n1 "$target"           >  "$tmp"
        echo "$PAM_MARKER"           >> "$tmp"
        echo "$PAM_LINE"             >> "$tmp"
        tail -n +2 "$target"         >> "$tmp"
    else
        echo "$PAM_MARKER"           >  "$tmp"
        echo "$PAM_LINE"             >> "$tmp"
        cat "$target"                >> "$tmp"
    fi
    install -m 0644 -o root -g root "$tmp" "$target"
    rm -f "$tmp"
    echo "  → $target patched"
}

if [ $ENABLE_SUDO -eq 1 ] || [ $ENABLE_SU -eq 1 ] || [ $ENABLE_SDDM -eq 1 ]; then
    echo
    echo "→ installing PAM wrapper to $PAM_LIB"
    install -m 0755 packaging/pam/synaptics-mis-pam.sh "$PAM_LIB"

    if [ $ENABLE_SUDO -eq 1 ]; then echo "→ wiring fingerprint for sudo"; wire_pam_service sudo; fi
    if [ $ENABLE_SU   -eq 1 ]; then echo "→ wiring fingerprint for su";   wire_pam_service su;   fi
    if [ $ENABLE_SDDM -eq 1 ]; then echo "→ wiring fingerprint for sddm"; wire_pam_service sddm; fi

    cat <<EOF

  ⚠ Test PAM changes in a NEW terminal — keep this shell open as a
    recovery escape. To revert, restore the .bak-smm backup, e.g.:
        sudo mv /etc/pam.d/sudo.bak-smm /etc/pam.d/sudo
EOF
fi

# ──────────────── done ────────────────

cat <<EOF

✓ install complete.

  Binary:    $BIN_DST  (with CAP_DAC_READ_SEARCH)
  Udev rule: $UDEV_DIR/$UDEV_FILE
  State:     $STATE_DIR
EOF

if [ $ENABLE_SUDO -eq 1 ] || [ $ENABLE_SU -eq 1 ] || [ $ENABLE_SDDM -eq 1 ]; then
    echo "  PAM:       $PAM_LIB (sudo=$ENABLE_SUDO su=$ENABLE_SU sddm=$ENABLE_SDDM)"
fi

cat <<EOF

Test as your normal user (no sudo):

  synaptics-metallica-mis list
  synaptics-metallica-mis version
  synaptics-metallica-mis diagnose

If those still ask for root, re-plug the sensor (or reboot) so udev
re-applies the new rule, and verify your account is in the
'$GROUP' group:  groups | grep $GROUP
EOF
