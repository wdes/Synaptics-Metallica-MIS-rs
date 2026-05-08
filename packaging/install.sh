#!/bin/sh
# install.sh — system-wide install of think-touch with no-sudo runtime.
#
# What this does:
#   1. Copies target/release/think-touch → /usr/local/bin/think-touch
#   2. Grants it CAP_DAC_READ_SEARCH so it can read
#      /sys/class/dmi/id/product_serial without root.
#   3. Installs the udev rule so unprivileged users can claim the USB
#      device once they're at the local console.
#   4. Creates /var/lib/think-touch/ owned by the `plugdev` group
#      (configurable via THINK_TOUCH_GROUP env var) so the cache file
#      survives across reboots and is reachable by group members.
#
# Run with sudo. Idempotent — safe to re-run.
set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN_SRC="${BIN_SRC:-target/release/think-touch}"
BIN_DST="${PREFIX}/bin/think-touch"
UDEV_DIR="${UDEV_DIR:-/etc/udev/rules.d}"
UDEV_FILE="70-think-touch.rules"
STATE_DIR="${STATE_DIR:-/var/lib/think-touch}"
GROUP="${THINK_TOUCH_GROUP:-plugdev}"

if [ "$(id -u)" -ne 0 ]; then
    echo "$0: must run as root (try: sudo $0)" >&2
    exit 1
fi

if [ ! -x "$BIN_SRC" ]; then
    echo "$0: $BIN_SRC not found — run \`cargo build --release\` first." >&2
    exit 1
fi

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
    echo "        re-run with THINK_TOUCH_GROUP=<groupname>."
    chmod 0700 "$STATE_DIR"
fi

cat <<EOF

✓ install complete.

  Binary:    $BIN_DST  (with CAP_DAC_READ_SEARCH)
  Udev rule: $UDEV_DIR/$UDEV_FILE
  State:     $STATE_DIR

Test as your normal user (no sudo):

  think-touch list
  think-touch version
  think-touch diagnose

If those still ask for root, re-plug the sensor (or reboot) so udev
re-applies the new rule, and verify your account is in the
'$GROUP' group:  groups | grep $GROUP
EOF
