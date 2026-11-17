#!/bin/sh
# install-tumbleweed.sh — install metallica-fprintd as the system's fprintd
# on openSUSE Tumbleweed (works on other systemd distros with fprintd too).
#
#   cargo build --release                       # as your normal user, first
#   sudo ./packaging/fprintd/install-tumbleweed.sh
#   sudo ./packaging/fprintd/install-tumbleweed.sh --uninstall
#
# What it does:
#   1. Installs the stock fprintd + fprintd-pam packages if missing. We
#      reuse their D-Bus policy, polkit actions and pam_fprintd.so; only
#      the daemon itself is replaced.
#   2. Copies target/release/metallica-fprintd to /usr/local/libexec/.
#   3. Installs /etc/systemd/system/fprintd.service, overriding the stock
#      unit so D-Bus activation starts our daemon.
#   4. Restarts the service.
# It does NOT change PAM. See packaging/fprintd/README.md for that.
set -eu

BIN_SRC="${BIN_SRC:-target/release/metallica-fprintd}"
BIN_DST="/usr/local/libexec/metallica-fprintd"
UNIT_DST="/etc/systemd/system/fprintd.service"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "$0: must run as root (try: sudo $0)" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    echo "→ removing $UNIT_DST and $BIN_DST"
    systemctl stop fprintd.service 2>/dev/null || true
    rm -f "$UNIT_DST" "$BIN_DST"
    systemctl daemon-reload
    echo "✓ stock fprintd restored (it will start on demand)."
    echo "  Fingerprints stay stored on the sensor itself."
    exit 0
fi

if [ ! -x "$BIN_SRC" ]; then
    echo "$0: $BIN_SRC not found — run \`cargo build --release\` (as your user) first." >&2
    exit 1
fi

if ! grep -qi '06cb' /sys/bus/usb/devices/*/idVendor 2>/dev/null; then
    echo "  warn: no Synaptics (06cb) USB device found right now — continuing anyway."
fi

echo "→ ensuring fprintd and fprintd-pam are installed"
if command -v zypper >/dev/null 2>&1; then
    rpm -q fprintd fprintd-pam >/dev/null 2>&1 || zypper --non-interactive install fprintd fprintd-pam
else
    echo "  (not zypper-based: make sure your distro's fprintd + its PAM module are installed)"
fi

echo "→ installing daemon to $BIN_DST"
install -D -m 0755 "$BIN_SRC" "$BIN_DST"

echo "→ installing service override to $UNIT_DST"
install -m 0644 "$HERE/fprintd.service" "$UNIT_DST"
systemctl daemon-reload
systemctl restart fprintd.service

# Warn about the older pam_exec wiring from packaging/install.sh — with
# pam_fprintd in use you'd otherwise be asked for your finger twice.
for f in /etc/pam.d/*; do
    if grep -qF '# synaptics-metallica-mis' "$f" 2>/dev/null; then
        echo "  note: $f still has the old pam_exec fingerprint line."
        echo "        Restore its backup to avoid double prompts:  sudo mv $f.bak-smm $f"
    fi
done

sleep 1
if systemctl is-active --quiet fprintd.service; then
    echo
    echo "✓ metallica-fprintd is running as fprintd."
else
    echo
    echo "✗ service failed to start — see: journalctl -u fprintd -b"
    exit 1
fi

cat <<'MSG'

Next steps (as your normal user):
  fprintd-enroll -f right-index-finger      # or use System Settings → Users
  fprintd-verify
Watch the daemon:   journalctl -u fprintd -f
PAM (sudo/login):   see packaging/fprintd/README.md
Undo everything:    sudo ./packaging/fprintd/install-tumbleweed.sh --uninstall
MSG
