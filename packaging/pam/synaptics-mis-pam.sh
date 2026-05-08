#!/bin/sh
# synaptics-mis-pam.sh — wrapper invoked by `pam_exec` to authenticate
# the calling user against an enrolled fingerprint.
#
# pam_exec contract:
#   exit 0    → auth success (PAM_SUCCESS), no password needed
#   exit ≠ 0  → auth fail (PAM_AUTH_ERR), PAM falls through to next module
#
# This wrapper exists so we can bake in sane defaults (timeout, retries)
# without polluting /etc/pam.d/* with command-line flags.
set -u

BIN="${SMM_BIN:-/usr/local/bin/synaptics-metallica-mis}"
RETRIES="${SMM_RETRIES:-3}"
TIMEOUT="${SMM_TIMEOUT:-15}"
LOG_TAG="synaptics-mis-pam"

if [ ! -x "$BIN" ]; then
    logger -t "$LOG_TAG" "binary not found at $BIN — denying"
    exit 1
fi

# pam_exec puts the username PAM is authenticating in $PAM_USER. We
# don't currently filter by user (the matcher knows from the enrolled
# DB which user dbid is hit), but log it for audit purposes.
logger -t "$LOG_TAG" "auth attempt for user=${PAM_USER:-?} service=${PAM_SERVICE:-?}"

# Run the matcher with a hard wall-clock timeout so a stuck press
# doesn't hang the login flow forever. `match-finger` writes the
# MATCH line to stdout; we capture it for the syslog.
RESULT=$(timeout "$TIMEOUT" "$BIN" match-finger --retries "$RETRIES" 2>&1)
RC=$?

if [ $RC -eq 0 ]; then
    logger -t "$LOG_TAG" "auth OK: $RESULT"
    exit 0
else
    logger -t "$LOG_TAG" "auth fail (rc=$RC): $RESULT"
    exit 1
fi
