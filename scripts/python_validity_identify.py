#!/usr/bin/env python3
"""Drive python-validity through one read-only identify cycle so we can
compare its on-wire behaviour against `think-touch try-identify`.

Read-only: uses python-validity's standard `init.open()` which:
  - returns immediately from `init_flash()` because the device is paired
  - returns immediately from `upload_fwext()` because v1.2 is already loaded
  - performs the TLS handshake using the existing pairing record
Then it calls `sensor.identify()` once.

Does NOT pair, enrol, or write flash. If anything in here logs a line
mentioning 'Formatting' or 'Uploading', abort with Ctrl-C immediately
— that would mean python-validity thinks the flash is empty.
"""
import logging
import sys
import traceback


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    try:
        from validitysensor import init
        from validitysensor.sensor import sensor
    except Exception as e:
        print(f"import failed: {e}", file=sys.stderr)
        return 2

    print("running init.open() (idempotent)...")
    init.open()
    print("python-validity init complete.")

    # Dump every cmd-02 (IDENTIFY/CALIBRATE/etc) sent over TLS.
    from validitysensor.tls import tls
    _orig_cmd = tls.cmd
    def _cmd_with_dump(payload):
        body = payload() if callable(payload) else payload
        if body and body[0] == 0x02:
            print(f"  [tls.cmd] cmd-02 ({len(body)} bytes): {body.hex()}")
        return _orig_cmd(payload)
    tls.cmd = _cmd_with_dump
    # Also intercept tls.app, which `Sensor.capture()` actually uses.
    _orig_app = tls.app
    def _app_with_dump(payload):
        body = payload() if callable(payload) else payload
        if body and body[0] == 0x02:
            print(f"  [tls.app] cmd-02 ({len(body)} bytes): {body.hex()}")
        return _orig_app(payload)
    tls.app = _app_with_dump

    def progress(*args, **kwargs):
        print(f"  [identify cb] args={args} kwargs={kwargs}")

    print("calling sensor.identify(update_cb)...")
    try:
        result = sensor.identify(progress)
        print("identify() returned:", repr(result))
    except Exception:
        print("identify() raised:")
        traceback.print_exc()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
