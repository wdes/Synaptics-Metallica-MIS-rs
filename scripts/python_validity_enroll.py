#!/usr/bin/env python3
"""Drive python-validity through one enroll cycle and dump the cmd-02
bytes it sends in ENROLL mode. We compare these against think-touch's
cmd-02 ENROLL output to confirm wire shape is identical.

Read-only-ish: writes the new enrollment to flash. Only run if you
are willing to add a fingerprint record to the device. Press the
right thumb 8-12 times when prompted; the device decides when it
has enough data.
"""
import logging
import sys
import traceback


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    try:
        from validitysensor import init
        from validitysensor.sensor import sensor
        from validitysensor.sid import SidIdentity
        from validitysensor.tls import tls
    except Exception as e:
        print(f"import failed: {e}", file=sys.stderr)
        return 2

    print("running init.open() (idempotent)...")
    init.open()
    print("python-validity init complete.")

    # Dump every cmd-02 sent over TLS, even those starting with 0x02.
    enroll_dumps = []
    _orig_app = tls.app
    def _app_with_dump(payload):
        body = payload() if callable(payload) else payload
        if body and body[0] == 0x02:
            print(f"  [tls.app] cmd-02 ({len(body)} bytes): {body[:64].hex()}...")
            enroll_dumps.append(bytes(body))
        return _orig_app(payload)
    tls.app = _app_with_dump

    def progress(header, exc):
        if exc is not None:
            print(f"  [enroll cb] error: {exc}")
        else:
            print(f"  [enroll cb] step done, header={header.hex() if header else None}")

    sid = SidIdentity(1, 5, [21, 1, 1, 1, 1000])
    print(f"calling sensor.enroll(sid={sid}, subtype=1)...")
    try:
        result = sensor.enroll(sid, 1, progress)
        print("enroll() returned:", repr(result))
    except Exception:
        print("enroll() raised:")
        traceback.print_exc()

    if enroll_dumps:
        print(f"\nCaptured {len(enroll_dumps)} cmd-02 dumps; saving the first ENROLL one to /tmp/pv_cmd02_enroll.hex")
        for b in enroll_dumps:
            # Heuristic: ENROLL has 0x26 chunk (kind bytes "26 00") which
            # CALIBRATE/IDENTIFY don't have.
            if b'\x26\x00' in b:
                with open('/tmp/pv_cmd02_enroll.hex', 'w') as f:
                    f.write(b.hex())
                print(f"  wrote {len(b)} bytes")
                break
        else:
            print("  no ENROLL-shaped dump found; printing all sizes")
            for i, b in enumerate(enroll_dumps):
                print(f"  [{i}] {len(b)} bytes")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
