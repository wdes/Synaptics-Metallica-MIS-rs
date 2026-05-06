#!/usr/bin/env python3
"""Walk a cmd-02 hex dump and print its chunk structure.

Usage:
    python3 scripts/walk_cmd02.py < scripts/captured/pv_cmd02_identify.hex
"""
import sys
from binascii import unhexlify
from struct import unpack


def main():
    raw = unhexlify(sys.stdin.read().strip())
    print(f"total: {len(raw)} bytes")
    print(f"header byte 0: 0x{raw[0]:02x} (must be 0x02)")
    bpl, req_lines = unpack('<HH', raw[1:5])
    print(f"bytes_per_line: 0x{bpl:04x} ({bpl})")
    print(f"req_lines: {req_lines}")
    p = raw[5:]
    print(f"\nchunks (offset {len(raw) - len(p)}):")
    i = 0
    while p:
        if len(p) < 4:
            print(f"  [{i}] truncated header ({len(p)} bytes)"); break
        kind, size = unpack('<HH', p[:4])
        body = p[4:4 + size]
        print(f"  [{i:2}] type=0x{kind:04x} size={size:4d}  first_bytes={body[:8].hex()}")
        p = p[4 + size:]
        i += 1
    print(f"\ntotal chunks: {i}")


if __name__ == "__main__":
    main()
