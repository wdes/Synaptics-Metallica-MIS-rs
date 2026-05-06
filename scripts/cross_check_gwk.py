#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Stand-alone reproduction of the pre-TLS GWK key derivation that
# `python-validity` performs, with no dependency on python-validity
# itself. Used to cross-check `think-touch`'s `crypto::GwkKeys::derive`
# implementation. Algorithm and constants are reproduced from
# `python-validity/tls.py` (MIT, (c) 2020 uunicorn) — see THIRD_PARTY.md.

import hmac, hashlib

PASSWORD = bytes.fromhex(
    '717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033'
)
GWK_SIGN = bytes.fromhex(
    '3a4c76b76a97981d1274247e166610e77f4d9c9d07d3c728e532916bdd28b454'
)


def prf(secret: bytes, seed: bytes, length: int) -> bytes:
    out = b''
    a = hmac.new(secret, seed, hashlib.sha256).digest()
    while len(out) < length:
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return out[:length]


def read_dmi(path: str, fallback: str) -> str:
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except OSError:
        return fallback


product_name = read_dmi('/sys/class/dmi/id/product_name', 'VirtualBox')
product_serial = read_dmi('/sys/class/dmi/id/product_serial', '0')

hw_key = product_name.encode('ascii') + b'\0' + product_serial.encode('ascii') + b'\0'
enc = prf(PASSWORD, b'GWK' + hw_key, 0x20)
val = prf(enc, b'GWK_SIGN' + GWK_SIGN, 0x20)

print(f'product_name      : {product_name!r}')
print(f'product_serial    : {product_serial!r}')
print(f'psk_encryption_key: {enc.hex()}')
print(f'psk_validation_key: {val.hex()}')
