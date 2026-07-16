// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Decoding logic mirrors `python-validity/validitysensor/tls.py`'s
// `handle_priv` / `handle_ecdh` (MIT, © 2020 uunicorn). No source code
// is copied; the byte layouts come from the upstream comments and we
// re-implement them in Rust. See `THIRD_PARTY.md`.

//! Decode the per-host TLS pairing record stored in the device's
//! flash partition 1.
//!
//! Three blocks matter:
//!
//! | id   | what                        | how to decode                         |
//! |------|-----------------------------|---------------------------------------|
//! | 0x03 | TLS client cert (raw blob)  | opaque, used as-is in handshake       |
//! | 0x04 | TLS client private key      | AES-256-CBC + HMAC-SHA256, GWK keys   |
//! | 0x06 | Device's ECDH public key Q  | raw P-256 (x, y) at fixed offsets     |
//!
//! All three blocks must be present for TLS to come up. The `id=0x04`
//! HMAC is keyed by `psk_validation_key` — if it fails to verify, the
//! device was paired with a *different host*, and the only path
//! forward is to re-pair.

use crate::crypto::{self, GwkKeys};
use crate::error::{Error, Result};

/// Raw P-256 secret key extracted from the encrypted flash block.
/// Both public coordinates and the private scalar are stored as
/// 32-byte **big-endian** values, ready to feed to a P-256 library.
#[derive(Debug, Clone)]
pub struct PrivKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub d: [u8; 32],
}

/// Decrypt the `id=0x04` priv-key block with the supplied GWK keys.
///
/// Body layout (as on the wire):
///
/// ```text
/// 0x02                          one-byte prefix
/// IV[16]                        AES-CBC IV
/// CIPHERTEXT[N]                 AES-256-CBC of (x || y || d || pkcs7-pad)
/// HMAC[32]                      HMAC-SHA256(psk_validation_key, IV || CIPHERTEXT)
/// ```
pub fn decrypt_priv(body: &[u8], keys: &GwkKeys) -> Result<PrivKey> {
    if body.is_empty() {
        return Err(Error::ShortResponse);
    }
    let prefix = body[0];
    if prefix != 0x02 {
        return Err(Error::PairingMalformed {
            reason: "priv key prefix is not 0x02",
        });
    }
    let inner = &body[1..];
    if inner.len() < 16 + 32 {
        return Err(Error::ShortResponse);
    }
    let (signed_part, hmac) = inner.split_at(inner.len() - 32);

    // HMAC check — keyed by psk_validation_key.
    let expected = crypto::hmac_sha256(&keys.psk_validation_key, signed_part);
    if !crypto::ct_eq(&expected, hmac) {
        return Err(Error::PairingHmac);
    }

    // Decrypt AES-256-CBC with psk_encryption_key.
    let iv: [u8; 16] = signed_part[..16].try_into().unwrap();
    let ct = &signed_part[16..];
    let pt = crypto::aes256_cbc_decrypt(&keys.psk_encryption_key, &iv, ct).ok_or(
        Error::PairingMalformed {
            reason: "AES-CBC decryption / padding failed",
        },
    )?;
    if pt.len() < 96 {
        return Err(Error::PairingMalformed {
            reason: "decrypted priv-key plaintext too short",
        });
    }

    // Plaintext layout: x[32] || y[32] || d[32], each little-endian on
    // the wire. We reverse to big-endian for downstream P-256 use.
    let mut x: [u8; 32] = pt[0..32].try_into().unwrap();
    let mut y: [u8; 32] = pt[32..64].try_into().unwrap();
    let mut d: [u8; 32] = pt[64..96].try_into().unwrap();
    x.reverse();
    y.reverse();
    d.reverse();
    Ok(PrivKey { x, y, d })
}

/// Server's P-256 public point Q, as big-endian (x, y).
#[derive(Debug, Clone, Copy)]
pub struct EcdhQ {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// Parse the `id=0x06` ECDH q block. Body layout:
///
/// * `key` = `body[..0x90]`
///   * `x = key[0x08..0x28]` (little-endian on wire)
///   * `y = key[0x4c..0x6c]` (little-endian on wire)
/// * `signature = body[0x90..]` — currently unused (no upstream check).
pub fn parse_ecdh(body: &[u8]) -> Result<EcdhQ> {
    if body.len() < 0x90 {
        return Err(Error::ShortResponse);
    }
    let mut x: [u8; 32] = body[0x08..0x28].try_into().unwrap();
    let mut y: [u8; 32] = body[0x4c..0x6c].try_into().unwrap();
    x.reverse();
    y.reverse();
    Ok(EcdhQ { x, y })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, GwkKeys};

    /// Build a simulated `id=0x04` priv-key block from known x/y/d and
    /// GWK keys. Returns the body bytes that `decrypt_priv` would
    /// receive on the wire.
    fn synth_priv_block(
        keys: &GwkKeys,
        x_be: &[u8; 32],
        y_be: &[u8; 32],
        d_be: &[u8; 32],
        iv: &[u8; 16],
    ) -> Vec<u8> {
        // On-wire plaintext layout: x_le || y_le || d_le.
        let mut pt = Vec::with_capacity(96);
        for src in [x_be, y_be, d_be] {
            let mut le = *src;
            le.reverse();
            pt.extend_from_slice(&le);
        }
        // AES-256-CBC encrypt with PKCS7 (priv-key block uses standard,
        // not the validity-pad variant).
        let ct = crypto::aes256_cbc_encrypt(&keys.psk_encryption_key, iv, &pt);
        let mut signed = Vec::with_capacity(16 + ct.len());
        signed.extend_from_slice(iv);
        signed.extend_from_slice(&ct);
        let tag = crypto::hmac_sha256(&keys.psk_validation_key, &signed);
        let mut body = Vec::with_capacity(1 + signed.len() + 32);
        body.push(0x02); // prefix
        body.extend_from_slice(&signed);
        body.extend_from_slice(&tag);
        body
    }

    fn fixture_keys() -> GwkKeys {
        // Use the documented "VirtualBox"/"0" fallback so the keys are
        // reproducible and don't rely on a host's DMI strings.
        GwkKeys::derive("VirtualBox", "0")
    }

    /// Round-trip: synthesize a priv-key blob with known coordinates,
    /// decrypt it, and confirm we recover the same big-endian values.
    #[test]
    fn decrypt_priv_roundtrip() {
        let keys = fixture_keys();
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let d = {
            let mut d = [0u8; 32];
            for (i, b) in d.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7) | 0x40;
            }
            d
        };
        let iv = [0xABu8; 16];
        let body = synth_priv_block(&keys, &x, &y, &d, &iv);

        let pk = decrypt_priv(&body, &keys).unwrap();
        assert_eq!(pk.x, x);
        assert_eq!(pk.y, y);
        assert_eq!(pk.d, d);
    }

    /// HMAC mismatch must surface as `Error::PairingHmac` (used by the
    /// user-visible "device paired with another host" error path).
    #[test]
    fn decrypt_priv_rejects_tampered_hmac() {
        let keys = fixture_keys();
        let mut body = synth_priv_block(&keys, &[1; 32], &[2; 32], &[3; 32], &[0xCD; 16]);
        let last = body.len() - 1;
        body[last] ^= 0x01;
        assert!(matches!(
            decrypt_priv(&body, &keys),
            Err(Error::PairingHmac)
        ));
    }

    /// Mid-ciphertext flip must also fail HMAC (signed_part covers the
    /// whole IV+ciphertext span).
    #[test]
    fn decrypt_priv_rejects_tampered_ciphertext() {
        let keys = fixture_keys();
        let mut body = synth_priv_block(&keys, &[1; 32], &[2; 32], &[3; 32], &[0xCD; 16]);
        // Flip a bit in the middle of the ciphertext (after the prefix
        // and IV, before the trailing HMAC tag).
        body[40] ^= 0x80;
        assert!(matches!(
            decrypt_priv(&body, &keys),
            Err(Error::PairingHmac)
        ));
    }

    /// Wrong prefix byte signals a different format — we don't try to
    /// guess what it means and bail out cleanly.
    #[test]
    fn decrypt_priv_rejects_unknown_prefix() {
        let keys = fixture_keys();
        let mut body = synth_priv_block(&keys, &[1; 32], &[2; 32], &[3; 32], &[0xEE; 16]);
        body[0] = 0x03;
        assert!(matches!(
            decrypt_priv(&body, &keys),
            Err(Error::PairingMalformed { .. })
        ));
    }

    /// Empty input → `ShortResponse`, not a panic.
    #[test]
    fn decrypt_priv_short_input_errors() {
        let keys = fixture_keys();
        assert!(matches!(
            decrypt_priv(&[], &keys),
            Err(Error::ShortResponse)
        ));
        // 0x02 prefix + truncated content too short to even hold the IV+HMAC.
        assert!(matches!(
            decrypt_priv(&[0x02, 0, 0], &keys),
            Err(Error::ShortResponse)
        ));
    }

    /// `parse_ecdh` must read the LE coords at offsets 0x08 and 0x4c
    /// and emit them as big-endian 32-byte arrays.
    #[test]
    fn parse_ecdh_reads_coords_at_documented_offsets() {
        let mut body = vec![0u8; 0x90];
        // Fill x at [0x08..0x28] with bytes 0..32 in little-endian on wire.
        for (i, b) in (0..32).zip(body.iter_mut().skip(0x08)) {
            *b = i as u8;
        }
        // Fill y at [0x4c..0x6c] with bytes 0x80..0xa0 in little-endian.
        for (i, b) in (0..32).zip(body.iter_mut().skip(0x4c)) {
            *b = 0x80u8 + i as u8;
        }
        let q = parse_ecdh(&body).unwrap();
        // After byte-reversal, x[0] should be the LAST byte we wrote (31)
        // and x[31] should be the FIRST (0).
        assert_eq!(q.x[0], 31);
        assert_eq!(q.x[31], 0);
        assert_eq!(q.y[0], 0x80 + 31);
        assert_eq!(q.y[31], 0x80);
    }

    /// User's ThinkPad P70 device, captured 2026-05-05. The (qx, qy)
    /// here is publicly readable from the device's flash partition 1
    /// — no secret is exposed by baking it into a regression vector.
    #[test]
    fn parse_ecdh_p70_real_block_shape() {
        // We don't have the full 400-byte block bytes, but we know its
        // post-parse public coords. Build a minimal synthetic block
        // that places those big-endian values correctly and confirm
        // parse_ecdh returns them.
        let qx_expected: [u8; 32] = [
            0xea, 0xf7, 0x30, 0xb6, 0xd4, 0x9d, 0xf0, 0x6e, 0x96, 0x23, 0x2d, 0xf2, 0x02, 0x68,
            0x24, 0x5d, 0x6c, 0x27, 0xb6, 0xfb, 0x5a, 0x9a, 0xfb, 0x9b, 0xf9, 0x4a, 0x42, 0x4c,
            0xaf, 0x54, 0xfd, 0x04,
        ];
        let qy_expected: [u8; 32] = [
            0x50, 0x7c, 0xd5, 0x28, 0xe6, 0xc8, 0x54, 0x5a, 0xd1, 0x9d, 0xb8, 0xe6, 0xa1, 0xee,
            0xf0, 0x1c, 0xda, 0x71, 0x96, 0x01, 0x21, 0x5a, 0x98, 0x82, 0xd1, 0xeb, 0x04, 0x7f,
            0x02, 0x9a, 0xfb, 0x24,
        ];
        let mut body = vec![0u8; 0x90];
        // On-wire is little-endian — reverse our big-endian expectation.
        let mut x_le = qx_expected;
        x_le.reverse();
        let mut y_le = qy_expected;
        y_le.reverse();
        body[0x08..0x28].copy_from_slice(&x_le);
        body[0x4c..0x6c].copy_from_slice(&y_le);

        let q = parse_ecdh(&body).unwrap();
        assert_eq!(q.x, qx_expected);
        assert_eq!(q.y, qy_expected);
    }

    #[test]
    fn parse_ecdh_short_input_errors() {
        assert!(matches!(
            parse_ecdh(&[0u8; 0x10]),
            Err(Error::ShortResponse)
        ));
    }
}
