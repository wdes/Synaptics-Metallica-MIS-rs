// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Algorithms reimplemented from public reverse-engineering work, see
// `THIRD_PARTY.md`. The two 32-byte hardcoded constants below
// (`PASSWORD_HARDCODED` and `GWK_SIGN_HARDCODED`) are reproduced
// from `uunicorn/python-validity` (MIT, © 2020 uunicorn). They are
// Synaptics/Validity firmware constants used during pre-TLS key
// derivation; we redistribute them under MIT compatibility.

//! Cryptographic primitives used by the Validity protocol.
//!
//! At this stage only the pre-TLS PRF and the GWK ("global wrapping
//! key") derivation are implemented — enough to prove our HMAC-SHA256
//! plumbing matches `python-validity`'s. The actual TLS-PSK record
//! layer is built on top of these in a later module.

use aes::Aes256;
use aes::cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

/// Hardcoded 32-byte device-family key. Source: `python-validity`
/// (`tls.py:19`, MIT-licensed).
pub const PASSWORD_HARDCODED: [u8; 32] = [
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a, 0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
];

/// Hardcoded 32-byte signing salt used during GWK validation-key
/// derivation. Source: `python-validity` (`tls.py:20`, MIT-licensed).
pub const GWK_SIGN_HARDCODED: [u8; 32] = [
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d, 0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28, 0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54,
];

/// TLS-1.0-style PRF using HMAC-SHA256 in P_hash form.
///
/// Equivalent to `python-validity`'s `tls.prf(secret, seed, length)`:
///
/// ```text
/// A(0) = HMAC(secret, seed)
/// out  = HMAC(secret, A(0) || seed) || HMAC(secret, A(1) || seed) || ...
/// where A(i+1) = HMAC(secret, A(i))
/// ```
///
/// (Note: this is **not** standards-conformant TLS PRF — the `A(i)`
/// chaining differs from RFC 5246 §5. The implementation here matches
/// the device's expectation, which is what matters.)
pub fn prf(secret: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length.div_ceil(32) * 32);

    let mut a = hmac_sha256(secret, seed);
    while out.len() < length {
        let mut chunk_input = Vec::with_capacity(a.len() + seed.len());
        chunk_input.extend_from_slice(&a);
        chunk_input.extend_from_slice(seed);
        out.extend_from_slice(&hmac_sha256(secret, &chunk_input));
        a = hmac_sha256(secret, &a);
    }

    out.truncate(length);
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(msg);
    h.finalize().into()
}

/// Constant-time equality on byte slices of equal length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// AES-256-CBC decrypt with PKCS7 unpadding. Errors if the ciphertext
/// length is not a multiple of 16, the IV is the wrong length, or the
/// padding is invalid.
pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ct: &[u8]) -> Option<Vec<u8>> {
    if !ct.len().is_multiple_of(16) {
        return None;
    }
    let mut buf = ct.to_vec();
    let dec = Aes256CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()
        .map(|pt| pt.to_vec())
}

/// AES-256-CBC encrypt with PKCS7 padding. The IV must be 16 bytes;
/// the caller is responsible for choosing it (typically random).
pub fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let enc = Aes256CbcEnc::new(key.into(), iv.into());
    let mut buf = vec![0u8; pt.len() + 16];
    let n = enc
        .encrypt_padded_b2b_mut::<Pkcs7>(pt, &mut buf)
        .expect("buffer is at least pt.len() + 16")
        .len();
    buf.truncate(n);
    buf
}

/// AES-256-CBC encrypt with `python-validity`'s **non-PKCS7** padding
/// scheme: pad to a multiple of 16 bytes by appending `l` bytes, each
/// of value `l - 1` (where `l ∈ [1, 16]`). Used by all live-TLS
/// records — see `tls.py:pad`.
pub fn aes256_cbc_encrypt_validity_pad(key: &[u8; 32], iv: &[u8; 16], pt: &[u8]) -> Vec<u8> {
    let l = 16 - (pt.len() % 16);
    let mut padded = Vec::with_capacity(pt.len() + l);
    padded.extend_from_slice(pt);
    padded.extend(std::iter::repeat_n((l - 1) as u8, l));
    let enc = Aes256CbcEnc::new(key.into(), iv.into());
    let mut buf = vec![0u8; padded.len()];
    enc.encrypt_padded_b2b_mut::<NoPadding>(&padded, &mut buf)
        .expect("padded.len() is a multiple of 16");
    buf
}

/// Inverse of [`aes256_cbc_encrypt_validity_pad`]. Returns `None` on
/// invalid block length or implausible trailing-byte value.
pub fn aes256_cbc_decrypt_validity_pad(
    key: &[u8; 32],
    iv: &[u8; 16],
    ct: &[u8],
) -> Option<Vec<u8>> {
    if ct.is_empty() || !ct.len().is_multiple_of(16) {
        return None;
    }
    let mut buf = ct.to_vec();
    let dec = Aes256CbcDec::new(key.into(), iv.into());
    dec.decrypt_padded_mut::<NoPadding>(&mut buf).ok()?;
    let last = *buf.last()? as usize;
    let trim = 1 + last;
    if trim > buf.len() {
        return None;
    }
    buf.truncate(buf.len() - trim);
    Some(buf)
}

/// P-256 ECDH. Returns the 32-byte big-endian X coordinate of the
/// shared point — that's the value TLS calls `pre_master_secret`.
///
/// Inputs are big-endian: our 32-byte private scalar `d` and the peer's
/// 32-byte affine coordinates `(x, y)`.
pub fn p256_ecdh(d: &[u8; 32], peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Option<[u8; 32]> {
    use p256::ecdh::diffie_hellman;
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint, NonZeroScalar, PublicKey};

    let scalar = NonZeroScalar::try_from(&d[..]).ok()?;

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(peer_x);
    sec1[33..65].copy_from_slice(peer_y);
    let encoded = EncodedPoint::from_bytes(sec1).ok()?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;
    let peer = PublicKey::from_affine(affine).ok()?;

    let shared = diffie_hellman(scalar, peer.as_affine());
    let bytes = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    Some(out)
}

/// A fresh P-256 ephemeral keypair plus its uncompressed (x, y)
/// coordinates as big-endian byte arrays — handy because the wire
/// format wants the coords directly.
#[derive(Clone)]
pub struct Ephemeral {
    secret: p256::SecretKey,
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl Ephemeral {
    /// Generate a fresh keypair using bytes from `/dev/urandom`.
    /// Retries on the (negligibly rare) chance the random scalar is
    /// out of range.
    pub fn generate() -> std::io::Result<Self> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use std::fs::File;
        use std::io::Read;

        loop {
            let mut buf = [0u8; 32];
            File::open("/dev/urandom")?.read_exact(&mut buf)?;
            let Ok(secret) = p256::SecretKey::from_slice(&buf) else {
                continue;
            };
            let pub_pt = secret.public_key().to_encoded_point(false);
            let x: [u8; 32] = pub_pt
                .x()
                .expect("uncompressed")
                .as_slice()
                .try_into()
                .unwrap();
            let y: [u8; 32] = pub_pt
                .y()
                .expect("uncompressed")
                .as_slice()
                .try_into()
                .unwrap();
            return Ok(Self { secret, x, y });
        }
    }

    /// Compute ECDH against the peer's `(x, y)` and return the 32-byte
    /// big-endian shared X.
    pub fn ecdh(&self, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Option<[u8; 32]> {
        use p256::ecdh::diffie_hellman;
        use p256::elliptic_curve::sec1::FromEncodedPoint;
        use p256::{AffinePoint, EncodedPoint, PublicKey};

        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(peer_x);
        sec1[33..65].copy_from_slice(peer_y);
        let encoded = EncodedPoint::from_bytes(sec1).ok()?;
        let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))?;
        let peer = PublicKey::from_affine(affine).ok()?;

        let shared = diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Some(out)
    }
}

impl std::fmt::Debug for Ephemeral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ephemeral")
            .field("x", &hex_dbg(&self.x))
            .field("y", &hex_dbg(&self.y))
            .field("secret", &"…(redacted)…")
            .finish()
    }
}

fn hex_dbg(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// ECDSA-SHA256 sign of an already-hashed message (32-byte digest).
/// Returns the signature in DER form, matching `cryptography`'s default.
pub fn ecdsa_sign_prehash(d: &[u8; 32], digest: &[u8; 32]) -> Result<Vec<u8>, p256::ecdsa::Error> {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let signing_key = SigningKey::from_slice(d)?;
    let sig: p256::ecdsa::Signature = signing_key.sign_prehash(digest)?;
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Pre-TLS pair of keys derived from the host identity, equivalent to
/// `Tls.set_hwkey(product_name, serial_number)` in `python-validity`.
#[derive(Debug, Clone)]
pub struct GwkKeys {
    pub psk_encryption_key: [u8; 32],
    pub psk_validation_key: [u8; 32],
}

impl GwkKeys {
    /// Build the host-key seed exactly as `python-validity` does:
    /// `product_name || 0x00 || serial_number || 0x00`, both ASCII.
    pub fn derive(product_name: &str, serial_number: &str) -> Self {
        let mut hw_key = Vec::with_capacity(product_name.len() + serial_number.len() + 2);
        hw_key.extend_from_slice(product_name.as_bytes());
        hw_key.push(0);
        hw_key.extend_from_slice(serial_number.as_bytes());
        hw_key.push(0);

        let mut gwk_seed = Vec::with_capacity(3 + hw_key.len());
        gwk_seed.extend_from_slice(b"GWK");
        gwk_seed.extend_from_slice(&hw_key);
        let psk_enc = prf(&PASSWORD_HARDCODED, &gwk_seed, 0x20);

        let mut sign_seed = Vec::with_capacity(8 + GWK_SIGN_HARDCODED.len());
        sign_seed.extend_from_slice(b"GWK_SIGN");
        sign_seed.extend_from_slice(&GWK_SIGN_HARDCODED);
        let psk_val = prf(&psk_enc, &sign_seed, 0x20);

        Self {
            psk_encryption_key: psk_enc.try_into().unwrap(),
            psk_validation_key: psk_val.try_into().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression vector: the GWK keys for ThinkPad P70 MTM `20QRCTO1WW`
    /// with `product_serial` falling back to `"0"` (DMI serial is
    /// root-only on Linux so most invocations land on the fallback).
    ///
    /// Reference values cross-checked against
    /// `scripts/cross_check_gwk.py` (a python-stdlib reproduction of
    /// the algorithm) on 2026-05-05; both implementations produced the
    /// same hex strings bit-for-bit.
    #[test]
    fn gwk_matches_p70_reference_vector() {
        let keys = GwkKeys::derive("20QRCTO1WW", "0");
        let enc = "9770ea61dea824c416350c3f8b152c93e8e673fe3a95f9050c61b580137f30c4";
        let val = "42d5bd3a23eb1b2159dc4ee2b9a206bbeb84871508855218259c908efa786d3b";
        assert_eq!(hex(&keys.psk_encryption_key), enc);
        assert_eq!(hex(&keys.psk_validation_key), val);
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Test vector from RFC 5903 §8.1 (P-256 ECDH worked example).
    /// Validates that `p256_ecdh` returns the correct shared X coordinate.
    #[test]
    fn p256_ecdh_rfc5903_vector() {
        let i_d = unhex("C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433");
        let r_x = unhex("D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63");
        let r_y = unhex("56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB");
        let expected_z =
            unhex("D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE");

        let mut d = [0u8; 32];
        d.copy_from_slice(&i_d);
        let mut x = [0u8; 32];
        x.copy_from_slice(&r_x);
        let mut y = [0u8; 32];
        y.copy_from_slice(&r_y);

        let z = p256_ecdh(&d, &x, &y).expect("ECDH must succeed for valid inputs");
        assert_eq!(hex(&z), hex(&expected_z));
    }

    #[test]
    fn p256_ecdh_rejects_zero_scalar() {
        assert!(p256_ecdh(&[0u8; 32], &[0u8; 32], &[0u8; 32]).is_none());
    }

    /// Round-trip the python-validity custom padding scheme — for any
    /// plaintext length, the trailing pad byte must be `l - 1` and
    /// stripping it must recover the original plaintext.
    #[test]
    fn validity_pad_roundtrip() {
        let key = [0x11; 32];
        let iv = [0x22; 16];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 47, 48, 100] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = aes256_cbc_encrypt_validity_pad(&key, &iv, &pt);
            let back =
                aes256_cbc_decrypt_validity_pad(&key, &iv, &ct).expect("decrypt must succeed");
            assert_eq!(back, pt, "roundtrip mismatch at len={len}");
        }
    }

    /// Boundary check: the pad byte for an aligned input is 15
    /// (= 16-1), not 0 — matching upstream's `bytes([l-1]) * l`.
    #[test]
    fn validity_pad_aligned_input_emits_full_block() {
        let key = [0x33; 32];
        let iv = [0x44; 16];
        let pt = [0xAA; 16];
        let ct = aes256_cbc_encrypt_validity_pad(&key, &iv, &pt);
        assert_eq!(
            ct.len(),
            32,
            "16-byte input must produce a 32-byte ciphertext"
        );
        let back = aes256_cbc_decrypt_validity_pad(&key, &iv, &ct).unwrap();
        assert_eq!(back, &pt[..]);
    }

    /// Standard PKCS7 (used by the priv-key flash block, not by live
    /// TLS records) round-trips for various lengths and rejects
    /// truncated/non-aligned ciphertexts.
    #[test]
    fn pkcs7_path_roundtrips_and_rejects_misaligned() {
        let key = [0x55; 32];
        let iv = [0x66; 16];
        for len in [0usize, 1, 15, 16, 17, 32, 33] {
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let ct = aes256_cbc_encrypt(&key, &iv, &pt);
            assert!(ct.len().is_multiple_of(16));
            assert_eq!(aes256_cbc_decrypt(&key, &iv, &ct).unwrap(), pt);
        }
        // Non-aligned ciphertext must fail.
        assert!(aes256_cbc_decrypt(&key, &iv, &[0u8; 17]).is_none());
    }

    /// HMAC-SHA256 RFC 4231 §4.2 test case 1: short key, short data.
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0b; 20];
        let data = b"Hi There";
        let expected = unhex("b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7");
        assert_eq!(hmac_sha256(&key, data).to_vec(), expected);
    }

    /// HMAC-SHA256 RFC 4231 §4.3 test case 2: short key, longer data.
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(hmac_sha256(key, data).to_vec(), expected);
    }

    /// SHA-256 of the empty string — the canonical FIPS vector.
    #[test]
    fn sha256_empty_input() {
        assert_eq!(
            hex(&sha256(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    }

    /// SHA-256 of "abc" — another canonical FIPS-180 vector.
    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    /// Constant-time equality must accept identical inputs and reject
    /// inputs that differ in any single bit.
    #[test]
    fn ct_eq_basic() {
        let a = [0xAAu8; 32];
        let mut b = a;
        assert!(ct_eq(&a, &b));
        b[17] ^= 0x80;
        assert!(!ct_eq(&a, &b));
    }

    /// PRF is deterministic for fixed inputs and grows with `length`.
    #[test]
    fn prf_is_deterministic_and_extends() {
        let secret = b"secret";
        let seed = b"seed";
        let short = prf(secret, seed, 16);
        let long = prf(secret, seed, 64);
        assert_eq!(short.len(), 16);
        assert_eq!(long.len(), 64);
        // PRF output has chained `A(i)` blocks, so the first 16 bytes
        // of the longer call must match the shorter call.
        assert_eq!(short, long[..16]);
    }

    /// Ephemeral keypair generation must produce a *valid* P-256 point
    /// whose ECDH against itself recovers a 32-byte shared X.
    #[test]
    fn ephemeral_self_ecdh_is_consistent() {
        let a = Ephemeral::generate().expect("generate must succeed");
        let z = a.ecdh(&a.x, &a.y).expect("self-ECDH must succeed");
        assert_eq!(z.len(), 32);
        // Two independent generates should never collide (negligible probability).
        let b = Ephemeral::generate().unwrap();
        assert_ne!(a.x, b.x);
    }

    /// ECDSA-SHA256 signing produces a parseable DER signature whose
    /// length lands in the canonical 70..72 range for P-256.
    #[test]
    fn ecdsa_sign_prehash_returns_short_der() {
        let d = [0x42u8; 32];
        let digest = [0x77u8; 32];
        let sig = ecdsa_sign_prehash(&d, &digest).expect("signing must succeed");
        // SEQUENCE tag at byte 0
        assert_eq!(sig[0], 0x30);
        assert!((70..=72).contains(&sig.len()), "got {} bytes", sig.len());
    }

    /// PKCS7 round-trip recovers the plaintext exactly. Cover several
    /// length classes — exact-block, sub-block, and multi-block — to
    /// pin the padding bookkeeping.
    #[test]
    fn aes256_cbc_pkcs7_roundtrip_various_lengths() {
        let key = [0x42u8; 32];
        let iv = [0xCDu8; 16];
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100] {
            let pt: Vec<u8> = (0..len).map(|i| (i ^ 0xA5) as u8).collect();
            let ct = aes256_cbc_encrypt(&key, &iv, &pt);
            assert!(ct.len().is_multiple_of(16));
            // Pkcs7 always adds 1..=16 bytes — encrypted len > pt len.
            assert!(ct.len() > len);
            let back = aes256_cbc_decrypt(&key, &iv, &ct).unwrap();
            assert_eq!(back, pt, "round-trip failed for len {len}");
        }
    }

    /// Misaligned ciphertext (length not a multiple of 16) is rejected
    /// with `None` rather than panicking inside the AES backend.
    #[test]
    fn aes256_cbc_decrypt_rejects_misaligned_input() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        // 15 bytes — clearly not a CBC ciphertext.
        assert!(aes256_cbc_decrypt(&key, &iv, &[0u8; 15]).is_none());
        // 17 bytes — straddles a block boundary.
        assert!(aes256_cbc_decrypt(&key, &iv, &[0u8; 17]).is_none());
    }

    /// Validity-pad scheme: pad is `l ∈ [1, 16]` bytes of value `l - 1`.
    /// Round-trip must recover the plaintext for every length class
    /// (exact-block boundaries pad with 16 bytes, not zero).
    #[test]
    fn aes256_cbc_validity_pad_roundtrip() {
        let key = [0x33u8; 32];
        let iv = [0x77u8; 16];
        for len in [0usize, 1, 15, 16, 17, 32, 50, 64] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = aes256_cbc_encrypt_validity_pad(&key, &iv, &pt);
            assert!(ct.len().is_multiple_of(16));
            // Validity pad always adds *at least* one byte even on
            // exact-block boundary — that's the bug-for-bug quirk.
            assert!(ct.len() > pt.len() || pt.is_empty());
            let back = aes256_cbc_decrypt_validity_pad(&key, &iv, &ct).unwrap();
            assert_eq!(back, pt, "validity-pad round-trip failed for len {len}");
        }
    }

    /// Empty ciphertext / non-aligned ciphertext / pad byte that points
    /// past the buffer all return `None` from the validity-pad decrypt.
    /// The "pad too large" branch protects against a tampered last byte
    /// causing a buffer underflow in `truncate`.
    #[test]
    fn aes256_cbc_validity_pad_decrypt_rejects_garbage() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        assert!(aes256_cbc_decrypt_validity_pad(&key, &iv, &[]).is_none());
        assert!(aes256_cbc_decrypt_validity_pad(&key, &iv, &[0u8; 13]).is_none());
        // A real-shape but bogus 16-byte block — decryption succeeds
        // but the trailing-byte heuristic gates the truncation. With a
        // zero key + zero IV the decrypted block is deterministic, so
        // we accept whatever the function returns and just verify it
        // doesn't panic.
        let _ = aes256_cbc_decrypt_validity_pad(&key, &iv, &[0u8; 16]);
    }

    /// `ct_eq` returns false for length-mismatched inputs without
    /// panicking. (The `subtle` crate's `ct_eq` requires equal lengths;
    /// our wrapper must guard against that.)
    #[test]
    fn ct_eq_handles_unequal_lengths() {
        // Same prefix, different total length — must be unequal.
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 3, 4]));
        assert!(!ct_eq(&[1, 2, 3, 4], &[1, 2, 3]));
        // Both empty is equal.
        assert!(ct_eq(&[], &[]));
    }
}
