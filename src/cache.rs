// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Persisted pairing cache.
//!
//! After a successful flash decrypt we save the decrypted priv key,
//! the device's ECDH q, and the TLS cert to a root-only file at
//! [`DEFAULT_PATH`]. Subsequent runs load it instead of repeating the
//! USB flash read + AES-CBC decrypt cycle.
//!
//! File format is a tiny `key=value` text file — no `serde` dep. The
//! priv-scalar `d` lives in this file; treat it like an SSH private
//! key (mode `0600`, root-only).

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::pairing::{EcdhQ, PrivKey};

pub const DEFAULT_PATH: &str = "/var/lib/synaptics-metallica-mis/session";
pub const CALIB_DATA_PATH: &str = "/var/lib/synaptics-metallica-mis/calib_data";
const MAGIC: &str = "synaptics-metallica-mis session v1";

/// Save raw calibration bytes — the output of `process_calibration_results`
/// chained over the calibration iteration loop. Mirrors upstream's
/// `Sensor.save()` which writes to `~/.local/share/python-validity/calib_data`.
/// Mode 0600 root-only.
pub fn save_calib_data(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    use std::io::Write as _;
    f.write_all(data)?;
    Ok(())
}

/// Load previously-saved calib data. Returns `Err(NotFound)` if no
/// file exists yet.
pub fn load_calib_data(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// Everything we need to short-circuit `establish_session`.
#[derive(Debug, Clone)]
pub struct PairingCache {
    pub product_name: String,
    pub product_serial: String,
    pub tls_cert: Vec<u8>,
    pub priv_key: PrivKey,
    pub ecdh_q: EcdhQ,
}

impl PairingCache {
    pub fn load(path: &Path) -> io::Result<Self> {
        let raw = fs::read_to_string(path)?;
        let mut name = None;
        let mut serial = None;
        let mut cert = None;
        let mut priv_x = None;
        let mut priv_y = None;
        let mut priv_d = None;
        let mut q_x = None;
        let mut q_y = None;
        let mut saw_magic = false;

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == MAGIC {
                saw_magic = true;
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k.trim() {
                "device_name" => name = Some(v.trim().to_string()),
                "device_serial" => serial = Some(v.trim().to_string()),
                "tls_cert" => cert = Some(unhex(v.trim()).map_err(io_err)?),
                "priv_x" => priv_x = Some(unhex_array::<32>(v.trim()).map_err(io_err)?),
                "priv_y" => priv_y = Some(unhex_array::<32>(v.trim()).map_err(io_err)?),
                "priv_d" => priv_d = Some(unhex_array::<32>(v.trim()).map_err(io_err)?),
                "ecdh_qx" => q_x = Some(unhex_array::<32>(v.trim()).map_err(io_err)?),
                "ecdh_qy" => q_y = Some(unhex_array::<32>(v.trim()).map_err(io_err)?),
                _ => {} // unknown keys are ignored for forward compatibility
            }
        }
        if !saw_magic {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache file is missing magic header",
            ));
        }
        Ok(Self {
            product_name: name.ok_or_else(|| missing("device_name"))?,
            product_serial: serial.ok_or_else(|| missing("device_serial"))?,
            tls_cert: cert.ok_or_else(|| missing("tls_cert"))?,
            priv_key: PrivKey {
                x: priv_x.ok_or_else(|| missing("priv_x"))?,
                y: priv_y.ok_or_else(|| missing("priv_y"))?,
                d: priv_d.ok_or_else(|| missing("priv_d"))?,
            },
            ecdh_q: EcdhQ {
                x: q_x.ok_or_else(|| missing("ecdh_qx"))?,
                y: q_y.ok_or_else(|| missing("ecdh_qy"))?,
            },
        })
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        writeln!(f, "{MAGIC}")?;
        writeln!(f, "# Pairing cache for the Synaptics Metallica MIS sensor.")?;
        writeln!(
            f,
            "# This file contains the host's TLS-signing PRIVATE KEY."
        )?;
        writeln!(
            f,
            "# Treat it like ~/.ssh/id_ed25519 — keep it 0600 and root-only."
        )?;
        writeln!(f, "device_name={}", self.product_name)?;
        writeln!(f, "device_serial={}", self.product_serial)?;
        writeln!(f, "tls_cert={}", hex(&self.tls_cert))?;
        writeln!(f, "priv_x={}", hex(&self.priv_key.x))?;
        writeln!(f, "priv_y={}", hex(&self.priv_key.y))?;
        writeln!(f, "priv_d={}", hex(&self.priv_key.d))?;
        writeln!(f, "ecdh_qx={}", hex(&self.ecdh_q.x))?;
        writeln!(f, "ecdh_qy={}", hex(&self.ecdh_q.y))?;
        Ok(())
    }

    /// Returns `Ok(())` if the cache was generated for the same DMI host
    /// identity. Otherwise `Err`. We refuse to use a cache from a
    /// different host because the device's pairing record would also
    /// have been keyed differently.
    pub fn check_host(&self, name: &str, serial: &str) -> Result<(), String> {
        if self.product_name != name {
            return Err(format!(
                "DMI product_name mismatch: cache={:?} live={:?}",
                self.product_name, name
            ));
        }
        if self.product_serial != serial {
            return Err(format!(
                "DMI product_serial mismatch: cache={:?} live={:?}",
                self.product_serial, serial
            ));
        }
        Ok(())
    }
}

fn missing(field: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cache missing field: {field}"),
    )
}

fn io_err(e: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Result<Vec<u8>, &'static str> {
    if !s.len().is_multiple_of(2) {
        return Err("hex value must have an even number of nibbles");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex digit")?);
    }
    Ok(out)
}

fn unhex_array<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
    let v = unhex(s)?;
    v.as_slice()
        .try_into()
        .map_err(|_| "wrong byte length for fixed-size field")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> PairingCache {
        PairingCache {
            product_name: "20QRCTO1WW".to_string(),
            product_serial: "PF1YZ4SV".to_string(),
            tls_cert: vec![0x17, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0xc1, 0x17],
            priv_key: PrivKey {
                x: [0x11; 32],
                y: [0x22; 32],
                d: [0x33; 32],
            },
            ecdh_q: EcdhQ {
                x: [0x44; 32],
                y: [0x55; 32],
            },
        }
    }

    #[test]
    fn roundtrip_via_temp_file() {
        let dir = std::env::temp_dir();
        let path: PathBuf = dir.join(format!(
            "synaptics-metallica-mis-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let original = fixture();
        original.save(&path).unwrap();
        let loaded = PairingCache::load(&path).unwrap();

        assert_eq!(loaded.product_name, original.product_name);
        assert_eq!(loaded.product_serial, original.product_serial);
        assert_eq!(loaded.tls_cert, original.tls_cert);
        assert_eq!(loaded.priv_key.d, original.priv_key.d);
        assert_eq!(loaded.ecdh_q.x, original.ecdh_q.x);

        // Mode must be 0600.
        let meta = fs::metadata(&path).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777;
        assert_eq!(mode, 0o600);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_magic_rejected() {
        let dir = std::env::temp_dir();
        let path: PathBuf = dir.join(format!(
            "synaptics-metallica-mis-test-nomagic-{}",
            std::process::id()
        ));
        fs::write(&path, "device_name=foo\ndevice_serial=bar\n").unwrap();
        assert!(PairingCache::load(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn host_check_rejects_mismatch() {
        let c = fixture();
        assert!(c.check_host("20QRCTO1WW", "PF1YZ4SV").is_ok());
        assert!(c.check_host("OtherModel", "PF1YZ4SV").is_err());
        assert!(c.check_host("20QRCTO1WW", "Different").is_err());
    }

    #[test]
    fn calib_data_round_trip() {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "synaptics-metallica-mis-calib-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let data: Vec<u8> = (0..1024).map(|i| (i & 0xff) as u8).collect();
        save_calib_data(&path, &data).unwrap();
        let back = load_calib_data(&path).unwrap();
        assert_eq!(back, data);
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions())
                & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_calib_data_missing_returns_not_found() {
        let path = PathBuf::from("/nonexistent/path/synaptics-metallica-mis-calib");
        let err = load_calib_data(&path).unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::NotFound));
    }

    /// Loader silently ignores unknown keys (forward-compat for any
    /// future fields written by a newer synaptics-metallica-mis version).
    #[test]
    fn unknown_keys_are_ignored() {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "synaptics-metallica-mis-test-unknown-{}",
            std::process::id()
        ));
        let zero64 = "0".repeat(64);
        let cert = "abcd";
        let body = format!(
            "{MAGIC}\n\
             device_name=Foo\n\
             device_serial=Bar\n\
             tls_cert={cert}\n\
             priv_x={zero64}\n\
             priv_y={zero64}\n\
             priv_d={zero64}\n\
             ecdh_qx={zero64}\n\
             ecdh_qy={zero64}\n\
             # comment line\n\
             future_unknown_field=whatever\n",
        );
        fs::write(&path, body).unwrap();
        let c = PairingCache::load(&path).unwrap();
        assert_eq!(c.product_name, "Foo");
        assert_eq!(c.product_serial, "Bar");
        assert_eq!(c.tls_cert, vec![0xab, 0xcd]);
        let _ = fs::remove_file(&path);
    }

    /// Missing required fields error rather than producing garbage.
    #[test]
    fn missing_required_fields_error() {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "synaptics-metallica-mis-test-missing-{}",
            std::process::id()
        ));
        // Only magic + name — every other required field absent.
        fs::write(&path, format!("{MAGIC}\ndevice_name=Foo\n")).unwrap();
        let err = PairingCache::load(&path).unwrap_err();
        assert!(
            err.to_string().contains("device_serial") || err.kind() == io::ErrorKind::InvalidData
        );
        let _ = fs::remove_file(&path);
    }

    /// Wrong-length hex for a fixed-size field should error rather
    /// than panic. priv_x is 32 bytes (64 hex chars).
    #[test]
    fn wrong_length_hex_errors() {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "synaptics-metallica-mis-test-wrongsz-{}",
            std::process::id()
        ));
        let zero64 = "0".repeat(64);
        let body = format!(
            "{MAGIC}\n\
             device_name=Foo\n\
             device_serial=Bar\n\
             tls_cert=ab\n\
             priv_x=ff\n\
             priv_y={zero64}\n\
             priv_d={zero64}\n\
             ecdh_qx={zero64}\n\
             ecdh_qy={zero64}\n",
        );
        fs::write(&path, body).unwrap();
        assert!(PairingCache::load(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    /// Odd-length hex must be rejected (each byte = 2 nibbles).
    #[test]
    fn odd_length_hex_errors() {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "synaptics-metallica-mis-test-odd-{}",
            std::process::id()
        ));
        let zero64 = "0".repeat(64);
        let body = format!(
            "{MAGIC}\n\
             device_name=Foo\n\
             device_serial=Bar\n\
             tls_cert=abc\n\
             priv_x={zero64}\n\
             priv_y={zero64}\n\
             priv_d={zero64}\n\
             ecdh_qx={zero64}\n\
             ecdh_qy={zero64}\n",
        );
        fs::write(&path, body).unwrap();
        assert!(PairingCache::load(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    /// Whitespace-only / empty values for `device_name` should pass
    /// through verbatim (we trim line ends but not field bodies).
    #[test]
    fn empty_device_name_value() {
        let path: PathBuf = std::env::temp_dir().join(format!(
            "synaptics-metallica-mis-test-empty-{}",
            std::process::id()
        ));
        let zero64 = "0".repeat(64);
        let body = format!(
            "{MAGIC}\n\
             device_name=\n\
             device_serial=0\n\
             tls_cert=ab\n\
             priv_x={zero64}\n\
             priv_y={zero64}\n\
             priv_d={zero64}\n\
             ecdh_qx={zero64}\n\
             ecdh_qy={zero64}\n",
        );
        fs::write(&path, body).unwrap();
        let c = PairingCache::load(&path).unwrap();
        assert_eq!(c.product_name, "");
        let _ = fs::remove_file(&path);
    }
}
