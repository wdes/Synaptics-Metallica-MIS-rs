// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Read host DMI identity exactly the way `python-validity` does so the
//! GWK key derivation matches.
//!
//! `python-validity` reads `/sys/class/dmi/id/product_name` and
//! `/sys/class/dmi/id/product_serial`, and falls back to the literal
//! strings `"VirtualBox"` and `"0"` if either file is unreadable. We
//! mirror that behaviour bit-for-bit because the strings feed straight
//! into a pre-TLS key derivation — any divergence yields a different
//! PSK and the device will reject our handshake.

use std::fs;

#[derive(Debug, Clone)]
pub struct HostId {
    pub product_name: String,
    pub product_serial: String,
}

impl HostId {
    pub fn read() -> Self {
        let product_name = read_dmi("/sys/class/dmi/id/product_name").unwrap_or_else(|| "VirtualBox".into());
        let product_serial = read_dmi("/sys/class/dmi/id/product_serial").unwrap_or_else(|| "0".into());
        Self { product_name, product_serial }
    }
}

fn read_dmi(path: &str) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    Some(raw.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_dmi_returns_trimmed_contents() {
        let path = std::env::temp_dir().join(format!("think-touch-dmi-{}", std::process::id()));
        let mut f = fs::File::create(&path).unwrap();
        // Real /sys/class/dmi/id files always carry a trailing newline.
        writeln!(f, "20QRCTO1WW").unwrap();
        let v = read_dmi(path.to_str().unwrap()).unwrap();
        assert_eq!(v, "20QRCTO1WW");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn read_dmi_returns_none_on_missing_file() {
        assert!(read_dmi("/this/path/does/not/exist/think-touch-dmi-test").is_none());
    }

    /// Empty file (DMI sometimes has empty product_serial on VMs)
    /// must read as an empty trimmed string, not `None`.
    #[test]
    fn read_dmi_empty_file_is_empty_string() {
        let path =
            std::env::temp_dir().join(format!("think-touch-dmi-empty-{}", std::process::id()));
        fs::write(&path, "").unwrap();
        let v = read_dmi(path.to_str().unwrap()).unwrap();
        assert_eq!(v, "");
        let _ = fs::remove_file(&path);
    }
}
