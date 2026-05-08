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
        let product_serial = read_dmi("/sys/class/dmi/id/product_serial").unwrap_or_else(|| {
            // /sys/class/dmi/id/product_serial is mode 0400 root-only on
            // most distros for security. If we can't read it, the
            // GWK-key derivation falls back to "0", which produces the
            // wrong PSK and the device rejects our handshake. Surface
            // a clear hint instead of silently failing.
            eprintln!(
                "warning: /sys/class/dmi/id/product_serial is unreadable.\n\
                 \n\
                 The GWK key derivation needs the host's DMI serial; without it,\n\
                 the TLS-PSK handshake will fail with `HMAC mismatch` or `bad MAC`.\n\
                 \n\
                 Two ways to fix:\n\
                   1. Re-run with sudo (one-shot).\n\
                   2. Grant the binary CAP_DAC_READ_SEARCH so it can read\n\
                      DMI without root:\n\
                          sudo setcap cap_dac_read_search+ep <path-to-synaptics-metallica-mis>\n\
                      Or run the installer:\n\
                          sudo ./packaging/install.sh\n\
                 \n\
                 Falling back to the python-validity stub serial \"0\" — handshake\n\
                 will almost certainly fail."
            );
            "0".into()
        });
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
        let path = std::env::temp_dir().join(format!("synaptics-metallica-mis-dmi-{}", std::process::id()));
        let mut f = fs::File::create(&path).unwrap();
        // Real /sys/class/dmi/id files always carry a trailing newline.
        writeln!(f, "20QRCTO1WW").unwrap();
        let v = read_dmi(path.to_str().unwrap()).unwrap();
        assert_eq!(v, "20QRCTO1WW");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn read_dmi_returns_none_on_missing_file() {
        assert!(read_dmi("/this/path/does/not/exist/synaptics-metallica-mis-dmi-test").is_none());
    }

    /// Empty file (DMI sometimes has empty product_serial on VMs)
    /// must read as an empty trimmed string, not `None`.
    #[test]
    fn read_dmi_empty_file_is_empty_string() {
        let path =
            std::env::temp_dir().join(format!("synaptics-metallica-mis-dmi-empty-{}", std::process::id()));
        fs::write(&path, "").unwrap();
        let v = read_dmi(path.to_str().unwrap()).unwrap();
        assert_eq!(v, "");
        let _ = fs::remove_file(&path);
    }
}
