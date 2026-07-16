// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! USB transport layer.
//!
//! Enumerates and opens supported Synaptics / Validity fingerprint sensors.
//! The supported list mirrors the device family handled by `python-validity`
//! upstream, even though the driver currently only targets `06cb:009a`
//! (Metallica MIS, ThinkPad P70 / T480 / X1 Carbon 6th gen / …).

use std::fmt;

use nusb::{Device, DeviceInfo, MaybeFuture};

use crate::error::{Error, Result};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SupportedDevice {
    pub vid: u16,
    pub pid: u16,
    pub codename: &'static str,
}

impl SupportedDevice {
    const fn new(vid: u16, pid: u16, codename: &'static str) -> Self {
        Self { vid, pid, codename }
    }
}

/// Devices the upstream Python driver knows how to talk to. Only `Metallica MIS`
/// is the primary target of this crate today; the rest are listed so that
/// enumeration code can recognise them and report a clear "not yet supported"
/// status instead of silently ignoring them.
pub const SUPPORTED: &[SupportedDevice] = &[
    SupportedDevice::new(0x06cb, 0x009a, "Metallica MIS"),
    SupportedDevice::new(0x138a, 0x0090, "Prometheus"),
    SupportedDevice::new(0x138a, 0x0097, "Prometheus 97"),
    SupportedDevice::new(0x138a, 0x009d, "Prometheus 9d"),
];

pub fn lookup(vid: u16, pid: u16) -> Option<SupportedDevice> {
    SUPPORTED
        .iter()
        .copied()
        .find(|d| d.vid == vid && d.pid == pid)
}

#[derive(Debug)]
pub struct SensorInfo {
    pub device: SupportedDevice,
    pub bus_number: u8,
    pub device_address: u8,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
}

impl fmt::Display for SensorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04x}:{:04x} ({}) — bus {:03} device {:03}",
            self.device.vid,
            self.device.pid,
            self.device.codename,
            self.bus_number,
            self.device_address,
        )?;
        if let Some(p) = &self.product {
            write!(f, " — {p}")?;
        }
        Ok(())
    }
}

/// Walk the USB bus and return every supported fingerprint sensor.
pub fn enumerate() -> Result<Vec<(SensorInfo, DeviceInfo)>> {
    let mut found = Vec::new();
    for info in nusb::list_devices().wait()? {
        let Some(dev) = lookup(info.vendor_id(), info.product_id()) else {
            continue;
        };
        let summary = SensorInfo {
            device: dev,
            bus_number: info.busnum(),
            device_address: info.device_address(),
            manufacturer: info.manufacturer_string().map(str::to_owned),
            product: info.product_string().map(str::to_owned),
            serial: info.serial_number().map(str::to_owned),
        };
        found.push((summary, info));
    }
    Ok(found)
}

/// An opened sensor handle. Currently just owns the `nusb::Device`; the
/// protocol/TLS layers will be built on top of this in subsequent commits.
pub struct Sensor {
    pub info: SensorInfo,
    device: Device,
}

impl Sensor {
    /// Open the first supported sensor on the bus.
    pub fn open_first() -> Result<Self> {
        let mut all = enumerate()?;
        let (info, dev_info) = all.pop().ok_or(Error::NoSensor)?;
        let device = dev_info.open().wait()?;
        Ok(Self { info, device })
    }

    /// Borrow the underlying nusb device for advanced use.
    pub fn nusb(&self) -> &Device {
        &self.device
    }
}
