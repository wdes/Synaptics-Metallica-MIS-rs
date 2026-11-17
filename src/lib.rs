// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! synaptics-metallica-mis — pure-Rust userspace driver for Synaptics/Validity
//! Metallica-MIS fingerprint sensors (USB id `06cb:009a`).
//!
//! The crate is a work in progress. The current public surface is limited
//! to USB enumeration and identification; protocol, TLS-PSK pairing and
//! image capture will land incrementally.

pub mod blobs;
pub mod cache;
pub mod capture;
pub mod chunks;
pub mod crypto;
pub mod db;
pub mod dmi;
pub mod enroll;
pub mod error;
pub mod handshake;
pub mod ops;
pub mod pairing;
pub mod protocol;
pub mod sensor_types;
pub mod tls;
pub mod usb;

pub use error::{Error, Result};
pub use protocol::{
    CMD_GET_PARTITION, CMD_GET_VERSION, CMD_PROBE_19, CMD_READ_FLASH, Channel,
    FIRMWARE_STALE_SECS, FWEXT_PARTITION, FlashIc, FlashLayout, FlashPartition, FwextState,
    ModuleInfo, PartitionInfo, RomExtra, RomInfo, STATUS_NO_FW, TLS_FLASH_PARTITION,
    TlsFlashBlock, parse_flash_info, parse_tls_flash, query_partition, read_flash, send_init,
    split_status, tls_flash_ids,
};
pub use usb::{Sensor, SensorInfo, SupportedDevice};
