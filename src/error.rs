// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no supported fingerprint sensor found on the USB bus")]
    NoSensor,

    #[error("USB error: {0}")]
    Usb(#[from] nusb::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("device returned a response shorter than 2 bytes (no status word)")]
    ShortResponse,

    #[error("read_flash failed with device status {status:#06x}")]
    FlashRead { status: u16 },

    #[error(
        "pairing record HMAC mismatch — this device was paired with a different host. \
         Re-pair by running the (not-yet-implemented) `pair` subcommand."
    )]
    PairingHmac,

    #[error("pairing record is malformed: {reason}")]
    PairingMalformed { reason: &'static str },

    #[error("flash block sha256 mismatch in id=0x{id:04x}")]
    FlashBlockHash { id: u16 },

    #[error("TLS handshake: unexpected protocol state ({hint})")]
    HandshakeUnexpected { hint: &'static str },

    #[error("TLS handshake: record could not be decrypted")]
    HandshakeBadRecord,

    #[error("TLS handshake: HMAC tag did not validate (record was tampered or keys differ)")]
    HandshakeMacMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;
