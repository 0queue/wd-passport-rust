use std::convert::TryFrom;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

use crate::passport::status::CipherId;
use crate::passport::status::CipherIdUnknownError;
use crate::passport::status::InvalidStatusSignature;
use crate::passport::status::KeyResetEnabler;
use crate::passport::status::SecurityStatus;
use crate::passport::status::SecurityStatusUnknownError;

mod sg;
pub mod status;

pub struct Passport {
    backing_file: File,
}

#[derive(Debug)]
pub enum StatusError {
    Signature(InvalidStatusSignature),
    Security(SecurityStatusUnknownError),
    Cipher(CipherIdUnknownError),
    IO(std::io::Error),
}

impl From<std::io::Error> for StatusError {
    fn from(error: std::io::Error) -> Self {
        StatusError::IO(error)
    }
}

impl From<InvalidStatusSignature> for StatusError {
    fn from(error: InvalidStatusSignature) -> Self {
        StatusError::Signature(error)
    }
}

impl From<SecurityStatusUnknownError> for StatusError {
    fn from(error: SecurityStatusUnknownError) -> Self {
        StatusError::Security(error)
    }
}

impl From<CipherIdUnknownError> for StatusError {
    fn from(error: CipherIdUnknownError) -> Self {
        StatusError::Cipher(error)
    }
}

impl std::error::Error for StatusError {
    fn description(&self) -> &str {
        match self {
            StatusError::Signature(e) => e.description(),
            StatusError::Security(e) => e.description(),
            StatusError::Cipher(e) => e.description(),
            StatusError::IO(e) => e.description(),
        }
    }
}

impl Display for StatusError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            StatusError::Signature(e) => e.fmt(f),
            StatusError::Security(e) => e.fmt(f),
            StatusError::Cipher(e) => e.fmt(f),
            StatusError::IO(e) => e.fmt(f),
        }
    }
}

/// A struct representing a connected Western Digital Passport
impl Passport {
    pub fn new(device_path: &str) -> std::io::Result<Passport> {
        let backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)?;

        Ok(Passport { backing_file })
    }

    fn fd(&self) -> i32 {
        self.backing_file.as_raw_fd()
    }

    /// Returns how the drive is locked, the kind of cipher in use, and the 4 bytes used
    /// to reset the keys
    ///
    /// The command buffer is structured as follows:
    ///
    /// | Byte Index/Indices | Content |
    /// | ------------------ | ------- |
    /// | 0 | Op Code (0xC0) |
    /// | 1 | Sub Code(0x45) |
    /// | 2-6 | Reserved (0x00) |
    /// | 7-8 | Allocation Length (Big Endian) |
    pub fn status(&self) -> Result<(SecurityStatus, CipherId, KeyResetEnabler), StatusError> {
        let mut buf: [u8; 512] = [0u8; 512];
        let mut cdb: [u8; 10] = [0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00];
        sg::read(self.fd(), &mut cdb, &mut buf).map_err(StatusError::from)?;

        if buf[0] != 0x45 {
            return Err(StatusError::from(InvalidStatusSignature));
        }

        let security = status::SecurityStatus::try_from(buf[3])?;
        let cipher = status::CipherId::try_from(buf[4])?;
        let key_reset_enabler = status::KeyResetEnabler([buf[8], buf[9], buf[10], buf[12]]);

        Ok((security, cipher, key_reset_enabler))
    }
}
