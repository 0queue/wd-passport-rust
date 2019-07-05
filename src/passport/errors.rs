use core::fmt;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// Unknown security status
#[derive(Debug, Clone)]
pub struct SecurityStatusUnknownError;

impl std::error::Error for SecurityStatusUnknownError {
    fn description(&self) -> &str {
        "Unknown security status"
    }
}

impl std::fmt::Display for SecurityStatusUnknownError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.description())
    }
}

/// Unknown cipher
#[derive(Debug, Clone)]
pub struct CipherIdUnknownError;

impl std::error::Error for CipherIdUnknownError {
    fn description(&self) -> &str {
        "Unknown cipher"
    }
}

impl Display for CipherIdUnknownError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.description())
    }
}

/// The current encryption status is unrecognized
#[derive(Debug, Clone)]
pub struct InvalidStatusSignature;

impl std::error::Error for InvalidStatusSignature {
    fn description(&self) -> &str {
        "Invalid encryption status signature"
    }
}

impl std::fmt::Display for InvalidStatusSignature {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.description())
    }
}

/// Error when reading the status of the hard drive
#[derive(Debug)]
pub enum StatusError {
    Signature(InvalidStatusSignature),
    Security(SecurityStatusUnknownError),
    Cipher(CipherIdUnknownError),
    IO(std::io::Error),
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

/// Error when reading the first handy store block, responsible
/// for holding some encryption information
#[derive(Debug)]
pub enum HandyStoreBlock1Error {
    IO(std::io::Error),
    Signature(String),
    Checksum(String),
}

impl Display for HandyStoreBlock1Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), core::fmt::Error> {
        match self {
            HandyStoreBlock1Error::IO(e) => e.fmt(f),
            HandyStoreBlock1Error::Signature(s) => write!(f, "{}", s),
            HandyStoreBlock1Error::Checksum(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for HandyStoreBlock1Error {
    fn description(&self) -> &str {
        match self {
            HandyStoreBlock1Error::IO(e) => e.description(),
            HandyStoreBlock1Error::Signature(s) => s,
            HandyStoreBlock1Error::Checksum(s) => s,
        }
    }
}

impl From<std::io::Error> for HandyStoreBlock1Error {
    fn from(e: std::io::Error) -> Self {
        HandyStoreBlock1Error::IO(e)
    }
}
