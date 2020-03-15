use core::fmt;
use std::fmt::{Display, Formatter};

/// Unknown security status
#[derive(Debug, Clone)]
pub struct SecurityStatusUnknownError;

impl std::error::Error for SecurityStatusUnknownError {}

impl std::fmt::Display for SecurityStatusUnknownError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Unknown security status")
    }
}

/// Unknown cipher
#[derive(Debug, Clone)]
pub struct CipherIdUnknownError;

impl std::error::Error for CipherIdUnknownError {}

impl Display for CipherIdUnknownError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Unknown Cipher")
    }
}

/// The current encryption status is unrecognized
#[derive(Debug, Clone)]
pub struct InvalidStatusSignature;

impl std::error::Error for InvalidStatusSignature {}

impl std::fmt::Display for InvalidStatusSignature {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "Invalid encryption status signature")
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

impl std::error::Error for StatusError {}

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

impl std::error::Error for HandyStoreBlock1Error {}

impl From<std::io::Error> for HandyStoreBlock1Error {
    fn from(e: std::io::Error) -> Self {
        HandyStoreBlock1Error::IO(e)
    }
}
