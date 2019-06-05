use core::fmt;
use std::convert::TryFrom;
use std::error::Error;
use std::fmt::Formatter;

use crate::status::CipherId::{AES_128_CBC, AES_128_ECB, AES_128_XTS, AES_256_CBC, AES_256_ECB, AES_256_XTS, FullDiskEncryption};

#[derive(Debug, Clone)]
pub enum SecurityStatus {
    NoLock,
    Locked,
    Unlocked,
    Blocked,
    NoKeys,
}

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

impl TryFrom<u8> for SecurityStatus {
    type Error = SecurityStatusUnknownError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => SecurityStatus::NoLock,
            0x01 => SecurityStatus::Locked,
            0x02 => SecurityStatus::Unlocked,
            0x06 => SecurityStatus::Blocked,
            0x07 => SecurityStatus::NoKeys,
            _ => {
                return Err(SecurityStatusUnknownError);
            }
        })
    }
}

#[derive(Debug, Clone)]
pub enum CipherId {
    AES_128_ECB,
    AES_128_CBC,
    AES_128_XTS,
    AES_256_ECB,
    AES_256_CBC,
    AES_256_XTS,
    FullDiskEncryption,
}

#[derive(Debug, Clone)]
pub struct CipherIdUnknownError;

impl std::error::Error for CipherIdUnknownError {
    fn description(&self) -> &str {
        "Unknown cipher"
    }
}

impl std::fmt::Display for CipherIdUnknownError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.description())
    }
}

impl TryFrom<u8> for CipherId {
    type Error = CipherIdUnknownError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x10 => AES_128_ECB,
            0x12 => AES_128_CBC,
            0x18 => AES_128_XTS,
            0x20 => AES_256_ECB,
            0x22 => AES_256_CBC,
            0x28 => AES_256_XTS,
            0x30 => FullDiskEncryption,
            _ => return Err(CipherIdUnknownError)
        })
    }
}

#[derive(Debug, Clone)]
pub struct KeyResetEnabler(pub [u8; 4]);

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