use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

use byteorder::ByteOrder;
use byteorder::LittleEndian;
use sha2::Digest;
use sha2::Sha256;

use crate::passport::errors::CipherIdUnknownError;
use crate::passport::errors::StatusError;
use crate::passport::errors::HandyStoreBlock1Error;
use crate::passport::errors::InvalidStatusSignature;
use crate::passport::errors::SecurityStatusUnknownError;

pub mod errors;
mod sg;

pub struct Passport {
    backing_file: File,
}

#[derive(Debug, Clone)]
pub enum SecurityStatus {
    NoLock,
    Locked,
    Unlocked,
    Blocked,
    NoKeys,
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

impl TryFrom<u8> for CipherId {
    type Error = CipherIdUnknownError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x10 => CipherId::AES_128_ECB,
            0x12 => CipherId::AES_128_CBC,
            0x18 => CipherId::AES_128_XTS,
            0x20 => CipherId::AES_256_ECB,
            0x22 => CipherId::AES_256_CBC,
            0x28 => CipherId::AES_256_XTS,
            0x30 => CipherId::FullDiskEncryption,
            _ => return Err(CipherIdUnknownError),
        })
    }
}

#[derive(Debug, Clone)]
pub struct KeyResetEnabler(pub [u8; 4]);

/// A struct representing a connected Western Digital Passport
impl Passport {
    /// Connect to a device at the given path
    ///
    /// Example:
    /// ```rust
    /// let passport = passport::Passport::new("/dev/sdc")
    /// ```
    pub fn new(device_path: &str) -> std::io::Result<Passport> {
        let backing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)?;

        Ok(Passport { backing_file })
    }

    fn fd(&self) -> i32 {
        self.backing_file.as_raw_fd() as i32
    }

    /// Returns how the drive is locked, the kind of cipher in use, and the 4 bytes used
    /// to reset the keys.
    ///
    /// # Internal Details
    ///
    /// ## Command buffer
    ///
    /// | Byte Index/Indices | Content | Notes |
    /// | ------------------ | ------- | ----- |
    /// | 0 | Op Code (0xC0) | Constant |
    /// | 1 | Sub Code(0x45) | Constant |
    /// | 2-6 | Reserved (0x00) | |
    /// | 7-8 | Allocation Length (Big Endian) | Requested size of return buffer |
    ///
    /// ## Return buffer
    ///
    /// | Byte index/indices | Content | Notes |
    /// | -------------------| ------- | ----- |
    /// | 0 | Signature (0x45) | Constant |
    /// | 1-2 | Reserved (0x00) | |
    /// | 3 | [Security Status](status/enum.SecurityStatus.html) | |
    /// | 4 | [Cipher ID](status/enum.CipherId.html) | |
    /// | 5 | Reserved (0x00) | |
    /// | 6-7 | Password length (Big Endian) | 16 for AES128 ciphers and 32 for the rest |
    /// | 8-11 | Key Reset Enabler | A set of 4 bytes to use with RESET DATA ENCRYPTION KEY.  Changes with each  |
    /// | 12-14 | Reserved | |
    /// | 15 | Number of ciphers supported by device | |
    /// | 16+n | [Cipher ID](status/enum.CipherId.html) n |  n >= 0 |
    ///
    pub fn status(&self) -> Result<(SecurityStatus, CipherId, KeyResetEnabler), StatusError> {
        let mut buf: [u8; 512] = [0u8; 512];
        let mut cdb: [u8; 10] = [0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00];
        sg::read(self.fd(), &mut cdb, &mut buf)?;

        if buf[0] != 0x45 {
            return Err(StatusError::from(InvalidStatusSignature));
        }

        let security = SecurityStatus::try_from(buf[3])?;
        let cipher = CipherId::try_from(buf[4])?;
        let key_reset_enabler = KeyResetEnabler([buf[8], buf[9], buf[10], buf[11]]);

        Ok((security, cipher, key_reset_enabler))
    }

    /// Read the first block of the handy store, which contains data readable
    /// in any lock/unlock state (only writable when unlocked however)
    ///
    /// Handy store block 1 contains the number of hashing rounds and the salt
    /// as well as the user password hint
    ///
    /// Of note, the number of hashing rounds is little endian, as is the salt,
    /// and password hint.  The salt and password hint are encoded using UCS-2
    ///
    /// # Internal details
    ///
    /// ## Command buffer
    ///
    /// | Byte index/indices | Content | Notes |
    /// | ------------------ | ------- | ----- |
    /// | 0 | Op Code (0xD8) | Constant |
    /// | 1 | Reserved | |
    /// | 2-5 | Block index | Big Endian |
    /// | 6 | Reserved | |
    /// | 7-8 | Transfer Length | Number of blocks |
    /// | 9 | Control | |
    ///
    /// ## Block 1 structure
    ///
    /// | Byte index/indices | Content | Notes |
    /// | ------------------ | ------- | ----- |
    /// | 0-3 | Signature | [0, 1, 'W', 'D'] |
    /// | 4-7 | Reserved | |
    /// | 8-12 | Number of hashing rounds | |
    /// | 12-19 | Salt | Little endian UCS-2, generally "WDC." unless changed by user :/ |
    /// | 20-23 | Reserved | |
    /// | 24-225 | Password Hint | Little endian UCS-2 |
    /// | 226-510 | Reserved | |
    /// | 511 | Checksum | Sum of all the other bits, see [handy_store_block_checksum](fn.handy_store_block_checksum.html) |
    ///
    fn ready_handy_store_block1(&self) -> Result<(u32, [u8; 8]), HandyStoreBlock1Error> {
        let mut buf = [0u8; 512];
        let mut cdb: [u8; 10] = [0xD8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00];

        sg::read(self.fd(), &mut cdb, &mut buf)?;

        // checksum
        let checksum = handy_store_block_checksum(&buf);
        if checksum != buf[511] {
            let msg = format!("Checksum {} does not match expected {}", checksum, buf[511]);
            return Err(HandyStoreBlock1Error::Checksum(msg));
        }

        // signature
        let signature: [u8; 4] = [0x00, 0x01, 0x44, 0x57];
        if signature != buf[0..4] {
            let msg = format!(
                "Signature mismatch: Found {:?} expected {:?}",
                &buf[0..4],
                signature
            );
            return Err(HandyStoreBlock1Error::Signature(msg));
        }

        // WD_Encryption_API.txt says Big Endian, but wd-passport-utils.py says
        // Little Endian, which works and agrees with the UCS-2 encoding
        let iteration = LittleEndian::read_u32(&buf[8..12]);

        // expected to succeed
        // unless manually changed, will be little endian encoded UCS-2 "WDC."
        let salt: [u8; 8] = buf[12..20].try_into().unwrap();

        // TODO password hint here

        Ok((iteration, salt))
    }

    /// Given a password, salt, hash and send it to
    /// the hard drive
    ///
    /// # Internal details
    ///
    /// ## Command block
    ///
    /// | Byte Index/Indices | Content | Notes |
    /// | ------------------ | ------- | ----- |
    /// | 0 | Op Code (0xC1) | |
    /// | 1 | Sub Code (0xE1) | |
    /// | 2-6 | Reserved | |
    /// | 7-8 | Parameter list length | Big endian, generally 0x28 due to 8 bytes of pw block header + salted hashed password |
    /// | 9 | Control | |
    ///
    /// ## Password block
    ///
    /// | Byte Index/Indices | Content | Notes |
    /// | ------------------ | ------- | ----- |
    /// | 0 | Signature (0x45) | |
    /// | 1-5 | Reserved | |
    /// | 6-7 | Password Length | Big endian, theoretically either 16 or 32 but usually 32 |
    /// | 8- | Password | Salted and hashed |
    ///
    pub fn unlock(&self, password: &str) -> bool {
        let mut cdb: [u8; 10] = [0xC1, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00];

        let mut pw_block = [0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20].to_vec();

        let (iterations, salt) = self.ready_handy_store_block1().unwrap();
        let mut hashed = hash_password(password, iterations, salt);

        pw_block.append(&mut hashed);

        sg::write(self.fd(), &mut cdb, &mut pw_block).is_ok()
    }
}

/// Sum of all the bits, but then for some reason
/// multiplied by -1
fn handy_store_block_checksum(buf: &[u8]) -> u8 {
    let mut c = 0i32;

    for i in 0..510 {
        c += buf[i] as i32;
    }

    ((c * -1) & 0xFF) as u8
}

fn utf16_le(string: &str) -> Vec<u8> {
    // TODO replace with real UCS-2 handling
    string
        .encode_utf16()
        .map(|utf16| {
            let mut res = vec![0u8; 2];
            LittleEndian::write_u16(&mut res, utf16);
            res
        })
        .flatten()
        .collect()
}

fn hash_password(password: &str, iterations: u32, salt: [u8; 8]) -> Vec<u8> {
    // 1. Prepend salt w/o utf-16 null terminator to utf-16 password
    // 2. hash it iterations number of times

    let mut salted = salt.to_vec();
    salted.append(&mut utf16_le(password));

    let mut res = salted;
    for _ in 0..iterations {
        let mut hasher = Sha256::default();
        hasher.input(res);
        res = hasher.result().to_vec();
    }

    res
}

#[cfg(test)]
mod test {
    use crate::passport::hash_password;
    use crate::passport::utf16_le;

    #[test]
    fn test_hash_password() {
        // a result I got from copy pasting the results
        // of the wdc() function in the cookpw.py script from KenMacD
        let expected: Vec<u8> = vec![
            0x58, 0x1d, 0xe8, 0xd4, 0x33, 0xc, 0x2d, 0x36, 0x20, 0x70, 0x6f, 0x3b, 0x7f, 0xe6,
            0x88, 0xfa, 0xdc, 0x0, 0xca, 0x89, 0x8a, 0x28, 0xef, 0x10, 0xbf, 0x1b, 0x68, 0xa8,
            0xa2, 0x14, 0x4, 0xd2,
        ];
        let actual = hash_password(
            "Hello",
            1000,
            [0x057, 0x00, 0x44, 0x00, 0x43, 0x00, 0x2e, 0x00],
        );

        assert_eq!(expected.len(), actual.len());
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_utf_16_le() {
        let wdc = "WDC.".to_string();

        // turns out the default python str.encode("utf-16") is little endian
        // so to replicate...
        let res = utf16_le(&wdc);

        assert_eq!(res, vec![0x57, 0x00, 0x44, 0x00, 0x43, 0x00, 0x2e, 0x00])
    }
}
