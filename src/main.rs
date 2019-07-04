#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::env;
use std::fs::OpenOptions;
use std::io::Write;

use byteorder::ByteOrder;
use byteorder::LittleEndian;
use byteorder::NetworkEndian;
use sha2::Digest;
use sha2::Sha256;
use termion::input::TermRead;

mod passport;

type Result<T> = std::result::Result<T, Box<std::error::Error>>;

/*
 * SCSI Info:
 *  cdb: Command Descriptor Block
 *      - one byte op code
 *      - 5 or more parameter bytes
 *  Initiator (us) -> target (them)
 *      - after command sent, responds with
 *          - 0x00 success
 *          - 0x02 error
 *          - 0x08 busy
 *
 *  4 kinds of commands:
 *      - N (non data)
 *      - W (write data to target)
 *      - R (read)
 *      - B (bidirectional)
 *
 *
 */

/*
 * From https://github.com/0-duke/wdpassport-utils
 * also ended up learning a bunch from https://github.com/KenMacD/wdpassport-utils
 *
 * SecurityStatus:
 *      0x00 => No lock
 *      0x01 => Locked
 *      0x02 => Unlocked
 *      0x06 => Locked, unlock blocked
 *      0x07 => No keys
 * CurrentCipherID
 *      0x10 =>	AES_128_ECB
 *      0x12 =>	AES_128_CBC
 *      0x18 =>	AES_128_XTS
 *      0x20 =>	AES_256_ECB
 *      0x22 =>	AES_256_CBC
 *      0x28 =>	AES_256_XTS
 *      0x30 =>	Full Disk Encryption
## KeyResetEnabler (4 bytes that change every time)
 */


fn hsb_checksum(buf: &[u8]) -> u8 {
    let mut c = 0i32;

    for i in 0..510 {
        c += buf[i] as i32;
    }

    c += buf[0] as i32;

    ((c * -1) & 0xFF) as u8
}

//fn read_handy_store_block1(fd: i32) -> Result<(u32, [u8; 10])> {
//    let mut buf = [0u8; 512];
//    let mut cdb: [u8; 10] = [0xD8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00];
//
//    sg::read(fd, &mut cdb, &mut buf)?;
//
//    // checksum
//    if hsb_checksum(&buf) != buf[511] {
//        Err(format!(
//            "Checksum {} does not match expected {}",
//            hsb_checksum(&buf),
//            buf[511]
//        ))?;
//    }
//
//    // signature
//    let signature: [u8; 4] = [0x00, 0x01, 0x44, 0x57];
//    for i in 0..4 {
//        if signature[i] != buf[i] {
//            Err(format!(
//                "Signature mismatch at {}: Found {} expected {}",
//                i, buf[i], signature[i]
//            ))?;
//        }
//    }
//
//    let iteration = LittleEndian::read_u32(&buf[8..12]);
//    let mut salt = [0u8; 10];
//    for i in 12..20 {
//        salt[i - 12] = buf[i];
//    }
//    // TODO password hint here
//
//    // salt is pretty much always utf-16-le encoded null terminated "WDC."
//    Ok((iteration, salt))
//}

fn utf16_le(string: String) -> Vec<u8> {
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

fn hash_password(password: String, iterations: u32, salt: [u8; 10]) -> Vec<u8> {
    // 1. Prepend salt w/o utf-16 null terminator to utf-16 password
    // 2. hash it iterations number of times

    let mut salted = (&salt[..salt.len() - 2]).to_vec();
    salted.append(&mut utf16_le(password));

    let mut res = salted;
    for _ in 0..iterations {
        let mut hasher = Sha256::default();
        hasher.input(res);
        res = hasher.result().to_vec();
    }

    res
}

#[test]
fn test_hash_password() {
    // a result I got from copy pasting the results
    // of the wdc() function in the cookpw.py script from KenMacD
    let expected: Vec<u8> = vec![
        0x58, 0x1d, 0xe8, 0xd4, 0x33, 0xc, 0x2d, 0x36, 0x20, 0x70, 0x6f, 0x3b, 0x7f, 0xe6, 0x88,
        0xfa, 0xdc, 0x0, 0xca, 0x89, 0x8a, 0x28, 0xef, 0x10, 0xbf, 0x1b, 0x68, 0xa8, 0xa2, 0x14,
        0x4, 0xd2,
    ];
    let actual = hash_password(
        "Hello".to_string(),
        1000,
        [0x057, 0x00, 0x44, 0x00, 0x43, 0x00, 0x2e, 0x00, 0x00, 0x00],
    );

    assert_eq!(expected.len(), actual.len());
    assert_eq!(expected, actual);
}

//fn unlock(fd: i32, password: String) {
//    // from WD_Encryption_API.txt:
//    //                  OPCODE,SUBCODE, V-------reserved-------V   data length, control
//    let mut cdb: [u8; 10] = [0xC1, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00];
//
//    let mut pw_block: [u8; 8] = [0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
//
//    let (iterations, salt) = read_handy_store_block1(fd).unwrap();
//    let mut hashed = hash_password(password, iterations, salt);
//
//    // this is a bit extra since I'm only concerned about sha256 == len of 32
//    NetworkEndian::write_u16(&mut pw_block[6..], hashed.len() as u16);
//
//    let mut pw_block = pw_block.to_vec();
//    pw_block.append(&mut hashed);
//
//    let attempt = sg::write(fd, &mut cdb, &mut pw_block);
//
//    if attempt.is_ok() {
//        println!("Success! Drive status:");
//        println!("{:?}", get_encryption_status(fd));
//    } else {
//        eprintln!("Wrong password");
//    }
//}

#[test]
fn test_network_endian() {
    let mut buf = [0u8; 2];

    NetworkEndian::write_u16(&mut buf, 32);

    assert_eq!(buf, [0u8, 32u8]);
}

#[test]
fn test_utf_16_le() {
    let mut wdc = "WDC.".to_string();

    // turns out the default python str.encode("utf-16") is little endian
    // so to replicate...
    let res = wdc
        .encode_utf16()
        .map(|utf16| {
            let mut res = vec![0u8; 2];
            LittleEndian::write_u16(&mut res, utf16);
            res
        })
        .flatten()
        .collect::<Vec<u8>>();

    assert_eq!(res, vec![0x57, 0x00, 0x44, 0x00, 0x43, 0x00, 0x2e, 0x00])
}

fn read_password() -> std::io::Result<String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();

    stdout.write_all(b"Drive password: ").unwrap();
    stdout.flush().unwrap();

    let pass = stdin.read_passwd(&mut stdout)?;

    stdout.write_all(b"\n").unwrap();
    stdout.flush().unwrap();
    Ok(pass.unwrap())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(args.get(1).unwrap_or(&"".to_string()))?;

    let passport = passport::Passport::new(args.get(1).unwrap())?;

    let (security, cipher, key_reset_enabler) = passport.status()?;

    println!(
        "SecurityStatus: {:?}, CipherId: {:?}, Key Reset Enabler: {:?}",
        security, cipher, key_reset_enabler
    );

//    let (iteration, salt) = read_handy_store_block1(file.as_raw_fd())?;

//    println!("iter: {} salt: {:?}", iteration, salt);

//    let password = read_password().unwrap();
//    unlock(file.as_raw_fd(), password);

    drop(file);
    Ok(())
}
