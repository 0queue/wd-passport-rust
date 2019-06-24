#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::convert::TryFrom;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::io::AsRawFd;

use byteorder::ByteOrder;
use byteorder::LittleEndian;
use termion::input::TermRead;

use crate::status::{CipherId, InvalidStatusSignature, KeyResetEnabler, SecurityStatus};

#[allow(unused)]
mod debug_bindings;
mod status;

pub mod sg {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

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


fn sg_read(fd: i32, cmd: &mut [u8], buf: &mut [std::os::raw::c_uchar]) -> std::io::Result<usize> {
    use std::os::raw;
    use std::io;

    let mut sense = [0 as raw::c_uchar; 32];
    let io = debug_bindings::sg_io_hdr {
        interface_id: 'S' as raw::c_int,
        dxfer_direction: debug_bindings::SG_DXFER_FROM_DEV,
        cmd_len: cmd.len() as u8,
        mx_sb_len: sense.len() as u8, // from sbp buffer
        iovec_count: 0,
        dxfer_len: buf.len() as u32, // probably just 512 (block size)
        dxferp: buf.as_mut_ptr() as *mut raw::c_void, // *mut ::std::os::raw::c_void
        cmdp: cmd.as_mut_ptr(),
        sbp: sense.as_mut_ptr(),
        timeout: 20_000, // ms
        flags: 0,
        pack_id: 0,
        usr_ptr: std::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        sb_len_wr: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };

    let r = unsafe { libc::ioctl(fd, debug_bindings::SG_IO as u64, &io) };

    if r == -1 {
        return Err(io::Error::last_os_error());
    } else if (io.info & debug_bindings::SG_INFO_OK_MASK) != debug_bindings::SG_INFO_OK {
        return Err(io::Error::new(io::ErrorKind::Other, "SCSI error"));
    }

    Ok((io.dxfer_len - io.resid as u32) as usize)
}

fn sg_write(fd: i32, cmd: &mut [u8], buf: &mut [std::os::raw::c_uchar]) -> std::io::Result<()> {
    use std::os::raw;
    use std::io;

    let mut sense = [0 as raw::c_uchar; 32];
    let io = debug_bindings::sg_io_hdr {
        interface_id: 'S' as raw::c_int,
        dxfer_direction: debug_bindings::SG_DXFER_TO_DEV,
        cmd_len: cmd.len() as u8,
        mx_sb_len: sense.len() as u8,
        iovec_count: 0,
        dxfer_len: buf.len() as u32,
        dxferp: buf.as_mut_ptr() as *mut raw::c_void,
        cmdp: cmd.as_mut_ptr(),
        sbp: sense.as_mut_ptr(),
        timeout: 20_000,
        flags: 0,
        pack_id: 0,
        usr_ptr: std::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        sb_len_wr: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };

    let r = unsafe { libc::ioctl(fd, debug_bindings::SG_IO as u64, &io) };

    if r == -1 {
        return Err(io::Error::last_os_error());
    } else if (io.info & debug_bindings::SG_INFO_OK_MASK) != debug_bindings::SG_INFO_OK {
        return Err(io::Error::new(io::ErrorKind::Other, "SCSI error"));
    }

    Ok(())
}

fn get_encryption_status(fd: i32) -> Result<(SecurityStatus, CipherId, KeyResetEnabler)> {
    let mut buf = [0u8; 512];
    let mut cdb: [u8; 10] = [0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00];
    sg_read(fd, &mut cdb, &mut buf)?;

    if buf[0] != 0x45 {
        return Err(Box::new(InvalidStatusSignature));
    }

    let security = status::SecurityStatus::try_from(buf[3])?;
    let cipher = status::CipherId::try_from(buf[4])?;
    // is there a better way?? who knows
    let key_reset_enabler = status::KeyResetEnabler([buf[8], buf[9], buf[10], buf[12]]);

    Ok((security, cipher, key_reset_enabler))
}

fn hsb_checksum(buf: &[u8]) -> u8 {
    let mut c = 0i32;

    for i in 0..510 {
        c += buf[i] as i32;
    }

    c += buf[0] as i32;

    ((c * -1) & 0xFF) as u8
}

fn read_handy_store_block1(fd: i32) -> Result<(u32, [u8; 10])> {
    let mut buf = [0u8; 512];
    let mut cdb: [u8; 10] = [0xD8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00];

    sg_read(fd, &mut cdb, &mut buf)?;

    // checksum
    if hsb_checksum(&buf) != buf[511] {
        Err(format!("Checksum {} does not match expected {}", hsb_checksum(&buf), buf[511]))?;
    }

    // signature
    let signature: [u8; 4] = [0x00, 0x01, 0x44, 0x57];
    for i in 0..4 {
        if signature[i] != buf[i] {
            Err(format!("Signature mismatch at {}: Found {} expected {}", i, buf[i], signature[i]))?;
        }
    }

    let iteration = LittleEndian::read_u32(&buf[8..12]);
    let mut salt = [0u8; 10];
    for i in 12..20 {
        salt[i - 12] = buf[i];
    }
    // TODO password hint here

    Ok((iteration, salt))
}

fn unlock(fd: i32, password: String) {
    let cdb: [u8; 10] = [0xC1, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00];

    let pw_block: [u8; 6] = [0x45, 0x00, 0x00, 0x00, 0x00, 0x00];
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

    let (security, cipher, key_reset_enabler) = get_encryption_status(file.as_raw_fd())?;

    println!("SecurityStatus: {:?}, CipherId: {:?}, Key Reset Enabler: {:?}", security, cipher, key_reset_enabler);

    let (iteration, salt) = read_handy_store_block1(file.as_raw_fd())?;

    drop(file);
    Ok(())
}
