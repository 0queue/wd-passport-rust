#[allow(unused)]
mod debug_bindings;

#[allow(unused)]
mod sg {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn read(fd: i32, cmd: &mut [u8], buf: &mut [u8]) -> std::io::Result<usize> {
    use std::io;
    use std::os::raw;

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

pub fn write(fd: i32, cmd: &mut [u8], buf: &mut [u8]) -> std::io::Result<()> {
    use std::io;
    use std::os::raw;

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
