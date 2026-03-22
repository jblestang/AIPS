//! macOS PHY driver using Berkeley Packet Filter (BPF).
//!
//! macOS does not support `AF_PACKET`; raw Ethernet capture is done via
//! `/dev/bpf*` devices. Two BPF file descriptors are opened (one per
//! interface) and used for bidirectional bump-in-the-wire forwarding.
//!
//! # Setup
//! A `bridge0` interface must exist bridging the two physical interfaces:
//! ```sh
//! sudo networksetup -createBridge bridge0 en3 en4
//! sudo ifconfig bridge0 up
//! ```
//! Then run AIPS with `sudo` (required for `/dev/bpf*`).
//!
//! # Zero-copy note
//! BPF on macOS uses a kernel-maintained buffer that is copied to user-space
//! in one `read()` call (not mmap). True zero-copy requires IOKit/DPDK or
//! Apple's Hypervisor framework; this driver is optimised for minimal copies
//! (single `read` into a pre-allocated ring buffer).

#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::io;
use std::os::unix::io::RawFd;

/// Size of the BPF read buffer (holds many frames per `read` call).
const BPF_BUF_SIZE: usize = 65536;

/// A BPF capture descriptor bound to one interface.
pub struct BpfSocket {
    fd:      RawFd,
    buf:     Box<[u8; BPF_BUF_SIZE]>,
    buf_pos: usize,
    buf_len: usize,
}

impl BpfSocket {
    /// Open a BPF socket bound to `iface` (e.g. `"en0"`).
    pub fn open(iface: &str) -> io::Result<Self> {
        let fd = Self::open_bpf_device()?;
        Self::configure(fd, iface)?;
        Ok(Self {
            fd,
            buf: Box::new([0u8; BPF_BUF_SIZE]),
            buf_pos: 0,
            buf_len: 0,
        })
    }

    fn open_bpf_device() -> io::Result<RawFd> {
        for i in 0..256u32 {
            let path = format!("/dev/bpf{i}\0");
            let fd = unsafe {
                libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR)
            };
            if fd >= 0 { return Ok(fd); }
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::EBUSY) { break; }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "no BPF device available"))
    }

    fn configure(fd: RawFd, iface: &str) -> io::Result<()> {
        let cname = CString::new(iface).unwrap();
        unsafe {
            // Set buffer length
            let buflen = BPF_BUF_SIZE as u32;
            if libc::ioctl(fd, BIOCSBLEN, &buflen) < 0 {
                return Err(io::Error::last_os_error());
            }

            // Bind to interface
            let mut req: libc::ifreq = core::mem::zeroed();
            let name_bytes = cname.as_bytes_with_nul();
            let copy_len = name_bytes.len().min(libc::IF_NAMESIZE);
            core::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const libc::c_char,
                req.ifr_name.as_mut_ptr(),
                copy_len,
            );
            if libc::ioctl(fd, BIOCSETIF, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            // Enable promiscuous mode
            let one: u32 = 1;
            let _ = libc::ioctl(fd, BIOCPROMISC, &one);

            // Return immediately if no data (non-blocking reads after select)
            let _ = libc::ioctl(fd, BIOCIMMEDIATE, &one);

            // See Ethernet header in captured frames
            let _ = libc::ioctl(fd, BIOCSHDRCMPLT, &one);
        }
        Ok(())
    }

    /// Attempt to read the next BPF-captured frame from the internal buffer.
    ///
    /// Returns a slice into the internal buffer (one copy from kernel → user).
    pub fn next_frame(&mut self) -> io::Result<Option<&[u8]>> {
        if self.buf_pos >= self.buf_len {
            // Refill buffer
            let n = unsafe {
                libc::read(
                    self.fd,
                    self.buf.as_mut_ptr() as *mut libc::c_void,
                    BPF_BUF_SIZE,
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EAGAIN) { return Ok(None); }
                return Err(e);
            }
            self.buf_len = n as usize;
            self.buf_pos = 0;
        }

        if self.buf_pos >= self.buf_len { return Ok(None); }

        // BPF header: struct bpf_hdr { ts(8), caplen(4), datalen(4), hdrlen(2) }
        let hdr_buf = &self.buf[self.buf_pos..];
        if hdr_buf.len() < 18 { return Ok(None); }
        let caplen = u32::from_ne_bytes([hdr_buf[8], hdr_buf[9], hdr_buf[10], hdr_buf[11]]) as usize;
        let hdrlen = u16::from_ne_bytes([hdr_buf[16], hdr_buf[17]]) as usize;

        let frame_start = self.buf_pos + hdrlen;
        let frame_end   = frame_start + caplen;
        if frame_end > self.buf_len { return Ok(None); }

        // Advance past this BPF record (BPF_WORDALIGN)
        let record_len = (hdrlen + caplen + 3) & !3;
        self.buf_pos += record_len;

        Ok(Some(&self.buf[frame_start..frame_end]))
    }

    /// Send a raw Ethernet frame out on this interface.
    pub fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        let ret = unsafe {
            libc::write(self.fd, frame.as_ptr() as *const libc::c_void, frame.len())
        };
        if ret < 0 { return Err(io::Error::last_os_error()); }
        Ok(())
    }
}

impl Drop for BpfSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

// BPF ioctl constants (macOS / BSD)
const BIOCSBLEN:    u64 = 0xC0044266;
const BIOCSETIF:    u64 = 0x8020426C;
const BIOCPROMISC:  u64 = 0x20004269;
const BIOCIMMEDIATE:u64 = 0x80044270;
const BIOCSHDRCMPLT:u64 = 0x80044275;
