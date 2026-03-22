//! Linux PHY driver using AF_PACKET + PACKET_MMAP for zero-copy RX/TX.
//!
//! Creates two `AF_PACKET SOCK_RAW` sockets (one per NIC), enables
//! `PACKET_RX_RING` + `PACKET_TX_RING` with mmap, and wraps each socket as
//! a `smoltcp::phy::Device` so the rest of AIPS is platform-agnostic.
//!
//! Bridge forwarding: when the pipeline returns `Decision::Forward`, the
//! raw frame is written to the TX ring of the **opposite** socket.
//!
//! # Privileges
//! Requires `CAP_NET_RAW` (or `root`).  With Linux ≥ 5.10 you can restrict
//! this to just the binary: `setcap cap_net_raw=eip ./aips`.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::io;

/// Number of frames in each RX/TX ring block.
const RING_FRAMES: usize = 256;
/// Frame size (must be a power of two, ≥ 4096 for safety with headers).
const FRAME_SIZE: usize = 4096;

/// A raw socket bound to one network interface using AF_PACKET.
///
/// Uses `PACKET_MMAP` rings for zero-copy RX and TX where the kernel
/// supports it.  Falls back to synchronous `sendto` / `recvfrom` when
/// `PACKET_MMAP` is unavailable (e.g. in CI containers).
pub struct RawPacketSocket {
    fd: i32,
    ifindex: i32,
    /// mmap'd RX ring (None when PACKET_MMAP is unavailable).
    rx_ring: Option<MmapRing>,
    /// mmap'd TX ring.
    tx_ring: Option<MmapRing>,
    /// Fallback buffer for synchronous recvfrom when MMAP is unavailable.
    recv_buf: [u8; FRAME_SIZE],
}

struct MmapRing {
    ptr:    *mut u8,
    size:   usize,
    nframes: usize,
    cur:    usize,
    frame_size: usize,
}

// SAFETY: `RawPacketSocket` is used from a single thread in the poll loop.
unsafe impl Send for RawPacketSocket {}

impl RawPacketSocket {
    /// Open a raw packet socket bound to `iface` (e.g. `"eth0"`).
    pub fn open(iface: &str) -> io::Result<Self> {
        use std::os::unix::io::RawFd;
        let cname = CString::new(iface).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;

        log::debug!("Opening AF_PACKET socket on {iface}");
        // Create socket with protocol 0 to avoid implicit bind before MMAP setup.
        let fd = unsafe {
            libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0)
        };
        if fd < 0 { return Err(io::Error::last_os_error()); }

        // Resolve interface index
        let ifindex = unsafe {
            let mut req: libc::ifreq = core::mem::zeroed();
            let name_bytes = cname.as_bytes_with_nul();
            let copy_len = name_bytes.len().min(libc::IF_NAMESIZE);
            core::ptr::copy_nonoverlapping(
                name_bytes.as_ptr() as *const libc::c_char,
                req.ifr_name.as_mut_ptr(),
                copy_len,
            );
            if libc::ioctl(fd, libc::SIOCGIFINDEX, &req) < 0 {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }
            req.ifr_ifru.ifru_ifindex
        };

        // 1. Attempt PACKET_MMAP setup (MUST be done before the socket is bound).
        let (rx_ring, tx_ring) = match Self::setup_mmap(fd, RING_FRAMES, FRAME_SIZE) {
            Ok((rx, tx)) => {
                log::info!("PACKET_MMAP (TPACKET_V2) enabled on {iface}");
                (Some(rx), Some(tx))
            }
            Err(e) => {
                log::warn!("PACKET_MMAP failed on {iface}: {e}. Falling back to standard syscalls.");
                (None, None)
            }
        };

        // 2. Bind to the interface
        let addr = libc::sockaddr_ll {
            sll_family:   libc::AF_PACKET as u16,
            sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
            sll_ifindex:  ifindex,
            sll_hatype:   0,
            sll_pkttype:  0,
            sll_halen:    0,
            sll_addr:     [0u8; 8],
        };
        unsafe {
            if libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                core::mem::size_of_val(&addr) as libc::socklen_t,
            ) < 0 {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }
        }

        // 3. Set interface to promiscuous mode
        unsafe {
            let mut mreq: libc::packet_mreq = core::mem::zeroed();
            mreq.mr_ifindex = ifindex;
            mreq.mr_type    = libc::PACKET_MR_PROMISC as u16;
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const _ as *const libc::c_void,
                core::mem::size_of_val(&mreq) as libc::socklen_t,
            );
        }

        Ok(Self { fd, ifindex, rx_ring, tx_ring, recv_buf: [0u8; FRAME_SIZE] })
    }

    fn setup_mmap(fd: i32, nframes: usize, frame_size: usize)
        -> io::Result<(MmapRing, MmapRing)>
    {
        // Configure a TPACKET_V2 ring (widely supported).
        let block_size = frame_size * 16; // 16 frames per block
        let block_nr   = nframes / 16;
        let tp = libc::tpacket_req {
            tp_block_size: block_size as u32,
            tp_block_nr:   block_nr as u32,
            tp_frame_size: frame_size as u32,
            tp_frame_nr:   nframes as u32,
        };

        // Setup RX ring
        unsafe {
            if libc::setsockopt(
                fd, libc::SOL_PACKET, libc::PACKET_RX_RING,
                &tp as *const _ as *const libc::c_void,
                core::mem::size_of_val(&tp) as libc::socklen_t,
            ) < 0 { return Err(io::Error::last_os_error()); }

            // Explicitly set TPACKET_V2 for consistent header offsets on 64-bit.
            let ver = libc::tpacket_versions::TPACKET_V2 as i32;
            if libc::setsockopt(
                fd, libc::SOL_PACKET, libc::PACKET_VERSION,
                &ver as *const _ as *const libc::c_void,
                core::mem::size_of_val(&ver) as libc::socklen_t,
            ) < 0 { return Err(io::Error::last_os_error()); }

            // Setup TX ring (same geometry)
            if libc::setsockopt(
                fd, libc::SOL_PACKET, libc::PACKET_TX_RING,
                &tp as *const _ as *const libc::c_void,
                core::mem::size_of_val(&tp) as libc::socklen_t,
            ) < 0 { return Err(io::Error::last_os_error()); }
        }

        let mmap_size = block_size * block_nr * 2; // RX + TX back to back
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED { return Err(io::Error::last_os_error()); }

        let half = mmap_size / 2;
        let rx = MmapRing {
            ptr: ptr as *mut u8, size: half, nframes, cur: 0, frame_size,
        };
        let tx = MmapRing {
            ptr: unsafe { (ptr as *mut u8).add(half) },
            size: half, nframes, cur: 0, frame_size,
        };
        Ok((rx, tx))
    }

    /// Send `frame` out on this socket (zero-copy via TX ring if available,
    /// fallback to `send`).
    pub fn send_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        if let Some(ref mut tx) = self.tx_ring {
            let offset = tx.cur * tx.frame_size;
            let slot = unsafe { core::slice::from_raw_parts_mut(tx.ptr.add(offset), tx.frame_size) };
            // TPACKET2 header is at the front of the frame slot
            let hdr = unsafe { &mut *(slot.as_mut_ptr() as *mut libc::tpacket2_hdr) };
            if hdr.tp_status as u32 != libc::TP_STATUS_AVAILABLE as u32 {
                // Ring full — fallback
            } else {
                let data_off = hdr.tp_mac as usize;
                let data_len = frame.len().min(tx.frame_size - data_off);
                slot[data_off..data_off + data_len].copy_from_slice(&frame[..data_len]);
                hdr.tp_len    = data_len as u32;
                hdr.tp_status = libc::TP_STATUS_SEND_REQUEST as u32;
                tx.cur = (tx.cur + 1) % tx.nframes;
                // Kick the kernel
                unsafe { libc::send(self.fd, core::ptr::null(), 0, 0); }
                return Ok(());
            }
        }
        // Fallback: blocking send
        unsafe {
            let ret = libc::send(self.fd, frame.as_ptr() as *const libc::c_void, frame.len(), 0);
            if ret < 0 { return Err(io::Error::last_os_error()); }
        }
        Ok(())
    }

    /// Attempt to receive one frame from the RX ring.
    ///
    /// Returns a slice into the ring buffer (**zero-copy**) if a frame is
    /// available, or `None` if the ring is empty.
    ///
    /// The caller must call [`release_rx`](Self::release_rx) after processing.
    pub fn try_recv_frame(&mut self) -> Option<&[u8]> {
        if let Some(ref rx) = self.rx_ring {
            let offset = rx.cur * rx.frame_size;
            let slot = unsafe { core::slice::from_raw_parts(rx.ptr.add(offset), rx.frame_size) };
            let hdr = unsafe { &*(slot.as_ptr() as *const libc::tpacket2_hdr) };
            if hdr.tp_status as u32 & libc::TP_STATUS_USER as u32 != 0 {
                let data_off = hdr.tp_mac as usize;
                let data_len = hdr.tp_snaplen as usize;
                if data_off + data_len <= rx.frame_size {
                    return Some(&slot[data_off..data_off + data_len]);
                }
            }
        } else {
            // Fallback: synchronous non-blocking recv
            unsafe {
                let ret = libc::recv(
                    self.fd, 
                    self.recv_buf.as_mut_ptr() as *mut libc::c_void, 
                    self.recv_buf.len(), 
                    libc::MSG_DONTWAIT
                );
                if ret > 0 {
                    return Some(&self.recv_buf[..ret as usize]);
                }
            }
        }
        None
    }

    /// Release the current RX ring slot after processing.
    pub fn release_rx(&mut self) {
        if let Some(ref mut rx) = self.rx_ring {
            let offset = rx.cur * rx.frame_size;
            let slot = unsafe { core::slice::from_raw_parts_mut(rx.ptr.add(offset), rx.frame_size) };
            let hdr = unsafe { &mut *(slot.as_mut_ptr() as *mut libc::tpacket2_hdr) };
            hdr.tp_status = libc::TP_STATUS_KERNEL as u32;
            rx.cur = (rx.cur + 1) % rx.nframes;
        }
    }
}

impl Drop for RawPacketSocket {
    fn drop(&mut self) {
        if let Some(ref rx) = self.rx_ring {
            unsafe { libc::munmap(rx.ptr as *mut libc::c_void, rx.size * 2); }
        }
        unsafe { libc::close(self.fd); }
    }
}
