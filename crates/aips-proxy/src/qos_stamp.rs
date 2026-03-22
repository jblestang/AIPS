//! QoS re-stamping helpers.
//!
//! After the L4 proxy constructs outbound IP packets via smoltcp, these helpers
//! patch the IP header's TOS/Traffic-Class and TTL/Hop-Limit fields in-place
//! to match the values captured from the original ingress packet.
//!
//! All operations are on `&mut [u8]` slices — no allocation.

use aips_core::qos::QosFields;

/// Patch an IPv4 header (starting at `buf[0]`) with the given QoS fields.
///
/// Recalculates the IP header checksum after modification.
/// `buf` must contain a complete IPv4 header (at minimum 20 bytes).
pub fn stamp_ipv4(buf: &mut [u8], qos: QosFields) {
    if buf.len() < 20 { return; }
    buf[1] = qos.to_tos();    // TOS byte
    buf[8] = qos.ttl;         // TTL
    // Recompute header checksum (bytes 10–11)
    buf[10] = 0;
    buf[11] = 0;
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    let hdr = &buf[..ihl.min(buf.len())];
    let csum = ipv4_checksum(hdr);
    buf[10] = (csum >> 8) as u8;
    buf[11] = (csum & 0xFF) as u8;
}

/// Standard RFC 1071 one's-complement checksum.
fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
