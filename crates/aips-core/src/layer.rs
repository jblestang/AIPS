//! Zero-copy Layer 2–4 packet view.
//!
//! All parse methods borrow from the original captured buffer — no data is copied.

use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol,
    Ipv4Packet, Ipv6Packet, IpProtocol,
    TcpPacket, UdpPacket,
};

use crate::qos::QosFields;

/// Transport-layer protocol tag carried in a [`PacketView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    /// TCP segment.
    Tcp,
    /// UDP datagram.
    Udp,
    /// ICMPv4 message.
    Icmp,
    /// ICMPv6 message.
    Icmpv6,
    /// Any other IP protocol number.
    Other(u8),
}

/// IP address version carried in a [`PacketView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

/// A zero-copy, lifetime-bound view of a raw Ethernet frame.
///
/// All fields are computed lazily by borrowing slices from the original
/// `buf` reference — the underlying bytes are never copied.
pub struct PacketView<'pkt> {
    /// The full raw frame (Ethernet header + payload).
    pub raw: &'pkt [u8],
    // Cached parse offsets (computed once by `parse`).
    l3_offset:  usize,
    l4_offset:  usize,
    payload_offset: usize,
    /// Source MAC address.
    pub src_mac: EthernetAddress,
    /// Destination MAC address.
    pub dst_mac: EthernetAddress,
    /// IP version (if the EtherType is IP).
    pub ip_version: Option<IpVersion>,
    /// Source IP (encoded as 16 bytes; first 4 used for IPv4).
    pub src_ip: [u8; 16],
    /// Destination IP.
    pub dst_ip: [u8; 16],
    /// Source port (TCP/UDP).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP).
    pub dst_port: Option<u16>,
    /// Transport protocol.
    pub l4_proto: Option<L4Proto>,
    /// QoS fields extracted at L3.
    pub qos: QosFields,
}

impl<'pkt> PacketView<'pkt> {
    /// Parse a raw Ethernet frame and build a zero-copy view.
    ///
    /// Returns `None` if the frame is too short or the EtherType is not
    /// recognised as IP (non-IP frames are treated as opaque pass-through).
    pub fn parse(buf: &'pkt [u8]) -> Option<Self> {
        if buf.len() < 14 { return None; }
        let eth = EthernetFrame::new_unchecked(buf);

        let src_mac = eth.src_addr();
        let dst_mac = eth.dst_addr();
        let l3_offset = 14; // Fixed Ethernet header without 802.1Q for now

        let mut pv = PacketView {
            raw: buf,
            l3_offset,
            l4_offset: l3_offset,
            payload_offset: l3_offset,
            src_mac,
            dst_mac,
            ip_version: None,
            src_ip: [0u8; 16],
            dst_ip: [0u8; 16],
            src_port: None,
            dst_port: None,
            l4_proto: None,
            qos: QosFields::default(),
        };

        match eth.ethertype() {
            EthernetProtocol::Ipv4 => pv.parse_ipv4(),
            EthernetProtocol::Ipv6 => pv.parse_ipv6(),
            _ => {} // non-IP — keep as opaque
        }

        Some(pv)
    }

    fn parse_ipv4(&mut self) {
        let ip_buf = &self.raw[self.l3_offset..];
        if ip_buf.len() < 20 { return; }
        let ip = Ipv4Packet::new_unchecked(ip_buf);

        self.ip_version = Some(IpVersion::V4);
        self.src_ip[..4].copy_from_slice(&ip.src_addr().octets());
        self.dst_ip[..4].copy_from_slice(&ip.dst_addr().octets());
        let tos = (ip.dscp() << 2) | ip.ecn();
        self.qos = QosFields::from_ipv4(tos, ip.hop_limit());

        let ihl = (ip.header_len() as usize).max(20);
        if ihl > ip_buf.len() { return; }
        self.l4_offset = self.l3_offset + ihl;

        let proto = ip.next_header();
        self.parse_l4(proto);
    }

    fn parse_ipv6(&mut self) {
        let ip_buf = &self.raw[self.l3_offset..];
        if ip_buf.len() < 40 { return; }
        let ip = Ipv6Packet::new_unchecked(ip_buf);

        self.ip_version = Some(IpVersion::V6);
        self.src_ip.copy_from_slice(&ip.src_addr().octets());
        self.dst_ip.copy_from_slice(&ip.dst_addr().octets());
        self.qos = QosFields::from_ipv6(ip.traffic_class(), ip.hop_limit());

        self.l4_offset = self.l3_offset + 40; // fixed IPv6 header
        if self.l4_offset > self.raw.len() { return; }
        let proto = ip.next_header();
        self.parse_l4(proto);
    }

    fn parse_l4(&mut self, proto: IpProtocol) {
        let l4_buf = &self.raw[self.l4_offset..];
        match proto {
            IpProtocol::Tcp => {
                self.l4_proto = Some(L4Proto::Tcp);
                if l4_buf.len() >= 20 {
                    let tcp = TcpPacket::new_unchecked(l4_buf);
                    self.src_port = Some(tcp.src_port());
                    self.dst_port = Some(tcp.dst_port());
                    let hl = (tcp.header_len() as usize).max(20);
                    self.payload_offset = (self.l4_offset + hl).min(self.raw.len());
                }
            }
            IpProtocol::Udp => {
                self.l4_proto = Some(L4Proto::Udp);
                if l4_buf.len() >= 8 {
                    let udp = UdpPacket::new_unchecked(l4_buf);
                    self.src_port = Some(udp.src_port());
                    self.dst_port = Some(udp.dst_port());
                    self.payload_offset = (self.l4_offset + 8).min(self.raw.len());
                }
            }
            IpProtocol::Icmp  => { self.l4_proto = Some(L4Proto::Icmp); }
            IpProtocol::Icmpv6 => { self.l4_proto = Some(L4Proto::Icmpv6); }
            other => {
                self.l4_proto = Some(L4Proto::Other(other.into()));
            }
        }
    }

    /// Returns the application-layer payload slice (zero-copy borrow).
    #[inline]
    pub fn payload(&self) -> &'pkt [u8] {
        &self.raw[self.payload_offset..]
    }

    /// Returns the raw IP + transport header, useful for the proxy to re-use.
    #[inline]
    pub fn l3_header(&self) -> &'pkt [u8] {
        &self.raw[self.l3_offset..self.l4_offset]
    }
}
