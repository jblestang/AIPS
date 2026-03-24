//! Zero-copy Layer 2–4 packet view.
//!
//! All parse methods borrow from the original captured buffer — no data is copied.

use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol,
    Ipv4Packet, IpProtocol,
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
    /// IGMP message (Protocol 2).
    Igmp,
    /// OSPF routing (Protocol 89).
    Ospf,
    /// PIM multicast (Protocol 103).
    Pim,
    /// Any other IP protocol number.
    Other(u8),
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
    /// Source IPv4.
    pub src_ip: [u8; 4],
    /// Destination IPv4.
    pub dst_ip: [u8; 4],
    /// Source port (TCP/UDP).
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP).
    pub dst_port: Option<u16>,
    /// Transport protocol.
    pub l4_proto: Option<L4Proto>,
    /// TCP Flags (if TCP).
    pub tcp_flags: Option<u8>,
    /// QoS fields extracted at L3.
    pub qos: QosFields,
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const _TCP_PSH: u8 = 0x08;
const _TCP_ACK: u8 = 0x10;

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
        
        let mut ethertype = eth.ethertype();
        let mut l3_offset = 14;

        // Handle 802.1Q VLAN tagging (0x8100)
        if ethertype == EthernetProtocol::Unknown(0x8100) {
            if buf.len() < 18 { return None; }
            l3_offset = 18;
            ethertype = EthernetProtocol::from(u16::from_be_bytes([buf[16], buf[17]]));
        }

        let mut pv = PacketView {
            raw: buf,
            l3_offset,
            l4_offset: l3_offset,
            payload_offset: l3_offset,
            src_mac,
            dst_mac,
            src_ip: [0u8; 4],
            dst_ip: [0u8; 4],
            src_port: None,
            dst_port: None,
            l4_proto: None,
            tcp_flags: None,
            qos: QosFields::default(),
        };

        if ethertype == EthernetProtocol::Ipv4 {
            pv.parse_ipv4();
        }

        Some(pv)
    }

    fn parse_ipv4(&mut self) {
        let ip_buf = &self.raw[self.l3_offset..];
        if ip_buf.len() < 20 { return; }
        let ip = Ipv4Packet::new_unchecked(ip_buf);

        self.src_ip.copy_from_slice(&ip.src_addr().octets());
        self.dst_ip.copy_from_slice(&ip.dst_addr().octets());
        let tos = (ip.dscp() << 2) | ip.ecn();
        self.qos = QosFields::from_ipv4(tos, ip.hop_limit());

        let ihl = (ip.header_len() as usize).max(20);
        if ihl > ip_buf.len() { return; }
        self.l4_offset = self.l3_offset + ihl;

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
                    
                    let mut flags = 0u8;
                    if tcp.fin() { flags |= TCP_FIN; }
                    if tcp.syn() { flags |= TCP_SYN; }
                    if tcp.rst() { flags |= TCP_RST; }
                    self.tcp_flags = Some(flags);

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
            IpProtocol::Igmp  => { self.l4_proto = Some(L4Proto::Igmp); }
            other => {
                let proto_num: u8 = other.into();
                match proto_num {
                    89  => self.l4_proto = Some(L4Proto::Ospf),
                    103 => self.l4_proto = Some(L4Proto::Pim),
                    _   => self.l4_proto = Some(L4Proto::Other(proto_num)),
                }
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

    /// Returns true if this is a TCP FIN packet.
    pub fn is_tcp_fin(&self) -> bool {
        self.tcp_flags.map_or(false, |f| f & TCP_FIN != 0)
    }

    /// Returns true if this is a TCP RST packet.
    pub fn is_tcp_rst(&self) -> bool {
        self.tcp_flags.map_or(false, |f| f & TCP_RST != 0)
    }

    /// Returns true if this is a TCP SYN packet.
    pub fn is_tcp_syn(&self) -> bool {
        self.tcp_flags.map_or(false, |f| f & TCP_SYN != 0)
    }

    /// Returns true if this is an ICMP Destination Unreachable packet.
    pub fn is_icmp_unreachable(&self) -> bool {
        if self.l4_proto != Some(L4Proto::Icmp) { return false; }
        let l4_buf = &self.raw[self.l4_offset..];
        if l4_buf.is_empty() { return false; }
        // Type 3 = Destination Unreachable
        l4_buf[0] == 3
    }
}
