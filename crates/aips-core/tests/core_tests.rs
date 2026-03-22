//! Unit tests for aips-core abstractions.

use aips_core::layer::{PacketView, L4Proto};
use aips_core::qos::QosFields;
use aips_core::defrag::DefragTable;

#[test]
fn test_parse_ipv4_udp() {
    // Hex dump of an Ethernet -> IPv4 -> UDP packet (e.g. DNS to 8.8.8.8)
    #[rustfmt::skip]
    let frame: &[u8] = &[
        // Ethernet (14 bytes)
        0x02, 0x42, 0xac, 0x11, 0x00, 0x02, // Dst MAC
        0x02, 0x42, 0xac, 0x11, 0x00, 0x03, // Src MAC
        0x08, 0x00,                         // IPv4
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x3d, // IHL=5, TOS=0, TotalLen=61
        0xcd, 0x6e, 0x40, 0x00, // ID=0xcd6e, Flags/Frag=DF
        0x40, 0x11, 0x98, 0x05, // TTL=64, Proto=17 (UDP), Checksum
        0xc0, 0xa8, 0x00, 0x64, // Src IP: 192.168.0.100
        0x08, 0x08, 0x08, 0x08, // Dst IP: 8.8.8.8
        // UDP (8 bytes)
        0x83, 0xff, 0x00, 0x35, // SrcPort=33791, DstPort=53
        0x00, 0x29, 0xb8, 0x24, // Len=41, Checksum
        // Payload (DNS query)
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
        b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    let pv = PacketView::parse(frame).expect("Failed to parse valid frame");

    assert_eq!(pv.src_ip, [192, 168, 0, 100]);
    assert_eq!(pv.dst_ip, [8, 8, 8, 8]);
    assert_eq!(pv.l4_proto, Some(L4Proto::Udp));
    assert_eq!(pv.src_port, Some(33791));
    assert_eq!(pv.dst_port, Some(53));
    assert_eq!(pv.qos.ttl, 64);
    assert_eq!(pv.qos.dscp, 0);

    let payload = pv.payload();
    // The explicit hex slice actually provides only 29 bytes of payload after the UDP header.
    assert_eq!(payload.len(), 29);
    // Payload starts with DNS ID 0xabcd
    assert_eq!(payload[0], 0xab);
    assert_eq!(payload[1], 0xcd);
}

#[test]
fn test_ipv4_defrag() {
    let mut table: DefragTable<4, 4096> = DefragTable::new(30_000);

    // Dummy IP header: ID=1234, Proto=Udp, Src=1.2.3.4, Dst=5.6.7.8
    // The IP header isn't parsed deeply by `process()`, it just needs offsets.
    let mut ip1 = [0u8; 20];
    ip1[4] = 0x04; ip1[5] = 0xd2; // ID=1234
    ip1[6] = 0x20; ip1[7] = 0x00; // Flags=MF (0x2000), Offset=0
    ip1[9] = 17; // Proto=UDP
    ip1[12..16].copy_from_slice(&[1, 2, 3, 4]); // Src
    ip1[16..20].copy_from_slice(&[5, 6, 7, 8]); // Dst

    let payload1 = [0xAA; 16];
    let res1 = table.process(&ip1, &payload1, 100);
    assert!(res1.is_none(), "Fragment 1 should not complete");

    let mut ip2 = ip1;
    // Flags=0, Offset=2 (16 bytes = 2 * 8)
    ip2[6] = 0x00; ip2[7] = 0x02;
    let payload2 = [0xBB; 8];
    let res2 = table.process(&ip2, &payload2, 101);

    assert!(res2.is_some(), "Fragment 2 completes the datagram");
    let reassembled = res2.unwrap();
    assert_eq!(reassembled.len(), 24);
    assert_eq!(&reassembled[0..16], &[0xAA; 16]);
    assert_eq!(&reassembled[16..24], &[0xBB; 8]);
}

#[test]
fn test_qos_fields() {
    // DS=46 (Expedited Forwarding = 0x2E), ECN=2 (ECT(0) = 0x02)
    // TOS byte = (46 << 2) | 2 = 184 | 2 = 186 = 0xBA
    let tos = 0xBA;
    let qos = QosFields::from_ipv4(tos, 64);
    assert_eq!(qos.dscp, 46);
    assert_eq!(qos.ecn, 2);
    assert_eq!(qos.to_tos(), tos);
}

#[test]
fn test_ipv4_defrag_overlapping_favor_new() {
    let mut table: DefragTable<4, 4096> = DefragTable::new(30_000);

    let mut ip_base = [0u8; 20];
    ip_base[4] = 0x05; ip_base[5] = 0x39; // ID=1337
    ip_base[9] = 17; // Proto=UDP
    ip_base[12..16].copy_from_slice(&[192, 168, 1, 1]);
    ip_base[16..20].copy_from_slice(&[10, 0, 0, 1]);

    // Fragment 1: Offset 0, Length 16, Payload A
    let mut ip1 = ip_base;
    ip1[6] = 0x20; ip1[7] = 0x00; // MF=1, Offset=0
    let payload1 = [0xAA; 16];
    let res1 = table.process(&ip1, &payload1, 200);
    assert!(res1.is_none());

    // Fragment 2: Offset 8, Length 16, Payload B (OVERLAPPING Fragment 1's second half)
    // Offset 8 means (8 / 8) = 1 in the IP header offset field.
    let mut ip2 = ip_base;
    ip2[6] = 0x20; ip2[7] = 0x01; // MF=1, Offset=1 (8 bytes)
    let payload2 = [0xBB; 16];
    let res2 = table.process(&ip2, &payload2, 201);
    assert!(res2.is_none());

    // Fragment 3: Offset 24, Length 8, Payload C (Completes the datagram)
    // Offset 24 means (24 / 8) = 3 in the IP header offset field.
    let mut ip3 = ip_base;
    ip3[6] = 0x00; ip3[7] = 0x03; // MF=0, Offset=3 (24 bytes)
    let payload3 = [0xCC; 8];
    let res3 = table.process(&ip3, &payload3, 202);
    
    assert!(res3.is_some(), "Overlapping fragment sequence should complete perfectly.");
    let reassembled = res3.unwrap();
    
    // Total length = 24 + 8 = 32 bytes
    assert_eq!(reassembled.len(), 32);
    // Bytes 0-7: A
    assert_eq!(&reassembled[0..8], &[0xAA; 8]);
    // Bytes 8-23: B (Favor New overlapped the A payload)
    assert_eq!(&reassembled[8..24], &[0xBB; 16]);
    // Bytes 24-31: C
    assert_eq!(&reassembled[24..32], &[0xCC; 8]);
}
