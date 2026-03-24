use aips_core::layer::PacketView;
use aips_core::classifier::{Classifier};
use aips_core::qos::QosFields;
use aips_core::defrag::DefragTable;
use aips_core::Decision;

#[test]
fn test_teardrop_attack_panic_safety() {
    let mut table: DefragTable<4, 4096> = DefragTable::new(30_000);
    
    // Malformed IP header with overlapping fragments (Teardrop)
    let mut hdr1 = [0u8; 20];
    hdr1[0] = 0x45; hdr1[9] = 17;
    hdr1[12..16].copy_from_slice(&[1, 1, 1, 1]);
    hdr1[16..20].copy_from_slice(&[2, 2, 2, 2]);
    
    // Fragment 1: offset 0, len 24, MF=1
    hdr1[4] = 0xDE; hdr1[5] = 0xAD; // ID
    hdr1[6] = 0x20; hdr1[7] = 0x00; // MF=1, Offset=0
    let p1 = [0xAA; 24];
    table.process(&hdr1, &p1, 100);

    // Fragment 2: offset 1 (8 bytes), len 24, MF=0 (OVERLAPS Fragment 1)
    hdr1[6] = 0x00; hdr1[7] = 0x01; // MF=0, Offset=8 bytes
    let p2 = [0xBB; 24];
    
    // This should not panic
    let res = table.process(&hdr1, &p2, 101);
    assert!(res.is_some());
    let pkt = res.unwrap();
    assert_eq!(pkt.len(), 32); // 8 + 24
}

#[test]
fn test_session_table_saturation_dos() {
    // Capacity 16
    let mut classifier: Classifier<16, _> = Classifier::new(aips_core::classifier::DefaultPolicy);

    let qos = QosFields::default();

    // 1. Fill the table with 16 unique flows
    for i in 0..16 {
        let mut buf = [0u8; 60]; // Enough space for Eth(14) + IP(20) + TCP(20)
        buf[12] = 0x08; buf[13] = 0x00; // Eth: IPv4
        buf[14] = 0x45; buf[23] = 6; // IP: TCP
        buf[26..30].copy_from_slice(&[10, 0, 0, i as u8]); // Src IP
        buf[34..36].copy_from_slice(&443u16.to_be_bytes()); // Src Port
        buf[36..38].copy_from_slice(&443u16.to_be_bytes()); // Dst Port
        
        let pkt = PacketView::parse(&buf).unwrap();
        classifier.classify(&pkt, qos, 100);
    }
    assert_eq!(classifier.session_count(), 16);

    // 2. 17th flow should fail to insert but still be processed
    let mut buf = [0u8; 60];
    buf[12] = 0x08; buf[13] = 0x00;
    buf[14] = 0x45; buf[23] = 6;
    buf[26..30].copy_from_slice(&[10, 0, 0, 99]); // New Src IP
    buf[34..36].copy_from_slice(&443u16.to_be_bytes());
    buf[36..38].copy_from_slice(&443u16.to_be_bytes());
    
    let pkt = PacketView::parse(&buf).unwrap();
    let decision = classifier.classify(&pkt, qos, 200);
    
    // FIXED: Now it returns Violation instead of ProxyTcp, because the table is full.
    assert_eq!(decision, Decision::Violation, "Fail-Secure: 17th flow should be dropped when table is full");
    
    // Table count remains 16.
    assert_eq!(classifier.session_count(), 16);
}

fn build_tcp_packet(payload: &[u8], dst_port: u16) -> std::vec::Vec<u8> {
    let mut buf = vec![0u8; 14 + 20 + 20 + payload.len()];
    // Ethernet: IPv4
    buf[12] = 0x08; buf[13] = 0x00;
    // IP: 
    buf[14] = 0x45; 
    let total_len = (20 + 20 + payload.len()) as u16;
    let tl_bytes = total_len.to_be_bytes();
    buf[14+2] = tl_bytes[0]; buf[14+3] = tl_bytes[1];
    buf[14+8] = 64; // TTL
    buf[14+9] = 6; // TCP
    buf[14+10] = 0; buf[14+11] = 0; // Checksum (ignored by PacketView)
    buf[14+12..14+16].copy_from_slice(&[1,1,1,1]);
    buf[14+16..14+20].copy_from_slice(&[2,2,2,2]);
    // TCP:
    buf[14+20+0..14+20+2].copy_from_slice(&50000u16.to_be_bytes()); // Src port
    buf[14+20+2..14+20+4].copy_from_slice(&dst_port.to_be_bytes()); // Dst port
    buf[14+20+12] = 0x50; // Data offset 5
    // Payload
    buf[14+20+20..].copy_from_slice(payload);
    buf
}
