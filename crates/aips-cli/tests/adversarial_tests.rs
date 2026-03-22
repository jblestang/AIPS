use aips_core::layer::PacketView;
use aips_core::classifier::{Classifier, L7Protocol, Service};
use aips_core::qos::QosFields;
use aips_rules::engine::{RuleEngine};
use aips_rules::rule::{BytePattern, MatchExpr, Rule};
use aips_rules::action::Action;
use aips_core::defrag::DefragTable;
use aips_l7::dispatcher::L7Dispatcher;

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
fn test_l7_evasion_via_tcp_segmentation() {
    // This test demonstrates the L7 bypass vulnerability
    let mut classifier = Classifier::<128>::new();
    classifier.add_service(Service {
        protocol: L7Protocol::Http,
        server_port: 80,
    }).unwrap();

    let _qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };

    // Attacker sends "SQL" but split across 3 packets
    let p1_raw = build_tcp_packet(b"S");
    let p2_raw = build_tcp_packet(b"Q");
    let p3_raw = build_tcp_packet(b"L");

    let mut engine = RuleEngine::<'static, 128, 512, 1024, 4096>::new();
    engine.add_rule(Rule {
        id: 1,
        name: "Block SQL",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"SQL", case_insensitive: true }),
        action: Action::Drop,
    }).unwrap();
    engine.build();

    let mut dns_buf = [0u8; 512];
    let mut http_buf = [httparse::EMPTY_HEADER; 32];
    let src_ip_full = [0; 4];

    // Packet 1
    {
        let mut http_buf = [httparse::EMPTY_HEADER; 32];
        let pkt1 = PacketView::parse(&p1_raw).unwrap();
        let verdict1 = L7Dispatcher::dispatch(pkt1.payload(), L7Protocol::Http, &mut dns_buf, &mut http_buf);
        let ctx1 = L7Dispatcher::to_match_ctx(&verdict1, pkt1.payload(), 80, src_ip_full);
        assert!(engine.evaluate(&ctx1, 0).is_none(), "Should not detect 'S'");
    }

    // Packet 2
    {
        let mut http_buf = [httparse::EMPTY_HEADER; 32];
        let pkt2 = PacketView::parse(&p2_raw).unwrap();
        let verdict2 = L7Dispatcher::dispatch(pkt2.payload(), L7Protocol::Http, &mut dns_buf, &mut http_buf);
        let ctx2 = L7Dispatcher::to_match_ctx(&verdict2, pkt2.payload(), 80, src_ip_full);
        assert!(engine.evaluate(&ctx2, 0).is_none(), "Should not detect 'Q'");
    }

    // Packet 3
    {
        let mut http_buf = [httparse::EMPTY_HEADER; 32];
        let pkt3 = PacketView::parse(&p3_raw).unwrap();
        let verdict3 = L7Dispatcher::dispatch(pkt3.payload(), L7Protocol::Http, &mut dns_buf, &mut http_buf);
        let ctx3 = L7Dispatcher::to_match_ctx(&verdict3, pkt3.payload(), 80, src_ip_full);
        assert!(engine.evaluate(&ctx3, 0).is_none(), "Should not detect 'L'");
    }
}

#[test]
fn test_aho_corasick_worst_case_aaaaa() {
    let mut engine = RuleEngine::<'static, 128, 4096, 4096, 8192>::new();
    engine.add_rule(Rule {
        id: 1,
        name: "A-Storm",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"aaaaaab", case_insensitive: false }),
        action: Action::Alert,
    }).unwrap();
    engine.build();

    // The text matches the prefix long enough to traverse failure links repeatedly
    let payload = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";
    let mut dns_buf = [0u8; 512];
    let mut http_buf = [httparse::EMPTY_HEADER; 32];
    let src_ip_full = [0; 4];

    let verdict = L7Dispatcher::dispatch(payload, L7Protocol::Http, &mut dns_buf, &mut http_buf);
    let ctx = L7Dispatcher::to_match_ctx(&verdict, payload, 80, src_ip_full);
    
    let res = engine.evaluate(&ctx, 0);
    assert!(res.is_some());
}

use aips_core::decision::Decision;

#[test]
fn test_session_table_saturation_dos() {
    // Capacity 16
    let mut classifier: Classifier<16> = Classifier::new();
    classifier.add_service(Service { protocol: L7Protocol::Http, server_port: 80 }).unwrap();

    let qos = QosFields::default();

    // 1. Fill the table with 16 unique flows
    for i in 0..16 {
        let mut buf = [0u8; 60]; // Enough space for Eth(14) + IP(20) + TCP(20)
        buf[12] = 0x08; buf[13] = 0x00; // Eth: IPv4
        buf[14] = 0x45; buf[23] = 6; // IP: TCP
        buf[26..30].copy_from_slice(&[10, 0, 0, i as u8]); // Src IP
        buf[34..36].copy_from_slice(&80u16.to_be_bytes()); // Src Port
        buf[36..38].copy_from_slice(&80u16.to_be_bytes()); // Dst Port
        
        let pkt = PacketView::parse(&buf).unwrap();
        classifier.classify(&pkt, qos);
    }
    assert_eq!(classifier.session_count(), 16);

    // 2. 17th flow should fail to insert but still be processed
    let mut buf = [0u8; 60];
    buf[12] = 0x08; buf[13] = 0x00;
    buf[14] = 0x45; buf[23] = 6;
    buf[26..30].copy_from_slice(&[10, 0, 0, 99]); // New Src IP
    buf[34..36].copy_from_slice(&80u16.to_be_bytes());
    buf[36..38].copy_from_slice(&80u16.to_be_bytes());
    
    let pkt = PacketView::parse(&buf).unwrap();
    let decision = classifier.classify(&pkt, qos);
    
    // FIXED: Now it returns Violation instead of ProxyTcp, because the table is full.
    assert_eq!(decision, Decision::Violation, "Fail-Secure: 17th flow should be dropped when table is full");
    
    // Table count remains 16.
    assert_eq!(classifier.session_count(), 16);
}

#[test]
fn test_http_duplicate_header_evasion() {
    let mut engine = RuleEngine::<'static, 128, 512, 1024, 4096>::new();
    engine.add_rule(Rule {
        id: 1,
        name: "Block Evil Host",
        match_expr: MatchExpr::HttpHost("evil.com"),
        action: Action::Drop,
    }).unwrap();
    engine.build();

    // Payload with duplicate Host headers
    let payload = b"GET / HTTP/1.1\r\nHost: safe.com\r\nHost: evil.com\r\n\r\n";
    
    let mut dns_buf = [0u8; 256];
    let mut http_buf = [httparse::EMPTY_HEADER; 32];
    
    let verdict = L7Dispatcher::dispatch(payload, L7Protocol::Http, &mut dns_buf, &mut http_buf);
    
    // FIXED: find_header now returns None on duplicate Host!
    assert_eq!(verdict.http_host, None, "Fix verified: Duplicate Host headers rejected!");

    let ctx = L7Dispatcher::to_match_ctx(&verdict, payload, 80, [0; 4]);
    let res = engine.evaluate(&ctx, 0);
    
    // Still none, because we rejected the host altogether.
    assert!(res.is_none());
}

#[test]
fn test_dns_null_byte_evasion() {
    let mut engine = RuleEngine::<'static, 128, 512, 1024, 4096>::new();
    engine.add_rule(Rule {
        id: 1,
        name: "Block Malicious",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"malicious", case_insensitive: true }),
        action: Action::Drop,
    }).unwrap();
    engine.build();

    // DNS Query for "mali\0cious.com"
    #[rustfmt::skip]
    let payload: &[u8] = &[
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, b'm', b'a', b'l', b'i', 0x00, b'c', b'i', b'o', b'u',
        0x03, b'c', b'o', b'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ];

    let mut dns_buf = [0u8; 256];
    let mut http_buf = [httparse::EMPTY_HEADER; 32];
    
    let verdict = L7Dispatcher::dispatch(payload, L7Protocol::Dns, &mut dns_buf, &mut http_buf);
    
    // FIXED: decode_name now returns None on null-byte!
    assert_eq!(verdict.dns_name, None, "Fix verified: Null-byte in DNS label rejected!");
}

fn build_tcp_packet(payload: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = vec![0u8; 14 + 20 + 20 + payload.len()];
    // Ethernet: IPv4
    buf[12] = 0x08; buf[13] = 0x00;
    // IP: 
    buf[14] = 0x45; 
    let total_len = (20 + 20 + payload.len()) as u16;
    let tl_bytes = total_len.to_be_bytes();
    buf[14+2] = tl_bytes[0]; buf[14+3] = tl_bytes[1];
    buf[14+9] = 6; // TCP
    buf[14+12..14+16].copy_from_slice(&[1,1,1,1]);
    buf[14+16..14+20].copy_from_slice(&[2,2,2,2]);
    // TCP:
    buf[14+20+3] = 80; // Dst port
    buf[14+20+12] = 0x50; // Data offset 5
    // Payload
    buf[14+20+20..].copy_from_slice(payload);
    buf
}
