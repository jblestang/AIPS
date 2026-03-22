use criterion::{black_box, criterion_group, criterion_main, Criterion};

use aips_core::layer::PacketView;
use aips_core::classifier::Classifier;
use aips_core::qos::QosFields;

use aips_rules::engine::{RuleEngine, MatchCtx};
use aips_rules::rule::{Rule, MatchExpr, BytePattern};
use aips_rules::action::Action;

use aips_l7::dispatcher::L7Dispatcher;

fn build_engine() -> RuleEngine<'static, 128, 512, 1024> {
    let mut engine = RuleEngine::new();
    engine.add_rule(Rule {
        id: 1, 
        name: "Block SQL injection",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"union select", case_insensitive: true }),
        action: Action::Drop,
    }).unwrap();
    engine.add_rule(Rule {
        id: 2, 
        name: "Block path traversal",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"../", case_insensitive: true }),
        action: Action::Drop,
    }).unwrap();
    engine.build();
    engine
}

fn bench_pipeline(c: &mut Criterion) {
    let mut engine = build_engine();
    let mut classifier: Classifier<1024> = Classifier::new();
    classifier.add_service(aips_core::classifier::Service {
        protocol: aips_core::classifier::L7Protocol::Bypass,
        server_port: 12345,
    }).unwrap();
    classifier.add_service(aips_core::classifier::Service {
        protocol: aips_core::classifier::L7Protocol::Http,
        server_port: 80,
    }).unwrap();
    
    // PassThrough packet (e.g. unknown high port bypassing proxy)
    // DstPort = 12345 (not proxy)
    let pkt_passthrough: &[u8] = &[
        // Ethernet (14)
        0,0,0,0,0,0, 0,0,0,0,0,0, 0x08, 0x00,
        // IPv4 (20)
        0x45, 0, 0, 44, 0, 0, 0, 0, 64, 6, 0,0, 1,2,3,4, 5,6,7,8,
        // TCP (20) - src 12345, dst 12345 (not proxy)
        0x30, 0x39, 0x30, 0x39,  0,0,0,0, 0,0,0,0, 0x50, 0, 0,0, 0,0,0,0,
        // Payload (4 bytes) "AIPS"
        b'A', b'I', b'P', b'S'
    ];

    // ProxyTcp packet (e.g. HTTP DstPort = 80)
    let pkt_proxytcp: &[u8] = &[
        // Ethernet (14)
        0,0,0,0,0,0, 0,0,0,0,0,0, 0x08, 0x00,
        // IPv4 (20)
        0x45, 0, 0, 58, 0, 0, 0, 0, 64, 6, 0,0, 1,2,3,4, 5,6,7,8,
        // TCP (20) - src 12345, dst 80
        0x30, 0x39, 0x00, 0x50,  0,0,0,0, 0,0,0,0, 0x50, 0, 0,0, 0,0,0,0,
        // Payload (18 bytes) "GET / HTTP/1.1\r\n\r\n"
        b'G', b'E', b'T', b' ', b'/', b' ', b'H', b'T', b'T', b'P', b'/', b'1', b'.', b'1', b'\r', b'\n', b'\r', b'\n'
    ];

    let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
    let mut dns_buf = [0u8; 512];
    
    // 1. Benchmark PassThrough (Forward fast path)
    c.bench_function("Pipeline::PassThrough", |b| {
        b.iter(|| {
            let pkt = PacketView::parse(black_box(pkt_passthrough)).unwrap();
            let decision = classifier.classify(&pkt, qos);
            black_box(decision);
        })
    });

    // 2. Benchmark ProxyTcp (Deep Packet Inspection including httparse & Aho-Corasick)
    c.bench_function("Pipeline::ProxyTcp", |b| {
        b.iter(|| {
            let pkt = PacketView::parse(black_box(pkt_proxytcp)).unwrap();
            let _decision = classifier.classify(&pkt, qos);
            
            let payload = pkt.payload();
            if !payload.is_empty() {
                let mut http_buf = [httparse::EMPTY_HEADER; 32];
                let dst_port = pkt.dst_port.unwrap_or(0);
                
                let verdict = L7Dispatcher::dispatch(payload, aips_core::classifier::L7Protocol::Http, &mut dns_buf, &mut http_buf);
                
                let mut src_ip = [0u8; 16];
                src_ip[12..16].copy_from_slice(&pkt.src_ip[0..4]);
                
                let ctx = L7Dispatcher::to_match_ctx(&verdict, payload, dst_port, src_ip);
                let action = engine.evaluate(&ctx, 0);
                black_box(action);
            }
        })
    });
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
