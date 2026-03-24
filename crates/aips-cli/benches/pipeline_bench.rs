use criterion::{black_box, criterion_group, criterion_main, Criterion};

use aips_core::layer::PacketView;
use aips_core::classifier::Classifier;
use aips_core::qos::QosFields;

use aips_rules::engine::RuleEngine;
use aips_rules::rule::{Rule, MatchExpr};
use aips_rules::action::Action;

fn build_engine() -> RuleEngine<'static, 128> {
    let mut engine = RuleEngine::new();
    engine.add_rule(Rule {
        id: 1, 
        name: "Block specific IP",
        match_expr: MatchExpr::DstIp([10, 0, 0, 1]),
        action: Action::Alert,
        bidirectional: true,
    }).unwrap();

    engine.build();
    engine
}

fn bench_pipeline(c: &mut Criterion) {
    let mut engine = build_engine();
    let mut classifier: Classifier<1024, _> = Classifier::new(aips_core::classifier::DefaultPolicy);
    
    // PassThrough packet (e.g. unknown high port bypassing proxy)
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

    // L4 packet (DstPort = 443)
    let pkt_l4_443: &[u8] = &[
        // Ethernet(14) IPv4(20) TCP(20)
        0,0,0,0,0,0, 0,0,0,0,0,0, 0x08, 0x00,
        0x45, 0, 0, 100, 0, 0, 0, 0, 64, 6, 0,0, 1,2,3,4, 5,6,7,8,
        0x30, 0x39, 0x01, 0xBB,  0,0,0,0, 0,0,0,0, 0x50, 0, 0,0, 0,0,0,0,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
    ];

    let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
    
    // 1. Benchmark Pipeline traversal (Stateless classify)
    c.bench_function("Pipeline::Classify", |b| {
        b.iter(|| {
            let pkt = PacketView::parse(black_box(pkt_passthrough)).unwrap();
            let decision = classifier.classify(&pkt, qos, 100);
            black_box(decision);
        })
    });

    // 2. Benchmark Full L3/L4 Pipeline (Classifier + Rule Engine)
    c.bench_function("Pipeline::Full_L3_L4", |b| {
        b.iter(|| {
            let pkt = PacketView::parse(black_box(pkt_l4_443)).unwrap();
            let _decision = classifier.classify(&pkt, qos, 100);
            
            let ctx = aips_rules::engine::MatchCtx {
                payload: pkt.payload(),
                src_ip:  pkt.src_ip,
                dst_ip:  pkt.dst_ip,
                src_port: pkt.src_port.unwrap_or(0),
                dst_port: pkt.dst_port.unwrap_or(0),
                ttl: qos.ttl,
                dscp: qos.dscp,
                ecn: qos.ecn,
            };
            let action = engine.evaluate(&ctx, 0);
            black_box(action);
        })
    });

    // 4. Benchmark Rule Engine Only
    c.bench_function("SubComponent::RuleEngine_1Rule", |b| {
        let pkt = PacketView::parse(pkt_l4_443).unwrap();
        let ctx = aips_rules::engine::MatchCtx {
            payload: pkt.payload(),
            src_ip:  pkt.src_ip,
            dst_ip:  pkt.dst_ip,
            src_port: pkt.src_port.unwrap_or(0),
            dst_port: pkt.dst_port.unwrap_or(0),
            ttl: qos.ttl,
            dscp: qos.dscp,
            ecn: qos.ecn,
        };
        b.iter(|| {
            let action = engine.evaluate(black_box(&ctx), 0);
            black_box(action);
        })
    });

    // 5. Benchmark Rule Engine with 100 rules
    let mut large_engine: RuleEngine<'static, 128> = RuleEngine::new();
    for i in 0..100 {
        large_engine.add_rule(Rule {
            id: i,
            name: "Dummy Rule",
            match_expr: MatchExpr::DstPort(1000 + i as u16),
            action: Action::Alert,
            bidirectional: false,
        }).unwrap();
    }
    large_engine.build();

    c.bench_function("SubComponent::RuleEngine_100Rules", |b| {
        let pkt = PacketView::parse(pkt_l4_443).unwrap();
        let ctx = aips_rules::engine::MatchCtx {
            payload: pkt.payload(),
            src_ip:  pkt.src_ip,
            dst_ip:  pkt.dst_ip,
            src_port: pkt.src_port.unwrap_or(0),
            dst_port: pkt.dst_port.unwrap_or(0),
            ttl: qos.ttl,
            dscp: qos.dscp,
            ecn: qos.ecn,
        };
        b.iter(|| {
            let action = large_engine.evaluate(black_box(&ctx), 0);
            black_box(action);
        })
    });
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
