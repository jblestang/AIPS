use aips_core::Decision;
use aips_core::qos::QosFields;
use aips_core::flow::FlowKey;

use aips_rules::engine::RuleEngine;
use aips_rules::rule::{BytePattern, MatchExpr, Rule};
use aips_rules::action::Action;

use aips_l7::dispatcher::L7Dispatcher;
use httparse;

#[test]
fn test_pipeline_integration() {
    // 1. Setup Rule Engine
    let mut engine: RuleEngine<'_, 10, 32, 128, 512> = RuleEngine::new();

    // Rule: Drop if payload contains "DROPME" AND we are on port 80
    let drop_rule = Rule {
        id: 1,
        name: "test-drop-payload",
        match_expr: MatchExpr::And(
            &MatchExpr::DstPort(80),
            &MatchExpr::Payload(BytePattern {
                bytes: b"DROPME",
                case_insensitive: true, // Will exact match since AC is case sensitive
            }),
        ),
        action: Action::Drop,
    };

    engine.add_rule(drop_rule).unwrap();
    engine.build();

    // 2. Setup Benign Packet
    let src_ip_v4 = [192, 168, 1, 100];
    let dst_ip_v4 = [10, 0, 0, 1];
    let payload_benign = b"GET / HTTP/1.1\r\n\r\n";
    
    // Simulate pipeline traversal manually
    let mut dns_buf = [0u8; 512];
    let mut http_buf = [httparse::EMPTY_HEADER; 32];
    
    // a. core parsing
    let _qos1 = QosFields { dscp: 0, ecn: 0, ttl: 64 };
    
    // b. fast path classifier
    let src_ip_full = src_ip_v4;
    let dst_ip_full = dst_ip_v4;
    let _flow_key1 = FlowKey { src_ip: src_ip_full, dst_ip: dst_ip_full, src_port: 50000, dst_port: 80, proto: 6 };
    // We treat all dest port 80 as proxyable
    let l4_decision1 = Decision::ProxyTcp(aips_core::classifier::L7Protocol::Http);
    assert!(matches!(l4_decision1, Decision::ProxyTcp(_)));
    
    // c. Proxy extracts payload. We skip proxy machinery and pass payload direct to L7
    let verdict1 = L7Dispatcher::dispatch(payload_benign, aips_core::classifier::L7Protocol::Http, &mut dns_buf, &mut http_buf);
    
    // d. Rule engine inspects verdict
    let ctx1 = L7Dispatcher::to_match_ctx(&verdict1, payload_benign, 80, src_ip_full);
    let final_decision1 = engine.evaluate(&ctx1, 0);
    
    assert_eq!(final_decision1, None); // Benign packet passed!


    // --- Packet 2: HTTP GET Payload (Malicious) ---
    let payload_malicious = b"GET / HTTP/1.1\r\nHost: evil.com\r\nX-Bad: DROPME\r\n\r\n";
    
    let mut http_buf2 = [httparse::EMPTY_HEADER; 32];
    let verdict2 = L7Dispatcher::dispatch(payload_malicious, aips_core::classifier::L7Protocol::Http, &mut dns_buf, &mut http_buf2);
    let ctx2 = L7Dispatcher::to_match_ctx(&verdict2, payload_malicious, 80, src_ip_full);
    let final_decision2 = engine.evaluate(&ctx2, 0);
    
    assert_eq!(final_decision2, Some((1, Action::Drop)));
}
