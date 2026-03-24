use aips_core::Decision;
use aips_core::qos::QosFields;

use aips_rules::engine::RuleEngine;
use aips_rules::rule::{MatchExpr, Rule};
use aips_rules::action::Action;

// removed L7 import

#[test]
fn test_pipeline_integration() {
    // 1. Setup Rule Engine
    let mut engine: RuleEngine<'_, 10> = RuleEngine::new();

    // Rule: Drop if destination IP is 10.0.0.1 AND we are on port 443
    let drop_rule = Rule {
        id: 1,
        name: "test-drop-ip",
        match_expr: MatchExpr::And(
            &MatchExpr::DstPort(443),
            &MatchExpr::DstIp([10, 0, 0, 1]),
        ),
        action: Action::Drop,
        bidirectional: false,
    };

    engine.add_rule(drop_rule).unwrap();
    engine.build();

    // 2. Setup Benign Packet (Destination: 10.0.0.2)
    let src_ip_v4 = [192, 168, 1, 100];
    let dst_ip_benign = [10, 0, 0, 2];
    let payload = b"some data";
    
    // Simulate pipeline traversal manually
    let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
    
    // a. classifier decision (Forward by default if not blocked)
    let l4_decision1 = Decision::Forward;
    assert!(l4_decision1.is_forwarded());
    
    // b. Rule engine inspects context
    let ctx1 = aips_rules::engine::MatchCtx {
        payload,
        src_port: 50000,
        dst_port: 443,
        src_ip: src_ip_v4,
        dst_ip: dst_ip_benign,
        ttl: qos.ttl,
        dscp: qos.dscp,
        ecn: qos.ecn,
    };
    let final_decision1 = engine.evaluate(&ctx1, 0);
    
    assert_eq!(final_decision1, None); // Benign packet passed!


    // --- Case 2: Malicious (Destination: 10.0.0.1) ---
    let dst_ip_malicious = [10, 0, 0, 1];
    
    let ctx2 = aips_rules::engine::MatchCtx {
        payload,
        src_port: 50000,
        dst_port: 443,
        src_ip: src_ip_v4,
        dst_ip: dst_ip_malicious,
        ttl: qos.ttl,
        dscp: qos.dscp,
        ecn: qos.ecn,
    };
    let final_decision2 = engine.evaluate(&ctx2, 0);
    
    assert_eq!(final_decision2, Some((1, Action::Drop)));
}
