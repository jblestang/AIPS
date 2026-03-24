use aips_rules::action::Action;
use aips_rules::engine::{MatchCtx, RuleEngine};
use aips_rules::rule::{MatchExpr, Rule};

#[test]
fn test_rule_engine_basic_match() {
    let mut engine: RuleEngine<'_, 10> = RuleEngine::new();

    let r1 = Rule {
        id: 1,
        name: "test_drop",
        match_expr: MatchExpr::And(
            &MatchExpr::DstPort(443),
            &MatchExpr::DstIp([10, 0, 0, 5]),
        ),
        action: Action::Drop,
        bidirectional: false,
    };

    let r2 = Rule {
        id: 2,
        name: "test_alert",
        match_expr: MatchExpr::SrcPort(22),
        action: Action::Alert,
        bidirectional: false,
    };

    engine.add_rule(r1).unwrap();
    engine.add_rule(r2).unwrap();
    engine.build(); 

    let ctx1 = MatchCtx {
        payload: b"",
        src_port: 50000,
        dst_port: 443,
        src_ip: [0; 4],
        dst_ip: [10, 0, 0, 5],
        ttl: 64,
        dscp: 0,
        ecn: 0,
    };
    
    let res1 = engine.evaluate(&ctx1, 0);
    assert_eq!(res1, Some((1, Action::Drop)));
}

#[test]
fn test_token_bucket_rate_limiter() {
    let mut engine: RuleEngine<'_, 1> = RuleEngine::new();

    let r1 = Rule {
        id: 100,
        name: "test_ratelimit",
        match_expr: MatchExpr::DstPort(123),
        action: Action::RateLimit { pps: 2 },
        bidirectional: false,
    };

    engine.add_rule(r1).unwrap();
    engine.build();

    let ctx = MatchCtx {
        payload: b"",
        src_port: 50000,
        dst_port: 123,
        src_ip: [0; 4],
        dst_ip: [0; 4],
        ttl: 64, dscp: 0, ecn: 0,
    };

    assert_eq!(engine.evaluate(&ctx, 0), None);
    assert_eq!(engine.evaluate(&ctx, 0), None);
    assert_eq!(engine.evaluate(&ctx, 0), Some((100, Action::Drop)));
}

#[test]
fn test_bidirectional_rule() {
    let mut engine: RuleEngine<'_, 1> = RuleEngine::new();

    let r_bi = Rule {
        id: 7,
        name: "bi_ssh",
        match_expr: MatchExpr::DstPort(22),
        action: Action::Alert,
        bidirectional: true,
    };

    engine.add_rule(r_bi).unwrap();
    engine.build();

    let ctx_fwd = MatchCtx {
        payload: b"",
        src_port: 12345,
        dst_port: 22,
        src_ip: [10, 0, 0, 1],
        dst_ip: [10, 0, 0, 2],
        ttl: 64, dscp: 0, ecn: 0,
    };
    assert_eq!(engine.evaluate(&ctx_fwd, 0), Some((7, Action::Alert)));

    let ctx_rev = MatchCtx {
        payload: b"",
        src_port: 22,
        dst_port: 12345,
        src_ip: [10, 0, 0, 2],
        dst_ip: [10, 0, 0, 1],
        ttl: 64, dscp: 0, ecn: 0,
    };
    assert_eq!(engine.evaluate(&ctx_rev, 0), Some((7, Action::Alert)));
}
