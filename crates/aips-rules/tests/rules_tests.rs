use aips_rules::action::Action;
use aips_rules::engine::{MatchCtx, RuleEngine};
use aips_rules::rule::{BytePattern, MatchExpr, Rule};

#[test]
fn test_rule_engine_basic_match() {
    let mut engine: RuleEngine<'_, 10, 32, 128> = RuleEngine::new();

    let r1 = Rule {
        id: 1,
        name: "test_drop",
        match_expr: MatchExpr::And(
            &MatchExpr::DstPort(80),
            &MatchExpr::Payload(BytePattern {
                bytes: b"malicious",
                case_insensitive: true,
            }),
        ),
        action: Action::Drop,
    };

    let r2 = Rule {
        id: 2,
        name: "test_alert",
        match_expr: MatchExpr::DnsNameSuffix("evil.com"),
        action: Action::Alert,
    };

    engine.add_rule(r1).unwrap();
    engine.add_rule(r2).unwrap();
    engine.build(); // compile Aho-Corasick

    let ctx1 = MatchCtx {
        payload: b"GET / HTTP/1.1\r\nHost: test.com\r\nX-malicious-payload: yes\r\n",
        http_host: Some("test.com"),
        dns_name: None,
        tls_sni: None,
        ntp_mode: None,
        dst_port: 80,
        src_ip: [0; 16],
        ssh_banner: None,
    };
    
    let mut tmp_ac: aips_rules::aho_corasick::AhoCorasick<32, 128> = aips_rules::aho_corasick::AhoCorasick::new();
    tmp_ac.add_pattern(b"malicious", 1).unwrap();
    tmp_ac.build();
    println!("Direct AC Search: {:?}", tmp_ac.search(b"GET / HTTP/1.1\r\nHost: test.com\r\nX-malicious-payload: yes\r\n"));

    let res1 = engine.evaluate(&ctx1, 0);
    println!("Test Case 1 Res: {:?}", res1);
    assert_eq!(res1, Some((1, Action::Drop)));
}

#[test]
fn test_token_bucket_rate_limiter() {
    let mut engine: RuleEngine<'_, 1, 1, 1> = RuleEngine::new();

    let r1 = Rule {
        id: 100,
        name: "test_ratelimit",
        match_expr: MatchExpr::DstPort(123),
        action: Action::RateLimit { pps: 2 },
    };

    engine.add_rule(r1).unwrap();
    engine.build();

    let ctx = MatchCtx {
        payload: b"",
        http_host: None,
        dns_name: None,
        tls_sni: None,
        ntp_mode: None,
        dst_port: 123,
        src_ip: [0; 16],
        ssh_banner: None,
    };

    println!("T=0, Pkt=1");
    assert_eq!(engine.evaluate(&ctx, 0), None);
    println!("T=0, Pkt=2");
    assert_eq!(engine.evaluate(&ctx, 0), None);
    println!("T=0, Pkt=3");
    let r = engine.evaluate(&ctx, 0);
    println!("T=0, Pkt=3 Res: {:?}", r);
    assert_eq!(r, Some((100, Action::Drop)));
}
