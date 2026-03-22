#![no_main]

use libfuzzer_sys::fuzz_target;
use aips_core::classifier::Classifier;
use aips_core::layer::PacketView;
use aips_rules::engine::RuleEngine;
use aips_rules::rule::*;
use aips_rules::action::*;

fuzz_target!(|data: &[u8]| {
    // 1. Setup minimal engine
    let mut engine = RuleEngine::<'static, 128, 512, 1024>::new();
    let _ = engine.add_rule(Rule {
        id: 1,
        name: "Fuzz Rule 1",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"attack", case_insensitive: true }),
        action: Action::Alert,
    });
    let _ = engine.add_rule(Rule {
        id: 2,
        name: "Fuzz SSH",
        match_expr: MatchExpr::SshBanner("OpenSSH"),
        action: Action::Alert,
    });
    engine.build();

    // 2. Setup classifier
    let mut classifier = Classifier::<1024>::new();
    let _ = classifier.add_service(aips_core::classifier::Service {
        protocol: aips_core::classifier::L7Protocol::Http,
        server_port: 80,
    });

    // 3. Fuzz the parser
    if let Some(pkt) = PacketView::parse(data) {
        let qos = aips_core::qos::QosFields { dscp: 0, ecn: 0, ttl: 64 };
        let decision = classifier.classify(&pkt, qos);

        // 4. Fuzz L7 Dispatcher if it's a proxied flow
        if let aips_core::Decision::ProxyTcp(proto) = decision {
            let mut dns_buf = [0u8; 512];
            let mut http_buf = [httparse::EMPTY_HEADER; 32];
            
            let verdict = aips_l7::dispatcher::L7Dispatcher::dispatch(
                pkt.payload(),
                proto,
                &mut dns_buf,
                &mut http_buf
            );

            // 5. Fuzz Rule Evaluation
            let mut src_ip = [0u8; 16];
            src_ip[12..16].copy_from_slice(&pkt.src_ip[0..4]);
            
            let ctx = aips_l7::dispatcher::L7Dispatcher::to_match_ctx(
                &verdict,
                pkt.payload(),
                pkt.dst_port.unwrap_or(0),
                src_ip
            );
            
            let _ = engine.evaluate(&ctx, 0);
        }
    }
});
