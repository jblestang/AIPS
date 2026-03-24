//! # L4 Connectionless UDP Datagram Proxy
//!
//! Unlike TCP which requires stateful complex session tracking and bidirectional Handshake interception, 
//! UDP is natively connectionless. The AIPS `UdpProxy` essentially acts as an instantaneous bump-in-the-wire 
//! buffer pool.
//!
//! ## Execution Lifecycle 
//! 1. **Ingest & Buffer**: An inbound UDP frame is sliced directly from the L2/L3 NIC rings safely.
//! 2. **L7 Protocol Dispatch**: Because there is no stream to reassemble, the raw payload is instantly fired 
//!    into the `L7Dispatcher` (e.g. searching for DNS Queries or Amplification attacks).
//! 3. **Rule Assessment**: The output of the Dispatcher maps against the user's explicit ACLs (`Drop`, `Alert`).
//! 4. **Egress or Void**: If `Forward`, the exact same payload slice is pushed to the transmission ring-buffer, 
//!    with the original captured `QosFields` (DSCP, ECN, TTL) explicitly injected onto the new IPv4 header.

use aips_core::qos::QosFields;
use aips_rules::engine::RuleEngine;
use aips_rules::action::Action;

#[allow(dead_code)]
const MAX_UDP_PAYLOAD: usize = 4096;

/// Deterministic action directive returned by the stateless UDP inspection engine safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpDecision {
    /// Zero critical signatures found. The routing platform should immediately serialize the 
    /// provided payload buffer onto the TX interface alongside its original network tags natively.
    Forward,
    /// Malicious signature matched (e.g. known CNC domain, Amplification vector). 
    /// The routing platform should securely void the buffer instantly.
    Drop,
    /// Diagnostic trace rules matched natively. The system must generate a log vector but 
    /// transmit the payload to avoid disrupting expected functional paths.
    Alert(u32 /* rule_id */),
}

/// `R` is forwarded to the underlying `RuleEngine`.
pub struct UdpProxy<'r, const R: usize> {
    rules: RuleEngine<'r, R>,
}

impl<'r, const R: usize> UdpProxy<'r, R> {
    /// Create a new UDP proxy with the given rule engine.
    pub fn new(rules: RuleEngine<'r, R>) -> Self {
        Self { rules }
    }

    /// Single-frame inspection fast-path evaluation loop natively.
    ///
    /// This function performs zero-copy classification of a raw `payload` buffer by temporarily 
    /// allocating DNS/HTTP parser scratch buffers on the local stack natively to prevent alloc panics.
    ///
    /// `payload`   — Absolute memory reference to the received interface segment natively.
    /// `protocol`  — Highly optimized heuristic L7 mapping (e.g. explicitly expecting DNS).
    /// `dst_port`  — Required parameter used for explicit `aips-rules` target mapping natively.
    /// `src_ip`    — Origin identifier mapped statically for IP-range based malicious dropping.
    /// `_qos`      — Passed purely syntactically; the higher level routing bridge extracts this for TX execution natively.
    /// `now_ms`    — Active time boundary mapping required for native rate-limit token-bucket processing safely.
    pub fn inspect(
        &mut self,
        payload:  &[u8],
        src_ip:   [u8; 4],
        dst_ip:   [u8; 4],
        src_port: u16,
        dst_port: u16,
        qos:      QosFields,
        now_ms:   u64,
    ) -> UdpDecision {
        let ctx = aips_rules::engine::MatchCtx {
            payload,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ttl:  qos.ttl,
            dscp: qos.dscp,
            ecn:  qos.ecn,
        };

        match self.rules.evaluate(&ctx, now_ms) {
            Some((_id, Action::Pass)) => UdpDecision::Forward,
            Some((_id, Action::Drop)) => UdpDecision::Drop,
            Some((id, Action::Alert)) => UdpDecision::Alert(id),
            // UDP Rate limits trigger a hard Drop to mathematically sever the amplification chain natively
            Some((_id, Action::RateLimit { .. })) => UdpDecision::Drop,
            None => UdpDecision::Forward,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evaluates base empty initialization generating Forward native bypass vectors strictly.
    #[test]
    fn test_udp_proxy_forwards_clean_payloads_safely() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let mut proxy = UdpProxy::new(rules);
        
        let dummy_payload = b"test payload";
        let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
        
        let decision = proxy.inspect(dummy_payload, [0; 4], [0; 4], 0, 1234, qos, 100);
        assert_eq!(decision, UdpDecision::Forward, "Test: Blank rule proxies definitively forward payloads inherently safely!");
    }

    /// Extends evaluation natively proving UDP rate limits drop natively gracefully.
    #[test]
    fn test_udp_rate_limit_forces_instant_drop() {
        // We simulate a rate limit triggering immediately manually via rule bindings natively
        let mut rules: RuleEngine<'static, 64> = RuleEngine::new();
        
        // Push a generic rule that RateLimits ALL SSH Traffic natively
        use aips_rules::rule::{Rule, MatchExpr};
        use aips_rules::action::Action;
        
        rules.add_rule(Rule {
            id: 1,
            name: "ssh_rate_limit",
            match_expr: MatchExpr::DstPort(22),
            action: Action::RateLimit { pps: 0 }, // 0 PPS forces constant guaranteed dropping naturally
            bidirectional: false,
        }).unwrap();

        let mut proxy = UdpProxy::new(rules);
        
        let query = b"SSH-2.0-OpenSSH_7.2"; 
        let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
        
        // Execute frame 1. Rule limits 0 PPS, so this instantly terminates the frame safely natively
        let decision1 = proxy.inspect(query, [0; 4], [10, 0, 0, 22], 50000, 22, qos, 1000);
        assert_eq!(decision1, UdpDecision::Drop, "Test: Hard limits structurally return silent localized Dropping successfully!");
    }
}
