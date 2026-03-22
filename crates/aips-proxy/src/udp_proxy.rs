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
//!    with the original captured `QosFields` (DSCP, ECN, TTL) explicitly injected onto the new IPv4/IPv6 header.

use aips_core::QosFields;
use aips_rules::engine::RuleEngine;
use aips_rules::action::Action;
use aips_l7::L7Dispatcher;

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

/// UDP proxy engine.
///
/// `R`, `P`, `S` are forwarded to the underlying `RuleEngine`.
pub struct UdpProxy<'r, const R: usize, const P: usize, const S: usize> {
    rules: RuleEngine<'r, R, P, S>,
}

impl<'r, const R: usize, const P: usize, const S: usize> UdpProxy<'r, R, P, S> {
    /// Create a new UDP proxy with the given rule engine.
    pub fn new(rules: RuleEngine<'r, R, P, S>) -> Self {
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
        protocol: aips_core::classifier::L7Protocol,
        dst_port: u16,
        src_ip:   [u8; 16],
        _qos:     QosFields,   // Currently bypassed natively as TX re-stamping occurs inside the bridge caller statically
        now_ms:   u64,
    ) -> UdpDecision {
        // High-density, allocation-free local scratch buffers statically initialized entirely on the stack natively
        let mut dns_name_buf    = [0u8; 256];
        let mut http_header_buf = [httparse::EMPTY_HEADER; 32];

        // L7 Dispatch securely interprets structural layout (e.g. jumping straight to DNS Query sections natively)
        let verdict = L7Dispatcher::dispatch(
            payload, protocol, &mut dns_name_buf, &mut http_header_buf,
        );
        let ctx = L7Dispatcher::to_match_ctx(&verdict, payload, dst_port, src_ip);

        match self.rules.evaluate(&ctx, now_ms) {
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
    use aips_core::classifier::L7Protocol;

    /// Evaluates base empty initialization generating Forward native bypass vectors strictly.
    #[test]
    fn test_udp_proxy_forwards_clean_payloads_safely() {
        let rules: RuleEngine<'static, 64, 64, 64> = RuleEngine::new();
        let mut proxy = UdpProxy::new(rules);
        
        let dummy_payload = b"test payload";
        let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
        
        let decision = proxy.inspect(dummy_payload, L7Protocol::Unknown, 1234, [0; 16], qos, 100);
        assert_eq!(decision, UdpDecision::Forward, "Test: Blank rule proxies definitively forward payloads inherently safely!");
    }

    /// Extends evaluation natively proving UDP rate limits drop natively gracefully.
    #[test]
    fn test_udp_rate_limit_forces_instant_drop() {
        // We simulate a rate limit triggering immediately manually via rule bindings natively
        let mut rules: RuleEngine<'static, 64, 64, 64> = RuleEngine::new();
        
        // Push a generic rule that RateLimits ALL UDP Port 53 Traffic natively
        use aips_rules::rule::{Rule, MatchExpr};
        use aips_rules::action::Action;
        
        rules.add_rule(Rule {
            id: 1,
            name: "dns_rate_limit",
            match_expr: MatchExpr::DstPort(53),
            action: Action::RateLimit { pps: 0 }, // 0 PPS forces constant guaranteed dropping naturally
        }).unwrap();

        let mut proxy = UdpProxy::new(rules);
        
        let query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"; // Generic valid DNS
        let qos = QosFields { dscp: 0, ecn: 0, ttl: 64 };
        
        // Execute frame 1. Rule limits 0 PPS, so this instantly terminates the frame safely natively
        let decision1 = proxy.inspect(query, L7Protocol::Dns, 53, [0; 16], qos, 1000);
        assert_eq!(decision1, UdpDecision::Drop, "Test: Hard limits structurally return silent localized Dropping successfully!");
    }
}
