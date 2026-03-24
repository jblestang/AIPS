//! Rule engine: evaluates rules against L7 analysis results.

use heapless::Vec;

use crate::{
    action::Action,
    rule::{MatchExpr, Rule},
};

/// Token-bucket rate limiter (per-flow, fixed table).
#[derive(Clone, Copy, Default)]
struct TokenBucket {
    tokens: u32,
    last_refill_ms: u64,
    max_pps: u32,
    initialized: bool,
}

impl TokenBucket {
    fn allow(&mut self, now_ms: u64) -> bool {
        if self.max_pps == 0 { return false; } // 0 PPS = block all

        if !self.initialized {
            self.tokens = self.max_pps;
            self.last_refill_ms = now_ms;
            self.initialized = true;
        }

        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        if elapsed > 0 {
            let refill = (elapsed as u32).saturating_mul(self.max_pps) / 1000;
            if refill > 0 {
                self.tokens = self.tokens.saturating_add(refill).min(self.max_pps);
                
                // Only advance the last refill timer by the time accounted for
                // by the generated tokens to prevent fractional time loss.
                let account_ms = (refill as u64 * 1000) / (self.max_pps as u64);
                self.last_refill_ms += account_ms;
            }
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Context passed to the rule engine for a single packet/stream.
pub struct MatchCtx<'a> {
    /// Raw L7 payload bytes.
    pub payload: &'a [u8],
    /// Source Port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Source IP (IPv4).
    pub src_ip: [u8; 4],
    /// Destination IP (IPv4).
    pub dst_ip: [u8; 4],
    /// IP Time-To-Live.
    pub ttl: u8,
    /// Differentiated Services Code Point.
    pub dscp: u8,
    /// Explicit Congestion Notification.
    pub ecn: u8,
}

impl<'a> MatchCtx<'a> {
    /// Helper to create a MatchCtx from a PacketView and QoS fields.
    pub fn from_packet(pkt: &'a aips_core::layer::PacketView<'a>, qos: &aips_core::qos::QosFields) -> Self {
        Self {
            payload: pkt.payload(),
            src_port: pkt.src_port.unwrap_or(0),
            dst_port: pkt.dst_port.unwrap_or(0),
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            ttl: qos.ttl,
            dscp: qos.dscp,
            ecn: qos.ecn,
        }
    }

    /// Create a reversed version of the context (swapping src/dst IPs and ports).
    /// Used for matching bi-directional rules.
    pub fn reverse(&self) -> Self {
        Self {
            payload: self.payload,
            src_port: self.dst_port,
            dst_port: self.src_port,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            ttl: self.ttl,
            dscp: self.dscp,
            ecn: self.ecn,
        }
    }
}

/// * `R` = max rules
pub struct RuleEngine<'r, const R: usize> {
    rules: Vec<Rule<'r>, R>,
    rate_limiters: [TokenBucket; R],
}

impl<'r, const R: usize> aips_core::classifier::Policy for RuleEngine<'r, R> {
    fn evaluate(&mut self, pkt: &aips_core::layer::PacketView<'_>, qos: &aips_core::qos::QosFields, now_ms: u64) -> aips_core::decision::Decision {
        let ctx = MatchCtx::from_packet(pkt, qos);
        match self.evaluate(&ctx, now_ms) {
            Some((_id, Action::Drop))  => aips_core::decision::Decision::Drop,
            Some((_id, Action::Alert)) => aips_core::decision::Decision::Forward, // Alert doesn't stop it
            Some((_id, Action::Pass))  => aips_core::decision::Decision::Forward,
            Some((_id, Action::RateLimit { .. })) => {
                // The internal evaluate() already handled rate limiting and might have returned Action::Drop
                // if the limit was exceeded.
                aips_core::decision::Decision::Forward
            }
            None => {
                // Default-deny for TCP/UDP if no rules matched
                match pkt.l4_proto {
                    Some(aips_core::layer::L4Proto::Tcp) | Some(aips_core::layer::L4Proto::Udp) => {
                        aips_core::decision::Decision::Violation
                    }
                    _ => aips_core::decision::Decision::Forward
                }
            }
        }
    }
}

impl<'r, const R: usize> RuleEngine<'r, R> {
    /// Creates an empty, unconfigured rule engine.
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            rate_limiters: [TokenBucket { tokens: 0, last_refill_ms: 0, max_pps: 0, initialized: false }; R],
        }
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: Rule<'r>) -> Result<(), ()> {
        self.rules.push(rule).map_err(|_| ())
    }

    /// No-op for backwards compatibility in API.
    pub fn build(&mut self) {}

    /// Evaluate all rules against `ctx`.
    ///
    /// Returns the first matching rule's `Action`, or `None` if no rule fires.
    /// `now_ms` is used for token-bucket rate limiting.
    pub fn evaluate(&mut self, ctx: &MatchCtx<'_>, now_ms: u64) -> Option<(u32, Action)> {
        for (i, rule) in self.rules.iter().enumerate() {
            let mut is_match = self.matches(rule, ctx);
            
            // If the rule is bidirectional and it didn't match the original context,
            // try matching the reversed context.
            if !is_match && rule.bidirectional {
                is_match = self.matches(rule, &ctx.reverse());
            }

            if is_match {
                let action = match rule.action {
                    Action::RateLimit { pps } => {
                        self.rate_limiters[i].max_pps = pps;
                        if self.rate_limiters[i].allow(now_ms) {
                            continue; // within limit — no action
                        }
                        Action::Drop
                    }
                    other => other,
                };
                return Some((rule.id, action));
            }
        }
        None
    }

    fn matches(&self, rule: &Rule<'_>, ctx: &MatchCtx<'_>) -> bool {
        self.eval_expr(&rule.match_expr, ctx)
    }

    fn eval_expr(&self, expr: &MatchExpr<'_>, ctx: &MatchCtx<'_>) -> bool {
        match expr {
            MatchExpr::DstPort(p) => ctx.dst_port == *p,
            MatchExpr::SrcPort(p) => ctx.src_port == *p,
            MatchExpr::SrcIp(ip)  => ctx.src_ip == *ip,
            MatchExpr::DstIp(ip)  => ctx.dst_ip == *ip,

            MatchExpr::SrcIpPrefix { prefix, prefix_len } => {
                ip_prefix_match(&ctx.src_ip, prefix, *prefix_len)
            }

            MatchExpr::Ttl(t)  => ctx.ttl == *t,
            MatchExpr::Dscp(d) => ctx.dscp == *d,
            MatchExpr::Ecn(e)  => ctx.ecn == *e,

            MatchExpr::And(a, b) => self.eval_expr(a, ctx) && self.eval_expr(b, ctx),
            MatchExpr::Or(a, b)  => self.eval_expr(a, ctx) || self.eval_expr(b, ctx),
        }
    }
}

// --- helpers ---

fn ip_prefix_match(addr: &[u8; 4], prefix: &[u8; 4], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let rem_bits   = bits % 8;
    for i in 0..full_bytes.min(4) {
        if addr[i] != prefix[i] { return false; }
    }
    if rem_bits > 0 && full_bytes < 4 {
        let mask = 0xFFu8 << (8 - rem_bits);
        if addr[full_bytes] & mask != (prefix[full_bytes] & mask) { return false; }
    }
    true
}
