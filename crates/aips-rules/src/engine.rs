//! Rule engine: evaluates rules against L7 analysis results.

use heapless::Vec;

use crate::{
    action::Action,
    aho_corasick::AhoCorasick,
    rule::{BytePattern, MatchExpr, Rule},
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
    /// HTTP `Host:` header value (if parsed).
    pub http_host: Option<&'a str>,
    /// DNS query name (if parsed).
    pub dns_name: Option<&'a str>,
    /// TLS SNI hostname (if parsed).
    pub tls_sni: Option<&'a str>,
    /// NTP mode byte (if parsed).
    pub ntp_mode: Option<u8>,
    /// SSH identification banner (if parsed).
    pub ssh_banner: Option<&'a str>,
    /// Destination port.
    pub dst_port: u16,
    /// Source IP (IPv4).
    pub src_ip: [u8; 4],
}

/// * `R` = max rules
/// * `P` / `S` / `T` = Aho-Corasick pattern/state/transition capacity
pub struct RuleEngine<'r, const R: usize, const P: usize, const S: usize, const T: usize> {
    rules: Vec<Rule<'r>, R>,
    ac:    AhoCorasick<P, S, T>,
    ac_built: bool,
    rate_limiters: [TokenBucket; R],
}

impl<'r, const R: usize, const P: usize, const S: usize, const T: usize> RuleEngine<'r, R, P, S, T> {
    /// Creates an empty, unconfigured rule engine.
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            ac: AhoCorasick::new(),
            ac_built: false,
            rate_limiters: [TokenBucket { tokens: 0, last_refill_ms: 0, max_pps: 0, initialized: false }; R],
        }
    }

    /// Add a rule. Call [`build`](Self::build) after adding all rules.
    pub fn add_rule(&mut self, rule: Rule<'r>) -> Result<(), ()> {
        // Register all payload patterns in the AC automaton.
        self.register_payloads(&rule.match_expr, rule.id)?;
        self.rules.push(rule).map_err(|_| ())
    }

    fn register_payloads(&mut self, expr: &MatchExpr<'_>, rule_id: u32) -> Result<(), ()> {
        match expr {
            MatchExpr::Payload(BytePattern { bytes, .. }) => {
                self.ac.add_pattern(bytes, rule_id)?;
            }
            MatchExpr::And(a, b) | MatchExpr::Or(a, b) => {
                self.register_payloads(a, rule_id)?;
                self.register_payloads(b, rule_id)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Compile the Aho-Corasick automaton. Must be called before `evaluate`.
    pub fn build(&mut self) {
        self.ac.build();
        self.ac_built = true;
    }

    /// Evaluate all rules against `ctx`.
    ///
    /// Returns the first matching rule's `Action`, or `None` if no rule fires.
    /// `now_ms` is used for token-bucket rate limiting.
    pub fn evaluate(&mut self, ctx: &MatchCtx<'_>, now_ms: u64) -> Option<(u32, Action)> {
        for (i, rule) in self.rules.iter().enumerate() {
            if self.matches(rule, ctx) {
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
        self.eval_expr(&rule.match_expr, ctx, rule.id)
    }

    fn eval_expr(&self, expr: &MatchExpr<'_>, ctx: &MatchCtx<'_>, rule_id: u32) -> bool {
        match expr {
            MatchExpr::DstPort(p) => ctx.dst_port == *p,

            MatchExpr::SrcIpPrefix { prefix, prefix_len } => {
                ip_prefix_match(&ctx.src_ip, prefix, *prefix_len)
            }

            MatchExpr::Payload(pat) => {
                // Fast path: use the AC automaton for patterns registered at build time.
                if self.ac_built {
                    self.ac.search(ctx.payload) == Some(rule_id)
                } else {
                    // Fallback naive search (before build())
                    naive_contains(ctx.payload, pat.bytes, pat.case_insensitive)
                }
            }

            MatchExpr::HttpHost(host) => ctx
                .http_host
                .map(|h| h.eq_ignore_ascii_case(host))
                .unwrap_or(false),

            MatchExpr::DnsNameSuffix(suffix) => ctx
                .dns_name
                .map(|n| {
                    n.len() >= suffix.len()
                        && n[n.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
                })
                .unwrap_or(false),

            MatchExpr::TlsSni(sni) => ctx
                .tls_sni
                .map(|s| s.eq_ignore_ascii_case(sni))
                .unwrap_or(false),

            MatchExpr::NtpMode(m) => ctx.ntp_mode == Some(*m),

            MatchExpr::SshBanner(b) => ctx.ssh_banner.map(|banner| banner.contains(b)).unwrap_or(false),

            MatchExpr::And(a, b) => self.eval_expr(a, ctx, rule_id) && self.eval_expr(b, ctx, rule_id),
            MatchExpr::Or(a, b)  => self.eval_expr(a, ctx, rule_id) || self.eval_expr(b, ctx, rule_id),
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

fn naive_contains(haystack: &[u8], needle: &[u8], ci: bool) -> bool {
    if needle.is_empty() { return true; }
    if haystack.len() < needle.len() { return false; }
    for window in haystack.windows(needle.len()) {
        let matches = if ci {
            window.iter().zip(needle.iter()).all(|(a, b)| {
                a.to_ascii_lowercase() == b.to_ascii_lowercase()
            })
        } else {
            window == needle
        };
        if matches { return true; }
    }
    false
}
