//! Rule definition types.

use crate::action::Action;

/// A byte pattern to match anywhere inside the L7 payload.
#[derive(Debug, Clone, Copy)]
pub struct BytePattern<'r> {
    /// The literal bytes to search for.
    pub bytes: &'r [u8],
    /// Whether the match is case-insensitive (for ASCII text protocols).
    pub case_insensitive: bool,
}

/// Conditions that can be checked against packet/stream metadata.
#[derive(Debug, Clone, Copy)]
pub enum MatchExpr<'r> {
    /// Match any packet on a specific destination port.
    DstPort(u16),
    /// Match a source IP prefix (first `prefix_len` bits).
    SrcIpPrefix {
        /// The IP prefix bytes (up to 16 bytes for IPv6).
        prefix: [u8; 16],
        /// Number of significant bits.
        prefix_len: u8,
    },
    /// Match a byte pattern in the L7 payload.
    Payload(BytePattern<'r>),
    /// Match an HTTP `Host:` header value (exact, case-insensitive).
    HttpHost(&'r str),
    /// Match a DNS query name suffix (e.g. `.malicious.example`).
    DnsNameSuffix(&'r str),
    /// Match a TLS SNI hostname.
    TlsSni(&'r str),
    /// Match an NTP mode byte (e.g. mode 7 = private/MONLIST).
    NtpMode(u8),
    /// Match an SSH identification string (e.g. "SSH-2.0-OpenSSH_7.2").
    SshBanner(&'r str),
    /// Logical AND of two expressions.
    And(&'r MatchExpr<'r>, &'r MatchExpr<'r>),
    /// Logical OR of two expressions.
    Or(&'r MatchExpr<'r>, &'r MatchExpr<'r>),
}

/// A single IPS/IDS rule.
#[derive(Debug, Clone, Copy)]
pub struct Rule<'r> {
    /// Unique rule identifier.
    pub id: u32,
    /// Human-readable description.
    pub name: &'r str,
    /// The match condition.
    pub match_expr: MatchExpr<'r>,
    /// The action to take when this rule matches.
    pub action: Action,
}
