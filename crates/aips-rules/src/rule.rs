//! Rule definition types.

use crate::action::Action;

/// Conditions that can be checked against packet/stream metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchExpr<'r> {
    /// Match any packet on a specific destination port.
    DstPort(u16),
    /// Match any packet on a specific source port.
    SrcPort(u16),
    /// Match a specific source IP (IPv4).
    SrcIp([u8; 4]),
    /// Match a specific destination IP (IPv4).
    DstIp([u8; 4]),
    /// Match a source IP prefix (first `prefix_len` bits).
    SrcIpPrefix {
        /// The IPv4 prefix bytes.
        prefix: [u8; 4],
        /// Number of significant bits (0-32).
        prefix_len: u8,
    },
    /// Match IP Time-To-Live.
    Ttl(u8),
    /// Match Differentiated Services Code Point.
    Dscp(u8),
    /// Match Explicit Congestion Notification.
    Ecn(u8),
    /// Logical AND of two expressions.
    And(&'r MatchExpr<'r>, &'r MatchExpr<'r>),
    /// Logical OR of two expressions.
    Or(&'r MatchExpr<'r>, &'r MatchExpr<'r>),
}

/// A single IPS/IDS rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule<'r> {
    /// Unique rule identifier.
    pub id: u32,
    /// Human-readable description.
    pub name: &'r str,
    /// The match condition.
    pub match_expr: MatchExpr<'r>,
    /// The action to take when this rule matches.
    pub action: Action,
    /// Whether the rule should also match the reverse of the packet context.
    pub bidirectional: bool,
}
