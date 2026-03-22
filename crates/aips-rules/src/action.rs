//! Rule action types.

/// The action to take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Generate an alert log entry but still forward the packet/stream.
    /// Used in IDS (alert-only) mode.
    Alert,
    /// Drop the packet / RST the connection.
    /// Used in IPS (inline prevention) mode.
    Drop,
    /// Rate-limit this flow to `pps` packets per second.
    RateLimit {
        /// Maximum packets per second for this flow.
        pps: u32,
    },
}
