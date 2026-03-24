//! Pipeline verdict type.

/// The action the pipeline wishes to take on a packet or flow.  
///
/// Returned by every [`Stage`](crate::pipeline::Stage) and consumed by the
/// platform PHY driver after the full pipeline has run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Pass the frame through to the egress interface unchanged.
    Forward,

    /// Silently discard the frame (IPS block mode).
    Drop,

    /// Generate an alert/log but still forward (IDS alert-only mode).
    Alert,

    /// The packet did not match any known service or rule and is dropped as a policy violation.
    Violation,
}

impl Decision {
    /// Returns `true` if the packet should be forwarded (with or without alerting).
    #[inline]
    pub fn is_forwarded(self) -> bool {
        matches!(self, Decision::Forward | Decision::Alert)
    }

    /// Returns `true` if the packet must be dropped.
    #[inline]
    pub fn is_dropped(self) -> bool {
        matches!(self, Decision::Drop | Decision::Violation)
    }
}
