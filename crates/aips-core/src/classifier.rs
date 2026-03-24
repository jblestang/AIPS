//! Flow classifier: decides per-packet whether to pass-through or proxy.

use crate::{
    decision::Decision,
    flow::{FlowKey, FlowState, SessionTable},
    layer::{L4Proto, PacketView},
    qos::QosFields,
};

/// A policy determines the decision for a new flow.
pub trait Policy {
    /// Evaluate a packet and return a decision.
    /// `now_ms` is the current uptime in milliseconds, used for rate limiting.
    fn evaluate(&mut self, pkt: &PacketView<'_>, qos: &QosFields, now_ms: u64) -> Decision;
}

/// A simple policy that forwards everything.
pub struct DefaultPolicy;
impl Policy for DefaultPolicy {
    fn evaluate(&mut self, _pkt: &PacketView<'_>, _qos: &QosFields, _now_ms: u64) -> Decision {
        Decision::Forward
    }
}

/// The classifier examines the flow key and session table to decide
/// whether a packet should be forwarded directly or dropped.
///
/// It uses a [`Policy`] to decide the outcome of new flows.
pub struct Classifier<const N: usize, P: Policy, D = ()> {
    sessions: SessionTable<N, D>,
    policy: P,
}

impl<const N: usize, P: Policy, D: Default + Copy> Classifier<N, P, D> {
    /// Creates a new classifier with an empty session table and the given policy.
    pub const fn new(policy: P) -> Self {
        Self { 
            sessions: SessionTable::new(),
            policy,
        }
    }

    /// Classify `pkt` and return a [`Decision`].
    ///
    /// * Established flows (Forward/Drop) → fast-path via session table.
    /// * New flows → consult the [`Policy`] and cache the result.
    pub fn classify(&mut self, pkt: &PacketView<'_>, qos: QosFields, now_ms: u64) -> Decision {
        let key = match self.flow_key(pkt) {
            Some(k) => k,
            None => return Decision::Forward, // non-IP or non-TCP/UDP
        };

        let (entry, is_new) = match self.sessions.get_or_insert(key, now_ms) {
            Some(res) => res,
            None => {
                // Table full! Fail secure: drop and alert to prevent CPU exhaustion.
                return Decision::Violation;
            }
        };

        // --- TCP Control Plane Wiring ---
        // If this is a FIN or RST, transition the flow to Closing immediately.
        if pkt.is_tcp_fin() || pkt.is_tcp_rst() {
            log::debug!("TCP Control segment (FIN/RST) detected. Closing flow.");
            self.sessions.update(key, FlowState::Closing, now_ms, pkt.src_ip);
            return Decision::Forward; // Allow the FIN/RST through to reach the stack
        }

        match entry.state {
            FlowState::Blocked     => return Decision::Drop,
            FlowState::Closing => {
                self.sessions.remove(key);
                return Decision::Forward;
            }
            FlowState::Proxied(_) => {
                self.sessions.touch(key, now_ms, pkt.src_ip);
                return Decision::Forward;
            }
            FlowState::PassThrough => {
                // Return path logic for UDP:
                // Only allowed for 1 second since the last packet received in the OTHER direction.
                if pkt.l4_proto == Some(L4Proto::Udp) {
                    let is_fwd = pkt.src_ip == entry.orig_src_ip;
                    let other_ts = if is_fwd { entry.last_rev_ms } else { entry.last_fwd_ms };
                    
                    // If we haven't seen the "other" side yet (last_rev_ms == 0 for initial return),
                    // it is allowed if it's within 1s of the start (already handled by common logic).
                    // Actually, if it's the very first return packet, entry.last_rev_ms is 0.
                    // The "other direction" is forward. So we check against last_fwd_ms.
                    
                    if other_ts > 0 {
                        let elapsed = now_ms.saturating_sub(other_ts);
                        if elapsed > 1000 {
                            log::debug!("UDP flow timed out for return path ({}ms > 1000ms)", elapsed);
                            return Decision::Violation;
                        }
                    } else if !is_fwd {
                        // First return packet. Check against last_fwd_ms.
                        let elapsed = now_ms.saturating_sub(entry.last_fwd_ms);
                        if elapsed > 1000 {
                            return Decision::Violation;
                        }
                    }
                }

                self.sessions.touch(key, now_ms, pkt.src_ip);
                return Decision::Forward;
            }
            FlowState::New => {}
        }

        if !is_new {
            return Decision::Forward;
        }

        // --- New flow: evaluate policy ---
        let decision = self.policy.evaluate(pkt, &qos, now_ms);

        if decision.is_forwarded() {
            self.sessions.update(key, FlowState::PassThrough, now_ms, pkt.src_ip);
        } else {
            self.sessions.update(key, FlowState::Blocked, now_ms, pkt.src_ip);
        }

        decision
    }

    /// Returns the current session state and whether it's a new flow.
    pub fn session_info(&mut self, pkt: &PacketView<'_>) -> (FlowState<D>, bool) {
        if let Some(key) = self.flow_key(pkt) {
            if let Some(entry) = self.sessions.get(key) {
                return (entry.state, false);
            }
        }
        (FlowState::New, false)
    }

    /// Block an existing flow.
    pub fn block_flow(&mut self, key: FlowKey, now_ms: u64, src_ip: [u8; 4]) {
        self.sessions.update(key, FlowState::Blocked, now_ms, src_ip);
    }

    /// Signal flow closure (FIN/RST seen).
    pub fn close_flow(&mut self, key: FlowKey) {
        self.sessions.remove(key);
    }
    
    /// Returns a mutable reference to the session state for a given packet.
    /// 
    /// Useful for platform drivers to access and update `Proxied(D)` payloads.
    pub fn session_state_mut(&mut self, pkt: &PacketView<'_>) -> Option<&mut FlowState<D>> {
        let key = self.flow_key(pkt)?.canonical();
        self.sessions.map.get_mut(&key).map(|v| &mut v.state)
    }

    pub fn flow_key(&self, pkt: &PacketView<'_>) -> Option<FlowKey> {
        let proto = match pkt.l4_proto? {
            L4Proto::Tcp    => 6,
            L4Proto::Udp    => 17,
            L4Proto::Icmp   => 1,
            L4Proto::Igmp   => 2,
            L4Proto::Ospf   => 89,
            L4Proto::Pim    => 103,
            L4Proto::Other(n) => n,
        };
        Some(FlowKey {
            src_ip:   pkt.src_ip,
            dst_ip:   pkt.dst_ip,
            src_port: pkt.src_port.unwrap_or(0),
            dst_port: pkt.dst_port.unwrap_or(0),
            proto,
        })
    }

    /// Expose the session table length for stats/logging.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_pkt(src_port: u16, dst_port: u16) -> [u8; 42] {
        let mut buf = [0u8; 42];
        // Ethernet header (IPv4)
        buf[12] = 0x08; buf[13] = 0x00;
        // IPv4 header (Proto: UDP=17)
        buf[14] = 0x45;
        buf[23] = 17;
        // IPs: 10.0.0.1 -> 10.0.0.2
        buf[26..30].copy_from_slice(&[10, 0, 0, 1]);
        buf[30..34].copy_from_slice(&[10, 0, 0, 2]);
        // UDP ports
        buf[34..36].copy_from_slice(&src_port.to_be_bytes());
        buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
        buf
    }

    #[test]
    fn test_policy_delegation() {
        struct Port443Policy;
        impl Policy for Port443Policy {
            fn evaluate(&mut self, pkt: &PacketView<'_>, _qos: &QosFields, _now_ms: u64) -> Decision {
                if pkt.dst_port == Some(443) || pkt.src_port == Some(443) {
                    Decision::Forward
                } else {
                    Decision::Violation
                }
            }
        }

        let mut classifier: Classifier<128, _> = Classifier::new(Port443Policy);
        let qos = QosFields::default();

        // 1. Packet not matching policy -> Violation
        let buf1 = make_test_pkt(1234, 8080);
        let pkt1 = PacketView::parse(&buf1).unwrap();
        let decision1 = classifier.classify(&pkt1, qos, 100);
        assert_eq!(decision1, Decision::Violation);

        // 2. Packet matching policy -> Forward
        let buf2 = make_test_pkt(2345, 443);
        let pkt2 = PacketView::parse(&buf2).unwrap();
        let decision2 = classifier.classify(&pkt2, qos, 101);
        assert_eq!(decision2, Decision::Forward);

        // 3. Subsequent packet for same flow -> Forward (hit session table, no re-eval)
        let decision2_sub = classifier.classify(&pkt2, qos, 102);
        assert_eq!(decision2_sub, Decision::Forward);
    }

    #[test]
    fn test_udp_return_flow_timeout() {
        let mut classifier: Classifier<128, _> = Classifier::new(DefaultPolicy);
        let qos = QosFields::default();

        // 1. Initial packet A -> B (creates session)
        let buf1 = make_test_pkt(1000, 2000);
        let pkt1 = PacketView::parse(&buf1).unwrap();
        assert_eq!(classifier.classify(&pkt1, qos, 1000), Decision::Forward);

        // 2. Return packet B -> A within 1s -> Forward
        let _buf2 = make_test_pkt(2000, 1000); // Created but then we create a custom one below
        // We need to fix make_test_pkt to actually use the ports for IP as well?
        // Actually, the flow key depends on IPs too.
        // Let's manually swap IPs in the buffer for the return packet.
        let mut buf2 = buf1;
        buf2[26..30].copy_from_slice(&[10, 0, 0, 2]); // src_ip = 10.0.0.2
        buf2[30..34].copy_from_slice(&[10, 0, 0, 1]); // dst_ip = 10.0.0.1
        buf2[34..36].copy_from_slice(&2000u16.to_be_bytes());
        buf2[36..38].copy_from_slice(&1000u16.to_be_bytes());

        let pkt2 = PacketView::parse(&buf2).unwrap();
        assert_eq!(classifier.classify(&pkt2, qos, 1500), Decision::Forward);

        // 3. Next return packet B -> A after >1s from LAST packet -> Violation
        // Wait, the requirement says "since the last packet received IN THE OTHER DIRECTION".
        // A -> B @ 1000
        // B -> A @ 1500 (Allowed, last A->B was 500ms ago)
        // B -> A @ 2600 (Violation, last A->B was 1600ms ago)
        assert_eq!(classifier.classify(&pkt2, qos, 2600), Decision::Violation);

        // 4. A -> B again @ 3000 -> Violation (last B->A was @ 1500, > 1s ago)
        assert_eq!(classifier.classify(&pkt1, qos, 3000), Decision::Violation);

        // 5. If A -> B sends again within 1s of a NEW B -> A, it works.
        // (Simulate a new session by waiting for the old one to be cleaned or just use new IPs)
        // For this test, let's just use a fresh classifier to test the "restart" logic.
        let mut classifier2: Classifier<128, _> = Classifier::new(DefaultPolicy);
        assert_eq!(classifier2.classify(&pkt1, qos, 4000), Decision::Forward); // A->B @ 4000
        assert_eq!(classifier2.classify(&pkt2, qos, 4500), Decision::Forward); // B->A @ 4500 (Allowed, <1s)
        assert_eq!(classifier2.classify(&pkt1, qos, 5000), Decision::Forward); // A->B @ 5000 (Allowed, <1s)
    }
}
