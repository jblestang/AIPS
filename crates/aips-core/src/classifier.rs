//! Flow classifier: decides per-packet whether to pass-through or proxy.

use crate::{
    decision::Decision,
    flow::{FlowKey, FlowState, SessionTable},
    layer::{L4Proto, PacketView},
    qos::QosFields,
};

/// Protocol to analyze in the L7 proxy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7Protocol {
    /// Standard cleartext HTTP/1.x payload evaluation.
    Http,
    /// Connectionless or TCP-based Domain Name System queries and responses.
    Dns,
    /// Encrypted Transport Layer Security stream; evaluated for SNI metadata mapping.
    Tls,
    /// Secure Shell version exchange and handshake metadata.
    Ssh,
    /// Network Time Protocol metrics and reflective amplification identification.
    Ntp,
    /// Unclassified payload; defaults to generic pattern matching exclusively.
    Unknown,
    /// Explicitly whitelisted flow that bypasses the L4 proxy (PassThrough).
    Bypass,
}

/// An explicitly configured Service definition.
#[derive(Debug, Clone, Copy)]
pub struct Service {
    /// The Layer 7 protocol analyser bound securely to this port service natively.
    pub protocol: L7Protocol,
    /// The static service port monitored by the classifier.
    pub server_port: u16,
}

/// The classifier examines the flow key and session table to decide
/// whether a packet should be forwarded directly or handed to
/// the L4 proxy for deep L7 inspection.
pub struct Classifier<const N: usize> {
    sessions: SessionTable<N>,
    services: heapless::Vec<Service, 32>,
}

impl<const N: usize> Classifier<N> {
    /// Creates a new classifier with an empty session table and no services.
    pub const fn new() -> Self {
        Self { 
            sessions: SessionTable::new(),
            services: heapless::Vec::new(),
        }
    }

    /// Register an explicitly configured L7 service definition.
    pub fn add_service(&mut self, service: Service) -> Result<(), ()> {
        self.services.push(service).map_err(|_| ())
    }

    /// Classify `pkt` and return a [`Decision`].
    ///
    /// * Already-blocked flows → `Drop` (fast-path, no re-inspection).
    /// * Already-proxied flows → `ProxyTcp` / `ProxyUdp`.
    /// * Already-passing flows → `Forward`.
    /// * New flows → classify by port and protocol.
    pub fn classify(&mut self, pkt: &PacketView<'_>, _qos: QosFields) -> Decision {
        let key = match self.flow_key(pkt) {
            Some(k) => k,
            None => return Decision::Forward, // non-IP or non-TCP/UDP
        };

        let (state, is_new) = match self.sessions.get_or_insert(key) {
            Some(res) => res,
            None => {
                // Table full! Fail secure: drop and alert to prevent CPU exhaustion.
                // We don't log a full violation here to avoid log spam, but
                // a dedicated "Table Full" metric/alert should be triggered.
                return Decision::Violation;
            }
        };

        match state {
            FlowState::Blocked     => return Decision::Drop,
            FlowState::PassThrough => return Decision::Forward,
            FlowState::Proxied(proto) => {
                return match pkt.l4_proto {
                    Some(L4Proto::Udp) => Decision::ProxyUdp(proto),
                    _                  => Decision::ProxyTcp(proto),
                };
            }
            FlowState::Closing => {
                self.sessions.remove(key);
                return Decision::Forward;
            }
            FlowState::New => {}
        }

        if !is_new {
            return Decision::Forward;
        }

        // --- New flow: classify by explicitly configured services ---
        let dst = pkt.dst_port.unwrap_or(0);
        let src = pkt.src_port.unwrap_or(0);

        let mut matched_proto = None;

        for s in &self.services {
            if dst == s.server_port || src == s.server_port {
                matched_proto = Some(s.protocol);
                break;
            }
        }

        if let Some(proto) = matched_proto {
            if proto == L7Protocol::Bypass {
                self.sessions.update(key, FlowState::PassThrough);
                Decision::Forward
            } else {
                self.sessions.update(key, FlowState::Proxied(proto));
                match pkt.l4_proto {
                    Some(L4Proto::Tcp) => Decision::ProxyTcp(proto),
                    Some(L4Proto::Udp) => Decision::ProxyUdp(proto),
                    _ => Decision::Forward,
                }
            }
        } else {
            // Default-deny only for TCP/UDP; allow ICMP/others by default.
            match pkt.l4_proto {
                Some(L4Proto::Tcp) | Some(L4Proto::Udp) => {
                    self.sessions.update(key, FlowState::Blocked);
                    Decision::Violation
                }
                _ => {
                    self.sessions.update(key, FlowState::PassThrough);
                    Decision::Forward
                }
            }
        }
    }

    /// Block an existing flow (e.g. after rule match in L7).
    pub fn block_flow(&mut self, key: FlowKey) {
        self.sessions.update(key, FlowState::Blocked);
    }

    /// Signal flow closure (FIN/RST seen).
    pub fn close_flow(&mut self, key: FlowKey) {
        self.sessions.remove(key);
    }

    fn flow_key(&self, pkt: &PacketView<'_>) -> Option<FlowKey> {
        let proto = match pkt.l4_proto? {
            L4Proto::Tcp    => 6,
            L4Proto::Udp    => 17,
            L4Proto::Icmp   => 1,
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

impl<const N: usize> Default for Classifier<N> {
    fn default() -> Self {
        Self::new()
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
    fn test_default_deny_posture() {
        let mut classifier: Classifier<128> = Classifier::new();
        let qos = QosFields::default();

        // 1. Packet not matching any service -> Violation
        let buf1 = make_test_pkt(1234, 8080);
        let pkt1 = PacketView::parse(&buf1).unwrap();
        let decision1 = classifier.classify(&pkt1, qos);
        assert_eq!(decision1, Decision::Violation, "Unrecognized port must be dropped as Violation");

        // 2. Register service for port 80 -> ProxyUdp(Http)
        classifier.add_service(Service { protocol: L7Protocol::Http, server_port: 80 }).unwrap();
        
        let buf2 = make_test_pkt(2345, 80);
        let pkt2 = PacketView::parse(&buf2).unwrap();
        let decision2 = classifier.classify(&pkt2, qos);
        assert_eq!(decision2, Decision::ProxyUdp(L7Protocol::Http), "Configured port must be proxied");

        // 3. Different port -> Violation
        let buf3 = make_test_pkt(3456, 443);
        let pkt3 = PacketView::parse(&buf3).unwrap();
        let decision3 = classifier.classify(&pkt3, qos);
        assert_eq!(decision3, Decision::Violation, "Non-matching port remains Violation");
    }
}
