//! # L4 TCP Stream Proxy Engine
//!
//! This module acts as the core traffic termination and bridging node for all layer-4 
//! sessions categorized as needing deep layer-7 inspection (e.g. HTTP, TLS).
//!
//! ## Architecture Overview
//!
//! Unlike simple pass-through firewall rules which assess packets one-by-one, deep L7 
//! inspection (like searching for SQL injection or HTTP headers) requires evaluating the 
//! entire reassembled TCP stream. AIPS creates a double-ended session proxy to accomplish this safely.
//!
//! ```text
//!              Ingress (Client Device)                   Egress (Destination Server)
//!                         │                                          ▲
//!                         ▼                                          │
//!   Client ──TCP──► ClientHalf (smoltcp)                 ServerHalf (smoltcp) ──TCP──► Server
//!                         │                                          ▲
//!                         └─────────► SPSC Inspection Buffer ────────┘
//! ```
//!
//! ## Execution Lifecycle
//! 1. **Handshake Arrest**: The `ClientHalf` intercepts the inbound SYN and completes a handshake natively.
//! 2. **Evaluation Pause**: Inbound bytes are stripped of L4 headers and pooled into a `heapless::spsc` queue.
//! 3. **L7 Execution**: The `RuleEngine` consumes the byte payloads.
//! 4. **Forwarding or Drop**: If allowed (`StreamVerdict::Forward`), the `ServerHalf` connects to the real 
//!    backend target and mirrors the bytes safely. If denied (`Drop`), both TCP sockets evaluate an instant `RST`.
//!
//! ## QoS Evasion Protections
//! Modern attacks sometimes wrap malicious payloads in High-QoS or unique TTL tracking loops.
//! The AIPS proxy inherently prevents TCP fragmentation overlap attacks unconditionally (via `smoltcp` tracking), 
//! while explicitly re-stamping original DSCP, ECN, and TTL values from the initial flow natively onto 
//! every bridge packet via [`crate::qos_stamp`], preserving complete routing transparency.


use aips_core::qos::QosFields;
use aips_rules::{action::Action, engine::RuleEngine};

#[allow(dead_code)]
const STREAM_BUF: usize = 16 * 1024; // 16 KiB

/// Granular state machine phase tracking the independent health of a connected proxy node.
/// 
/// The L4 engine maintains entirely independent state loops for both the internal `Client` target 
/// and the external routed `Server` target. A stream is only fully active when *both* phases 
/// achieve `Established`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalfState {
    /// Initial active synchronization mode. The engine is waiting for SYN/ACK phase completion.
    Connecting,
    /// Securely linked stream. Reassembled payload sequences are actively streaming into the inspection buffer.
    Established,
    /// Graceful termination sequence instantiated (FIN sent or received). Trailing buffer loops are draining.
    Closing,
    /// Hard termination. Stream encountered a fatal protocol error, timeout, or malicious block mechanism (RST).
    Reset,
}

/// The algorithmic decision state assigned to a specific byte block after deep payload analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamVerdict {
    /// Signature analysis succeeded cleanly. Instruct the opposite `HalfState` to encrypt/dispatch the chunk.
    Forward,
    /// A localized `Rule` threshold was breached requiring instant total mitigation. Instructs both `HalfStates` 
    /// to immediately serialize `RST` frames and abruptly kill the flow.
    Drop,
    /// A minor diagnostic `Rule` triggered. Continue pushing bytes normally but flag the system event stream.
    Alert(u32 /* rule_id */),
}

/// A comprehensive per-flow localized TCP proxy encapsulation object.
///
/// In a real environment this would be driven by two smoltcp `Interface` instances
/// sharing the AIPS event loop. Here we expose the core inspection logic so it
/// can be wired to any smoltcp socket pair by the platform layer.
///
/// `R`, `P`, `S`, `T` are rule engine capacity constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProxy<'r, const R: usize> {
    /// Rule engine for payload inspection.
    rules:        RuleEngine<'r, R>,
    /// QoS fields from the original client→server packets.
    client_qos:   QosFields,
    /// QoS fields from the original server→client packets.
    server_qos:   QosFields,
    /// Client-half state machine.
    pub client_state: HalfState,
    /// Server-half state machine.
    pub server_state: HalfState,
    /// Destination IP of the proxied flow.
    dst_ip:       [u8; 4],
    /// Source port of the proxied flow.
    src_port:     u16,
    /// Destination port of the proxied flow.
    dst_port:     u16,
    /// Source IP of the client (for rule matching).
    src_ip:       [u8; 4],
    /// Initial sequence number from the client.
    client_init_seq: u32,
    /// Initial sequence number from the server.
    server_init_seq: u32,
    /// Highest sequence number acknowledged by the backend server (translated to client-space).
    server_acked_seq: u32,
    /// Flag indicating if the NEXT packet to the client should have the ECN-Echo (ECE) flag set.
    pub pending_ecn_echo: bool,
}

impl<'r, const R: usize> TcpProxy<'r, R> {
    /// Fully initializes a fresh flow analysis bridge.
    ///
    /// The incoming `client_qos` parameters are immediately snapshotted locally so that when 
    /// `ServerHalf` ultimately opens outbound bridging sockets on the WAN, it exactly mimics the origin properties.
    pub fn new(
        rules:      RuleEngine<'r, R>,
        client_qos: QosFields,
        src_ip:     [u8; 4],
        dst_ip:     [u8; 4],
        src_port:   u16,
        dst_port:   u16,
        client_seq: u32,
    ) -> Self {
        Self {
            rules,
            client_qos,
            server_qos: QosFields::default(), // Populated exclusively during `on_server_connected` execution
            client_state: HalfState::Connecting,
            server_state: HalfState::Connecting,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            client_init_seq: client_seq,
            server_init_seq: 0,
            server_acked_seq: client_seq, // Initially, we've acked nothing new
            pending_ecn_echo: false,
        }
    }

    /// Executed deterministically when the outbound bridged destination successfully acknowledges our dialed SYN.
    pub fn on_server_connected(&mut self, server_qos: QosFields, server_seq: u32) {
        self.server_qos   = server_qos;
        self.server_init_seq = server_seq;
        self.client_state = HalfState::Established;
        self.server_state = HalfState::Established;
    }

    /// Translates a sequence number from Client-space to Server-space.
    pub fn client_to_server_seq(&self, seq: u32) -> u32 {
        let offset = self.server_init_seq.wrapping_sub(self.client_init_seq);
        seq.wrapping_add(offset)
    }

    /// Translates a sequence number from Server-space to Client-space.
    pub fn server_to_client_seq(&self, seq: u32) -> u32 {
        let offset = self.client_init_seq.wrapping_sub(self.server_init_seq);
        seq.wrapping_add(offset)
    }

    /// Internal: Update the highest server-acked sequence from a raw server ACK number safely.
    pub fn on_server_ack(&mut self, server_raw_ack: u32) {
        let translated = self.server_to_client_seq(server_raw_ack);
        // Only advance (handles wrapping/retransmissions safely)
        if translated.wrapping_sub(self.server_acked_seq) < (1 << 31) {
            self.server_acked_seq = translated;
        }
    }

    /// **ACK-Sync**: Returns true if the client's proposed ACK can be safely released.
    ///
    /// The client's ACK is only "safe" if the backend server has ALREADY acknowledged 
    /// that same segment of data. This prevents the proxy from over-promising 
    /// throughput that the backend cannot handle.
    pub fn should_ack_client(&self, client_proposed_ack: u32) -> bool {
        // If the client's ACK is <= what the server has acked, it's safe.
        client_proposed_ack.wrapping_sub(self.server_acked_seq) >= (1 << 31) || client_proposed_ack == self.server_acked_seq
    }

    /// **Dynamic Window Clamping**: Calculates the maximum window size to advertise to the client.
    ///
    /// As internal SPSC buffers fill up (e.g. while rules are being evaluated), we 
    /// aggressively shrink the advertised window to exert hardware-level backpressure.
    pub fn get_clamped_window(&self, buffer_fullness_bytes: usize, max_capacity: usize) -> u16 {
        let available = max_capacity.saturating_sub(buffer_fullness_bytes);
        
        // Linear clamping logic:
        // - 0-50% full: Advertise actual available space
        // - 50-90% full: Advertise 50% of available space (early backpressure)
        // - >90% full: Advertise 0 (Windows freeze)
        if buffer_fullness_bytes > (max_capacity * 9 / 10) {
            0
        } else if buffer_fullness_bytes > (max_capacity / 2) {
            (available / 2).min(u16::MAX as usize) as u16
        } else {
            available.min(u16::MAX as usize) as u16
        }
    }

    /// **ECN Reflection**: Propagates a "Congestion Experienced" (CE) signal from the WAN.
    pub fn handle_server_ecn_ce(&mut self) {
        self.pending_ecn_echo = true;
    }

    /// Inspect a chunk of reassembled bytes from the **client→server** direction.
    ///
    /// `chunk` is a slice from the smoltcp receive buffer (zero-copy borrow).
    /// Returns a [`StreamVerdict`] indicating what to do with these bytes.
    pub fn inspect_client_chunk(
        &mut self,
        chunk:    &[u8],
        now_ms:   u64,
    ) -> StreamVerdict {
        self.inspect_chunk(chunk, now_ms)
    }

    /// Inspect a chunk of reassembled bytes from the **server→client** direction.
    pub fn inspect_server_chunk(
        &mut self,
        chunk:    &[u8],
        now_ms:   u64,
    ) -> StreamVerdict {
        // For now, server→client response inspection uses the same rule set.
        // A future enhancement could use a separate response rule engine.
        self.inspect_chunk(chunk, now_ms)
    }

    /// High-throughput payload mapping protocol loop.
    ///
    /// Integrates the deep deterministic parsing of HTTP, DNS, and TLS parameters configured in `aips-l7`
    /// directly against the linear scanning Aho-Corasick engines operating inside `aips-rules`.
    /// 
    /// Uses absolute zero-copy `chunk` byte assignments straight out of `smoltcp` RingBuffers to 
    /// assess complex strings instantaneously.
    fn inspect_chunk(&mut self, chunk: &[u8], now_ms: u64) -> StreamVerdict {
        // Wrap parameter contexts uniformly for wildcard generic Rule matching arrays
        let ctx = aips_rules::engine::MatchCtx {
            payload: chunk,
            src_ip:       self.src_ip,
            dst_ip:       self.dst_ip,
            src_port:     self.src_port,
            dst_port:     self.dst_port,
            ttl:  self.client_qos.ttl,
            dscp: self.client_qos.dscp,
            ecn:  self.client_qos.ecn,
        };

        // Map evaluation rules recursively testing localized context flags against system patterns
        match self.rules.evaluate(&ctx, now_ms) {
            Some((_id, Action::Pass))           => StreamVerdict::Forward,
            Some((_id, Action::Drop))           => StreamVerdict::Drop,
            Some((id,  Action::Alert))          => StreamVerdict::Alert(id),
            // TCP inherently drops if we attempt to arbitrarily frame rate-limits within 
            // a single active unbroken data stream due to window collapse
            Some((_id, Action::RateLimit { .. }))=> StreamVerdict::Drop,
            None                                 => StreamVerdict::Forward,
        }
    }

    /// Signals an unforced orderly shutdown from the local origin client endpoint.
    pub fn on_client_fin(&mut self) {
        self.client_state = HalfState::Closing;
    }

    /// Signals an unforced orderly shutdown from the backend application endpoint.
    pub fn on_server_fin(&mut self) {
        self.server_state = HalfState::Closing;
    }

    /// Outputs origin mapping attributes to mirror precisely onto the outgoing remote target buffer.
    pub fn egress_qos_to_server(&self) -> QosFields { self.client_qos }
    /// Outputs the returned application characteristics to perfectly mimic on the backwards facing client flow.
    pub fn egress_qos_to_client(&self) -> QosFields { self.server_qos }

    /// System integration utility identifying entirely dead/zombified flows suitable for hash-map eviction.
    pub fn is_done(&self) -> bool {
        matches!(
            (self.client_state, self.server_state),
            (HalfState::Reset, _) | (_, HalfState::Reset) |
            (HalfState::Closing, HalfState::Closing)
        )
    }
}

impl<'r, const R: usize> aips_core::classifier::TcpSync for TcpProxy<'r, R> {
    fn should_stall_client(&self, pkt: &aips_core::layer::PacketView<'_>) -> bool {
        // Only stall data ACKs. Pure SYNs or non-TCP packets should not be stalled here.
        if pkt.l4_proto == Some(aips_core::layer::L4Proto::Tcp) {
            !self.should_ack_client(pkt.tcp_ack)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Evaluates initialization maps natively mapping states perfectly correctly.
    #[test]
    fn test_proxy_startup_state_initialization() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let qos = QosFields { dscp: 10, ecn: 2, ttl: 64 };
        let proxy = TcpProxy::new(rules, qos, [192, 168, 1, 10], [10, 0, 0, 1], 50000, 443, 1000);

        assert_eq!(proxy.client_state, HalfState::Connecting, "Test: Initial client state tracks handshake setup");
        assert_eq!(proxy.server_state, HalfState::Connecting, "Test: Initial server state limits dispatch awaiting dialing");
        assert_eq!(proxy.egress_qos_to_server().dscp, 10, "Test: Client QoS successfully mapped to output buffer");
        assert_eq!(proxy.egress_qos_to_client().ttl, 0, "Test: Server QoS stays blank safely until actively connected");
    }

    /// Tests the handshake execution binding phase modifying output metadata deterministically.
    #[test]
    fn test_server_connection_established() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let client_qos = QosFields { dscp: 0, ecn: 0, ttl: 128 };
        let mut proxy = TcpProxy::new(rules, client_qos, [0; 4], [0; 4], 0, 22, 1000);

        let server_qos = QosFields { dscp: 46, ecn: 1, ttl: 64 };
        proxy.on_server_connected(server_qos, 5000);

        assert_eq!(proxy.client_state, HalfState::Established, "Test: Client opens immediately upon server binding");
        assert_eq!(proxy.server_state, HalfState::Established, "Test: Server actively tracking payloads natively");
        assert_eq!(proxy.egress_qos_to_client().dscp, 46, "Test: Validated QoS parameters locked strictly into state parameters");
        assert!(!proxy.is_done(), "Test: Live sessions are definitively not done");
    }

    /// Verifies functional shutdown operations correctly evict state bounds natively.
    #[test]
    fn test_shutdown_transitions_are_done() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let mut proxy = TcpProxy::new(rules, QosFields::default(), [0; 4], [0; 4], 0, 443, 0);
        
        // Assert basic operations
        proxy.on_server_connected(QosFields::default(), 0);
        assert!(!proxy.is_done(), "Test: Live proxy is not done");
        
        // Unforced graceful loop
        proxy.on_client_fin();
        assert_eq!(proxy.client_state, HalfState::Closing, "Test: Client signals closing correctly");
        assert!(!proxy.is_done(), "Test: Proxy awaits trailing server finish naturally before unmapping memory bounds");
        
        proxy.on_server_fin();
        assert_eq!(proxy.server_state, HalfState::Closing, "Test: Server signals closing correctly");
        assert!(proxy.is_done(), "Test: Full graceful FIN interaction guarantees garbage collection safely");
    }

    /// Tests fatal RST scenarios violently clearing hashmap resources instantly natively.
    #[test]
    fn test_fatal_reset_immediately_done() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let mut proxy = TcpProxy::new(rules, QosFields::default(), [0; 4], [0; 4], 0, 443, 0);
        
        proxy.client_state = HalfState::Reset;
        assert!(proxy.is_done(), "Test: A client reset natively shatters the proxy link instantly!");
    }

    /// Evaluates functional L7 evaluations resolving default empty bounds safely natively.
    #[test]
    fn test_inspect_chunk_forward() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let mut proxy = TcpProxy::new(rules, QosFields::default(), [0; 4], [0; 4], 0, 443, 0);

        let dummy_chunk = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        let verdict = proxy.inspect_client_chunk(dummy_chunk, 100);
        assert_eq!(verdict, StreamVerdict::Forward, "Test: Native untracked operations seamlessly ignore safely.");
    }

    #[test]
    fn test_ack_sync_gating() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        // Client starts at SEQ 1000
        let mut proxy = TcpProxy::new(rules, QosFields::default(), [0; 4], [0; 4], 0, 80, 1000);
        proxy.on_server_connected(QosFields::default(), 5000); // Server starts at SEQ 5000

        // Client wants to ACK 1100
        assert!(!proxy.should_ack_client(1100), "Test: Proxy MUST NOT release client ACK until server confirms data");

        // Server ACKs 5100 (which maps to 1100)
        proxy.on_server_ack(5100);
        assert!(proxy.should_ack_client(1100), "Test: Proxy releases client ACK once translated server-ACK arrives");
    }

    #[test]
    fn test_dynamic_window_clamping() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let proxy = TcpProxy::new(rules, QosFields::default(), [0; 4], [0; 4], 0, 80, 0);
        let cap = 10000;

        // 10% full: Full window advertised
        assert_eq!(proxy.get_clamped_window(1000, cap), 9000);
        // 60% full: 50% penalty applied
        assert_eq!(proxy.get_clamped_window(6000, cap), 2000);
        // 95% full: Hard clamp to 0
        assert_eq!(proxy.get_clamped_window(9500, cap), 0);
    }

    #[test]
    fn test_ecn_reflection_propagation() {
        let rules: RuleEngine<'static, 64> = RuleEngine::new();
        let mut proxy = TcpProxy::new(rules, QosFields::default(), [0; 4], [0; 4], 0, 80, 0);

        assert!(!proxy.pending_ecn_echo);
        proxy.handle_server_ecn_ce();
        assert!(proxy.pending_ecn_echo, "Test: Server CE triggers Client ECE reflection");
    }
}
