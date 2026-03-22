//! Flow key and session state table.

use heapless::FnvIndexMap;

/// A 5-tuple flow key (IP src/dst, port src/dst, proto).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source IPv4.
    pub src_ip:   [u8; 4],
    /// Destination IPv4.
    pub dst_ip:   [u8; 4],
    /// Source port (0 for ICMP/other).
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// IP protocol number.
    pub proto:    u8,
}

impl FlowKey {
    /// Returns the canonical (lower-first) direction key so that
    /// client→server and server→client map to the same entry.
    pub fn canonical(mut self) -> Self {
        if (self.src_ip, self.src_port) > (self.dst_ip, self.dst_port) {
            core::mem::swap(&mut self.src_ip, &mut self.dst_ip);
            core::mem::swap(&mut self.src_port, &mut self.dst_port);
        }
        self
    }
}

/// Per-flow connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// Observed first packet; awaiting SYN-ACK.
    New,
    /// TCP handshake complete; flow is being proxied for the specifically matched layer 7 protocol.
    Proxied(crate::classifier::L7Protocol),
    /// Flow is allowed to pass through directly (no proxy needed).
    PassThrough,
    /// Flow has been blocked by a rule.
    Blocked,
    /// Flow is in the process of closing (FIN/RST seen).
    Closing,
}

/// Session tracking table.
///
/// Uses a fixed-capacity `heapless::FnvIndexMap` — no heap allocation.
/// Capacity `N` must be a power of 2.
pub struct SessionTable<const N: usize> {
    map: FnvIndexMap<FlowKey, FlowState, N>,
}

impl<const N: usize> SessionTable<N> {
    /// Creates an empty session table.
    pub const fn new() -> Self {
        Self { map: FnvIndexMap::new() }
    }

    /// Look up or insert a flow entry.
    ///
    /// Returns `Some((FlowState, bool))` if successful. Returns `None`
    /// if the table is full and a new entry could not be inserted.
    pub fn get_or_insert(&mut self, key: FlowKey) -> Option<(FlowState, bool)> {
        let k = key.canonical();
        if let Some(state) = self.map.get(&k) {
            return Some((*state, false));
        }
        if self.map.insert(k, FlowState::New).is_err() {
            return None;
        }
        Some((FlowState::New, true))
    }

    /// Update the state of an existing flow.
    pub fn update(&mut self, key: FlowKey, state: FlowState) {
        let k = key.canonical();
        if let Some(v) = self.map.get_mut(&k) {
            *v = state;
        }
    }

    /// Remove a flow (e.g. after FIN/RST).
    pub fn remove(&mut self, key: FlowKey) {
        self.map.remove(&key.canonical());
    }

    /// Number of tracked flows.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if no flows are tracked.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl<const N: usize> Default for SessionTable<N> {
    fn default() -> Self {
        Self::new()
    }
}
