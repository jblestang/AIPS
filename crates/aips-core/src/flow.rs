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
pub enum FlowState<D = ()> {
    /// Observed first packet; awaiting further classification.
    New,
    /// Flow is allowed to pass through directly.
    PassThrough,
    /// Flow has been explicitly blocked by a rule or policy.
    Blocked,
    /// Flow is in the process of closing (FIN/RST seen).
    Closing,
    /// Flow is being proxied for deep inspection.
    Proxied(D),
}

/// A session entry in the lookup table, including state and timing.
#[derive(Debug, Clone, Copy)]
pub struct SessionEntry<D = ()> {
    /// The current classification state.
    pub state: FlowState<D>,
    /// Timestamp of the last packet seen in the FORWARD direction (milliseconds).
    pub last_fwd_ms: u64,
    /// Timestamp of the last packet seen in the REVERSE direction (milliseconds).
    pub last_rev_ms: u64,
    /// The source IP that initiated this flow. 
    /// Used to distinguish forward vs reverse direction.
    pub orig_src_ip: [u8; 4],
}

impl<D: Default> SessionEntry<D> {
    /// Creates a new entry with the given state and current timestamp.
    pub fn new(state: FlowState<D>, now_ms: u64, src_ip: [u8; 4]) -> Self {
        Self {
            state,
            last_fwd_ms: now_ms,
            last_rev_ms: 0,
            orig_src_ip: src_ip,
        }
    }
}

/// Session tracking table.
///
/// Uses a fixed-capacity `heapless::FnvIndexMap` — no heap allocation.
/// Capacity `N` must be a power of 2.
pub struct SessionTable<const N: usize, D = ()> {
    pub(crate) map: FnvIndexMap<FlowKey, SessionEntry<D>, N>,
}

impl<const N: usize, D: Default + Copy> SessionTable<N, D> {
    /// Creates an empty session table.
    pub const fn new() -> Self {
        Self { map: FnvIndexMap::new() }
    }

    /// Look up or insert a flow entry.
    ///
    /// Returns `Some((SessionEntry, bool))` if successful. Returns `None`
    /// if the table is full and a new entry could not be inserted.
    pub fn get_or_insert(&mut self, key: FlowKey, now_ms: u64) -> Option<(SessionEntry<D>, bool)> {
        let k = key.canonical();
        if let Some(entry) = self.map.get(&k) {
            return Some((*entry, false));
        }
        let entry = SessionEntry::new(FlowState::New, now_ms, key.src_ip);
        if self.map.insert(k, entry).is_err() {
            return None;
        }
        Some((entry, true))
    }

    /// Returns a reference to an existing session entry without creating one.
    pub fn get(&self, key: FlowKey) -> Option<&SessionEntry<D>> {
        self.map.get(&key.canonical())
    }

    /// Update the state and timestamp of an existing flow.
    pub fn update(&mut self, key: FlowKey, state: FlowState<D>, now_ms: u64, src_ip: [u8; 4]) {
        let k = key.canonical();
        if let Some(v) = self.map.get_mut(&k) {
            v.state = state;
            if src_ip == v.orig_src_ip {
                v.last_fwd_ms = now_ms;
            } else {
                v.last_rev_ms = now_ms;
            }
        }
    }

    /// Just update the timestamp and direction, keeping the existing state.
    pub fn touch(&mut self, key: FlowKey, now_ms: u64, src_ip: [u8; 4]) {
        let k = key.canonical();
        if let Some(v) = self.map.get_mut(&k) {
            if src_ip == v.orig_src_ip {
                v.last_fwd_ms = now_ms;
            } else {
                v.last_rev_ms = now_ms;
            }
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

impl<const N: usize, D: Default + Copy> Default for SessionTable<N, D> {
    fn default() -> Self {
        Self::new()
    }
}
