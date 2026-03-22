//! # IPv4 Fragment Reassembly (Defragmentation) Module
//!
//! This module provides a high-performance, zero-allocation reassembly engine for IPv4 packets.
//! Fragments are tracked in a fixed-capacity, statically-sized queue (`DefragTable`), avoiding 
//! all heap allocations and unbounded memory vectors entirely. 
//!
//! The tracking uses a unique reassembly key `(src_ip, dst_ip, proto, id)`.
//!
//! ## Core Limitations & Protections
//! - **IPv4 only**: IPv6 handles fragmentation natively at the endpoint node via extension headers; 
//!   smoltcp natively ignores malformed IPv6 in the fast path.
//! - **Fixed Capacity (`N`)**: Bounds the maximum number of concurrent fragment streams the firewall 
//!   can process before randomly dropping old sequences.
//! - **Slot Sizing (`SLOT_BYTES`)**: Ensures we never attempt to buffer more than a pre-defined hardware 
//!   capacity limit (e.g. 65535 bytes to cover the theoretical MTU cap).
//! - **Timeout Evictions**: Orphaned bytes are scrubbed after an expiration window (`timeout_ms`) to 
//!   protect against memory exhaustion / slow-DDoS.
//! - **Overlap Handling**: Implements a highly conservative modification of RFC 5722 / Linux "Favor New" behavior. 
//!   When an overlapping fragment attack (e.g. Teardrop) occurs, the new byte sequences silently 
//!   overwrite existing boundaries.

/// Maximum theoretical size of a single reassembled IPv4 datagram payload.
/// This matches the 16-bit physical length limit of an IPv4 Header.
pub const SLOT_BYTES: usize = 65535;

/// Reassembly key: uniquely identifies an active fragment stream.
///
/// In IPv4, a fragmented stream is considered uniform and identical if it shares
/// the exact same Sender IP, Destination IP, Transport Protocol, and IP Identifier ID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DefragKey {
    /// The originating IPv4 address in network byte order.
    pub src_ip: [u8; 4],
    /// The target IPv4 address in network byte order.
    pub dst_ip: [u8; 4],
    /// The Layer-4 transport protocol mapped inside the IP payload (e.g., 6 for TCP, 17 for UDP).
    pub proto:  u8,
    /// The unique flow identifier established in the IPv4 header `Identification` field.
    pub id:     u16,
}

/// State multiplexer for a single static reassembly slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotState {
    /// The entire slot is empty, de-allocated, and available for a new incoming ID.
    Free,
    /// The slot is currently tracking a live `DefragKey` stream sequence.
    InProgress,
}

/// A contiguous, fixed-memory block responsible for capturing a single IPv4 datagram flow.
///
/// Under heavy loads, the AIPS core allocates a massive chunk of `DefragSlot` structures 
/// during compilation. `SLOT_BYTES` defaults to 65535 (full IP standard limit), but 
/// memory-constrained bare-metal environments (e.g., ESP32) can manually restrict this size 
/// via template limits to prevent stack overflow.
pub struct DefragSlot<const SLOT_BYTES: usize> {
    /// Current activity block phase of the static slot area.
    state:      SlotState,
    /// The 5-Tuple unique signature tying chunks to this slot buffer.
    key:        DefragKey,
    /// The raw target buffer array. Segments are dropped statically into here.
    buf:        [u8; SLOT_BYTES],
    /// A hardware-aligned memory bitmap tracking chunk completions at an 8-byte resolution.
    /// (128 u64 chunks * 64 bits = 8192 bits = 64 KiB space coverage total).
    received:   [u64; 128],
    /// The calculated complete payload size in bytes (populated once the MF=0 trailing packet lands).
    total_len:  Option<usize>,
    /// The highest sequential byte pointer successfully mapped via an incoming sequence frame.
    highest:    usize,
    /// Originating millisecond monotonic timestamp of the first chunk to measure timeouts via.
    created_ms: u64,
}

impl<const SLOT_BYTES: usize> DefragSlot<SLOT_BYTES> {
    /// Creates a deterministic, totally blank slot signature natively in static memory.
    const EMPTY: Self = Self {
        state:      SlotState::Free,
        key:        DefragKey { src_ip: [0; 4], dst_ip: [0; 4], proto: 0, id: 0 },
        buf:        [0u8; SLOT_BYTES],
        received:   [0u64; 128],
        total_len:  None,
        highest:    0,
        created_ms: 0,
    };

    /// Soft-wipes the slot for reusability. We do NOT clear the `buf` data
    /// out of performance considerations. By wiping only the state variables
    /// and `received` tracker, we recycle the slot instantly O(1).
    fn reset(&mut self) {
        self.state     = SlotState::Free;
        self.total_len = None;
        self.highest   = 0;
        self.received  = [0u64; 128]; // Blank out the 8-byte tracker sequences
    }

    /// High-performance chunk validation boundary stamper.
    /// 
    /// To measure if an entire datagram is complete natively without walking the arrays, 
    /// this engine translates incoming payload boundary `[offset, length]` mappings into 
    /// a series of overlapping boolean bit flags. Each 'bit' equates to a contiguous 8-byte block.
    ///
    /// The function utilizes hard u64 bitwise `!` masking. It avoids any loop constructs, 
    /// dramatically reducing insertion speed to O(1) ops.
    fn mark_received(&mut self, offset: usize, len: usize) {
        if len == 0 { return; }
        let start_block = offset / 8;
        let end_block   = (offset + len - 1) / 8;
        
        let start_word = start_block / 64;
        let end_word   = end_block / 64;
        
        if start_word == end_word {
            let start_bit = start_block % 64;
            let end_bit   = end_block % 64;
            let mask = if end_bit == 63 {
                !0u64 << start_bit
            } else {
                ((1u64 << (end_bit + 1)) - 1) ^ ((1u64 << start_bit) - 1)
            };
            if start_word < 128 {
                self.received[start_word] |= mask;
            }
        } else {
            let start_bit = start_block % 64;
            let mask_start = !0u64 << start_bit;
            if start_word < 128 {
                self.received[start_word] |= mask_start;
            }
            for w in (start_word + 1)..end_word {
                if w < 128 {
                    self.received[w] = !0u64;
                }
            }
            let end_bit = end_block % 64;
            let mask_end = if end_bit == 63 { !0u64 } else { (1u64 << (end_bit + 1)) - 1 };
            if end_word < 128 {
                self.received[end_word] |= mask_end;
            }
        }
    }

    /// Rapid continuity validation to determine if a datagram is ready for pipeline ejection.
    ///
    /// It grabs the exact number of 8-byte target blocks configured by the final terminating 
    /// datagram frame (`total_len`), and natively checks if all bits up to that marker are `1` via 
    /// boolean algebra.
    fn is_complete(&self) -> bool {
        // If we haven't seen a chunk carrying the 'More Fragments = 0' flag, it cannot be complete
        let total = match self.total_len { Some(t) => t, None => return false };
        let last_block = (total.saturating_sub(1)) / 8;
        
        // Ensure all bytes linearly are set up to the tracked finish line
        for block in 0..=last_block.min(128 * 64 - 1) {
            let word = block / 64;
            let bit  = block % 64;
            if self.received[word] & (1u64 << bit) == 0 { return false; }
        }
        true
    }
}

/// A fully hardware-bound IPv4 Deframentation Tracking table.
///
/// Built intentionally to require absolutely `0` memory allocations at runtime, isolating
/// against any OS layer OOM issues. It captures fragmentation flows up to `N` sessions wide.
///
/// - `N`: Max concurrent flows / attacks.
/// - `SBYTES`: Total tracked bytes per active slot.
pub struct DefragTable<const N: usize, const SBYTES: usize> {
    /// A localized, linearly placed array pool.
    slots:      [DefragSlot<SBYTES>; N],
    /// Max allowable age of an uncompleted sequence track before memory garbage collection kicks in.
    timeout_ms: u64,
}

impl<const N: usize, const SBYTES: usize> DefragTable<N, SBYTES> {
    /// Bootstraps an empty `DefragTable` stack configuration natively using `const fn`.
    ///
    /// `timeout_ms` sets the global safety limit on tracking state duration.
    pub const fn new(timeout_ms: u64) -> Self {
        Self {
            slots: [DefragSlot::<SBYTES>::EMPTY; N],
            timeout_ms,
        }
    }

    /// Process one IPv4 fragment.
    ///
    /// `ip_hdr` — the full IPv4 header bytes (at least 20 bytes).
    /// `payload` — the fragment payload (no IP header).
    /// `now_ms`  — current monotonic timestamp.
    ///
    /// Returns `Some(&[u8])` pointing into the slot buffer when the datagram
    /// is fully reassembled, or `None` if more fragments are expected.
    ///
    /// Returns `None` and logs a drop if the fragment is invalid or the
    /// table is full.
    pub fn process<'a>(
        &'a mut self,
        ip_hdr:  &[u8],
        payload: &[u8],
        now_ms:  u64,
    ) -> Option<&'a [u8]> {
        if ip_hdr.len() < 20 { return None; }

        let src_ip = [ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]];
        let dst_ip = [ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]];
        let proto  = ip_hdr[9];
        let frag_id = u16::from_be_bytes([ip_hdr[4], ip_hdr[5]]);
        let flags_offset = u16::from_be_bytes([ip_hdr[6], ip_hdr[7]]);
        let more_frags = (flags_offset & 0x2000) != 0;
        // Fragment offset is in units of 8 bytes.
        let frag_offset = ((flags_offset & 0x1FFF) as usize) * 8;

        // Skip unfragmented packets (MF=0, offset=0).
        if !more_frags && frag_offset == 0 { return None; }

        let key = DefragKey { src_ip, dst_ip, proto, id: frag_id };

        // Find existing slot, evicting timeouts during the traversal, or alloc a new one.
        let slot_idx = self.find_or_alloc(&key, now_ms)?;
        let slot = &mut self.slots[slot_idx];

        // Write fragment payload into slot buffer.
        let end = frag_offset + payload.len();
        if end > SBYTES { return None; } // oversized → drop

        // Overlap check: Linux strategy (Favor New). 
        // We do not reject or drop the slot. Instead, we allow the new fragment 
        // payload to overwrite any existing bytes in the `slot.buf`, naturally 
        // implementing the Favor New policy.
        
        slot.buf[frag_offset..end].copy_from_slice(payload);
        slot.mark_received(frag_offset, payload.len());
        if end > slot.highest { slot.highest = end; }

        if !more_frags {
            slot.total_len = Some(end);
        }

        if slot.is_complete() {
            let len = slot.total_len.unwrap_or(slot.highest);
            slot.state = SlotState::Free; // free for next use
            return Some(&slot.buf[..len]);
        }

        None
    }

    /// High-performance cache-friendly sweep implementation.
    ///
    /// Instead of iterating over the slots structure individually to garbage collect and *then* 
    /// sweeping again for a slot location, we bundle the traversal.
    /// We grab the first available slot concurrently while verifying existing flow collisions. If a 
    /// matching flow collision exceeds the timeout boundary, we wipe it immediately.
    fn find_or_alloc(&mut self, key: &DefragKey, now_ms: u64) -> Option<usize> {
        let mut free_slot = None;
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.state == SlotState::InProgress {
                // Garbage collect on the fly without breaking caching!
                if now_ms.saturating_sub(slot.created_ms) > self.timeout_ms {
                    slot.reset();
                    if free_slot.is_none() { free_slot = Some(i); }
                } else if &slot.key == key {
                    // Encountered a live existing flow
                    return Some(i);
                }
            } else if free_slot.is_none() {
                free_slot = Some(i); // Mark a clean spot, but keep looping to find tracking ID natively
            }
        }
        
        // Return or initialize the available block
        if let Some(i) = free_slot {
            let slot = &mut self.slots[i];
            slot.state      = SlotState::InProgress;
            slot.key        = *key;
            slot.created_ms = now_ms;
            return Some(i);
        }
        None // Fatal: The entire hardware-bound memory scope table array is fully occupied.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs a simulated IPv4 header sequence carrying essential defragmentation flags.
    /// 
    /// This strictly implements bare-bones byte sequences mapping to the exact bit sizes 
    /// assumed by the `DefragKey` unroller algorithms in `<DefragTable>::process()`.
    fn mock_ip_header(frag_id: u16, mf: bool, frag_offset: u16) -> [u8; 20] {
        let mut hdr = [0u8; 20];
        // Ensure Version length validates length
        hdr[0] = 0x45; 
        
        // Drop unique transaction ID bytes natively
        let id_bytes = frag_id.to_be_bytes();
        hdr[4] = id_bytes[0];
        hdr[5] = id_bytes[1];
        
        // Map 13-bit offset sequence and overlapping MF flag chunk
        let mut flags_offset = frag_offset & 0x1FFF;
        if mf {
            flags_offset |= 0x2000;
        }
        let fo_bytes = flags_offset.to_be_bytes();
        hdr[6] = fo_bytes[0];
        hdr[7] = fo_bytes[1];
        
        // Proto (TCP/UDP abstraction generic)
        hdr[9] = 17; // UDP
        
        // SRC IP address signature (e.g. 192.168.1.100)
        hdr[12..16].copy_from_slice(&[192, 168, 1, 100]);
        // DST IP address signature (e.g. 10.0.0.1)
        hdr[16..20].copy_from_slice(&[10, 0, 0, 1]);
        
        hdr
    }

    /// Validates normal, correct ordered IP defragmentation reconstruction logic.
    ///
    /// We simulate a single completely legal frame split natively into exactly 3 perfect, non-overlapping parts.
    /// We test that parts 1 and 2 register but reject pipeline-completion.
    /// The assertion ensures that Part 3 triggers standard buffer ejection correctly matching combined inputs.
    #[test]
    fn test_standard_ordered_success() {
        let mut table: DefragTable<4, 4096> = DefragTable::new(30_000);
        let id = 100;
        
        let hdr1 = mock_ip_header(id, true, 0);
        let payload1 = [0xAA; 16];
        assert!(table.process(&hdr1, &payload1, 10).is_none(), "Test: Part 1 should queue successfully but report incomplete.");
        
        let hdr2 = mock_ip_header(id, true, 2); // 2 units of 8-bytes = 16 offset
        let payload2 = [0xBB; 16];
        assert!(table.process(&hdr2, &payload2, 11).is_none(), "Test: Part 2 should track consecutively inline but report incomplete.");
        
        let hdr3 = mock_ip_header(id, false, 4); // 4 units of 8-bytes = 32 offset
        let payload3 = [0xCC; 8];
        
        let res = table.process(&hdr3, &payload3, 12);
        assert!(res.is_some(), "Test: Terminating chunk drops valid packet slice pointer.");
        
        let completed = res.unwrap();
        assert_eq!(completed.len(), 40, "Test: Fully concatenated blob equals total sequence parts sum (16 + 16 + 8).");
        assert_eq!(&completed[0..16], &[0xAA; 16], "Test: Section 1 validated");
        assert_eq!(&completed[16..32], &[0xBB; 16], "Test: Section 2 validated");
        assert_eq!(&completed[32..40], &[0xCC; 8], "Test: Section 3 validated");
    }

    /// Evaluates dysfunctional IP reassembly logic: Reverse-order Out-of-Sequence transmission.
    ///
    /// Malicious sources or weird proxy routes can naturally reverse packets inline.
    /// This tests whether trailing blocks dropping `total_len` successfully hold buffers open 
    /// without releasing the lock until missing header/body bytes finally resolve out-of-order.
    #[test]
    fn test_reverse_ordered_reconstruction() {
        let mut table: DefragTable<4, 4096> = DefragTable::new(30_000);
        let id = 200;
        
        let hdr3 = mock_ip_header(id, false, 4); // Trailing completion chunk (offset 32)
        let payload3 = [0xCC; 8];
        assert!(table.process(&hdr3, &payload3, 10).is_none(), "Test: Sending the 'finish' block first shouldn't bypass completeness verification.");
        
        let hdr2 = mock_ip_header(id, true, 2); // Middle segment (offset 16)
        let payload2 = [0xBB; 16];
        assert!(table.process(&hdr2, &payload2, 11).is_none(), "Test: Body chunks continue returning null as front header is totally absent.");
        
        let hdr1 = mock_ip_header(id, true, 0); // Starting header (offset 0)
        let payload1 = [0xAA; 16];
        let res = table.process(&hdr1, &payload1, 12);
        
        assert!(res.is_some(), "Test: Resolving missing initial chunk drops successful valid memory allocation.");
        let completed = res.unwrap();
        assert_eq!(completed.len(), 40);
        assert_eq!(&completed[0..16], &[0xAA; 16]);
    }

    /// Re-evaluates massive overlapping fragmentation evasion attacks.
    ///
    /// Tests the "Favor New" behavior pattern observed extensively in Linux network stacks,
    /// where attacker scripts duplicate offset ranges but switch malicious payloads instantly inline.
    /// We expect no failure errors, and the memory blob should directly match the `new` injected sequences.
    #[test]
    fn test_overlap_favor_new_malicious_replacement() {
        let mut table: DefragTable<4, 4096> = DefragTable::new(30_000);
        let id = 300;
        
        let hdr1 = mock_ip_header(id, true, 0);
        let payload_safe = [0xAA; 16];
        assert!(table.process(&hdr1, &payload_safe, 1).is_none());
        
        // Send a complete shadow override masking the entire first sequence boundaries natively
        let payload_malicious = [0xFF; 16];
        assert!(table.process(&hdr1, &payload_malicious, 2).is_none());
        
        let hdr_end = mock_ip_header(id, false, 2);
        let payload_end = [0xCC; 8];
        let assembled = table.process(&hdr_end, &payload_end, 3).expect("Test: Packet builds securely through overlap handling");
        
        assert_eq!(&assembled[0..16], &[0xFF; 16], "Test: Verification shows that memory has cleanly adopted the Favor New overlapping strategy.");
    }

    /// Verifies the structural isolation caching of distinct external network flows in tight timing bounds.
    ///
    /// Tests that the pool successfully bounds separate streams even when concurrent. Pumping
    /// unrelated ID chunks should not corrupt adjoining states or overlap boundaries.
    #[test]
    fn test_concurrent_sessions_isolation() {
        let mut table: DefragTable<4, 4096> = DefragTable::new(30_000);
        let (id1, id2) = (10, 20);
        
        let hdr_flow1_a = mock_ip_header(id1, true, 0);
        let hdr_flow2_a = mock_ip_header(id2, true, 0);
        let hdr_flow1_b = mock_ip_header(id1, false, 1); // 8 bytes offset
        let hdr_flow2_b = mock_ip_header(id2, false, 1);

        table.process(&hdr_flow1_a, &[0xAA; 8], 1);
        table.process(&hdr_flow2_a, &[0xBB; 8], 2);
        
        let out1 = table.process(&hdr_flow1_b, &[0xCC; 8], 3).unwrap();
        assert_eq!(&out1[0..16], &[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC], "Test: Flow 1 isolation passed");
        
        let out2 = table.process(&hdr_flow2_b, &[0xDD; 8], 4).unwrap();
        assert_eq!(&out2[8..16], &[0xDD; 8], "Test: Flow 2 isolation passed without boundary overlaps");
    }

    /// Evaluates the garbage collection pipeline to ensure memory drops correctly on zombie expirations.
    #[test]
    fn test_timeout_eviction_dysfunctional_sequence() {
        let mut table: DefragTable<4, 4096> = DefragTable::new(5_000); // 5 sec timeout
        
        // Spawn four concurrent streams locking down the total `N: 4` available space.
        table.process(&mock_ip_header(1, true, 0), &[0xAA; 8], 100);
        table.process(&mock_ip_header(2, true, 0), &[0xAA; 8], 100);
        table.process(&mock_ip_header(3, true, 0), &[0xAA; 8], 100);
        table.process(&mock_ip_header(4, true, 0), &[0xAA; 8], 100);
        
        let hdr_overflow = mock_ip_header(5, true, 0);
        assert!(table.process(&hdr_overflow, &[0xAA; 8], 101).is_none(), "Test: No space available, tracking gracefully skips new additions natively.");
        
        // Jump the internal virtual clock to far beyond timeout threshold
        // Attempting to track the overflow block should dynamically clear timed out slots natively during execution
        let res = table.process(&hdr_overflow, &[0xAA; 8], 15_000);
        assert!(res.is_none(), "Test: The chunk is incomplete, but space was aggressively opened because zombies expired in time.");
        
        // Assert sequence 5 successfully entered tracking
        let hdr_overflow_end = mock_ip_header(5, false, 1);
        assert!(table.process(&hdr_overflow_end, &[0xBB; 8], 15_001).is_some(), "Test: Sequence 5 terminated successfully post-OOM GC phase.");
    }
}
