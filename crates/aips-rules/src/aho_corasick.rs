//! Minimal no_std Aho-Corasick automaton for multi-pattern payload matching.
//!
//! Supports up to `P` patterns and `S` automaton states, all stored on the
//! stack (no heap allocation).
//!
//! This is a simplified version — suitable for a small, fixed rule set
//! (e.g. ≤ 32 patterns, ≤ 512 states) that can be compiled at startup.

const ALPHA: usize = 256;

/// A single state in the Aho-Corasick automaton.
#[derive(Clone, Copy)]
struct AcState {
    /// `goto[byte]` — next state index, or 0 for root.
    goto: [u16; ALPHA],
    /// Failure link.
    fail: u16,
    /// Rule ID that matched at this state (u32::MAX = none).
    output: u32,
}

impl AcState {
    const fn empty() -> Self {
        Self {
            goto: [0u16; ALPHA],
            fail: 0,
            output: u32::MAX,
        }
    }
}

/// Aho-Corasick multi-pattern search automaton.
///
/// `P` = max patterns, `S` = max states.
pub struct AhoCorasick<const P: usize, const S: usize> {
    states: [AcState; S],
    num_states: usize,
}

impl<const P: usize, const S: usize> AhoCorasick<P, S> {
    /// Creates an empty (uncompiled) automaton.
    pub const fn new() -> Self {
        Self {
            states: [AcState::empty(); S],
            num_states: 1, // root is state 0
        }
    }

    /// Add a pattern and associate it with `rule_id`.
    /// Returns `Err` if the automaton is full.
    pub fn add_pattern(&mut self, pattern: &[u8], rule_id: u32) -> Result<(), ()> {
        let mut cur = 0usize;
        for &byte in pattern {
            let b = byte as usize;
            let next = self.states[cur].goto[b] as usize;
            if next == 0 {
                if self.num_states >= S {
                    return Err(());
                }
                let new_state = self.num_states;
                self.states[cur].goto[b] = new_state as u16;
                self.num_states += 1;
                cur = new_state;
            } else {
                cur = next;
            }
        }
        self.states[cur].output = rule_id;
        Ok(())
    }

    /// Build failure links (BFS). Must be called after all `add_pattern` calls.
    pub fn build(&mut self) {
        // BFS queue using a fixed-size array
        let mut queue = [0u16; 1024];
        let mut head = 0usize;
        let mut tail = 0usize;

        // Depth-1 states: fail → root
        for b in 0..ALPHA {
            let s = self.states[0].goto[b] as usize;
            if s != 0 {
                self.states[s].fail = 0;
                queue[tail] = s as u16;
                tail += 1;
            }
        }

        while head < tail {
            let r = queue[head] as usize;
            head += 1;
            for b in 0..ALPHA {
                let s = self.states[r].goto[b] as usize;
                if s == 0 { continue; }
                queue[tail] = s as u16;
                tail += 1;

                let mut f = self.states[r].fail as usize;
                while f != 0 && self.states[f].goto[b] == 0 {
                    f = self.states[f].fail as usize;
                }
                self.states[s].fail = self.states[f].goto[b];
                
                // Propagate output
                let fail_out = self.states[self.states[s].fail as usize].output;
                if self.states[s].output == u32::MAX {
                    self.states[s].output = fail_out;
                }
            }
        }
    }

    /// Search `text` for any added pattern.
    ///
    /// Returns the rule ID of the first match, or `None` if no match.
    pub fn search(&self, text: &[u8]) -> Option<u32> {
        let mut cur = 0usize;
        for &byte in text {
            let b = byte as usize;
            
            while cur != 0 && self.states[cur].goto[b] == 0 {
                cur = self.states[cur].fail as usize;
            }
            
            let next = self.states[cur].goto[b] as usize;
            if next != 0 {
                cur = next;
            } else {
                cur = 0;
            }
            
            if self.states[cur].output != u32::MAX {
                return Some(self.states[cur].output);
            }
        }
        None
    }
}
