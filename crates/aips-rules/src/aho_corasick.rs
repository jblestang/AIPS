//! Minimal no_std Aho-Corasick automaton for multi-pattern payload matching.
//!
//! Supports up to `P` patterns, `S` states, and `T` total transitions, 
//! all stored on the stack (no heap allocation).
//!
//! This version uses a sparse transition table (linked list of transitions)
//! to dramatically reduce the stack footprint compared to a dense 256-entry array.

const NULL: u16 = u16::MAX;

/// A single transition from one state to another on a specific byte.
#[derive(Clone, Copy)]
struct Transition {
    byte: u8,
    next: u16,
    next_sibling: u16,
}

/// A single state in the Aho-Corasick automaton.
#[derive(Clone, Copy)]
struct AcState {
    /// Index into the transitions array for the first outgoing transition.
    first_transition: u16,
    /// Failure link.
    fail: u16,
    /// Rule ID that matched at this state (u32::MAX = none).
    output: u32,
}

impl AcState {
    const fn empty() -> Self {
        Self {
            first_transition: NULL,
            fail: 0,
            output: u32::MAX,
        }
    }
}

/// Aho-Corasick multi-pattern search automaton.
///
/// `P` = max patterns, `S` = max states, `T` = max transitions.
pub struct AhoCorasick<const P: usize, const S: usize, const T: usize> {
    states: [AcState; S],
    num_states: usize,
    transitions: [Transition; T],
    num_transitions: usize,
}

impl<const P: usize, const S: usize, const T: usize> AhoCorasick<P, S, T> {
    /// Creates an empty (uncompiled) automaton.
    pub const fn new() -> Self {
        Self {
            states: [AcState::empty(); S],
            num_states: 1, // root is state 0
            transitions: [Transition { byte: 0, next: 0, next_sibling: NULL }; T],
            num_transitions: 0,
        }
    }

    fn get_goto(&self, state: usize, byte: u8) -> u16 {
        let mut t_idx = self.states[state].first_transition;
        while t_idx != NULL {
            let t = &self.transitions[t_idx as usize];
            if t.byte == byte {
                return t.next;
            }
            t_idx = t.next_sibling;
        }
        0
    }

    fn set_goto(&mut self, state: usize, byte: u8, next: u16) -> Result<(), ()> {
        // Check if transition already exists
        let mut t_idx = self.states[state].first_transition;
        while t_idx != NULL {
            let t = &mut self.transitions[t_idx as usize];
            if t.byte == byte {
                t.next = next;
                return Ok(());
            }
            t_idx = t.next_sibling;
        }

        // Add new transition
        if self.num_transitions >= T {
            return Err(());
        }
        let new_idx = self.num_transitions as u16;
        self.transitions[new_idx as usize] = Transition {
            byte,
            next,
            next_sibling: self.states[state].first_transition,
        };
        self.states[state].first_transition = new_idx;
        self.num_transitions += 1;
        Ok(())
    }

    /// Add a pattern and associate it with `rule_id`.
    /// Returns `Err` if the automaton or transition table is full.
    pub fn add_pattern(&mut self, pattern: &[u8], rule_id: u32) -> Result<(), ()> {
        let mut cur = 0usize;
        for &byte in pattern {
            let next = self.get_goto(cur, byte) as usize;
            if next == 0 {
                if self.num_states >= S {
                    return Err(());
                }
                let new_state = self.num_states;
                self.set_goto(cur, byte, new_state as u16)?;
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
        let mut t_idx = self.states[0].first_transition;
        while t_idx != NULL {
            let s = self.transitions[t_idx as usize].next as usize;
            self.states[s].fail = 0;
            if tail < queue.len() {
                queue[tail] = s as u16;
                tail += 1;
            }
            t_idx = self.transitions[t_idx as usize].next_sibling;
        }

        while head < tail {
            let r = queue[head] as usize;
            head += 1;
            
            let mut t_idx = self.states[r].first_transition;
            while t_idx != NULL {
                let (byte, s) = {
                    let t = &self.transitions[t_idx as usize];
                    (t.byte, t.next as usize)
                };
                
                if tail < queue.len() {
                    queue[tail] = s as u16;
                    tail += 1;
                }

                let mut f = self.states[r].fail as usize;
                while f != 0 && self.get_goto(f, byte) == 0 {
                    f = self.states[f].fail as usize;
                }
                self.states[s].fail = self.get_goto(f, byte);
                
                // Propagate output
                let fail_out = self.states[self.states[s].fail as usize].output;
                if self.states[s].output == u32::MAX {
                    self.states[s].output = fail_out;
                }
                
                t_idx = self.transitions[t_idx as usize].next_sibling;
            }
        }
    }

    /// Search `text` for any added pattern.
    ///
    /// Returns the rule ID of the first match, or `None` if no match.
    pub fn search(&self, text: &[u8]) -> Option<u32> {
        let mut cur = 0usize;
        for &byte in text {
            while cur != 0 && self.get_goto(cur, byte) == 0 {
                cur = self.states[cur].fail as usize;
            }
            
            let next = self.get_goto(cur, byte) as usize;
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
