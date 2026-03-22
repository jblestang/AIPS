//! # HyperCuts/HiCuts Multi-Dimensional Packet Classification
//!
//! Provides mathematically accelerated `O(log N)` to worst-case `O(1)` classification 
//! of massive L3/L4 5-tuple Access Control Lists (SrcIP, DstIP, SrcPort, DstPort, Protocol).
//!
//! ## Operation Constraints
//! Standard firewall implementations evaluate rules linearly `O(N)`, which completely collapses 
//! throughput when rulesets exceed a few hundred entries. The HyperCuts algorithm fixes this by 
//! recursively projecting N-dimensional rulesets into a geometrically cut bounding-box tree.
//!
//! During ingress, the routing engine simply drops the packet's 5-Tuple signature down the 
//! tree nodes until hitting a Leaf bucket, converting what used to be 100,000 linear checks 
//! into just a dozen quick integer comparisons.

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;

use crate::action::Action;

/// Defines a localized, inclusive 1D span constraint representing a single parameter 
/// of a network traffic sequence (e.g. Ports 80 to 443).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range<T> {
    /// The absolute lowest acceptable metric boundary (inclusive).
    pub min: T,
    /// The absolute highest acceptable metric boundary (inclusive).
    pub max: T,
}

impl<T: PartialOrd> Range<T> {
    /// Highly optimized bounds overlap detection logic.
    /// Determines if the local mathematical constraint spatially collides with another constraint `other`.
    pub fn overlaps(&self, other: &Range<T>) -> bool {
        self.min <= other.max && self.max >= other.min
    }
}

/// A comprehensive, hardware-independent Layer 3 / Layer 4 Access Control List rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3Rule {
    /// Globally unique, monotonically generated identifier utilized for analytical reporting.
    pub id: u32,
    /// Execution precedence level. If two rules collide on an assessment, the one carrying 
    /// the definitively lower numerical precedence score mathematically forces ejection of the other.
    pub priority: u32,
    
    /// IPv4 CIDR representation converted into direct bounds format. Network -> Host limits.
    pub src_ip: Range<u32>,
    /// Identical integer limits marking authorized targeting IPs.
    pub dst_ip: Range<u32>,
    /// Source physical connection interface parameters.
    pub src_port: Range<u16>,
    /// Authorized target interaction sockets.
    pub dst_port: Range<u16>,
    /// Protocol ID classification (e.g. TCP 6, UDP 17, ICMP 1).
    pub proto: Range<u8>,
    
    /// Conclusive reaction strategy executed by the pipeline upon verified signature mapping.
    pub action: Action,
}

/// Represents an abstract, localized multi-dimensional geographic volume enclosing a slice of possible traffic sequences.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    src_ip: Range<u32>,
    dst_ip: Range<u32>,
    src_port: Range<u16>,
    dst_port: Range<u16>,
    proto: Range<u8>,
}

impl Bounds {
    fn root() -> Self {
        Self {
            src_ip: Range { min: 0, max: u32::MAX },
            dst_ip: Range { min: 0, max: u32::MAX },
            src_port: Range { min: 0, max: u16::MAX },
            dst_port: Range { min: 0, max: u16::MAX },
            proto: Range { min: 0, max: u8::MAX },
        }
    }

    /// Recursively isolates and slices the geographic hyper-body limits natively.
    /// Dim tracks dimensions (0=SrcIp, 1=DstIp, 2=SrcPort, 3=DstPort, 4=Proto).
    fn split(&self, dim: u8, cut_val: u32) -> (Bounds, Bounds) {
        let mut left = *self;
        let mut right = *self;
        // Bisects the limit boundary to forcefully segment the traffic population into deterministic routing limits
        match dim {
            0 => { left.src_ip.max = cut_val; right.src_ip.min = cut_val + 1; }
            1 => { left.dst_ip.max = cut_val; right.dst_ip.min = cut_val + 1; }
            2 => { left.src_port.max = cut_val as u16; right.src_port.min = (cut_val + 1) as u16; }
            3 => { left.dst_port.max = cut_val as u16; right.dst_port.min = (cut_val + 1) as u16; }
            4 => { left.proto.max = cut_val as u8; right.proto.min = (cut_val + 1) as u8; }
            _ => unreachable!(),
        }
        (left, right)
    }
}

/// Evaluates absolute containment overlap between an explicit configured ACL signature and generated spatial dimension cut-boxes.
fn overlaps(rule: &L3Rule, bounds: &Bounds) -> bool {
    rule.src_ip.overlaps(&bounds.src_ip) &&
    rule.dst_ip.overlaps(&bounds.dst_ip) &&
    rule.src_port.overlaps(&bounds.src_port) &&
    rule.dst_port.overlaps(&bounds.dst_port) &&
    rule.proto.overlaps(&bounds.proto)
}

/// Operational navigation matrix inside the algorithmic HyperCuts hierarchy.
#[derive(Debug)]
pub enum HyperNode {
    /// Deepest hierarchy termination point carrying the absolute remaining rule sequence conflicts.
    Leaf(Vec<L3Rule>),
    /// Dynamic directional pivot mapping isolated variable targets.
    Internal {
        /// Axis constraint identification: 0=SrcIp, 1=DstIp, 2=SrcPort, 3=DstPort, 4=Proto.
        dim: u8,
        /// Execution integer boundary metric determining Left <= logic flows.
        cut_val: u32,
        /// Child structural representation allocating isolated lower value distributions.
        left: Box<HyperNode>,
        /// Child structural representation allocating isolated higher value distributions.
        right: Box<HyperNode>,
    },
}

impl HyperNode {
    /// Limit indicating maximum acceptable L3 rules compacted natively into a single processing leaf.
    pub const BUCKET_SIZE: usize = 8;
    /// Anti-memory-exhaustion recursive scaling constraint natively blocking stack overflow DDoS events.
    pub const MAX_DEPTH: usize = 32;

    /// Build a decision tree from a list of rules.
    pub fn build(mut rules: Vec<L3Rule>) -> Self {
        // Sort rules by priority (highest priority first)
        rules.sort_by_key(|r| r.priority);
        Self::build_recursive(rules, Bounds::root(), 0)
    }

    fn build_recursive(rules: Vec<L3Rule>, bounds: Bounds, depth: usize) -> Self {
        if rules.len() <= Self::BUCKET_SIZE || depth >= Self::MAX_DEPTH {
            return HyperNode::Leaf(rules);
        }

        // Extremely simple heuristic: cut the dimension that has the widest range
        let mut max_spread = 0u64;
        let mut best_dim = 0;
        let mut cut_val = 0;

        let spreads = [
            ((bounds.src_ip.max as u64) - (bounds.src_ip.min as u64), 0),
            ((bounds.dst_ip.max as u64) - (bounds.dst_ip.min as u64), 1),
            ((bounds.src_port.max as u64) - (bounds.src_port.min as u64), 2),
            ((bounds.dst_port.max as u64) - (bounds.dst_port.min as u64), 3),
            ((bounds.proto.max as u64) - (bounds.proto.min as u64), 4),
        ];

        for (spread, dim) in spreads {
            if spread > max_spread {
                max_spread = spread;
                best_dim = dim;
                cut_val = match dim {
                    0 => bounds.src_ip.min as u64 + spread / 2,
                    1 => bounds.dst_ip.min as u64 + spread / 2,
                    2 => bounds.src_port.min as u64 + spread / 2,
                    3 => bounds.dst_port.min as u64 + spread / 2,
                    4 => bounds.proto.min as u64 + spread / 2,
                    _ => unreachable!(),
                } as u32;
            }
        }

        // If spread is 0 across all dimensions, all rules are identical 5-tuples.
        if max_spread == 0 {
            return HyperNode::Leaf(rules);
        }

        let (left_bounds, right_bounds) = bounds.split(best_dim, cut_val);

        let mut left_rules = Vec::new();
        let mut right_rules = Vec::new();

        for r in rules {
            if overlaps(&r, &left_bounds) {
                left_rules.push(r.clone());
            }
            if overlaps(&r, &right_bounds) {
                right_rules.push(r.clone());
            }
        }

        HyperNode::Internal {
            dim: best_dim,
            cut_val,
            left: Box::new(Self::build_recursive(left_rules, left_bounds, depth + 1)),
            right: Box::new(Self::build_recursive(right_rules, right_bounds, depth + 1)),
        }
    }

    /// Top-level hardware-accelerated classification endpoint generating 0(log N) evaluations.
    ///
    /// Natively loops down the tree utilizing solely integer branch prediction checks until
    /// a Leaf node matches perfectly against the inbound sequence parameter variables.
    pub fn evaluate(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> Option<(u32, Action)> {
        let mut curr = self;
        loop {
            match curr {
                HyperNode::Leaf(rules) => {
                    // We found an endpoint localized bucket! Linearly assess the narrowed targets.
                    // Because trees are pre-sorted by Priority, the *first* validating hit is strictly 
                    // mathematically correct natively via rule shadowing definitions.
                    for r in rules {
                        if src_ip >= r.src_ip.min && src_ip <= r.src_ip.max &&
                           dst_ip >= r.dst_ip.min && dst_ip <= r.dst_ip.max &&
                           src_port >= r.src_port.min && src_port <= r.src_port.max &&
                           dst_port >= r.dst_port.min && dst_port <= r.dst_port.max &&
                           proto >= r.proto.min && proto <= r.proto.max 
                        {
                            return Some((r.id, r.action.clone()));
                        }
                    }
                    return None; // Completely bypassed any valid limits
                }
                HyperNode::Internal { dim, cut_val, left, right } => {
                    // High-performance branching lookup directly mapping parameter to dimensional axes boundaries
                    let val = match dim {
                        0 => src_ip,
                        1 => dst_ip,
                        2 => src_port as u32,
                        3 => dst_port as u32,
                        4 => proto as u32,
                        _ => unreachable!(),
                    };
                    if val <= *cut_val {
                        curr = left;
                    } else {
                        curr = right;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Bootstraps realistic, extremely broadly focused L3 traffic limitation rules for internal verification.
    fn make_rule(id: u32, priority: u32, action: Action, src_port_min: u16, src_port_max: u16) -> L3Rule {
        L3Rule {
            id,
            priority,
            src_ip: Range { min: 10, max: 10 },
            dst_ip: Range { min: 10, max: 10 },
            src_port: Range { min: src_port_min, max: src_port_max },
            dst_port: Range { min: 10, max: 10 },
            proto: Range { min: 10, max: 10 },
            action,
        }
    }

    /// Ensures that mathematically discrete non-colliding segments resolve deterministically without conflict.
    #[test]
    fn test_discrete_disjoint_separation() {
        let rules = vec![
            make_rule(1, 10, Action::Drop, 0, 10),
            make_rule(2, 10, Action::Alert, 20, 30),
        ];

        let tree = HyperNode::build(rules);

        // Test: Expect Rule 1 match because port falls between 0 and 10.
        let match1 = tree.evaluate(10, 10, 5, 10, 10);
        assert_eq!(match1.unwrap().0, 1, "Test: Precise discrete lookup targeted Rule 1 natively");
        assert_eq!(match1.unwrap().1, Action::Drop);

        // Test: Expect Rule 2 match because port falls between 20 and 30.
        let match2 = tree.evaluate(10, 10, 25, 10, 10);
        assert_eq!(match2.unwrap().0, 2, "Test: Precise discrete lookup targeted Rule 2 natively");
        assert_eq!(match2.unwrap().1, Action::Alert);

        // Test: Dysfunctional targeting hitting gaps specifically designed to fail filtering natively.
        let miss = tree.evaluate(10, 10, 15, 10, 10);
        assert!(miss.is_none(), "Test: Empty void limits natively bypass the engine as designed.");
    }

    /// Evaluates dysfunctional nested geometric shadowing interactions prioritizing precedence execution.
    #[test]
    fn test_overlapping_dysfunctional_shadowing() {
        // Shadow Rule Set:
        // Rule 1 encompasses a massive space (Port 0-100), but has LOWER priority mathematically (100).
        // Rule 2 targets a sniper-precision area INSIDE Rule 1 (Port 50-60) with HIGHER precedence (10).
        let rules = vec![
            make_rule(1, 100, Action::Drop, 0, 100),
            make_rule(2, 10, Action::Alert, 50, 60),
        ];

        let tree = HyperNode::build(rules);

        // Test: Assess the outer geometric body. This should trigger Rule 1 directly.
        let m1 = tree.evaluate(10, 10, 10, 10, 10);
        assert_eq!(m1.unwrap().0, 1, "Test: Evaluates outer non-overlapping segments natively.");
        assert_eq!(m1.unwrap().1, Action::Drop);

        // Test: Assess the dysfunctional overlap zone. Because Rule 2 holds precedence, the algorithm 
        // MUST natively bypass Rule 1 and strictly authorize Rule 2's alerting requirement!
        let m2 = tree.evaluate(10, 10, 55, 10, 10);
        assert_eq!(m2.unwrap().0, 2, "Test: Mathematical bounds shadowing resolved using hierarchical priority successfully!");
        assert_eq!(m2.unwrap().1, Action::Alert);
    }

    /// Tests that the tree behaves elegantly and safely when built completely empty.
    #[test]
    fn test_totally_empty_tree_bypassing() {
        let tree = HyperNode::build(vec![]);
        assert!(tree.evaluate(1, 1, 1, 1, 1).is_none(), "Test: Total void generation avoids panic paths gracefully native to Rust.");
    }

    /// Tests extreme depth boundary generation (mass colliding identical blocks).
    #[test]
    fn test_identical_collisions_depth_ceiling() {
        let mut massive_identical = Vec::new();
        for i in 0..100 {
            // Generating identical identical constraints forces the HyperCuts mathematical generator 
            // into an infinite loop attempt if dimension slicing heuristics fail. The max_depth constraint
            // stops this instantly.
            massive_identical.push(make_rule(i, i, Action::Drop, 50, 50));
        }

        let tree = HyperNode::build(massive_identical);
        
        // Assert sorting rules properly prioritize execution of the tightest priority even when stuck in a mass Leaf node.
        let m = tree.evaluate(10, 10, 50, 10, 10);
        assert_eq!(m.unwrap().0, 0, "Test: Max depth collision safely isolates top priority without engine panic.");
    }
}
