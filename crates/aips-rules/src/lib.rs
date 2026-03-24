//! # aips-rules
//!
//! Rule engine for the AIPS IPS/IDS.
//!
//! `no_std` compatible. No heap allocation required.

#![no_std]
#![warn(missing_docs)]


pub mod action;
pub mod engine;
pub mod rule;
pub mod hypercuts;

pub use action::Action;
pub use engine::RuleEngine;
pub use rule::{MatchExpr, Rule};
