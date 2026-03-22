//! # aips-core
//!
//! Zero-copy Layer 2–4 packet pipeline for the AIPS intrusion prevention system.
//!
//! `no_std` compatible. Requires `alloc` only when the `alloc` feature is enabled.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod classifier;
pub mod decision;
pub mod defrag;
pub mod flow;
pub mod layer;
pub mod pipeline;
pub mod qos;

pub use decision::Decision;
pub use flow::{FlowKey, FlowState, SessionTable};
pub use pipeline::Pipeline;
pub use qos::QosFields;
