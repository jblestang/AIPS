//! # aips-l7
//!
//! Layer 7 protocol analysers for AIPS.
//!
//! All analysers are zero-copy: they borrow `&[u8]` slices and return
//! lifetime-bound view types. No heap allocation is required.
//!
//! `no_std` compatible.

#![no_std]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod dns;
pub mod http;
pub mod ntp;
pub mod ssh;
pub mod tls;
pub mod dispatcher;

pub use dispatcher::L7Dispatcher;
