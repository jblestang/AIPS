//! # aips-proxy
//!
//! Layer 4 proxy engine for AIPS.
//!
//! When the classifier emits `Decision::ProxyTcp` or `Decision::ProxyUdp`,
//! the packet is handed here. The proxy terminates the client-side session,
//! runs L7 inspection on the reassembled stream, and re-establishes a new
//! connection to the real server — preserving DSCP, ECN, and TTL on all
//! outbound segments.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod tcp_proxy;
pub mod udp_proxy;
pub mod qos_stamp;

pub use tcp_proxy::TcpProxy;
pub use udp_proxy::UdpProxy;
