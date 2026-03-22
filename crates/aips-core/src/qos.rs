//! QoS field extraction and re-stamping.
//!
//! IPv4: `TOS` byte carries `DSCP` (bits 7–2) and `ECN` (bits 1–0). `TTL` is the hop limit.
//! IPv6: `Traffic Class` byte carries `DSCP` (bits 7–2) and `ECN` (bits 1–0). `Hop Limit` is TTL.

/// QoS fields extracted from an IP packet's L3 header.
///
/// These are captured at ingress and **re-stamped verbatim** on every
/// outbound segment emitted by the L4 proxy, so that Differentiated Services
/// markings and TTL scoping are transparent across the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QosFields {
    /// Differentiated Services Code Point (6 bits, from TOS/TrafficClass).
    pub dscp: u8,
    /// Explicit Congestion Notification (2 bits, from TOS/TrafficClass).
    pub ecn: u8,
    /// IP Time-To-Live (IPv4) or Hop Limit (IPv6).
    pub ttl: u8,
}

impl QosFields {
    /// Reconstruct the IPv4 TOS byte (`DSCP << 2 | ECN`).
    #[inline]
    pub fn to_tos(self) -> u8 {
        (self.dscp << 2) | (self.ecn & 0x03)
    }

    /// Reconstruct the IPv6 Traffic Class byte (same encoding as IPv4 TOS).
    #[inline]
    pub fn to_traffic_class(self) -> u8 {
        self.to_tos()
    }

    /// Parse from an IPv4 TOS byte + TTL.
    #[inline]
    pub fn from_ipv4(tos: u8, ttl: u8) -> Self {
        Self { dscp: tos >> 2, ecn: tos & 0x03, ttl }
    }

    /// Parse from an IPv6 Traffic Class byte + Hop Limit.
    #[inline]
    pub fn from_ipv6(traffic_class: u8, hop_limit: u8) -> Self {
        Self::from_ipv4(traffic_class, hop_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ipv4() {
        // TOS = 0xB8 → DSCP = 46 (EF), ECN = 0
        let q = QosFields::from_ipv4(0xB8, 64);
        assert_eq!(q.dscp, 46);
        assert_eq!(q.ecn, 0);
        assert_eq!(q.ttl, 64);
        assert_eq!(q.to_tos(), 0xB8);
    }

    #[test]
    fn roundtrip_ecn() {
        // ECN = 3 (CE mark)
        let q = QosFields::from_ipv4(0x03, 128);
        assert_eq!(q.dscp, 0);
        assert_eq!(q.ecn, 3);
        assert_eq!(q.to_tos(), 0x03);
    }
}
