//! NTP zero-copy analyser.
//!
//! Parses NTPv2–v4 datagrams (48-byte fixed header) without any heap allocation.
//! Detects NTP amplification/reflection attacks and legacy mode 7 (MONLIST).

/// NTP mode constants.
pub mod mode {
    /// Symmetric passive / peer.
    pub const SYMMETRIC_PASSIVE: u8 = 2;
    /// Client request.
    pub const CLIENT: u8 = 3;
    /// Server reply.
    pub const SERVER: u8 = 4;
    /// Broadcast.
    pub const BROADCAST: u8 = 5;
    /// Private / control (mode 7 — used by MONLIST).
    pub const CONTROL: u8 = 6;
    /// Private (mode 7 — MONLIST amplification vector).
    pub const PRIVATE: u8 = 7;
}

/// Zero-copy view of a parsed NTP packet.
#[derive(Debug, Clone, Copy)]
pub struct NtpView {
    /// Leap Indicator (2 bits).
    pub leap:    u8,
    /// NTP version (3 bits, values 2–4 valid).
    pub version: u8,
    /// NTP mode (3 bits).
    pub mode:    u8,
    /// Stratum level (0 = unspecified/kiss-o-death, 1 = primary, ≥2 = secondary).
    pub stratum: u8,
    /// Reference clock identifier (4 bytes, interpreted as ASCII for stratum 1).
    pub ref_id:  [u8; 4],
    /// `true` if this looks like an amplification reflection attempt.
    pub is_amplification_risk: bool,
}

/// Parse a NTP UDP payload.
///
/// Standard NTP packets are exactly 48 bytes (ignoring optional extension fields).
/// Returns `None` if `buf` is shorter than 48 bytes or the version is invalid.
pub fn parse(buf: &[u8]) -> Option<NtpView> {
    if buf.len() < 48 { return None; }

    let li_vn_mode = buf[0];
    let leap    = (li_vn_mode >> 6) & 0x03;
    let version = (li_vn_mode >> 3) & 0x07;
    let mode    = li_vn_mode & 0x07;

    if version < 1 || version > 4 { return None; }

    let stratum = buf[1];
    let ref_id  = [buf[12], buf[13], buf[14], buf[15]];

    // Amplification heuristic:
    // - Mode 7 (PRIVATE) can be used for MONLIST amplification (100× factor).
    // - Mode 6 READVAR is also a common amplification vector.
    // - Stratum 0 "KISS" packets with unusual ref_id can be used in reflection.
    let is_amplification_risk = mode == mode::PRIVATE
        || mode == mode::CONTROL
        || (stratum == 0 && mode == mode::SERVER);

    Some(NtpView { leap, version, mode, stratum, ref_id, is_amplification_risk })
}

/// Check if the `ref_id` for a stratum-1 server matches a set of known-good
/// reference clock identifiers (e.g. `GPS `, `PPS `, `LOCL`).
pub fn is_known_refid(ref_id: &[u8; 4]) -> bool {
    const KNOWN: &[[u8; 4]] = &[
        *b"GPS ", *b"PPS ", *b"LOCL", *b"DCF ", *b"MSF ",
        *b"GOES", *b"WWV ", *b"WWVB", *b"CHU ", *b"IRIG",
    ];
    KNOWN.contains(ref_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_client_request() {
        // Minimal NTPv4 client request (all-zeros is valid for a client)
        let mut buf = [0u8; 48];
        buf[0] = 0b_00_100_011; // LI=0, VN=4, Mode=3 (CLIENT)
        let view = parse(&buf).unwrap();
        assert_eq!(view.version, 4);
        assert_eq!(view.mode, mode::CLIENT);
        assert!(!view.is_amplification_risk);
    }

    #[test]
    fn detect_monlist() {
        let mut buf = [0u8; 48];
        buf[0] = 0b_00_010_111; // LI=0, VN=2, Mode=7 (PRIVATE)
        let view = parse(&buf).unwrap();
        assert_eq!(view.mode, mode::PRIVATE);
        assert!(view.is_amplification_risk);
    }
}
