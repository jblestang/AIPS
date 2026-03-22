//! SSH version exchange and handshake parser.
//!
//! Extracts the SSH identification string (e.g. "SSH-2.0-OpenSSH_9.6")
//! at the start of a TCP session.

use core::str;

/// Extracted SSH metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshView<'a> {
    /// The software version part of the identification string (e.g. "OpenSSH_9.6").
    pub version: &'a str,
    /// The full identification string (e.g. "SSH-2.0-OpenSSH_9.6").
    pub banner: &'a str,
}

/// Parse the SSH identification string from the start of the stream.
pub fn parse_version(payload: &[u8]) -> Option<SshView<'_>> {
    if !payload.starts_with(b"SSH-") {
        return None;
    }

    // Identify the end of the line (CR or LF)
    let mut len = 0;
    while len < payload.len() && payload[len] != b'\r' && payload[len] != b'\n' {
        len += 1;
    }
    
    if len == 0 {
        return None; 
    }

    let banner = str::from_utf8(&payload[..len]).ok()?;
    
    // Banner format: SSH-protoversion-softwareversion
    // We want to skip "SSH-" (4) and the protoversion part (e.g. "2.0-")
    if banner.len() > 8 && &banner[0..4] == "SSH-" {
        let remainder = &banner[4..];
        if let Some(dash_idx) = remainder.find('-') {
            return Some(SshView {
                version: &remainder[dash_idx + 1..],
                banner,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_version() {
        let payload = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n";
        let view = parse_version(payload).unwrap();
        assert_eq!(view.version, "OpenSSH_8.2p1 Ubuntu-4ubuntu0.1");
        assert_eq!(view.banner, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1");
    }

    #[test]
    fn test_parse_ssh_short() {
        let payload = b"SSH-2.0-JSCH-0.1.54\n";
        let view = parse_version(payload).unwrap();
        assert_eq!(view.version, "JSCH-0.1.54");
    }

    #[test]
    fn test_non_ssh() {
        assert!(parse_version(b"GET / HTTP/1.1").is_none());
    }
}
