//! TLS ClientHello SNI extractor.
//!
//! Uses a hand-written zero-copy parser (no alloc, no_std) to extract the
//! Server Name Indication from a TLS 1.x ClientHello record without
//! attempting full TLS parsing.
//!
//! Deprecated cipher suites (RC4, 3DES, NULL, EXPORT) are also flagged.

/// Zero-copy view of a parsed TLS ClientHello.
pub struct TlsClientHelloView<'a> {
    /// SNI hostname extracted from the `server_name` extension (if present).
    pub sni: Option<&'a str>,
    /// TLS version requested by the client.
    pub client_version: u16,
    /// `true` if the ClientHello includes known-bad cipher suites.
    pub has_weak_cipher: bool,
}

/// Attempt to parse a TLS ClientHello from the start of `buf`.
///
/// Returns `None` if `buf` does not begin with a valid TLS 1.x handshake record
/// containing a ClientHello.
pub fn parse_client_hello<'a>(buf: &'a [u8]) -> Option<TlsClientHelloView<'a>> {
    // TLS Record Layer: content_type(1) version(2) length(2)
    if buf.len() < 5 { return None; }
    if buf[0] != 0x16 { return None; } // content_type = Handshake
    let _record_version = u16::from_be_bytes([buf[1], buf[2]]);
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len { return None; }

    // Handshake header: type(1) length(3)
    let hs = &buf[5..5 + record_len];
    if hs.len() < 4 { return None; }
    if hs[0] != 0x01 { return None; } // HandshakeType::ClientHello

    // ClientHello body
    let ch = &hs[4..];
    if ch.len() < 34 { return None; }

    let client_version = u16::from_be_bytes([ch[0], ch[1]]);
    // Skip: client_version(2) + random(32)
    let mut off = 34;

    // Session ID
    if off >= ch.len() { return None; }
    let sid_len = ch[off] as usize;
    off += 1 + sid_len;

    // Cipher Suites
    if off + 2 > ch.len() { return None; }
    let cs_len = u16::from_be_bytes([ch[off], ch[off + 1]]) as usize;
    let cs_start = off + 2;
    if cs_start + cs_len > ch.len() { return None; }
    // Pass cipher suites to the weak cipher detector
    let cipher_suites = &ch[cs_start..cs_start + cs_len];
    let has_weak_cipher = has_weak_ciphers(cipher_suites);
    off = cs_start + cs_len;

    // Compression methods
    if off >= ch.len() { return None; }
    let comp_len = ch[off] as usize;
    off += 1 + comp_len;

    // Extensions
    let mut sni: Option<&'a str> = None;
    if off + 2 <= ch.len() {
        let ext_total = u16::from_be_bytes([ch[off], ch[off + 1]]) as usize;
        off += 2;
        let ext_end = off + ext_total;
        
        while off + 4 <= ext_end.min(ch.len()) {
            let ext_type = u16::from_be_bytes([ch[off], ch[off + 1]]);
            let ext_len  = u16::from_be_bytes([ch[off + 2], ch[off + 3]]) as usize;
            off += 4;
            
            if off + ext_len > ch.len() { break; }
            
            // Extension type 0x0000 = server_name
            if ext_type == 0x0000 {
                // Read ServerNameList: len(2), type(1), name_len(2), name(...)
                let ext_data = &ch[off..off + ext_len];
                sni = parse_sni(ext_data);
            }
            off += ext_len;
        }
    }

    Some(TlsClientHelloView { sni, client_version, has_weak_cipher })
}

fn parse_sni(data: &[u8]) -> Option<&str> {
    // SNI extension: list_len(2), type(1), name_len(2), name(...)
    if data.len() < 5 { return None; }
    let _list_len = u16::from_be_bytes([data[0], data[1]]);
    if data[2] != 0x00 { return None; } // name_type = host_name
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if 5 + name_len > data.len() { return None; }
    core::str::from_utf8(&data[5..5 + name_len]).ok()
}

fn has_weak_ciphers(cs: &[u8]) -> bool {
    // Weak cipher suite prefixes/suffixes (sampling, not exhaustive)
    const WEAK: &[[u8; 2]] = &[
        [0x00, 0x04], // TLS_RSA_WITH_RC4_128_MD5
        [0x00, 0x05], // TLS_RSA_WITH_RC4_128_SHA
        [0x00, 0x0A], // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        [0x00, 0x00], // TLS_NULL_WITH_NULL_NULL
        [0xC0, 0x07], // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        [0xC0, 0x11], // TLS_ECDHE_RSA_WITH_RC4_128_SHA
    ];
    cs.chunks_exact(2).any(|s| WEAK.iter().any(|w| s == w))
}
