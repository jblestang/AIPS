//! Unit tests for aips-l7 protocols.

use aips_l7::http;
use aips_l7::dns;
use aips_l7::tls;
use aips_l7::ntp;

#[test]
fn test_http_parse() {
    let req = b"GET /../../etc/passwd HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    let mut headers = [httparse::EMPTY_HEADER; 32];
    
    let view = http::parse_request(req, &mut headers).expect("Valid HTTP request");
    assert_eq!(view.method, Some("GET"));
    assert_eq!(view.path, Some("/../../etc/passwd"));
    assert_eq!(view.host, Some("example.com"));
    
    // Check path traversal heuristic
    assert!(http::has_path_traversal(view.path.unwrap()));
}

#[test]
fn test_dns_parse() {
    // DNS query for "test.com" (type A)
    #[rustfmt::skip]
    let pkt: &[u8] = &[
        0xAB, 0xCD,       // ID
        0x01, 0x00,       // Flags: QR=0 (query), RD=1
        0x00, 0x01,       // QDCOUNT = 1
        0x00, 0x00,       // ANCOUNT = 0
        0x00, 0x00,       // NSCOUNT = 0
        0x00, 0x00,       // ARCOUNT = 0
        // QNAME: 4 "test" 3 "com" 0
        0x04, b't', b'e', b's', b't',
        0x03, b'c', b'o', b'm', 0x00,
        0x00, 0x01,       // QTYPE  = A
        0x00, 0x01,       // QCLASS = IN
    ];
    let mut name_buf = [0u8; 256];
    let view = dns::parse(pkt, &mut name_buf).expect("Valid DNS packet");
    assert_eq!(view.id, 0xABCD);
    assert!(!view.is_response);
    assert_eq!(view.first_query_name, Some("test.com"));
    assert!(!view.high_entropy_label);
    assert!(!view.has_long_label);
}

#[test]
fn test_dns_tunneling_heuristic() {
    // DNS query with highly entropic, long label
    #[rustfmt::skip]
    let pkt: &[u8] = &[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // QNAME: 32 bytes of high entropy -> "vX9kZ3pQa1bW4cY8fR2jN5mH6tS0dL7x"
        0x20,
        b'v', b'X', b'9', b'k', b'Z', b'3', b'p', b'Q', b'a', b'1', b'b', b'W', b'4', b'c', b'Y', b'8',
        b'f', b'R', b'2', b'j', b'N', b'5', b'm', b'H', b'6', b't', b'S', b'0', b'd', b'L', b'7', b'x',
        0x03, b'c', b'o', b'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
    ];
    let mut name_buf = [0u8; 256];
    let view = dns::parse(pkt, &mut name_buf).expect("Valid DNS packet");
    
    // Shannon entropy estimate will flag this pseudo-base64 string
    assert!(view.high_entropy_label);
}

#[test]
fn test_tls_sni_extraction() {
    // Exact TLS 1.2 ClientHello with SNI "example.com"
    #[rustfmt::skip]
    let pkt: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x47, // Record Layer (length 71)
        0x01, 0x00, 0x00, 0x43,       // Handshake ClientHello (length 67)
        0x03, 0x03,                   // Version TLS 1.2
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // Random
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,                         // Session ID Length: 0
        0x00, 0x02, 0x13, 0x01,       // Cipher Suites: length 2, TLS_AES_128_GCM_SHA256
        0x01, 0x00,                   // Compression Length: 1, Method: Null
        0x00, 0x18,                   // Extensions length (24 bytes)
        // Extension 1: Server Name (type 0x0000)
        0x00, 0x00, 0x00, 0x14,       // Extension Type: 0, Length: 20
        0x00, 0x12,                   // Server Name List Length: 18
        0x00,                         // Server Name Type: host_name (0)
        0x00, 0x0f,                   // Host Name Length: 15
        b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm' // "www.example.com"
    ];
    
    let view = tls::parse_client_hello(pkt).expect("Valid ClientHello");
    assert_eq!(view.sni, Some("www.example.com"));
    assert!(!view.has_weak_cipher);
}

#[test]
fn test_tls_weak_cipher_detection() {
    // ClientHello with RC4 (0x0004)
    // Structured precisely to match TLS 1.2
    #[rustfmt::skip]
    let pkt: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x2f, // Record Layer (length 47)
        0x01, 0x00, 0x00, 0x2b,       // Handshake ClientHello (length 43)
        0x03, 0x03,                   // Version TLS 1.2
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // Random
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,                         // Session ID Length: 0
        0x00, 0x04,                   // Cipher Suites Length: 4
        0x00, 0x04, 0x00, 0x2f,       // Ciphers: TLS_RSA_WITH_RC4_128_MD5, TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00,                   // Compression Length: 1, Method: Null
        0x00, 0x00,                   // Extensions Length: 0
    ];
    let view = tls::parse_client_hello(pkt).expect("Valid ClientHello");
    assert!(view.has_weak_cipher);
}

#[test]
fn test_ntp_parse() {
    // Mode 7 (PRIVATE) - MONLIST vector
    let mut pkt = [0u8; 48];
    pkt[0] = 0b_00_010_111; // VN=2, Mode=7
    
    let view = ntp::parse(&pkt).expect("Valid NTP packet");
    assert_eq!(view.mode, 7);
    assert!(view.is_amplification_risk);
}
