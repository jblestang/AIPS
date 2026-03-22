//! DNS zero-copy analyser.
//!
//! Hand-written zero-copy DNS parser for the wire format (RFC 1035).
//! No heap allocation, no external DNS crate API dependency — parses the
//! raw UDP payload directly.

/// Zero-copy view of a parsed DNS message.
pub struct DnsView<'a> {
    /// Message ID.
    pub id: u16,
    /// `true` if this is a response (QR bit set).
    pub is_response: bool,
    /// The first question's decoded name (written into `name_buf`).
    pub first_query_name: Option<&'a str>,
    /// Number of questions in this message.
    pub question_count: u16,
    /// Number of answers.
    pub answer_count: u16,
    /// `true` if the first label name is suspiciously long (> 128 chars).
    pub has_long_label: bool,
    /// `true` if the name appears high-entropy (potential DNS tunneling).
    pub high_entropy_label: bool,
}

/// Parse a raw DNS UDP payload.
///
/// `name_buf` is a caller-supplied scratch buffer (≥ 256 bytes) for the
/// decoded first query name.
pub fn parse<'a>(buf: &[u8], name_buf: &'a mut [u8]) -> Option<DnsView<'a>> {
    if buf.len() < 12 { return None; }

    let id             = u16::from_be_bytes([buf[0], buf[1]]);
    let flags          = u16::from_be_bytes([buf[2], buf[3]]);
    let is_response    = (flags & 0x8000) != 0;
    let question_count = u16::from_be_bytes([buf[4], buf[5]]);
    let answer_count   = u16::from_be_bytes([buf[6], buf[7]]);

    // Decode the first question name.
    let first_query_name = if question_count > 0 {
        decode_name(buf, 12, name_buf)
    } else {
        None
    };

    let has_long_label = first_query_name
        .map(|n: &str| n.len() > 128)
        .unwrap_or(false);

    let high_entropy_label = first_query_name
        .map(|n: &str| is_high_entropy(n.as_bytes()))
        .unwrap_or(false);

    Some(DnsView {
        id,
        is_response,
        first_query_name,
        question_count,
        answer_count,
        has_long_label,
        high_entropy_label,
    })
}

/// Decode a DNS name at `offset` in `buf` into `out`.
///
/// Returns `Some(&str)` pointing into `out`, or `None` on parse error.
fn decode_name<'a>(buf: &[u8], mut offset: usize, out: &'a mut [u8]) -> Option<&'a str> {
    let mut out_pos = 0usize;
    let mut jumps   = 0usize;

    loop {
        if offset >= buf.len() { return None; }
        let len = buf[offset] as usize;
        offset += 1;

        if len == 0 { break; } // root label

        if len & 0xC0 == 0xC0 {
            // Pointer compression
            if offset >= buf.len() { return None; }
            if jumps > 10 { return None; } // loop guard
            let ptr = ((len & 0x3F) << 8) | buf[offset] as usize;
            offset = ptr;
            jumps += 1;
            continue;
        }

        if len & 0xC0 != 0 { return None; } // reserved

        if offset + len > buf.len() { return None; }

        if out_pos > 0 {
            if out_pos >= out.len() { return None; }
            out[out_pos] = b'.';
            out_pos += 1;
        }
        let label = &buf[offset..offset + len];
        if out_pos + len > out.len() { return None; }
        out[out_pos..out_pos + len].copy_from_slice(label);
        out_pos += len;
        offset   += len;
    }

    core::str::from_utf8(&out[..out_pos]).ok()
}

/// A fast, float-free heuristic for detecting highly entropic (random) labels
/// common in DNS tunneling (e.g. base64, hex encoding).
/// Returns true if the label is long and has a high ratio of unique characters.
fn is_high_entropy(data: &[u8]) -> bool {
    let n = data.len();
    if n < 24 { return false; } // Too short to reliably measure entropy

    let mut seen = [false; 256];
    let mut unique_count = 0;
    
    for &b in data {
        if !seen[b as usize] {
            seen[b as usize] = true;
            unique_count += 1;
        }
    }
    
    // If unique character count > 60% of total length for a long string,
    // it's highly likely to be a random hash or base64 (tunneling).
    // Avoids floats: unique * 100 / n > 60
    (unique_count * 100 / n) > 60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_query() {
        // DNS query for "example.com" (type A)
        #[rustfmt::skip]
        let pkt: &[u8] = &[
            0xAB, 0xCD,       // ID
            0x01, 0x00,       // Flags: QR=0 (query), RD=1
            0x00, 0x01,       // QDCOUNT = 1
            0x00, 0x00,       // ANCOUNT = 0
            0x00, 0x00,       // NSCOUNT = 0
            0x00, 0x00,       // ARCOUNT = 0
            // QNAME: 7 "example" 3 "com" 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00,
            0x00, 0x01,       // QTYPE  = A
            0x00, 0x01,       // QCLASS = IN
        ];
        let mut name_buf = [0u8; 256];
        let view = parse(pkt, &mut name_buf).unwrap();
        assert_eq!(view.id, 0xABCD);
        assert!(!view.is_response);
        assert_eq!(view.first_query_name, Some("example.com"));
        assert!(!view.high_entropy_label);
    }
}
