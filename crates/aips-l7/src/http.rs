//! HTTP/1.x zero-copy analyser.
//!
//! Uses `httparse` (no_std, no alloc) to parse the request/response line
//! and up to 32 headers from the reassembled L7 stream.

use httparse::{Request, Response};

/// Maximum number of HTTP headers parsed in one pass.
const MAX_HEADERS: usize = 32;

/// Zero-copy view of a parsed HTTP/1.x request.
pub struct HttpRequestView<'a> {
    /// HTTP method (e.g. `"GET"`).
    pub method:  Option<&'a str>,
    /// Request path (e.g. `"/index.html"`).
    pub path:    Option<&'a str>,
    /// HTTP version (e.g. `1` for HTTP/1.1).
    pub version: Option<u8>,
    /// `Host:` header value (zero-copy slice).
    pub host:    Option<&'a str>,
    /// `Content-Type:` header value.
    pub content_type: Option<&'a str>,
    /// `User-Agent:` header value.
    pub user_agent: Option<&'a str>,
}

/// Zero-copy view of a parsed HTTP/1.x response.
pub struct HttpResponseView<'a> {
    /// HTTP status code.
    pub status:  Option<u16>,
    /// HTTP version.
    pub version: Option<u8>,
    /// `Content-Type:` header value.
    pub content_type: Option<&'a str>,
}

/// Parse an HTTP/1.x request from a reassembled byte slice.
///
/// Returns `None` if `buf` is not a complete HTTP request header block.
pub fn parse_request<'a>(
    buf: &'a [u8],
    header_buf: &'a mut [httparse::Header<'a>; MAX_HEADERS],
) -> Option<HttpRequestView<'a>> {
    let mut req = Request::new(header_buf);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {}
        Err(_) => return None,
    }

    let host = find_header(req.headers, "host");
    let content_type = find_header(req.headers, "content-type");
    let user_agent = find_header(req.headers, "user-agent");

    Some(HttpRequestView {
        method:       req.method,
        path:         req.path,
        version:      req.version,
        host,
        content_type,
        user_agent,
    })
}

/// Parse an HTTP/1.x response from a reassembled byte slice.
pub fn parse_response<'a>(
    buf: &'a [u8],
    header_buf: &'a mut [httparse::Header<'a>; MAX_HEADERS],
) -> Option<HttpResponseView<'a>> {
    let mut resp = Response::new(header_buf);
    match resp.parse(buf) {
        Ok(httparse::Status::Complete(_)) | Ok(httparse::Status::Partial) => {}
        Err(_) => return None,
    }

    let content_type = find_header(resp.headers, "content-type");

    Some(HttpResponseView {
        status:  resp.code,
        version: resp.version,
        content_type,
    })
}

/// Quick check: does the buffer look like a path traversal attempt?
///
/// Checks for `../`, `..\`, and URL-encoded variants.
pub fn has_path_traversal(path: &str) -> bool {
    path.contains("../") || path.contains("..\\")
        || path.contains("%2e%2e%2f") || path.contains("%2e%2e%5c")
        || path.contains("%2e%2e/")   || path.contains("..%2f")
}

/// Quick check: does the path contain common SQLi signatures?
pub fn has_sqli_pattern(path: &str) -> bool {
    // Simplified heuristic – the rule engine's Aho-Corasick handles more patterns.
    let lower = path.as_bytes();
    contains_ci(lower, b"union select")
        || contains_ci(lower, b"' or '1'='1")
        || contains_ci(lower, b"drop table")
        || contains_ci(lower, b"--")
}

fn find_header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Option<&'a str> {
    for h in headers {
        if h.name.eq_ignore_ascii_case(name) {
            return core::str::from_utf8(h.value).ok();
        }
    }
    None
}

fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() { return false; }
    haystack.windows(needle.len()).any(|w| {
        w.iter().zip(needle.iter()).all(|(a, b)| {
            a.to_ascii_lowercase() == b.to_ascii_lowercase()
        })
    })
}
