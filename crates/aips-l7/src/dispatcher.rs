//! L7 protocol dispatcher.
//!
//! Selects the appropriate analyser based on port heuristics, then populates
//! a [`L7Verdict`] that the rule engine consumes.

use crate::{http, dns, ntp, ssh, tls};
use aips_core::classifier::L7Protocol;
use aips_rules::engine::MatchCtx;

/// Result of L7 analysis for a single stream chunk or datagram.
pub struct L7Verdict<'a> {
    /// HTTP Host header (if HTTP).
    pub http_host:   Option<&'a str>,
    /// DNS query name (if DNS).
    pub dns_name:    Option<&'a str>,
    /// TLS SNI (if TLS ClientHello).
    pub tls_sni:     Option<&'a str>,
    /// SSH identification string (if SSH).
    pub ssh_banner:  Option<&'a str>,
    /// NTP mode (if NTP).
    pub ntp_mode:    Option<u8>,
    /// `true` if the NTP packet is a potential amplification vector.
    pub ntp_amp:     bool,
    /// `true` if DNS tunneling is suspected.
    pub dns_tunnel:  bool,
    /// `true` if TLS uses a weak cipher.
    pub tls_weak:    bool,
    /// `true` if HTTP path contains traversal pattern.
    pub http_traversal: bool,
}

/// The L7 dispatcher consumes a payload + port pair and returns an analysis verdict.
pub struct L7Dispatcher;

impl L7Dispatcher {
    /// Analyse `payload` from a flow with `dst_port`.
    ///
    /// The caller must supply scratch buffers for protocols that need them:
    /// - `dns_name_buf`: at least 256 bytes, used to decode DNS names.
    /// - `http_header_buf`: an `httparse::Header` array for HTTP.
    pub fn dispatch<'a>(
        payload:         &'a [u8],
        protocol:        aips_core::classifier::L7Protocol,
        dns_name_buf:    &'a mut [u8],
        http_header_buf: &'a mut [httparse::Header<'a>; 32],
    ) -> L7Verdict<'a> {
        let mut v = L7Verdict {
            http_host:    None,
            dns_name:     None,
            tls_sni:      None,
            tls_weak:     false,
            ssh_banner:   None,
            dns_tunnel:   false,
            ntp_mode:     None,
            ntp_amp:      false,
            http_traversal: false,
        };

        use crate::{http, dns, ntp, ssh, tls};
        use aips_core::classifier::L7Protocol;
        match protocol {
            L7Protocol::Http => {
                if let Some(req) = http::parse_request(payload, http_header_buf) {
                    v.http_host = req.host;
                    v.http_traversal = req.path
                        .map(http::has_path_traversal)
                        .unwrap_or(false);
                }
            }
            L7Protocol::Tls => {
                if let Some(hello) = tls::parse_client_hello(payload) {
                    v.tls_sni  = hello.sni;
                    v.tls_weak = hello.has_weak_cipher;
                }
            }
            L7Protocol::Dns => {
                if let Some(d) = dns::parse(payload, dns_name_buf) {
                    v.dns_name   = d.first_query_name;
                    v.dns_tunnel = d.high_entropy_label || d.has_long_label;
                }
            }
            L7Protocol::Ntp => {
                if let Some(n) = ntp::parse(payload) {
                    v.ntp_amp  = n.is_amplification_risk;
                }
            }
            L7Protocol::Ssh => {
                if let Some(s) = ssh::parse_version(payload) {
                    v.ssh_banner = Some(s.banner);
                }
            }
            L7Protocol::Unknown => {
                // DPI fallback: try all parsers heuristically.
                if let Some(hello) = tls::parse_client_hello(payload) {
                    v.tls_sni  = hello.sni;
                    v.tls_weak = hello.has_weak_cipher;
                } else if let Some(s) = ssh::parse_version(payload) {
                    v.ssh_banner = Some(s.banner);
                } else if let Some(d) = dns::parse(payload, dns_name_buf) {
                    v.dns_name   = d.first_query_name;
                    v.dns_tunnel = d.high_entropy_label || d.has_long_label;
                } else if let Some(n) = ntp::parse(payload) {
                    v.ntp_mode = Some(n.mode);
                    v.ntp_amp  = n.is_amplification_risk;
                }
            }
            L7Protocol::Bypass => {
                // Should be handled by Classifier (Decision::Forward)
            }
        }
        v
    }

    /// Convert an [`L7Verdict`] into a [`MatchCtx`] for the rule engine.
    pub fn to_match_ctx<'a>(
        verdict: &'a L7Verdict<'a>,
        payload: &'a [u8],
        dst_port: u16,
        src_ip: [u8; 16],
    ) -> MatchCtx<'a> {
        MatchCtx {
            payload,
            http_host:  verdict.http_host,
            dns_name:   verdict.dns_name,
            tls_sni:    verdict.tls_sni,
            ntp_mode:   verdict.ntp_mode,
            ssh_banner: verdict.ssh_banner,
            dst_port,
            src_ip,
        }
    }
}
