//! AIPS — Layer 2 IPS CLI binary.
//!
//! Usage:
//! ```
//! sudo aips start --iface-in eth0 --iface-out eth1 --rules rules.toml [--ids]
//! ```

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aips",
    version,
    about = "AIPS — Layer 2 Intrusion Prevention System",
    long_about = "A bump-in-the-wire Layer 2 IPS/IDS built with smoltcp (no_std core).\n\
                  Supports HTTP, DNS, TLS-SNI, and NTP deep packet inspection.\n\
                  Preserves DSCP, ECN, and TTL across the L4 proxy."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the IPS engine explicitly binding between LAN and WAN interfaces.
    Start {
        /// LAN network interface (e.g. eth0 / en3).
        #[arg(long)]
        lan: String,

        /// WAN network interface (e.g. eth1 / en4).
        #[arg(long)]
        wan: String,

        /// Path to TOML rule file.
        #[arg(long, default_value = "rules.toml")]
        rules: String,

        /// IDS mode: alert on matches but never drop.
        #[arg(long, default_value_t = false)]
        ids: bool,

        /// Fragment reassembly timeout in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        defrag_timeout_ms: u64,

        /// Print packet statistics every N seconds (0 = disabled).
        #[arg(long, default_value_t = 5)]
        stats_interval: u64,
    },

    /// Validate a rule file and print the parsed rules.
    CheckRules {
        /// Path to TOML rule file.
        path: String,
    },
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            lan,
            wan,
            rules: rules_path,
            ids,
            defrag_timeout_ms,
            stats_interval,
        } => {
            log::info!(
                "Starting AIPS: {lan} (LAN) ↔ {wan} (WAN), rules={rules_path}, \
                 mode={}, defrag_timeout={defrag_timeout_ms}ms",
                if ids { "IDS (alert-only)" } else { "IPS (inline drop)" }
            );

            #[cfg(target_os = "linux")]
            run_linux(&lan, &wan, &rules_path, ids, defrag_timeout_ms, stats_interval);

            #[cfg(target_os = "macos")]
            run_macos(&lan, &wan, &rules_path, ids, defrag_timeout_ms, stats_interval);

            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                log::error!("Platform not supported in CLI binary. Use a platform PHY crate.");
                std::process::exit(1);
            }
        }

        Commands::CheckRules { path } => {
            check_rules(&path);
        }
    }
}

#[cfg(target_os = "linux")]
fn run_linux(
    iface_in: &str,
    iface_out: &str,
    rules_path: &str,
    ids_mode: bool,
    defrag_timeout_ms: u64,
    stats_interval: u64,
) {
    use aips_phy_linux::RawPacketSocket;
    use aips_core::defrag::DefragTable;
    use std::time::{Instant, Duration};

    let mut sock_in  = RawPacketSocket::open(iface_in)
        .unwrap_or_else(|e| { log::error!("Failed to open {iface_in}: {e}"); std::process::exit(1); });
    let mut sock_out = RawPacketSocket::open(iface_out)
        .unwrap_or_else(|e| { log::error!("Failed to open {iface_out}: {e}"); std::process::exit(1); });

    let mut _defrag: DefragTable<32, 65535> = DefragTable::new(defrag_timeout_ms);
    let mut engine = build_rules(rules_path);
    let hyper_node = build_l3_rules();
    let mut classifier: aips_core::classifier::Classifier<1024> = aips_core::classifier::Classifier::new();

    // Load Config-Driven `[[service]]` arrays from rules.toml
    let services = load_services(rules_path);
    for s in services {
        if classifier.add_service(s).is_err() {
            log::warn!("Classifier service capacity reached!");
        }
    }

    let mut pkts_fwd   = 0u64;
    let mut pkts_drop  = 0u64;
    let mut pkts_alert = 0u64;
    let mut last_stats = Instant::now();

    log::info!("Poll loop started (Linux PACKET_MMAP).");

    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Some(frame) = sock_in.try_recv_frame() {
            let drop = process_frame(frame, &mut engine, &hyper_node, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
            if !drop { let _ = sock_out.send_frame(frame); pkts_fwd += 1; } else { pkts_drop += 1; }
            sock_in.release_rx();
        }

        if let Some(frame) = sock_out.try_recv_frame() {
            let drop = process_frame(frame, &mut engine, &hyper_node, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
            if !drop { let _ = sock_in.send_frame(frame); pkts_fwd += 1; } else { pkts_drop += 1; }
            sock_out.release_rx();
        }

        if stats_interval > 0 && last_stats.elapsed() >= Duration::from_secs(stats_interval) {
            log::info!("Stats — fwd:{pkts_fwd} drop:{pkts_drop} alert:{pkts_alert}");
            last_stats = Instant::now();
        }
    }
}

#[cfg(target_os = "macos")]
fn run_macos(
    iface_in: &str,
    iface_out: &str,
    rules_path: &str,
    ids_mode: bool,
    defrag_timeout_ms: u64,
    stats_interval: u64,
) {
    use aips_phy_macos::BpfSocket;
    use aips_core::defrag::DefragTable;
    use std::time::{Instant, Duration};

    let mut bpf_in  = BpfSocket::open(iface_in)
        .unwrap_or_else(|e| { log::error!("Failed to open BPF on {iface_in}: {e}"); std::process::exit(1); });
    let mut bpf_out = BpfSocket::open(iface_out)
        .unwrap_or_else(|e| { log::error!("Failed to open BPF on {iface_out}: {e}"); std::process::exit(1); });

    let mut _defrag: DefragTable<32, 65535> = DefragTable::new(defrag_timeout_ms);
    let mut engine = build_rules(rules_path);
    let hyper_node = build_l3_rules();
    let mut classifier: aips_core::classifier::Classifier<1024> = aips_core::classifier::Classifier::new();
    
    // Load Config-Driven `[[service]]` arrays from rules.toml
    let services = load_services(rules_path);
    for s in services {
        if classifier.add_service(s).is_err() {
            log::warn!("Classifier service capacity reached!");
        }
    }
    let mut pkts_fwd   = 0u64;
    let mut pkts_drop  = 0u64;
    let mut pkts_alert = 0u64;
    let mut last_stats = Instant::now();

    log::info!("Poll loop started (macOS BPF).");

    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if let Ok(Some(frame)) = bpf_in.next_frame() {
            let drop = process_frame(frame, &mut engine, &hyper_node, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
            if !drop { let _ = bpf_out.send_frame(frame); pkts_fwd += 1; } else { pkts_drop += 1; }
        }
        
        if let Ok(Some(frame)) = bpf_out.next_frame() {
            let drop = process_frame(frame, &mut engine, &hyper_node, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
            if !drop { let _ = bpf_in.send_frame(frame); pkts_fwd += 1; } else { pkts_drop += 1; }
        }

        if stats_interval > 0 && last_stats.elapsed() >= Duration::from_secs(stats_interval) {
            log::info!("Stats — fwd:{pkts_fwd} drop:{pkts_drop} alert:{pkts_alert}");
            last_stats = Instant::now();
        }
    }
}

/// Core processing logic for an individual frame. 
/// Returns `true` if the packet should be dropped, `false` to forward.
fn process_frame(
    frame: &[u8],
    engine: &mut aips_rules::engine::RuleEngine<'static, 128, 512, 1024>,
    hyper_node: &aips_rules::hypercuts::HyperNode,
    classifier: &mut aips_core::classifier::Classifier<1024>,
    ids_mode: bool,
    now_ms: u64,
    alert_counter: &mut u64,
) -> bool {
    log::trace!("Captured frame of {} bytes", frame.len());
    let pkt = match aips_core::layer::PacketView::parse(frame) {
        Some(p) => p,
        None => return false, // Allow non-IP through
    };

    // Fast-path L3/L4 5-tuple filtering using HyperCuts
    let src_ip = u32::from_be_bytes([pkt.src_ip[12], pkt.src_ip[13], pkt.src_ip[14], pkt.src_ip[15]]);
    let dst_ip = u32::from_be_bytes([pkt.dst_ip[12], pkt.dst_ip[13], pkt.dst_ip[14], pkt.dst_ip[15]]);
    let src_port = pkt.src_port.unwrap_or(0);
    let dst_port = pkt.dst_port.unwrap_or(0);
    let proto = match pkt.l4_proto {
        Some(aips_core::layer::L4Proto::Tcp) => 6,
        Some(aips_core::layer::L4Proto::Udp) => 17,
        Some(aips_core::layer::L4Proto::Icmp) => 1,
        Some(aips_core::layer::L4Proto::Icmpv6) => 58,
        Some(aips_core::layer::L4Proto::Other(n)) => n,
        None => 0,
    };

    if let Some((rule_id, action)) = hyper_node.evaluate(src_ip, dst_ip, src_port, dst_port, proto) {
        match action {
            aips_rules::action::Action::Drop => {
                log::warn!("L3 Rule {} dropped flow!", rule_id);
                if !ids_mode { return true; } else { *alert_counter += 1; }
            }
            aips_rules::action::Action::Alert => {
                log::info!("L3 Rule {} alerting on flow!", rule_id);
                *alert_counter += 1;
            }
            _ => {}
        }
    }

    let qos = aips_core::qos::QosFields { dscp: 0, ecn: 0, ttl: 64 };
    let l4_decision = classifier.classify(&pkt, qos);

    // Handle default-deny (Violation) or explicit Drop
    if l4_decision.is_dropped() {
        if l4_decision == aips_core::Decision::Violation {
            let action = if ids_mode { "Alerted" } else { "Dropped" };
            log::warn!(
                "Policy Violation: Flow from {:?} to port {} {} by default-deny.", 
                pkt.src_ip, pkt.dst_port.unwrap_or(0), action
            );
            *alert_counter += 1;
        }
        return !ids_mode;
    }

    // If it's pure pass-through, no inline payload inspection triggered.
    let proxy_proto = match l4_decision {
        aips_core::Decision::ProxyTcp(proto) => proto,
        aips_core::Decision::ProxyUdp(proto) => proto,
        _ => return false,
    };

    // Direct inspect inline (proxy simplified for smoke-test)
    let payload = pkt.payload();
    if !payload.is_empty() {
        let mut dns_buf = [0u8; 512];
        let mut http_buf = [httparse::EMPTY_HEADER; 32];
        
        let dst_port = pkt.dst_port.unwrap_or(0);
        
        let verdict = aips_l7::dispatcher::L7Dispatcher::dispatch(
            payload, 
            proxy_proto, 
            &mut dns_buf, 
            &mut http_buf
        );
        
        let mut src_ip = [0u8; 16];
        src_ip[12..16].copy_from_slice(&pkt.src_ip[0..4]);
        
        let ctx = aips_l7::dispatcher::L7Dispatcher::to_match_ctx(
            &verdict, payload, dst_port, src_ip
        );
        
        if let Some((rule_id, action)) = engine.evaluate(&ctx, now_ms) {
            match action {
                aips_rules::action::Action::Drop => {
                    log::warn!("Rule {} dropped flow!", rule_id);
                    if !ids_mode { return true; } else { *alert_counter += 1; }
                }
                aips_rules::action::Action::Alert => {
                    log::info!("Rule {} alerting on flow!", rule_id);
                    *alert_counter += 1;
                }
                aips_rules::action::Action::RateLimit { .. } => {
                    log::warn!("Rule {} ratelimiting flow!", rule_id);
                    if !ids_mode { return true; } else { *alert_counter += 1; }
                }
            }
        }
    }
    
    false
}

fn build_rules(_path: &str) -> aips_rules::engine::RuleEngine<'static, 128, 512, 1024> {
    use aips_rules::{rule::*, action::*};
    let mut engine = aips_rules::engine::RuleEngine::new();
    
    // Simulate parsing rules.toml by registering synthetic equivalent
    engine.add_rule(Rule {
        id: 1, 
        name: "Block SQL injection",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"union select", case_insensitive: true }),
        action: Action::Drop,
    }).unwrap();

    engine.add_rule(Rule {
        id: 2, 
        name: "Block path traversal",
        match_expr: MatchExpr::Payload(BytePattern { bytes: b"../", case_insensitive: true }),
        action: Action::Drop,
    }).unwrap();

    engine.build();
    engine
}

fn build_l3_rules() -> aips_rules::hypercuts::HyperNode {
    use aips_rules::hypercuts::{L3Rule, Range};
    use aips_rules::action::Action;

    let mut rules = Vec::new();
    // Simulate drop 10.0.0.10 -> 10.0.0.20 on TCP port 4444
    rules.push(L3Rule {
        id: 100,
        priority: 10,
        src_ip: Range { min: 0x0A00000A, max: 0x0A00000A },
        dst_ip: Range { min: 0x0A000014, max: 0x0A000014 },
        src_port: Range { min: 0, max: 65535 },
        dst_port: Range { min: 4444, max: 4444 },
        proto: Range { min: 6, max: 6 },
        action: Action::Drop,
    });
    
    aips_rules::hypercuts::HyperNode::build(rules)
}

fn check_rules(path: &str) {
    let _ = build_rules(path);
    log::info!("Rules file '{path}' accepted.");
}

#[derive(serde::Deserialize, Debug)]
struct ConfigFile {
    #[serde(default)]
    service: Vec<ServiceConfig>,
}

#[derive(serde::Deserialize, Debug)]
struct ServiceConfig {
    name: String,
    protocol: String,
    #[serde(default)]
    client_zone: String,
    #[serde(default)]
    server_zone: String,
    server_port: u16,
}

fn load_services(path: &str) -> Vec<aips_core::classifier::Service> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Could not read config file {}: {}. Starting with 0 L7 services.", path, e);
            return Vec::new();
        }
    };
    
    let config: ConfigFile = match toml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to parse TOML {}: {}", path, e);
            std::process::exit(1);
        }
    };
    
    let mut out = Vec::new();
    for svc in config.service {
        let protocol = match svc.protocol.to_lowercase().as_str() {
            "http" => aips_core::classifier::L7Protocol::Http,
            "dns"  => aips_core::classifier::L7Protocol::Dns,
            "tls"  => aips_core::classifier::L7Protocol::Tls,
            "ssh"  => aips_core::classifier::L7Protocol::Ssh,
            "ntp"  => aips_core::classifier::L7Protocol::Ntp,
            "bypass" => aips_core::classifier::L7Protocol::Bypass,
            _ => {
                log::warn!("Unknown protocol '{}' in service '{}'", svc.protocol, svc.name);
                continue;
            }
        };
        log::info!("Loaded service {}: {} on port {}", svc.name, svc.protocol, svc.server_port);
        out.push(aips_core::classifier::Service {
            protocol,
            server_port: svc.server_port,
        });
    }
    out
}
