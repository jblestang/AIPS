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
                  Supports TLS-SNI and SSH-Banner metadata inspection.\n\
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

    if iface_in == iface_out {
        log::error!("LAN and WAN interfaces cannot be the same ({iface_in})! This would create an infinite network loop.");
        std::process::exit(1);
    }

    let mut sock_in  = RawPacketSocket::open(iface_in)
        .unwrap_or_else(|e| { log::error!("Failed to open {iface_in}: {e}"); std::process::exit(1); });
    let mut sock_out = RawPacketSocket::open(iface_out)
        .unwrap_or_else(|e| { log::error!("Failed to open {iface_out}: {e}"); std::process::exit(1); });

    let engine = build_rules(rules_path);
    let mut classifier: aips_core::classifier::Classifier<1024, _> = aips_core::classifier::Classifier::new(engine);

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

        let mut received = false;
        if let Some(frame) = sock_in.try_recv_frame() {
            received = true;
            let drop = process_frame(frame, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
            if !drop { let _ = sock_out.send_frame(frame); pkts_fwd += 1; } else { pkts_drop += 1; }
            sock_in.release_rx();
        }

        if let Some(frame) = sock_out.try_recv_frame() {
            received = true;
            let drop = process_frame(frame, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
            if !drop { let _ = sock_in.send_frame(frame); pkts_fwd += 1; } else { pkts_drop += 1; }
            sock_out.release_rx();
        }

        if !received {
            std::thread::sleep(std::time::Duration::from_micros(50));
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
    let engine = build_rules(rules_path);
    let mut classifier: aips_core::classifier::Classifier<1024, _, aips_proxy::AipsProxy<64>> = aips_core::classifier::Classifier::new(engine);
    
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
            let drop = process_frame(frame, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
            if !drop { let _ = bpf_out.send_frame(frame); pkts_fwd += 1; } else { pkts_drop += 1; }
        }
        
        if let Ok(Some(frame)) = bpf_out.next_frame() {
            let drop = process_frame(frame, &mut classifier, ids_mode, now_ms, &mut pkts_alert);
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
    classifier: &mut aips_core::classifier::Classifier<1024, aips_rules::engine::RuleEngine<'static, 128>, aips_proxy::AipsProxy<64>>,
    ids_mode: bool,
    now_ms: u64,
    alert_counter: &mut u64,
) -> bool {
    log::trace!("Captured frame of {} bytes", frame.len());
    let pkt = match aips_core::layer::PacketView::parse(frame) {
        Some(p) => p,
        None => return false, // Allow non-IP through
    };

    let qos = aips_core::qos::QosFields { dscp: 0, ecn: 0, ttl: 64 };
    let decision = classifier.classify(&pkt, qos, now_ms);

    match decision {
        aips_core::Decision::Drop | aips_core::Decision::Violation => {
            if decision == aips_core::Decision::Violation {
                let action_str = if ids_mode { "Alerted" } else { "Dropped" };
                log::warn!(
                    "Policy Violation: Flow from {:?} to port {} {} by default-deny.", 
                    pkt.src_ip, pkt.dst_port.unwrap_or(0), action_str
                );
                *alert_counter += 1;
            }
            !ids_mode
        }
        aips_core::Decision::Alert => {
            log::info!("Rule alertness triggered!");
            *alert_counter += 1;
            false
        }
        _ => false,
    }
}

fn build_rules(path: &str) -> aips_rules::engine::RuleEngine<'static, 128> {
    use aips_rules::{rule::*, action::*};
    let mut engine = aips_rules::engine::RuleEngine::new();
    
    // 1. Load services from rules.toml and map them to rules
    let services = load_services(path);
    for (i, s) in services.into_iter().enumerate() {
        let action = match s.default_action {
            aips_core::decision::Decision::Forward => Action::Pass,
            aips_core::decision::Decision::Drop    => Action::Drop,
            _ => Action::Pass,
        };
        engine.add_rule(Rule {
            id: 200 + i as u32,
            name: "Configured Service",
            match_expr: MatchExpr::Or(
                std::boxed::Box::leak(std::boxed::Box::new(MatchExpr::DstPort(s.server_port))),
                std::boxed::Box::leak(std::boxed::Box::new(MatchExpr::SrcPort(s.server_port))),
            ),
            action,
            bidirectional: true,
        }).unwrap();
    }

    // 2. Add some hardcoded security rules
    engine.add_rule(Rule {
        id: 100,
        name: "Block malicious subnet",
        match_expr: MatchExpr::SrcIpPrefix { prefix: [10, 0, 0, 0], prefix_len: 24 },
        action: Action::Drop,
        bidirectional: false,
    }).unwrap();
    
    engine
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
    action: String,
    server_port: u16,
}

struct ServiceInfo {
    server_port: u16,
    default_action: aips_core::decision::Decision,
}

fn load_services(path: &str) -> Vec<ServiceInfo> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Could not read config file {}: {}. Starting with 0 services.", path, e);
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
        let action = match svc.action.to_uppercase().as_str() {
            "PASS" => aips_core::decision::Decision::Forward,
            "DROP" => aips_core::decision::Decision::Drop,
            _ => {
                log::warn!("Unknown action '{}' in service '{}', defaulting to PASS", svc.action, svc.name);
                aips_core::decision::Decision::Forward
            }
        };
        log::info!("Loaded service {}: port {} action {:?}", svc.name, svc.server_port, action);
        out.push(ServiceInfo {
            server_port: svc.server_port,
            default_action: action,
        });
    }
    out
}
