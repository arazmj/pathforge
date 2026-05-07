use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

use crate::fsm::BgpState;
use crate::metrics::Metrics;
use crate::rib::Rib;

/// Peer summary info for show commands.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub remote_as: u32,
    pub state: BgpState,
    pub description: Option<String>,
    pub uptime_secs: u64,
    pub routes_received: usize,
}

/// Shared management state (peers + RIB reference).
#[derive(Default)]
pub struct MgmtState {
    pub peers: HashMap<SocketAddr, PeerInfo>,
}

impl MgmtState {
    pub fn shared() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self::default()))
    }
}

/// Management API server over a Unix domain socket.
///
/// Accepts line-oriented commands and returns text responses.
/// Supported commands:
///   show bgp summary
///   show bgp rib
///   show bgp neighbors [<ip>]
///   show bgp rib prefix <prefix>
///   show bgp metrics
///   metrics (Prometheus format)
pub struct MgmtServer {
    socket_path: String,
    state: Arc<RwLock<MgmtState>>,
    rib: Arc<RwLock<Rib>>,
    metrics: Arc<Metrics>,
}

impl MgmtServer {
    pub fn new(
        socket_path: &str,
        state: Arc<RwLock<MgmtState>>,
        rib: Arc<RwLock<Rib>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            state,
            rib,
            metrics,
        }
    }

    /// Start the management socket listener.
    pub async fn run(&self) -> Result<()> {
        // Remove stale socket file
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path)?;
        info!(path = %self.socket_path, "Management socket listening");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let state = self.state.clone();
                    let rib = self.rib.clone();
                    let metrics = self.metrics.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_mgmt_conn(stream, state, rib, metrics).await {
                            warn!(error = %e, "Management connection error");
                        }
                    });
                }
                Err(e) => warn!(error = %e, "Management accept error"),
            }
        }
    }
}

async fn handle_mgmt_conn(
    stream: UnixStream,
    state: Arc<RwLock<MgmtState>>,
    rib: Arc<RwLock<Rib>>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    write.write_all(b"PathForge BGP Management\n> ").await?;

    while let Ok(Some(line)) = lines.next_line().await {
        let response = process_command(line.trim(), &state, &rib, &metrics);
        write.write_all(response.as_bytes()).await?;
        write.write_all(b"\n> ").await?;
    }
    Ok(())
}

fn process_command(
    cmd: &str,
    state: &Arc<RwLock<MgmtState>>,
    rib: &Arc<RwLock<Rib>>,
    metrics: &Arc<Metrics>,
) -> String {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    match parts.as_slice() {
        ["show", "bgp", "summary"] => cmd_bgp_summary(state, rib),
        ["show", "bgp", "rib"] => cmd_bgp_rib(rib),
        ["show", "bgp", "rib", "prefix", prefix] => cmd_bgp_rib_prefix(rib, prefix),
        ["show", "bgp", "neighbors"] => cmd_bgp_neighbors(state, None),
        ["show", "bgp", "neighbors", ip] => cmd_bgp_neighbors(state, Some(ip)),
        ["show", "bgp", "metrics"] => metrics.text_summary(),
        ["metrics"] => metrics.prometheus_text(),
        ["help"] | [] => cmd_help(),
        ["quit"] | ["exit"] => "Bye!\n".to_string(),
        _ => format!(
            "Unknown command: '{}'\nType 'help' for available commands.\n",
            cmd
        ),
    }
}

fn cmd_bgp_summary(state: &Arc<RwLock<MgmtState>>, rib: &Arc<RwLock<Rib>>) -> String {
    let state = state.read().unwrap();
    let rib = rib.read().unwrap();
    let (_, _, loc_count) = rib.summary();

    let mut out = String::new();
    out.push_str("BGP Summary\n");
    out.push_str("===========\n");
    out.push_str(&format!("Total prefixes in Loc-RIB: {}\n\n", loc_count));
    out.push_str(&format!(
        "{:<22} {:>8} {:>12} {}\n",
        "Neighbor", "AS", "State", "Description"
    ));
    out.push_str(&format!("{}\n", "-".repeat(70)));

    for peer in state.peers.values() {
        out.push_str(&format!(
            "{:<22} {:>8} {:>12} {}\n",
            peer.addr,
            peer.remote_as,
            peer.state,
            peer.description.as_deref().unwrap_or(""),
        ));
    }

    if state.peers.is_empty() {
        out.push_str("(no peers configured)\n");
    }
    out
}

fn cmd_bgp_rib(rib: &Arc<RwLock<Rib>>) -> String {
    let rib = rib.read().unwrap();
    let loc_rib = rib.loc_rib();

    if loc_rib.is_empty() {
        return "Loc-RIB is empty.\n".to_string();
    }

    let mut out = String::new();
    out.push_str("BGP Routing Table (Loc-RIB)\n");
    out.push_str("===========================\n");
    out.push_str(&format!(
        "{:<20} {:>8} {:>6} {:>6} {:<20} {}\n",
        "Network", "Local-Pref", "MED", "AS-Path", "Next-Hop", "Origin"
    ));
    out.push_str(&format!("{}\n", "-".repeat(80)));

    let mut prefixes: Vec<_> = loc_rib.iter().collect();
    prefixes.sort_by_key(|(k, _)| (k.address.octets(), k.prefix_len));

    for (key, route) in &prefixes {
        let lp = route.attrs.local_pref.unwrap_or(100);
        let med = route.attrs.multi_exit_disc.unwrap_or(0);
        let nh = route
            .attrs
            .next_hop
            .map(|a| a.to_string())
            .unwrap_or_else(|| "-".into());
        let origin = route
            .attrs
            .origin
            .map(|o| format!("{}", o))
            .unwrap_or_else(|| "?".into());
        let as_path: String = route
            .attrs
            .as_path
            .iter()
            .flat_map(|seg| seg.as_numbers())
            .map(|asn| asn.to_string())
            .collect::<Vec<_>>()
            .join(" ");

        out.push_str(&format!(
            "{:<20} {:>10} {:>6} {:>6} {:<20} {}\n",
            key.to_string(),
            lp,
            med,
            if as_path.is_empty() {
                "-".into()
            } else {
                as_path
            },
            nh,
            origin,
        ));
    }
    out
}

fn cmd_bgp_rib_prefix(rib: &Arc<RwLock<Rib>>, prefix_str: &str) -> String {
    use crate::rib::PrefixKey;
    let rib = rib.read().unwrap();

    let (addr_s, len_s) = match prefix_str.split_once('/') {
        Some(p) => p,
        None => return format!("Invalid prefix format: '{}'. Use X.X.X.X/LEN\n", prefix_str),
    };
    let addr: std::net::Ipv4Addr = match addr_s.parse() {
        Ok(a) => a,
        Err(_) => return format!("Invalid address: '{}'\n", addr_s),
    };
    let len: u8 = match len_s.parse() {
        Ok(l) => l,
        Err(_) => return format!("Invalid prefix length: '{}'\n", len_s),
    };

    let key = PrefixKey {
        address: addr,
        prefix_len: len,
    };
    match rib.loc_rib().get(&key) {
        Some(route) => {
            let mut out = format!("BGP Prefix {}\n", prefix_str);
            out.push_str(&format!("  Best path from:  {}\n", route.peer_addr));
            out.push_str(&format!("  Peer AS:         {}\n", route.peer_as));
            out.push_str(&format!(
                "  Next-hop:        {}\n",
                route
                    .attrs
                    .next_hop
                    .map(|a| a.to_string())
                    .unwrap_or("-".into())
            ));
            out.push_str(&format!(
                "  Local-pref:      {}\n",
                route.attrs.local_pref.unwrap_or(100)
            ));
            out.push_str(&format!(
                "  MED:             {}\n",
                route.attrs.multi_exit_disc.unwrap_or(0)
            ));
            out.push_str(&format!(
                "  Origin:          {}\n",
                route
                    .attrs
                    .origin
                    .map(|o| format!("{}", o))
                    .unwrap_or("?".into())
            ));
            let as_path: String = route
                .attrs
                .as_path
                .iter()
                .flat_map(|seg| seg.as_numbers())
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&format!(
                "  AS-path:         {}\n",
                if as_path.is_empty() {
                    "(empty)".into()
                } else {
                    as_path
                }
            ));
            if !route.attrs.communities.is_empty() {
                let comms: Vec<_> = route
                    .attrs
                    .communities
                    .iter()
                    .map(|c| c.to_string())
                    .collect();
                out.push_str(&format!("  Communities:     {}\n", comms.join(" ")));
            }
            out
        }
        None => format!("Prefix {} not found in Loc-RIB.\n", prefix_str),
    }
}

fn cmd_bgp_neighbors(state: &Arc<RwLock<MgmtState>>, filter_ip: Option<&&str>) -> String {
    let state = state.read().unwrap();
    let mut out = String::new();

    let peers: Vec<&PeerInfo> = if let Some(ip) = filter_ip {
        state
            .peers
            .values()
            .filter(|p| p.addr.ip().to_string() == *ip)
            .collect()
    } else {
        state.peers.values().collect()
    };

    if peers.is_empty() {
        return "No matching neighbors.\n".to_string();
    }

    for peer in peers {
        out.push_str(&format!("BGP neighbor {}\n", peer.addr));
        out.push_str(&format!("  Remote AS:    {}\n", peer.remote_as));
        out.push_str(&format!("  State:        {}\n", peer.state));
        out.push_str(&format!("  Routes rcvd:  {}\n", peer.routes_received));
        out.push_str(&format!("  Uptime:       {}s\n", peer.uptime_secs));
        if let Some(desc) = &peer.description {
            out.push_str(&format!("  Description:  {}\n", desc));
        }
        out.push('\n');
    }
    out
}

fn cmd_help() -> String {
    "Available commands:\n\
     \n\
     show bgp summary              — Peer summary and RIB count\n\
     show bgp rib                  — Full BGP routing table (Loc-RIB)\n\
     show bgp rib prefix X.X.X.X/N — Detail for a specific prefix\n\
     show bgp neighbors            — All neighbor detail\n\
     show bgp neighbors <ip>       — Specific neighbor detail\n\
     show bgp metrics              — Human-readable counters\n\
     metrics                       — Prometheus exposition format\n\
     help                          — Show this help\n\
     quit / exit                   — Close connection\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rib::Rib;

    fn empty_state() -> Arc<RwLock<MgmtState>> {
        MgmtState::shared()
    }

    fn empty_rib() -> Arc<RwLock<Rib>> {
        Rib::shared()
    }

    #[test]
    fn test_show_bgp_summary_empty() {
        let out = cmd_bgp_summary(&empty_state(), &empty_rib());
        assert!(out.contains("Loc-RIB: 0") || out.contains("no peers"));
    }

    #[test]
    fn test_show_bgp_rib_empty() {
        let out = cmd_bgp_rib(&empty_rib());
        assert!(out.contains("empty"));
    }

    #[test]
    fn test_show_bgp_rib_prefix_not_found() {
        let out = cmd_bgp_rib_prefix(&empty_rib(), "10.0.0.0/8");
        assert!(out.contains("not found"));
    }

    #[test]
    fn test_help() {
        let out = cmd_help();
        assert!(out.contains("show bgp summary"));
        assert!(out.contains("show bgp rib"));
    }

    #[test]
    fn test_unknown_command() {
        let state = empty_state();
        let rib = empty_rib();
        let metrics = Metrics::shared();
        let out = process_command("foo bar", &state, &rib, &metrics);
        assert!(out.contains("Unknown command"));
    }

    #[test]
    fn test_show_rib_with_routes() {
        use crate::attr::{AsPathSegment, Origin, PathAttributes};
        use crate::message::update::Prefix;
        use std::net::Ipv4Addr;

        let rib_arc = empty_rib();
        {
            let mut rib = rib_arc.write().unwrap();
            let attrs = PathAttributes {
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                next_hop: Some(Ipv4Addr::new(10, 0, 0, 1)),
                as_path: vec![AsPathSegment::AsSequence(vec![65001, 65002])],
                ..Default::default()
            };
            let prefix = Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 24);
            let peer: SocketAddr = "10.0.0.2:179".parse().unwrap();
            rib.process_update(peer, 65001, &[prefix], &attrs, &[]);
        }
        let out = cmd_bgp_rib(&rib_arc);
        assert!(out.contains("192.168.0.0/24"));
        assert!(out.contains("65001"));
    }
}
