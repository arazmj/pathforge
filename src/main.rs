use anyhow::Result;
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use tracing_subscriber::EnvFilter;

use pathforge::config;
use pathforge::metrics::Metrics;
use pathforge::mgmt::{MgmtServer, MgmtState};
use pathforge::server::Server;
use pathforge::timer::LocalConfig;

#[derive(Parser, Debug)]
#[command(
    name = "pathforge",
    about = "PathForge — A BGP-4 daemon written in Rust 🦀"
)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short, long)]
    config: Option<std::path::PathBuf>,

    /// Address to listen on for BGP connections (overrides config)
    #[arg(short, long)]
    listen: Option<SocketAddr>,

    /// Local AS number (overrides config)
    #[arg(long)]
    local_as: Option<u32>,

    /// Router ID IPv4 address (overrides config)
    #[arg(long)]
    router_id: Option<Ipv4Addr>,

    /// Hold time in seconds (overrides config)
    #[arg(long)]
    hold_time: Option<u16>,

    /// Unix socket path for management interface
    #[arg(long, default_value = "/tmp/pathforge.sock")]
    mgmt_socket: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("pathforge=info".parse()?))
        .init();

    let cli = Cli::parse();

    let (local, listen) = if let Some(config_path) = cli.config {
        let cfg = config::Config::from_file(&config_path)?;
        tracing::info!(
            path = %config_path.display(),
            neighbors = cfg.neighbors.len(),
            prefix_lists = cfg.policy.prefix_lists.len(),
            "Loaded configuration"
        );
        let mut lc = LocalConfig::new(cfg.router.local_as, cfg.router.router_id);
        lc.hold_time = cfg.router.hold_time;
        let listen = cli.listen.unwrap_or(cfg.router.listen);
        (lc, listen)
    } else {
        let mut lc = LocalConfig::new(
            cli.local_as.unwrap_or(65000),
            cli.router_id.unwrap_or(Ipv4Addr::new(1, 1, 1, 1)),
        );
        lc.hold_time = cli.hold_time.unwrap_or(90);
        let listen = cli
            .listen
            .unwrap_or_else(|| "0.0.0.0:179".parse().expect("valid default bind address"));
        (lc, listen)
    };
    let metrics = Metrics::shared();
    let server = Server::new(listen, local, metrics.clone());
    let rib = server.rib();
    let mgmt_state = MgmtState::shared();

    // Start management server concurrently
    let mgmt = MgmtServer::new(&cli.mgmt_socket, mgmt_state, rib, metrics);
    tokio::spawn(async move {
        if let Err(e) = mgmt.run().await {
            tracing::error!(error = %e, "Management server error");
        }
    });

    server.run().await
}
