mod fsm;
mod message;
mod peer;
mod server;
mod timer;

use anyhow::Result;
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr};
use tracing_subscriber::EnvFilter;

use server::Server;
use timer::LocalConfig;

#[derive(Parser, Debug)]
#[command(name = "pathforge", about = "PathForge — A BGP-4 daemon written in Rust 🦀")]
struct Cli {
    /// Address to listen on for BGP connections
    #[arg(short, long, default_value = "0.0.0.0:179")]
    listen: SocketAddr,

    /// Local AS number
    #[arg(long, default_value_t = 65000)]
    local_as: u32,

    /// Router ID (IPv4 address)
    #[arg(long, default_value = "1.1.1.1")]
    router_id: Ipv4Addr,

    /// Hold time in seconds
    #[arg(long, default_value_t = 90)]
    hold_time: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("pathforge=info".parse()?))
        .init();

    let cli = Cli::parse();
    let mut local = LocalConfig::new(cli.local_as, cli.router_id);
    local.hold_time = cli.hold_time;
    let server = Server::new(cli.listen, local);
    server.run().await
}
