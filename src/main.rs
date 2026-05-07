mod fsm;
mod peer;
mod server;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

use server::Server;

#[derive(Parser, Debug)]
#[command(name = "pathforge", about = "PathForge — A BGP-4 daemon written in Rust 🦀")]
struct Cli {
    /// Address to listen on for BGP connections
    #[arg(short, long, default_value = "0.0.0.0:179")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("pathforge=info".parse()?))
        .init();

    let cli = Cli::parse();
    let server = Server::new(cli.listen);
    server.run().await
}
