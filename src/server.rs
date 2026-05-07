use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

use crate::peer::Peer;

/// BGP server that listens for incoming peer connections on port 179.
pub struct Server {
    bind_addr: SocketAddr,
}

impl Server {
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self { bind_addr }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!(addr = %self.bind_addr, "PathForge BGP server listening");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            info!(peer = %peer_addr, "Accepted TCP connection");
            tokio::spawn(async move {
                if let Err(e) = Peer::handle_incoming(stream, peer_addr).await {
                    tracing::error!(peer = %peer_addr, error = %e, "Peer error");
                }
            });
        }
    }
}
