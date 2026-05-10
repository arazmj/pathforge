use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tracing::info;

use crate::metrics::Metrics;
use crate::peer::Peer;
use crate::rib::Rib;
use crate::timer::LocalConfig;

/// BGP server that listens for incoming peer connections on port 179.
pub struct Server {
    bind_addr: SocketAddr,
    local: LocalConfig,
    rib: Arc<RwLock<Rib>>,
    metrics: Arc<Metrics>,
}

impl Server {
    pub fn new(bind_addr: SocketAddr, local: LocalConfig, metrics: Arc<Metrics>) -> Self {
        Self {
            bind_addr,
            local,
            rib: Rib::shared(),
            metrics,
        }
    }

    pub fn rib(&self) -> Arc<RwLock<Rib>> {
        self.rib.clone()
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!(addr = %self.bind_addr, local_as = self.local.local_as, router_id = %self.local.router_id, "PathForge BGP server listening");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            info!(peer = %peer_addr, "Accepted TCP connection");
            let local = self.local.clone();
            let rib = self.rib.clone();
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = Peer::handle_incoming(stream, peer_addr, local, rib, metrics).await
                {
                    tracing::error!(peer = %peer_addr, error = %e, "Peer session error");
                }
            });
        }
    }
}
