use std::net::SocketAddr;
use anyhow::Result;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::fsm::{BgpEvent, BgpState};

/// Represents a BGP peer connection.
pub struct Peer {
    pub addr: SocketAddr,
    pub remote_as: u32,
    pub local_as: u32,
    pub router_id: std::net::Ipv4Addr,
    pub state: BgpState,
}

impl Peer {
    pub fn new(addr: SocketAddr, remote_as: u32, local_as: u32, router_id: std::net::Ipv4Addr) -> Self {
        Self {
            addr,
            remote_as,
            local_as,
            router_id,
            state: BgpState::Idle,
        }
    }

    pub fn transition(&mut self, event: BgpEvent) {
        let prev = self.state;
        self.state = match (self.state, &event) {
            (BgpState::Idle, BgpEvent::ManualStart) => BgpState::Connect,
            (BgpState::Connect, BgpEvent::TcpConnectionConfirmed) => BgpState::OpenSent,
            (BgpState::Connect, BgpEvent::TcpConnectionFail) => BgpState::Active,
            (BgpState::Active, BgpEvent::TcpConnectionConfirmed) => BgpState::OpenSent,
            (BgpState::OpenSent, BgpEvent::BgpOpen) => BgpState::OpenConfirm,
            (BgpState::OpenConfirm, BgpEvent::KeepAliveMsg) => BgpState::Established,
            (BgpState::Established, BgpEvent::NotifMsg) => BgpState::Idle,
            (BgpState::Established, BgpEvent::TcpConnectionFail) => BgpState::Idle,
            (_, BgpEvent::ManualStop) => BgpState::Idle,
            (_, BgpEvent::HoldTimerExpired) => BgpState::Idle,
            _ => self.state,
        };
        if self.state != prev {
            info!(peer = %self.addr, "{} -> {}", prev, self.state);
        }
    }

    /// Handle an incoming TCP connection from a peer.
    pub async fn handle_incoming(stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        info!(peer = %peer_addr, "Incoming TCP connection");
        // Full session handling will be implemented in subsequent iterations.
        drop(stream);
        warn!(peer = %peer_addr, "Session handling not yet implemented — closing connection");
        Ok(())
    }
}
