use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use anyhow::Result;
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::fsm::{BgpEvent, BgpState};
use crate::message::{BgpMessage, MessageType, HEADER_LEN};
use crate::message::keepalive::KeepaliveMessage;
use crate::message::notification::NotificationMessage;
use crate::message::open::OpenMessage;
use crate::message::update::UpdateMessage;
use crate::rib::Rib;
use crate::timer::{BgpTimers, LocalConfig};

/// Represents a BGP peer session.
pub struct Peer {
    pub addr: SocketAddr,
    pub remote_as: u32,
    pub local: LocalConfig,
    pub state: BgpState,
    pub timers: BgpTimers,
    pub negotiated_hold_time: u16,
    pub peer_router_id: Option<std::net::Ipv4Addr>,
    pub rib: Arc<RwLock<Rib>>,
}

impl Peer {
    pub fn new(addr: SocketAddr, remote_as: u32, local: LocalConfig, rib: Arc<RwLock<Rib>>) -> Self {
        let timers = BgpTimers::new(local.hold_time);
        Self {
            addr,
            remote_as,
            local,
            state: BgpState::Idle,
            timers,
            negotiated_hold_time: 90,
            peer_router_id: None,
            rib,
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

    /// Run the BGP session for an incoming TCP connection.
    pub async fn handle_incoming(
        stream: TcpStream,
        peer_addr: SocketAddr,
        local: LocalConfig,
        rib: Arc<RwLock<Rib>>,
    ) -> Result<()> {
        info!(peer = %peer_addr, "Incoming TCP connection");
        let mut peer = Peer::new(peer_addr, 0, local.clone(), rib);
        peer.transition(BgpEvent::ManualStart);
        peer.transition(BgpEvent::TcpConnectionConfirmed);
        peer.run_session(stream).await
    }

    /// Run the BGP session event loop on an established TCP stream.
    async fn run_session(&mut self, mut stream: TcpStream) -> Result<()> {
        // Send OPEN
        let open = OpenMessage::new(
            self.local.local_as as u16,
            self.local.hold_time,
            self.local.router_id,
        );
        stream.write_all(&open.serialize()).await?;
        debug!(peer = %self.addr, "Sent OPEN (AS={}, hold_time={})", self.local.local_as, self.local.hold_time);

        let mut buf = BytesMut::with_capacity(4096);

        loop {
            // Check hold timer
            if self.timers.hold_timer_expired() {
                warn!(peer = %self.addr, "Hold timer expired");
                let notif = NotificationMessage::hold_timer_expired();
                let _ = stream.write_all(&notif.serialize()).await;
                self.transition(BgpEvent::HoldTimerExpired);
                // Clean up RIB
                if let Ok(mut rib) = self.rib.write() {
                    rib.remove_peer(self.addr);
                }
                return Ok(());
            }

            // Send KEEPALIVE if due (Established state)
            if self.state == BgpState::Established && self.timers.keepalive_due() {
                stream.write_all(&KeepaliveMessage.serialize()).await?;
                self.timers.reset_keepalive_timer();
                debug!(peer = %self.addr, "Sent KEEPALIVE");
            }

            // Read available data
            let mut tmp = [0u8; 4096];
            tokio::select! {
                result = stream.read(&mut tmp) => {
                    match result {
                        Ok(0) => {
                            info!(peer = %self.addr, "Connection closed by peer");
                            self.transition(BgpEvent::TcpConnectionFail);
                            if let Ok(mut rib) = self.rib.write() {
                                let removed = rib.remove_peer(self.addr);
                                if !removed.is_empty() {
                                    info!(peer = %self.addr, "Withdrew {} routes from RIB", removed.len());
                                }
                            }
                            return Ok(());
                        }
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(e) => {
                            error!(peer = %self.addr, error = %e, "Read error");
                            self.transition(BgpEvent::TcpConnectionFail);
                            return Err(e.into());
                        }
                    }
                }
                _ = sleep(Duration::from_millis(100)) => {
                    continue;
                }
            }

            // Process all complete messages in the buffer
            while let Some(msg) = BgpMessage::parse(&mut buf)? {
                self.handle_message(msg, &mut stream).await?;
            }
        }
    }

    async fn handle_message(&mut self, msg: BgpMessage, stream: &mut TcpStream) -> Result<()> {
        match msg.header.msg_type {
            MessageType::Open => {
                let open = OpenMessage::parse(msg.body)?;
                info!(peer = %self.addr, "Received OPEN AS={} hold_time={} id={}", open.my_as, open.hold_time, open.bgp_id);
                self.peer_router_id = Some(open.bgp_id);
                self.remote_as = open.my_as as u32;
                self.negotiated_hold_time = self.local.hold_time.min(open.hold_time);
                self.timers = BgpTimers::new(self.negotiated_hold_time);
                self.timers.reset_hold_timer();
                self.transition(BgpEvent::BgpOpen);
                stream.write_all(&KeepaliveMessage.serialize()).await?;
                debug!(peer = %self.addr, "Sent KEEPALIVE (OPEN acknowledgement)");
            }
            MessageType::Keepalive => {
                debug!(peer = %self.addr, "Received KEEPALIVE");
                self.timers.reset_hold_timer();
                if self.state == BgpState::OpenConfirm {
                    self.transition(BgpEvent::KeepAliveMsg);
                    self.timers.reset_keepalive_timer();
                    info!(peer = %self.addr, "BGP session established 🎉");
                }
            }
            MessageType::Update => {
                let update = UpdateMessage::parse(msg.body)?;
                self.timers.reset_hold_timer();
                self.transition(BgpEvent::UpdateMsg);

                let nlri_count = update.nlri.len();
                let withdrawn_count = update.withdrawn_routes.len();

                if let Ok(mut rib) = self.rib.write() {
                    rib.process_update(
                        self.addr,
                        self.remote_as,
                        &update.nlri,
                        &update.path_attributes,
                        &update.withdrawn_routes,
                    );
                    let (_, _, loc_count) = rib.summary();
                    info!(
                        peer = %self.addr,
                        "+{} -{} routes | Loc-RIB: {} prefixes",
                        nlri_count, withdrawn_count, loc_count
                    );
                }
            }
            MessageType::Notification => {
                let notif = NotificationMessage::parse(msg.body)?;
                warn!(peer = %self.addr, "Received NOTIFICATION code={} subcode={}", notif.error_code, notif.error_subcode);
                self.transition(BgpEvent::NotifMsg);
                if let Ok(mut rib) = self.rib.write() {
                    rib.remove_peer(self.addr);
                }
            }
            MessageType::RouteRefresh => {
                debug!(peer = %self.addr, "Received ROUTE-REFRESH");
            }
        }
        Ok(())
    }
}
