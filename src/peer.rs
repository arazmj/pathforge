use anyhow::Result;
use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument, warn};

use crate::capabilities::Capability;
use crate::fsm::{BgpEvent, BgpState};
use crate::message::keepalive::KeepaliveMessage;
use crate::message::notification::NotificationMessage;
use crate::message::open::OpenMessage;
use crate::message::update::UpdateMessage;
use crate::message::{BgpMessage, MessageType};
use crate::metrics::Metrics;
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
    pub peer_capabilities: Vec<Capability>,
    pub rib: Arc<RwLock<Rib>>,
    pub metrics: Arc<Metrics>,
}

impl Peer {
    pub fn new(
        addr: SocketAddr,
        remote_as: u32,
        local: LocalConfig,
        rib: Arc<RwLock<Rib>>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let timers = BgpTimers::new(local.hold_time);
        Self {
            addr,
            remote_as,
            local,
            state: BgpState::Idle,
            timers,
            negotiated_hold_time: 90,
            peer_router_id: None,
            peer_capabilities: Vec::new(),
            rib,
            metrics,
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
    #[instrument(name = "bgp_session", skip_all, fields(peer = %peer_addr))]
    pub async fn handle_incoming(
        stream: TcpStream,
        peer_addr: SocketAddr,
        local: LocalConfig,
        rib: Arc<RwLock<Rib>>,
        metrics: Arc<Metrics>,
    ) -> Result<()> {
        info!("Incoming TCP connection");
        metrics.inc(&metrics.sessions_active);
        let mut peer = Peer::new(peer_addr, 0, local.clone(), rib, metrics);
        peer.transition(BgpEvent::ManualStart);
        peer.transition(BgpEvent::TcpConnectionConfirmed);
        peer.run_session(stream).await
    }

    /// Run the BGP session event loop on an established TCP stream.
    #[instrument(name = "session_loop", skip_all, fields(peer = %self.addr))]
    async fn run_session(&mut self, mut stream: TcpStream) -> Result<()> {
        self.metrics.inc(&self.metrics.messages_tx_open);

        // Send OPEN with capabilities (RFC 5492)
        let local_caps = [
            Capability::FourOctetAsn {
                asn: self.local.local_as,
            },
            Capability::RouteRefresh,
            Capability::MultiProtocol { afi: 1, safi: 1 }, // IPv4 Unicast
            Capability::GracefulRestart {
                restart_time: 120,
                flags: 0,
            },
        ];
        let open = OpenMessage::new_with_capabilities(
            self.local.local_as.min(u16::MAX as u32) as u16,
            self.local.hold_time,
            self.local.router_id,
            &local_caps,
        );
        stream.write_all(&open.serialize()).await?;
        debug!(peer = %self.addr, "Sent OPEN (AS={}, hold_time={})", self.local.local_as, self.local.hold_time);

        let mut buf = BytesMut::with_capacity(4096);

        loop {
            // Check hold timer
            if self.timers.hold_timer_expired() {
                warn!(peer = %self.addr, "Hold timer expired");
                self.metrics.inc(&self.metrics.hold_timer_expirations);
                let notif = NotificationMessage::hold_timer_expired();
                let _ = stream.write_all(&notif.serialize()).await;
                self.metrics.inc(&self.metrics.messages_tx_notification);
                self.transition(BgpEvent::HoldTimerExpired);
                self.metrics.inc(&self.metrics.sessions_failed);
                self.metrics.set(&self.metrics.sessions_active, 0);
                self.handle_disconnect().await;
                return Ok(());
            }

            // Send KEEPALIVE if due (Established state)
            if self.state == BgpState::Established && self.timers.keepalive_due() {
                stream.write_all(&KeepaliveMessage.serialize()).await?;
                self.timers.reset_keepalive_timer();
                self.metrics.inc(&self.metrics.messages_tx_keepalive);
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
                            self.metrics.set(&self.metrics.sessions_active, 0);
                            self.handle_disconnect().await;
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

    /// Handle peer disconnect: use Graceful Restart (RFC 4724) if negotiated,
    /// otherwise remove routes immediately.
    async fn handle_disconnect(&mut self) {
        let peer_supports_gr = self
            .peer_capabilities
            .iter()
            .any(|c| matches!(c, Capability::GracefulRestart { .. }));

        let restart_time = self
            .peer_capabilities
            .iter()
            .find_map(|c| {
                if let Capability::GracefulRestart { restart_time, .. } = c {
                    Some(*restart_time)
                } else {
                    None
                }
            })
            .unwrap_or(120);

        if peer_supports_gr && self.state == BgpState::Established {
            info!(
                peer = %self.addr,
                "Peer supports Graceful Restart — marking routes stale ({}s timer)",
                restart_time
            );
            if let Ok(mut rib) = self.rib.write() {
                rib.mark_peer_stale(self.addr);
            }
            // Spawn background task to purge stale routes after restart_time
            let rib = self.rib.clone();
            let addr = self.addr;
            tokio::spawn(async move {
                sleep(Duration::from_secs(restart_time as u64)).await;
                if let Ok(mut rib) = rib.write() {
                    let removed = rib.remove_stale_for_peer(addr);
                    if !removed.is_empty() {
                        tracing::info!(
                            peer = %addr,
                            "Graceful restart timer expired: purged {} stale routes",
                            removed.len()
                        );
                    }
                }
            });
        } else if let Ok(mut rib) = self.rib.write() {
            let removed = rib.remove_peer(self.addr);
            if !removed.is_empty() {
                info!(peer = %self.addr, "Withdrew {} routes from RIB", removed.len());
            }
        }
    }

    #[instrument(name = "bgp_msg", skip_all, fields(peer = %self.addr, msg_type = ?msg.header.msg_type))]
    async fn handle_message(&mut self, msg: BgpMessage, stream: &mut TcpStream) -> Result<()> {
        match msg.header.msg_type {
            MessageType::Open => {
                self.metrics.inc(&self.metrics.messages_rx_open);
                let open = OpenMessage::parse(msg.body)?;
                self.peer_capabilities = Capability::parse_from_open_params(&open.optional_params);
                let cap_strs: Vec<String> = self
                    .peer_capabilities
                    .iter()
                    .map(|c| c.to_string())
                    .collect();
                info!(
                    peer = %self.addr,
                    "Received OPEN AS={} hold_time={} id={} caps=[{}]",
                    open.my_as, open.hold_time, open.bgp_id, cap_strs.join(", ")
                );
                self.peer_router_id = Some(open.bgp_id);
                self.remote_as = open.my_as as u32;
                self.negotiated_hold_time = self.local.hold_time.min(open.hold_time);
                self.timers = BgpTimers::new(self.negotiated_hold_time);
                self.timers.reset_hold_timer();
                self.transition(BgpEvent::BgpOpen);
                stream.write_all(&KeepaliveMessage.serialize()).await?;
                self.metrics.inc(&self.metrics.messages_tx_keepalive);
                debug!(peer = %self.addr, "Sent KEEPALIVE (OPEN acknowledgement)");
            }
            MessageType::Keepalive => {
                self.metrics.inc(&self.metrics.messages_rx_keepalive);
                debug!(peer = %self.addr, "Received KEEPALIVE");
                self.timers.reset_hold_timer();
                if self.state == BgpState::OpenConfirm {
                    self.transition(BgpEvent::KeepAliveMsg);
                    self.timers.reset_keepalive_timer();
                    self.metrics.inc(&self.metrics.sessions_established);
                    info!(peer = %self.addr, "BGP session established");
                }
            }
            MessageType::Update => {
                self.metrics.inc(&self.metrics.messages_rx_update);
                let update = UpdateMessage::parse(msg.body)?;
                self.timers.reset_hold_timer();
                self.transition(BgpEvent::UpdateMsg);

                let nlri_count = update.nlri.len();
                let withdrawn_count = update.withdrawn_routes.len();

                // RFC 4724 §4.1: End-of-RIB marker — empty withdrawn, empty NLRI, empty attrs
                let is_end_of_rib =
                    nlri_count == 0 && withdrawn_count == 0 && update.path_attributes.is_empty();

                self.metrics
                    .routes_received
                    .fetch_add(nlri_count as u64, std::sync::atomic::Ordering::Relaxed);
                self.metrics
                    .routes_withdrawn
                    .fetch_add(withdrawn_count as u64, std::sync::atomic::Ordering::Relaxed);

                if let Ok(mut rib) = self.rib.write() {
                    rib.process_update(
                        self.addr,
                        self.remote_as,
                        &update.nlri,
                        &update.path_attributes,
                        &update.withdrawn_routes,
                    );

                    if is_end_of_rib {
                        // Remove any stale routes not refreshed by the restarting peer
                        let stale_removed = rib.remove_stale_for_peer(self.addr);
                        if !stale_removed.is_empty() {
                            info!(
                                peer = %self.addr,
                                "End-of-RIB: removed {} stale routes",
                                stale_removed.len()
                            );
                        } else {
                            debug!(peer = %self.addr, "End-of-RIB received");
                        }
                    }

                    let (_, _, loc_count) = rib.summary();
                    self.metrics
                        .routes_loc_rib
                        .store(loc_count as u64, std::sync::atomic::Ordering::Relaxed);
                    if nlri_count > 0 || withdrawn_count > 0 {
                        info!(
                            peer = %self.addr,
                            "+{} -{} routes | Loc-RIB: {} prefixes",
                            nlri_count, withdrawn_count, loc_count
                        );
                    }
                }
            }
            MessageType::Notification => {
                self.metrics.inc(&self.metrics.messages_rx_notification);
                let notif = NotificationMessage::parse(msg.body)?;
                warn!(peer = %self.addr, "Received NOTIFICATION code={} subcode={}", notif.error_code, notif.error_subcode);
                self.transition(BgpEvent::NotifMsg);
                self.metrics.inc(&self.metrics.sessions_failed);
                self.metrics.set(&self.metrics.sessions_active, 0);
                // NOTIFICATION means the peer is closing — remove routes immediately
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
