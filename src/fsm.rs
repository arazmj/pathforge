/// BGP Finite State Machine states as defined in RFC 4271 Section 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BgpState {
    /// The BGP peer is not active. Waiting for a start event.
    Idle,
    /// Waiting for the TCP connection to be established.
    Connect,
    /// TCP connection failed; listening for incoming connections.
    Active,
    /// TCP connection established; OPEN message sent, waiting for peer's OPEN.
    OpenSent,
    /// OPEN received and validated; KEEPALIVE sent, waiting for peer's KEEPALIVE.
    OpenConfirm,
    /// BGP session fully established; exchanging UPDATE messages.
    Established,
}

impl std::fmt::Display for BgpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BgpState::Idle => write!(f, "Idle"),
            BgpState::Connect => write!(f, "Connect"),
            BgpState::Active => write!(f, "Active"),
            BgpState::OpenSent => write!(f, "OpenSent"),
            BgpState::OpenConfirm => write!(f, "OpenConfirm"),
            BgpState::Established => write!(f, "Established"),
        }
    }
}

/// BGP FSM events as defined in RFC 4271 Section 8.1.
#[derive(Debug, Clone)]
pub enum BgpEvent {
    /// Administrative start (operator brings up the peer).
    ManualStart,
    /// Administrative stop (operator brings down the peer).
    ManualStop,
    /// TCP connection successfully established.
    TcpConnectionConfirmed,
    /// TCP connection failed.
    TcpConnectionFail,
    /// Valid BGP OPEN message received.
    BgpOpen,
    /// KEEPALIVE message received.
    KeepAliveMsg,
    /// UPDATE message received.
    UpdateMsg,
    /// NOTIFICATION message received.
    NotifMsg,
    /// Hold timer expired.
    HoldTimerExpired,
    /// Keepalive timer expired (time to send a KEEPALIVE).
    KeepaliveTimerExpired,
}
