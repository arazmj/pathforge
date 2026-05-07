use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::Instant;

/// BGP timer state.
#[derive(Debug)]
pub struct BgpTimers {
    /// Negotiated hold time in seconds (0 means disabled).
    pub hold_time: u16,
    /// Keepalive interval (hold_time / 3).
    pub keepalive_interval: u16,
    /// When the hold timer was last reset.
    pub hold_timer_start: Option<Instant>,
    /// When the keepalive timer was last reset.
    pub keepalive_timer_start: Option<Instant>,
}

impl BgpTimers {
    pub fn new(hold_time: u16) -> Self {
        let keepalive_interval = if hold_time > 0 { hold_time / 3 } else { 0 };
        Self {
            hold_time,
            keepalive_interval,
            hold_timer_start: None,
            keepalive_timer_start: None,
        }
    }

    pub fn reset_hold_timer(&mut self) {
        if self.hold_time > 0 {
            self.hold_timer_start = Some(Instant::now());
        }
    }

    pub fn reset_keepalive_timer(&mut self) {
        if self.keepalive_interval > 0 {
            self.keepalive_timer_start = Some(Instant::now());
        }
    }

    pub fn hold_timer_expired(&self) -> bool {
        if self.hold_time == 0 {
            return false;
        }
        self.hold_timer_start
            .map(|s| s.elapsed() >= Duration::from_secs(self.hold_time as u64))
            .unwrap_or(false)
    }

    pub fn keepalive_due(&self) -> bool {
        if self.keepalive_interval == 0 {
            return false;
        }
        self.keepalive_timer_start
            .map(|s| s.elapsed() >= Duration::from_secs(self.keepalive_interval as u64))
            .unwrap_or(true) // Send immediately if timer not yet started
    }
}

/// Configuration for a local BGP speaker.
#[derive(Debug, Clone)]
pub struct LocalConfig {
    pub local_as: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
}

impl LocalConfig {
    pub fn new(local_as: u32, router_id: Ipv4Addr) -> Self {
        Self {
            local_as,
            router_id,
            hold_time: 90,
        }
    }
}
