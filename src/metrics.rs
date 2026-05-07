use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// BGP daemon metrics counters.
///
/// All counters use atomic u64 for thread-safe updates without locking.
pub struct Metrics {
    // Session counters
    pub sessions_established: AtomicU64,
    pub sessions_failed: AtomicU64,
    pub sessions_active: AtomicU64,

    // Message counters
    pub messages_rx_open: AtomicU64,
    pub messages_rx_keepalive: AtomicU64,
    pub messages_rx_update: AtomicU64,
    pub messages_rx_notification: AtomicU64,
    pub messages_tx_open: AtomicU64,
    pub messages_tx_keepalive: AtomicU64,
    pub messages_tx_update: AtomicU64,
    pub messages_tx_notification: AtomicU64,

    // Route counters
    pub routes_received: AtomicU64,
    pub routes_withdrawn: AtomicU64,
    pub routes_loc_rib: AtomicU64,
    pub routes_advertised: AtomicU64,

    // Error counters
    pub hold_timer_expirations: AtomicU64,
    pub parse_errors: AtomicU64,
    pub fsm_errors: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            sessions_established: AtomicU64::new(0),
            sessions_failed: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            messages_rx_open: AtomicU64::new(0),
            messages_rx_keepalive: AtomicU64::new(0),
            messages_rx_update: AtomicU64::new(0),
            messages_rx_notification: AtomicU64::new(0),
            messages_tx_open: AtomicU64::new(0),
            messages_tx_keepalive: AtomicU64::new(0),
            messages_tx_update: AtomicU64::new(0),
            messages_tx_notification: AtomicU64::new(0),
            routes_received: AtomicU64::new(0),
            routes_withdrawn: AtomicU64::new(0),
            routes_loc_rib: AtomicU64::new(0),
            routes_advertised: AtomicU64::new(0),
            hold_timer_expirations: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            fsm_errors: AtomicU64::new(0),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set(&self, counter: &AtomicU64, value: u64) {
        counter.store(value, Ordering::Relaxed);
    }

    pub fn get(&self, counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Render metrics in Prometheus exposition format.
    pub fn prometheus_text(&self) -> String {
        let mut out = String::new();

        macro_rules! gauge {
            ($name:expr, $help:expr, $counter:expr) => {
                out.push_str(&format!("# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                    $name, $help, $name, $name, self.get($counter)));
            };
        }
        macro_rules! counter {
            ($name:expr, $help:expr, $counter:expr) => {
                out.push_str(&format!("# HELP {} {}\n# TYPE {} counter\n{} {}\n",
                    $name, $help, $name, $name, self.get($counter)));
            };
        }

        gauge!("bgp_sessions_active", "Currently active BGP sessions", &self.sessions_active);
        counter!("bgp_sessions_established_total", "Total BGP sessions ever established", &self.sessions_established);
        counter!("bgp_sessions_failed_total", "Total BGP session failures", &self.sessions_failed);

        counter!("bgp_messages_received_total{type=\"open\"}", "OPEN messages received", &self.messages_rx_open);
        counter!("bgp_messages_received_total{type=\"keepalive\"}", "KEEPALIVE messages received", &self.messages_rx_keepalive);
        counter!("bgp_messages_received_total{type=\"update\"}", "UPDATE messages received", &self.messages_rx_update);
        counter!("bgp_messages_received_total{type=\"notification\"}", "NOTIFICATION messages received", &self.messages_rx_notification);
        counter!("bgp_messages_sent_total{type=\"open\"}", "OPEN messages sent", &self.messages_tx_open);
        counter!("bgp_messages_sent_total{type=\"keepalive\"}", "KEEPALIVE messages sent", &self.messages_tx_keepalive);
        counter!("bgp_messages_sent_total{type=\"update\"}", "UPDATE messages sent", &self.messages_tx_update);
        counter!("bgp_messages_sent_total{type=\"notification\"}", "NOTIFICATION messages sent", &self.messages_tx_notification);

        counter!("bgp_routes_received_total", "Total routes received (NLRI)", &self.routes_received);
        counter!("bgp_routes_withdrawn_total", "Total routes withdrawn", &self.routes_withdrawn);
        gauge!("bgp_routes_loc_rib", "Current routes in Loc-RIB", &self.routes_loc_rib);
        counter!("bgp_routes_advertised_total", "Total routes advertised to peers", &self.routes_advertised);

        counter!("bgp_hold_timer_expirations_total", "Hold timer expiration events", &self.hold_timer_expirations);
        counter!("bgp_parse_errors_total", "BGP message parse errors", &self.parse_errors);
        counter!("bgp_fsm_errors_total", "BGP FSM state errors", &self.fsm_errors);

        out
    }

    /// Render metrics as human-readable text (for management socket).
    pub fn text_summary(&self) -> String {
        format!(
            "PathForge BGP Metrics\n\
             =====================\n\
             Sessions:\n\
               active:      {}\n\
               established: {} (total)\n\
               failed:      {} (total)\n\
             Messages received:\n\
               OPEN:         {}\n\
               KEEPALIVE:    {}\n\
               UPDATE:       {}\n\
               NOTIFICATION: {}\n\
             Messages sent:\n\
               OPEN:         {}\n\
               KEEPALIVE:    {}\n\
               UPDATE:       {}\n\
               NOTIFICATION: {}\n\
             Routes:\n\
               Loc-RIB:    {}\n\
               received:   {} (total)\n\
               withdrawn:  {} (total)\n\
               advertised: {} (total)\n\
             Errors:\n\
               hold timer:  {}\n\
               parse:       {}\n\
               fsm:         {}\n",
            self.get(&self.sessions_active),
            self.get(&self.sessions_established),
            self.get(&self.sessions_failed),
            self.get(&self.messages_rx_open),
            self.get(&self.messages_rx_keepalive),
            self.get(&self.messages_rx_update),
            self.get(&self.messages_rx_notification),
            self.get(&self.messages_tx_open),
            self.get(&self.messages_tx_keepalive),
            self.get(&self.messages_tx_update),
            self.get(&self.messages_tx_notification),
            self.get(&self.routes_loc_rib),
            self.get(&self.routes_received),
            self.get(&self.routes_withdrawn),
            self.get(&self.routes_advertised),
            self.get(&self.hold_timer_expirations),
            self.get(&self.parse_errors),
            self.get(&self.fsm_errors),
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment() {
        let m = Metrics::new();
        m.inc(&m.sessions_established);
        m.inc(&m.sessions_established);
        m.inc(&m.messages_rx_update);
        assert_eq!(m.get(&m.sessions_established), 2);
        assert_eq!(m.get(&m.messages_rx_update), 1);
        assert_eq!(m.get(&m.sessions_active), 0);
    }

    #[test]
    fn test_prometheus_output() {
        let m = Metrics::new();
        m.inc(&m.sessions_active);
        m.inc(&m.routes_received);
        m.inc(&m.routes_received);
        let out = m.prometheus_text();
        assert!(out.contains("bgp_sessions_active 1"));
        assert!(out.contains("bgp_routes_received_total 2"));
        assert!(out.contains("# HELP"));
        assert!(out.contains("# TYPE"));
    }

    #[test]
    fn test_text_summary() {
        let m = Metrics::new();
        m.set(&m.routes_loc_rib, 42);
        let out = m.text_summary();
        assert!(out.contains("Loc-RIB:    42"));
    }

    #[test]
    fn test_thread_safe_shared() {
        let m = Metrics::shared();
        let m2 = m.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..1000 {
                m2.inc(&m2.messages_rx_keepalive);
            }
        });
        for _ in 0..1000 {
            m.inc(&m.messages_rx_keepalive);
        }
        handle.join().unwrap();
        assert_eq!(m.get(&m.messages_rx_keepalive), 2000);
    }
}
