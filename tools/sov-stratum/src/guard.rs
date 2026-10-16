//! Connection and share-rate limits for a stratum port on the open internet.
//!
//! Fake shares already earn nothing: every submission is re-sealed. The cost
//! that has to be bounded is CPU and threads — connection floods and share
//! spam that keep the verifier busy.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default simultaneous connections from one address.
pub const DEFAULT_MAX_PER_IP: usize = 16;
/// Default accepted-or-attempted shares per second per address.
pub const DEFAULT_SHARE_RATE: u64 = 30;
/// Strikes (rate-limit hits) before the address is banned.
const BAN_AFTER: u32 = 8;
/// How long a ban lasts.
const BAN_FOR: Duration = Duration::from_secs(10 * 60);

struct Rate {
    window_start: Instant,
    count: u64,
    strikes: u32,
}

/// Per-address connection cap, share-rate limit, and a short ban.
pub struct Guard {
    max_per_ip: usize,
    share_per_sec: u64,
    conns: Mutex<HashMap<IpAddr, usize>>,
    rates: Mutex<HashMap<IpAddr, Rate>>,
    bans: Mutex<HashMap<IpAddr, Instant>>,
}

impl Guard {
    /// Limits used by the running bridge.
    pub fn new(max_per_ip: usize, share_per_sec: u64) -> Self {
        Self {
            max_per_ip: max_per_ip.max(1),
            share_per_sec: share_per_sec.max(1),
            conns: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
            bans: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `ip` is currently banned.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let mut bans = self.bans.lock().expect("bans");
        match bans.get(&ip).copied() {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                bans.remove(&ip);
                false
            }
            None => false,
        }
    }

    /// Reserve a connection slot. `false` if banned or at the per-address cap.
    pub fn allow_conn(&self, ip: IpAddr) -> bool {
        if self.is_banned(ip) {
            return false;
        }
        let mut conns = self.conns.lock().expect("conns");
        let n = conns.entry(ip).or_insert(0);
        if *n >= self.max_per_ip {
            return false;
        }
        *n += 1;
        true
    }

    /// Release a slot reserved by [`allow_conn`](Self::allow_conn).
    pub fn release_conn(&self, ip: IpAddr) {
        let mut conns = self.conns.lock().expect("conns");
        if let Some(n) = conns.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                conns.remove(&ip);
            }
        }
    }

    /// One share attempt. `false` when the address is over its rate (and may
    /// now be banned). Call this before the seal, so a flood never reaches
    /// the verifier.
    pub fn allow_share(&self, ip: IpAddr) -> bool {
        if self.is_banned(ip) {
            return false;
        }
        let mut rates = self.rates.lock().expect("rates");
        let entry = rates.entry(ip).or_insert(Rate {
            window_start: Instant::now(),
            count: 0,
            strikes: 0,
        });
        if entry.window_start.elapsed() >= Duration::from_secs(1) {
            entry.window_start = Instant::now();
            entry.count = 0;
        }
        if entry.count >= self.share_per_sec {
            entry.strikes = entry.strikes.saturating_add(1);
            let strikes = entry.strikes;
            drop(rates);
            if strikes >= BAN_AFTER {
                self.bans
                    .lock()
                    .expect("bans")
                    .insert(ip, Instant::now() + BAN_FOR);
            }
            return false;
        }
        entry.count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
    }

    #[test]
    fn per_ip_cap_refuses_the_extra_connection() {
        let guard = Guard::new(2, 100);
        assert!(guard.allow_conn(ip()));
        assert!(guard.allow_conn(ip()));
        assert!(!guard.allow_conn(ip()));
        guard.release_conn(ip());
        assert!(guard.allow_conn(ip()));
    }

    #[test]
    fn share_rate_then_ban() {
        let guard = Guard::new(4, 2);
        assert!(guard.allow_share(ip()));
        assert!(guard.allow_share(ip()));
        assert!(!guard.allow_share(ip()));
        for _ in 0..BAN_AFTER {
            let _ = guard.allow_share(ip());
        }
        assert!(guard.is_banned(ip()));
        assert!(!guard.allow_conn(ip()));
    }
}
