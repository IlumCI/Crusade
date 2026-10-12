//! The TCP connect scanner.
//!
//! [`TcpScanner`] fans out connection attempts across the configured ports of
//! each target, bounded by the [`RateLimiter`]. It only ever completes a TCP
//! handshake — a port that accepts the connection is reported open; everything
//! else (refused, timed out, unreachable) is silently dropped.
//!
//! The blocklist is consulted twice: once up front when building the work list,
//! and again just before each connect, so a blocked address can never be reached
//! even if one is passed directly to [`TcpScanner::scan`].

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use tokio::net::TcpStream;

use crate::blocklist::Blocklist;
use crate::rate::{RateLimiter, RateLimiterParams};

/// Configuration for a scan run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Ports to probe on every target.
    pub ports: Vec<u16>,
    /// Per-connection timeout.
    pub connect_timeout: Duration,
    /// Rate-limiter tuning (connections/sec and concurrency).
    pub rate: RateLimiterParams,
    /// Whether to permit the built-in private/loopback ranges (for a sanctioned
    /// local test rig). Mirrors [`Blocklist`]'s own toggle.
    pub allow_private: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            ports: vec![80, 443],
            connect_timeout: Duration::from_secs(3),
            rate: RateLimiterParams::default(),
            allow_private: false,
        }
    }
}

/// A rate-limited, blocklist-enforcing TCP connect scanner.
#[derive(Debug)]
pub struct TcpScanner {
    config: ScanConfig,
    blocklist: Blocklist,
    limiter: RateLimiter,
}

impl TcpScanner {
    /// Build a scanner from a config and the blocklist it must honour.
    ///
    /// Note the blocklist is authoritative for what may be connected to; its own
    /// `allow_private` governs enforcement (keep it consistent with
    /// [`ScanConfig::allow_private`]).
    pub fn new(config: ScanConfig, blocklist: Blocklist) -> Self {
        let limiter = RateLimiter::new(config.rate);
        TcpScanner { config, blocklist, limiter }
    }

    /// The blocklist this scanner enforces.
    pub fn blocklist(&self) -> &Blocklist {
        &self.blocklist
    }

    /// Scan `targets` and return the `(ip, port)` pairs that accepted a TCP
    /// connection. Blocked addresses are skipped and never connected to.
    pub async fn scan(&self, targets: &[IpAddr]) -> Vec<(IpAddr, u16)> {
        // Build the work list, dropping blocked addresses up front.
        let mut jobs: Vec<(IpAddr, u16)> = Vec::new();
        for &ip in targets {
            if self.blocklist.is_blocked(ip) {
                tracing::warn!(%ip, "refusing to scan blocklisted address");
                continue;
            }
            for &port in &self.config.ports {
                jobs.push((ip, port));
            }
        }

        let concurrency = self.config.rate.concurrency.max(1);
        stream::iter(jobs)
            .map(|(ip, port)| self.probe_one(ip, port))
            .buffer_unordered(concurrency)
            .filter_map(|result| async move { result })
            .collect()
            .await
    }

    /// Attempt a single connection, honouring the rate limiter and re-checking
    /// the blocklist defensively. Returns `Some` only on a completed handshake.
    async fn probe_one(&self, ip: IpAddr, port: u16) -> Option<(IpAddr, u16)> {
        // Hold the permit for the whole connection attempt.
        let _permit = self.limiter.acquire().await;

        // Defence in depth: never connect to a blocked address, even if it
        // somehow reached this far.
        if self.blocklist.is_blocked(ip) {
            tracing::warn!(%ip, "refusing to connect to blocklisted address");
            return None;
        }

        let addr = SocketAddr::new(ip, port);
        match tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => Some((ip, port)),
            // Refused, unreachable, or timed out: not open (for our purposes).
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_skips_blocked_targets_without_connecting() {
        // allow_private = false, so loopback/private/reserved are all blocked.
        let config = ScanConfig {
            ports: vec![80, 443],
            connect_timeout: Duration::from_millis(50),
            rate: RateLimiterParams::default(),
            allow_private: false,
        };
        let scanner = TcpScanner::new(config, Blocklist::new(false));

        // Every target here is blocked (loopback, RFC1918, documentation), so
        // no real connection is attempted and the result is empty.
        let targets = vec![
            "127.0.0.1".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
        ];
        let open = scanner.scan(&targets).await;
        assert!(open.is_empty());
    }

    #[test]
    fn default_config_is_conservative() {
        let c = ScanConfig::default();
        assert_eq!(c.rate.conn_per_sec, 100.0);
        assert_eq!(c.rate.concurrency, 50);
        assert!(!c.allow_private);
    }
}
